/**
 * Remove the live RBAC fixtures (webapp/scripts/e2e-rbac-seed.mjs, and the `upg-*`
 * accounts of the upgrade harness should one ever reach this database): every
 * `rbac-*@e2e.local` / `upg-*@e2e.local` user, their projects with the projects' graph
 * nodes and agent checkpoints, and the audit rows their sessions left.
 *
 * Each project goes in the order DELETE /api/projects/[id] uses for the rows the
 * seed and the matrix create: queued jobs canceled, authorization records checked,
 * then the project's graph and the checkpoints of its agent runs, then the row (its
 * conversations, remediations, reports and schedules cascade), then the agent
 * workspace a matrix read may have created purged. The seed writes no authorization
 * record; a project that has one is left in place and reported, because only the
 * delete route may archive it.
 *
 * The graph and the checkpoints are found by the project and user ids, which exist
 * only while the rows do, so they go first: when either cannot be cleared no row is
 * deleted, the script exits 1, and a rerun finishes the job. A checkpoint thread is
 * "<user>:<project>:<session>"; besides the fixtures' own, the threads of an `rbac-*`
 * session (the stub-run drivers name theirs so) whose user and project are both gone
 * are removed: an earlier run's leftovers, never a live account's or project's.
 *
 * The matrix deletes its throwaway account (`rbac-deleted@e2e.local`) by SQL in the
 * middle of a run, so it is no longer a user here: the seed gives it a fixed id
 * (DELETED_FIXTURE_ID) and its rows are matched by that id, and failed sign-ins of any
 * fixture address by the address they record.
 *
 * Idempotent: a second run finds nothing and prints CLEANED=0.
 *
 * Run (no image rebuild needed, the script is read from the host):
 *   docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-rbac-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

// Exact shape, so a real account that merely starts with "rbac-" is never matched.
export const FIXTURE_EMAIL = /^(rbac|upg)-[a-z0-9-]+@e2e\.local$/
const FIXTURE_PREFIXES = ['rbac-', 'upg-']

// The seed's id for the account the matrix deletes mid-run (a test keeps them equal).
export const DELETED_FIXTURE_ID = 'rbac-deleted-fixture'

// Shared by every project that found them (graphRestore.ts GLOBAL_REFERENCE_LABELS,
// a test keeps them equal): never deleted with one project.
export const GLOBAL_REFERENCE_LABELS = ['CVE', 'MitreData', 'Capec']

// langgraph's Postgres checkpointer, in the application's database.
export const CHECKPOINT_TABLES = ['checkpoint_writes', 'checkpoint_blobs', 'checkpoints']

const LIVE_JOB_STATUSES = ['queued', 'dispatching', 'running', 'needs_review']

/** Delete the nodes of `projectIds`, keeping the shared reference nodes. Returns the count. */
export async function clearFixtureGraph(session, projectIds) {
  if (!projectIds.length) return 0
  const result = await session.run(
    `MATCH (n)
     WHERE n.project_id IN $pids AND NONE(l IN labels(n) WHERE l IN $excluded)
     DETACH DELETE n`,
    { pids: projectIds, excluded: GLOBAL_REFERENCE_LABELS },
  )
  return result.summary.counters.updates().nodesDeleted
}

/**
 * Delete the checkpoint rows of the fixtures' agent runs, and of `rbac-*` sessions whose
 * user and project are both gone. A missing table (no persistent checkpointer) is skipped.
 */
export async function deleteFixtureCheckpoints(db, { userIds, projectIds }) {
  let total = 0
  for (const table of CHECKPOINT_TABLES) {
    const [{ present }] = await db.$queryRawUnsafe(`SELECT to_regclass('public.${table}') IS NOT NULL AS present`)
    if (!present) continue
    total += await db.$executeRawUnsafe(
      `DELETE FROM "${table}" AS t
       WHERE split_part(t.thread_id, ':', 1) = ANY($1::text[])
          OR split_part(t.thread_id, ':', 2) = ANY($2::text[])
          OR (split_part(t.thread_id, ':', 3) LIKE 'rbac-%'
              AND NOT EXISTS (SELECT 1 FROM "users" u WHERE u.id = split_part(t.thread_id, ':', 1))
              AND NOT EXISTS (SELECT 1 FROM "projects" p WHERE p.id = split_part(t.thread_id, ':', 2)))`,
      userIds, projectIds,
    )
  }
  return total
}

/**
 * The whole cleanup, on injected clients: `prisma`, a Neo4j `graph` session (null when
 * the driver could not be loaded), `purgeWorkspace(projectId)` and `log` / `warn`.
 */
export async function cleanupRbacFixtures({ prisma, graph, purgeWorkspace, warn = console.error }) {
  const summary = { cleaned: 0, projectsDeleted: 0, auditRowsDeleted: 0, graphNodesDeleted: 0, checkpointRowsDeleted: 0, failed: false }

  const candidates = await prisma.user.findMany({
    where: { OR: FIXTURE_PREFIXES.map(prefix => ({ email: { startsWith: prefix, endsWith: '@e2e.local' } })) },
    select: { id: true, email: true },
  })
  const users = candidates.filter(u => FIXTURE_EMAIL.test(u.email))
  const userIds = users.map(u => u.id)
  const kept = new Set()

  const projects = userIds.length
    ? await prisma.project.findMany({ where: { userId: { in: userIds } }, select: { id: true, userId: true } })
    : []
  const deletable = []
  for (const p of projects) {
    await prisma.jobQueue.updateMany({
      where: { projectId: p.id, status: { in: LIVE_JOB_STATUSES } },
      data: { status: 'canceled', finishedAt: new Date() },
    })
    const authorizations = await prisma.engagementAuthorization.count({ where: { projectId: p.id } })
    if (authorizations > 0) {
      warn(`CLEANUP_ERROR: project ${p.id} holds ${authorizations} authorization record(s); delete it through DELETE /api/projects/${p.id}`)
      kept.add(p.userId)
      summary.failed = true
      continue
    }
    deletable.push(p)
  }
  const removable = userIds.filter(id => !kept.has(id))
  const projectIds = deletable.filter(p => !kept.has(p.userId)).map(p => p.id)

  // Before any row goes: the rows are the only record of which ids are fixtures'.
  try {
    if (projectIds.length && !graph) throw new Error('no Neo4j session')
    summary.graphNodesDeleted = await clearFixtureGraph(graph, projectIds)
    summary.checkpointRowsDeleted = await deleteFixtureCheckpoints(prisma, {
      userIds: [...removable, DELETED_FIXTURE_ID], projectIds,
    })
  } catch (err) {
    warn(`CLEANUP_ERROR: the fixtures' graph or agent checkpoints could not be cleared (${err?.code || err?.name || 'error'}); no fixture row was deleted, rerun the cleanup`)
    summary.failed = true
    return summary
  }

  for (const p of deletable) {
    if (kept.has(p.userId)) continue
    await prisma.project.delete({ where: { id: p.id } })
    summary.projectsDeleted += 1
    await purgeWorkspace(p.id)
  }

  const { count } = removable.length
    ? await prisma.user.deleteMany({ where: { id: { in: removable } } })
    : { count: 0 }
  summary.cleaned = count

  // Sign-ins, act-as and the routes the matrix calls write these rows; their actor
  // or target is a fixture account or project, so nothing else is touched. A failed
  // sign-in names no user, only the address it tried.
  const accountIds = [...removable, DELETED_FIXTURE_ID]
  const keptEmails = new Set(users.filter(u => kept.has(u.id)).map(u => u.email))
  const signIns = await prisma.auditLog.findMany({
    where: { actorId: null, OR: FIXTURE_PREFIXES.map(prefix => ({ after: { path: ['email'], string_starts_with: prefix } })) },
    select: { id: true, after: true },
  })
  const signInIds = signIns
    .filter(r => FIXTURE_EMAIL.test(String(r.after?.email ?? '')) && !keptEmails.has(r.after.email))
    .map(r => r.id)
  const audit = await prisma.auditLog.deleteMany({
    where: {
      OR: [
        { actorId: { in: accountIds } },
        { targetId: { in: [...accountIds, ...projectIds] } },
        { id: { in: signInIds } },
      ],
    },
  })
  const actAs = await prisma.actAsAudit.deleteMany({
    where: { OR: [{ adminId: { in: accountIds } }, { targetUserId: { in: accountIds } }] },
  })
  summary.auditRowsDeleted = audit.count + actAs.count
  return summary
}

function agentBaseUrl() {
  return process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://agent:8080'
}

/** Best-effort, like purgeProjectWorkspace: an unreachable agent never blocks cleanup. */
async function purgeWorkspace(projectId) {
  try {
    const res = await fetch(`${agentBaseUrl()}/workspace/project-purge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-internal-key': process.env.INTERNAL_API_KEY || '' },
      body: JSON.stringify({ projectId }),
      signal: AbortSignal.timeout(60_000),
    })
    if (!res.ok) console.error(`CLEANUP_WARN: workspace purge for ${projectId} answered ${res.status}`)
  } catch (err) {
    console.error(`CLEANUP_WARN: workspace purge for ${projectId} failed: ${err?.name || 'error'}`)
  }
}

async function openGraph() {
  try {
    const { default: neo4j } = await import('neo4j-driver')
    const driver = neo4j.driver(
      process.env.NEO4J_URI || 'bolt://localhost:7687',
      neo4j.auth.basic(process.env.NEO4J_USER || 'neo4j', process.env.NEO4J_PASSWORD || 'password'),
    )
    return { driver, session: driver.session() }
  } catch (err) {
    console.error(`CLEANUP_WARN: Neo4j unavailable: ${err?.code || err?.name || 'error'}`)
    return { driver: null, session: null }
  }
}

async function main() {
  const prisma = new PrismaClient()
  const { driver, session } = await openGraph()
  let failed = false
  try {
    const s = await cleanupRbacFixtures({ prisma, graph: session, purgeWorkspace })
    failed = s.failed
    console.log(`CLEANED=${s.cleaned}`)
    console.log(`PROJECTS_DELETED=${s.projectsDeleted}`)
    console.log(`AUDIT_ROWS_DELETED=${s.auditRowsDeleted}`)
    console.log(`GRAPH_NODES_DELETED=${s.graphNodesDeleted}`)
    console.log(`CHECKPOINT_ROWS_DELETED=${s.checkpointRowsDeleted}`)
  } catch (err) {
    console.error('CLEANUP_ERROR:', err.message)
    failed = true
  } finally {
    await session?.close()
    await driver?.close()
    await prisma.$disconnect()
  }
  if (failed) process.exitCode = 1
}

// Fed on stdin (`node --input-type=module -`, the documented way) or run as a file;
// imported by its test, it only exports.
if (process.argv[1] === '-' || (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)) {
  await main()
}

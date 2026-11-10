/**
 * Remove the live RBAC matrix fixtures (webapp/scripts/e2e-rbac-seed.mjs): every
 * `rbac-*@e2e.local` user, their projects, and the audit rows their sessions left.
 *
 * Each project goes in the order DELETE /api/projects/[id] uses for the rows the
 * seed and the matrix create: queued jobs canceled, authorization records checked,
 * the row deleted (its conversations, remediations, reports and schedules cascade),
 * then the agent workspace a matrix read may have created purged. The seed writes
 * no authorization record; a project that has one is left in place and reported,
 * because only the delete route may archive it. No scan or agent run ever belongs
 * to these projects, so the route's stop calls have nothing to stop.
 *
 * Idempotent: a second run finds nothing and prints CLEANED=0.
 *
 * Run (no image rebuild needed, the script is read from the host):
 *   docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-rbac-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'

// Exact shape, so a real account that merely starts with "rbac-" is never matched.
const FIXTURE_EMAIL = /^rbac-[a-z0-9-]+@e2e\.local$/

const prisma = new PrismaClient()

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

let failed = false
try {
  const candidates = await prisma.user.findMany({
    where: { email: { startsWith: 'rbac-', endsWith: '@e2e.local' } },
    select: { id: true, email: true },
  })
  const users = candidates.filter(u => FIXTURE_EMAIL.test(u.email))
  const userIds = users.map(u => u.id)
  const kept = new Set()

  const projects = userIds.length
    ? await prisma.project.findMany({ where: { userId: { in: userIds } }, select: { id: true, userId: true } })
    : []
  let projectsDeleted = 0
  for (const p of projects) {
    await prisma.jobQueue.updateMany({
      where: { projectId: p.id, status: { in: ['queued', 'dispatching', 'running', 'needs_review'] } },
      data: { status: 'canceled', finishedAt: new Date() },
    })
    const authorizations = await prisma.engagementAuthorization.count({ where: { projectId: p.id } })
    if (authorizations > 0) {
      console.error(`CLEANUP_ERROR: project ${p.id} holds ${authorizations} authorization record(s); delete it through DELETE /api/projects/${p.id}`)
      kept.add(p.userId)
      failed = true
      continue
    }
    await prisma.project.delete({ where: { id: p.id } })
    projectsDeleted += 1
    await purgeWorkspace(p.id)
  }

  const removable = userIds.filter(id => !kept.has(id))
  const projectIds = projects.filter(p => !kept.has(p.userId)).map(p => p.id)
  const { count } = removable.length
    ? await prisma.user.deleteMany({ where: { id: { in: removable } } })
    : { count: 0 }
  // Sign-ins, act-as and the routes the matrix calls write these rows; their actor
  // or target is a fixture account or project, so nothing else is touched. A failed
  // sign-in of the passwordless account names no user, only the email it tried.
  const removableEmails = users.filter(u => !kept.has(u.id)).map(u => u.email)
  const audit = removable.length
    ? await prisma.auditLog.deleteMany({
      where: {
        OR: [
          { actorId: { in: removable } },
          { targetId: { in: [...removable, ...projectIds] } },
          ...removableEmails.map(email => ({ actorId: null, targetId: null, after: { path: ['email'], equals: email } })),
        ],
      },
    })
    : { count: 0 }
  const actAs = removable.length
    ? await prisma.actAsAudit.deleteMany({
      where: { OR: [{ adminId: { in: removable } }, { targetUserId: { in: removable } }] },
    })
    : { count: 0 }

  console.log(`CLEANED=${count}`)
  console.log(`PROJECTS_DELETED=${projectsDeleted}`)
  console.log(`AUDIT_ROWS_DELETED=${audit.count + actAs.count}`)
} catch (err) {
  console.error('CLEANUP_ERROR:', err.message)
  failed = true
} finally {
  await prisma.$disconnect()
}
if (failed) process.exitCode = 1

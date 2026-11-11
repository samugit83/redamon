/**
 * The teardown of one project: everything DELETE /api/projects/[id] does after its
 * access check, shared with DELETE /api/users/[id], which runs it for each of the
 * account's projects before deleting the account (HD-11). The database cascade
 * alone removes the rows but leaves the graph, the output files, the workspace and
 * any running work behind, and is refused outright by a project that holds an
 * engagement authorization (that foreign key is Restrict).
 *
 * The order is the contract. In-flight work stops first: a scan mid-write would
 * otherwise recreate the project's graph after the clear. The authorization
 * records are archived before the row. The workspace goes only once the row is
 * gone, because the agent purges only a project the web app answers 404 for. The
 * files and the graph go last.
 *
 * Two steps stop the teardown: the archive (nothing has been deleted when it
 * fails) and the row delete. Every other step is best effort and only reports
 * its outcome. Every step that names a tenant uses the project's owner, never the
 * actor: an admin deleting a member's account tears down the member's projects.
 */
import { unlink } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import prisma from '@/lib/prisma'
import { agentFetch } from '@/lib/agentFetch'
import { archiveProjectAuthorizations } from '@/lib/engagementArchive'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { batchGroupFiles } from '@/lib/reconOutputFiles'
import { clearProjectGraph } from '@/lib/graphRestore'
import { orchestratorFetch } from '@/lib/orchestrator'
import { purgeProjectWorkspace } from '@/lib/workspacePurge'
import { graphTriage } from '@/lib/triageClient'

// Fallback for the file deletion when the orchestrator is unreachable.
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export const TEARDOWN_STEPS = [
  'collect_body_refs',
  'cancel_jobs',
  'stop_triage',
  'stop_chats',
  'stop_scans',
  'archive_authorizations',
  'delete_project',
  'purge_workspace',
  'gc_bodies',
  'delete_files',
  'clear_graph',
] as const

export type TeardownStepName = typeof TEARDOWN_STEPS[number]

export interface TeardownStep {
  step: TeardownStepName
  outcome: 'ok' | 'failed' | 'skipped'
}

export type TeardownResult =
  | { ok: true; steps: TeardownStep[] }
  | {
    ok: false
    steps: TeardownStep[]
    failedStep: 'archive_authorizations'
    code: 'authorization_archive_failed'
  }
  | {
    ok: false
    steps: TeardownStep[]
    failedStep: 'delete_project'
    /** `project_not_found`: the row was already gone (P2025). */
    code: 'project_not_found' | 'delete_failed'
    /** The Prisma error, for the caller's own 404 / `internalError` answer. */
    error: unknown
  }

export interface TeardownOptions {
  /** Who asked: named in the log line of a failed step, never used as a tenant. */
  actorUserId: string
  /** Stored on each archived authorization record. */
  archiveReason?: string
}

/**
 * Stop every running partial recon of a project. They are run-keyed, so each
 * one is listed and stopped by id. A partial run over a Domain batch walks up to
 * fifty roots, long enough to keep writing into a project that no longer exists.
 */
async function stopPartialRecons(projectId: string): Promise<boolean> {
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/all`)
    if (!res.ok) return true
    const data = await res.json().catch(() => ({}))
    const runs: Array<{ run_id?: unknown; status?: unknown }> = Array.isArray(data?.runs) ? data.runs : []
    await Promise.allSettled(
      runs
        .filter(run => typeof run?.run_id === 'string'
          && (run.status === 'running' || run.status === 'starting' || run.status === 'stopping'))
        .map(run => orchestratorFetch(
          `${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${encodeURIComponent(run.run_id as string)}/stop?graceful=false`,
          { method: 'POST' },
        )),
    )
    return true
  } catch (e) {
    console.warn('Could not stop partial recons before project delete:', e)
    return false
  }
}

/** Stop every live chat run of a project, best-effort (never throws). */
async function stopProjectChatRuns(projectId: string): Promise<boolean> {
  let running: { userId: string; sessionId: string }[] = []
  try {
    running = await prisma.conversation.findMany({
      where: { projectId, agentRunning: true },
      select: { userId: true, sessionId: true },
    })
  } catch (e) {
    console.warn('Could not read the running chats before project delete:', e)
    return false
  }
  const results = await Promise.allSettled(running.map(c => agentFetch('/agent-session/stop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: c.userId, project_id: projectId, session_id: c.sessionId }),
  })))
  let allStopped = true
  results.forEach((r, i) => {
    if (r.status === 'rejected' || !r.value.ok) {
      allStopped = false
      console.warn(`Could not stop chat ${running[i].sessionId} before project delete (continuing)`)
    }
  })
  return allStopped
}

/** Delete the project's output JSON files: through the orchestrator, which can write them. */
async function deleteOutputFiles(id: string): Promise<boolean> {
  try {
    const orchestratorResponse = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/project/${id}/files`, {
      method: 'DELETE',
    })
    if (orchestratorResponse.ok) {
      const result = await orchestratorResponse.json()
      console.log(`Orchestrator deleted files:`, result.deleted)
      return true
    }
    console.warn(`Orchestrator failed to delete files: ${orchestratorResponse.status}`)
    return false
  } catch (orchestratorError) {
    console.warn(`Failed to call orchestrator for file deletion: ${orchestratorError}`)

    // Fallback: try to delete locally (may fail in Docker due to read-only mounts)
    const filesToDelete = [
      { path: path.join(RECON_OUTPUT_PATH, `recon_${id}.json`), name: 'recon' },
      ...(await batchGroupFiles(RECON_OUTPUT_PATH, id)).map(p => ({ path: p, name: 'recon group' })),
      { path: path.join(GVM_OUTPUT_PATH, `gvm_${id}.json`), name: 'GVM' },
      { path: path.join(GITHUB_HUNT_OUTPUT_PATH, `github_hunt_${id}.json`), name: 'GitHub hunt' },
    ]
    for (const file of filesToDelete) {
      if (existsSync(file.path)) {
        try {
          await unlink(file.path)
          console.log(`Deleted ${file.name} file locally: ${file.path}`)
        } catch (err) {
          console.warn(`Failed to delete ${file.name} file locally: ${err}`)
        }
      }
    }
    return false
  }
}

export async function teardownProject(
  project: { id: string; userId: string },
  opts: TeardownOptions,
): Promise<TeardownResult> {
  const { id } = project
  const steps: TeardownStep[] = []
  const record = (step: TeardownStepName, ok: boolean | 'skipped') => {
    steps.push({ step, outcome: ok === 'skipped' ? 'skipped' : ok ? 'ok' : 'failed' })
  }
  const logFatal = (step: TeardownStepName) => console.error(
    `[project-teardown] step=${step} failed project=${id} owner=${project.userId} actor=${opts.actorUserId}`)

  // Captured-traffic body refs are read BEFORE the cascade removes the rows, so
  // the now-unreferenced blobs can be ref-count collected afterwards (§6.6).
  // Prisma's cascade never touches the filesystem.
  let capturedBodyRefs: (string | null)[] = []
  try {
    const doomed = await prisma.capturedHttpTransaction.findMany({
      where: { projectId: id }, select: { reqBodyRef: true, respBodyRef: true },
    })
    capturedBodyRefs = doomed.flatMap(r => [r.reqBodyRef, r.respBodyRef])
    record('collect_body_refs', true)
  } catch (e) {
    console.warn('Could not enumerate captured body refs before project delete:', e)
    record('collect_body_refs', false)
  }

  // C-7: stop in-flight work BEFORE deleting. A container that is mid-write keeps
  // writing project_id-stamped nodes after the row is gone, resurrecting the
  // deleted project's graph as unreachable orphans; and a scanner falls back to
  // DEFAULT_*_SETTINGS on a 404, so a job dispatched against a deleted project
  // would scan with defaults. Cancel queued work and stop running scans first.
  try {
    await prisma.jobQueue.updateMany({
      where: { projectId: id, status: { in: ['queued', 'dispatching', 'running', 'needs_review'] } },
      data: { status: 'canceled', finishedAt: new Date() },
    })
    record('cancel_jobs', true)
  } catch (e) {
    console.warn('Could not cancel queued jobs before project delete:', e)
    record('cancel_jobs', false)
  }

  // A triage run lives in the agent's memory. Deleting the project without
  // telling it leaves the run working against a project that no longer
  // exists, for as long as it takes the next heartbeat to fail (X12).
  // Best-effort: an unreachable agent must not block the delete, because the
  // run's publish and heartbeat both fail closed on the missing project.
  try {
    const { status } = await graphTriage('stop_run', { userId: project.userId, projectId: id })
    record('stop_triage', status >= 200 && status < 300)
  } catch (e) {
    console.warn('Could not stop a triage run before project delete:', e)
    record('stop_triage', false)
  }
  // A running chat of this project is an orphan once the row is gone, whatever
  // its model, and an Agent in the Loop run would keep offering its steps to
  // the owner's agent. Stopped the way a conversation delete stops its run.
  // The conversations cascade with the project, so they are read first.
  record('stop_chats', await stopProjectChatRuns(id))
  // Best-effort stop of each PROJECT-LEVEL scan container. ai_attack runs are
  // keyed by run-id, not project, so they are not stopped here; they finish on
  // their own and their orphaned nodes are swept by the graph read-path
  // reconcile.
  // GVM and the GitHub hunt write a stopped run's saved results to the graph
  // before removing the container, as a backstop for a scan killed mid-write.
  // The graph is cleared below, so here that write could only land after the
  // clear and leave the deleted project's nodes behind: ingest=false skips it.
  // A recon stop drains its queued writes for up to RECON_STOP_GRACE_S unless
  // it is hard: graceful=false kills it and answers once it is gone.
  const stopQuery: Record<string, string> = {
    recon: '?graceful=false', gvm: '?ingest=false', 'github-hunt': '?ingest=false',
  }
  const stops = await Promise.allSettled([
    ...['recon', 'gvm', 'github-hunt', 'supply-chain'].map(kind =>
      orchestratorFetch(
        `${RECON_ORCHESTRATOR_URL}/${kind}/${id}/stop${stopQuery[kind] ?? ''}`,
        { method: 'POST' },
      ),
    ),
    // TruffleHog is run-keyed (one run per source, several in parallel), so a
    // single project-level stop would leave every source but one running with
    // its project row already gone. stop-all loops the nested state dict.
    orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${id}/stop-all`, { method: 'POST' }),
    stopPartialRecons(id),
  ])
  record('stop_scans', stops.every(s => s.status === 'fulfilled' && s.value !== false))

  // Archive the authorization records BEFORE the delete. Every other Project
  // child cascades; these do not, because the record of what authorized a
  // project is the thing an incident review needs most and deleting the
  // project is exactly when it stops being recoverable. The foreign key is
  // `Restrict`, so a failed archive fails the delete rather than quietly
  // taking the records with it.
  const archived = await archiveProjectAuthorizations(id, opts.archiveReason)
  if (archived.error) {
    record('archive_authorizations', false)
    logFatal('archive_authorizations')
    return { ok: false, steps, failedStep: 'archive_authorizations', code: 'authorization_archive_failed' }
  }
  record('archive_authorizations', true)
  if (archived.archived > 0) {
    console.log(`[project-delete] archived ${archived.archived} authorization record(s) for ${id}`)
  }

  // The row; its captured_http_transactions and job_queue rows cascade.
  try {
    await prisma.project.delete({ where: { id } })
    record('delete_project', true)
  } catch (error) {
    record('delete_project', false)
    const gone = !!error && typeof error === 'object' && 'code' in error && error.code === 'P2025'
    if (!gone) logFatal('delete_project')
    return { ok: false, steps, failedStep: 'delete_project', code: gone ? 'project_not_found' : 'delete_failed', error }
  }

  // The agent workspace, only once the row is gone: the agent acts only on a
  // project the web app answers 404 for.
  try {
    await purgeProjectWorkspace(id)
    record('purge_workspace', true)
  } catch (e) {
    console.warn(`[project-delete] workspace purge failed for ${id}:`, e)
    record('purge_workspace', false)
  }

  // GC captured body blobs this project exclusively owned (ref-counted).
  if (capturedBodyRefs.length > 0) {
    try {
      const { gcOrphanBodies } = await import('@/lib/captureBodies')
      const gc = await gcOrphanBodies(capturedBodyRefs)
      if (gc.deleted > 0) console.log(`[project-delete] GC'd ${gc.deleted} captured body blobs for project ${id}`)
      record('gc_bodies', true)
    } catch (e) {
      console.warn('Captured body-blob GC failed on project delete:', e)
      record('gc_bodies', false)
    }
  } else {
    record('gc_bodies', 'skipped')
  }

  // Recon, GVM and GitHub Secret Hunt output files.
  record('delete_files', await deleteOutputFiles(id))

  try {
    const session = getGraphSession()
    try {
      // Via the shared helper: a raw `MATCH (n {project_id})` here also swept
      // the global CVE/CWE/CAPEC nodes, which are shared with every other
      // project that found them, taking those projects' links down too.
      await clearProjectGraph(session, id)
      console.log(`Deleted Neo4j nodes for project: ${id}`)
    } finally {
      await session.close()
    }
    record('clear_graph', true)
  } catch (neo4jError) {
    console.warn(`Failed to delete Neo4j data: ${neo4jError}`)
    record('clear_graph', false)
  }

  return { ok: true, steps }
}

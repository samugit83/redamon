/**
 * The queue: "run it when the machine is free" instead of a dead end.
 *
 * A busy project is a hard refusal today. `start_recon` says no, and the agent
 * has no way to express "later", so it must invent a retry loop against a
 * per-project window that only allows one start every five minutes. The Scan
 * Queue already exists and the UI already uses it.
 *
 * WHY ITS OWN SCOPE, and it is not bureaucracy. A queued job dispatches LATER,
 * and there is no way to cancel it when the token is revoked: `JobQueue`
 * carries no token id and revoking writes only `revokedAt`, so work queued by a
 * credential outlives the credential. That is a materially different grant from
 * "start a scan now", and folding it into `recon:scan` would retroactively
 * widen every token already minted.
 *
 * Only the FULL recon is queueable. Partial recon lets the caller name hosts,
 * which makes its inputs target fields in disguise, and the other scanners each
 * need their own preconditions.
 */
import prisma from '@/lib/prisma'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { assertJobInProject } from '@/lib/mcp/childAccess'
import { enqueueJob } from '@/lib/enqueueJob'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

/** The only kind this surface queues. */
const KIND = 'full_recon'

/** States in which a job still exists as far as a caller is concerned. */
const ACTIVE = ['queued', 'dispatching', 'needs_review'] as const

/**
 * Cancellable states, identical to the UI's.
 *
 * `running` is absent on purpose: a dispatched scan is stopped with stop_recon,
 * not un-queued.
 */
const CANCELLABLE = ['queued', 'dispatching', 'needs_review'] as const

/**
 * How many jobs one project may have waiting at once.
 *
 * Nothing serialises enqueue - it is an unconditional create and `JobQueue` has
 * no uniqueness constraint - and the damage is upstream of the dispatcher: the
 * memory governor holds ONE process-global committed-bytes ledger across all
 * projects and all tenants, and the dispatcher breaks head-of-line rather than
 * skipping when the next job does not fit. So a few fat jobs from one caller
 * can stall every other tenant's queue.
 *
 * Ideally this would be per token. It cannot be: `JobQueue` has no column
 * recording which token queued a row, which is the same missing column that
 * makes revocation unable to cancel queued work. Per project is what the schema
 * supports today.
 */
const MAX_ACTIVE_PER_PROJECT = 3

/** `envelopeBytes` is a BigInt and JSON.stringify throws on one. */
const num = (v: unknown): number | null =>
  typeof v === 'bigint' ? Number(v) : typeof v === 'number' ? v : null

function describeJob(row: {
  id: string
  kind: string
  status: string
  priority: number
  blockedCode: string
  blockedReason: string
  enqueuedAt: Date
  envelopeBytes?: bigint | null
}) {
  return {
    jobId: row.id,
    kind: row.kind,
    status: row.status,
    priority: row.priority,
    enqueuedAt: row.enqueuedAt.toISOString(),
    ...(row.blockedCode ? { blockedCode: row.blockedCode, blockedReason: row.blockedReason } : {}),
    ...(row.envelopeBytes != null ? { envelopeBytes: num(row.envelopeBytes) } : {}),
  }
}

const JOB_NOTES = [
  'A queued job runs when the host has room, which can be minutes or hours. Poll it with ' +
    'get_project_activity or get_recon_status rather than re-queueing.',
  'A job whose status becomes "needs_review" is PARKED and will not run until a person ' +
    're-confirms it in the app: either the project settings changed after it was queued ' +
    '(blockedCode settings_changed), or its start got no answer from the orchestrator, so the ' +
    'scan may or may not have started (start_unknown). Nothing on this surface can re-confirm one.',
  'A start that fails on a passing error (the orchestrator answered 500 or 503) is retried with ' +
    'a growing backoff, for about 7.5 hours before the job is marked failed.',
  'A queued job OUTLIVES the token that created it. Revoking this token does not cancel it; ' +
    'cancel_queued_scan does.',
  'When it dispatches it behaves exactly like start_recon in "new" mode: the current graph is ' +
    'saved as a version first, which consumes a retention slot.',
]

/**
 * Queue a full recon for when the project is free.
 *
 * The `start` bucket, not `write`: an enqueue reaches the same dispatcher that
 * a start reaches, so metering it as an ordinary write would be an unmetered
 * path to the same version-retention churn the start bucket exists to bound.
 */
export async function queueRecon(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:queue')
  // OWNERSHIP FIRST. The start bucket is keyed per PROJECT, so its counter is
  // shared across every token in the deployment; charging it before proving
  // ownership let anyone holding a project id burn that project's
  // one-start-per-five-minutes window, and its owner was then refused with
  // "Rate limit reached for this token" - blaming their own credential for a
  // stranger's call. `startRecon` orders these the same way.
  await assertMcpProjectAccess(ctx.token, projectId)
  enforceRate(ctx, 'start', projectId, { perProject: true })

  // `enqueueJob` does NOT check ownership - its header says callers own that -
  // and does NOT dedupe: it is an unconditional create against a table with no
  // uniqueness constraint, so an agent retry loop mints duplicate jobs.
  const active = await prisma.jobQueue.findMany({
    where: { projectId, status: { in: [...ACTIVE] } },
    select: {
      id: true, kind: true, status: true, priority: true,
      blockedCode: true, blockedReason: true, enqueuedAt: true, envelopeBytes: true,
    },
    orderBy: { enqueuedAt: 'asc' },
  })

  const sameKind = active.find(j => j.kind === KIND)
  if (sameKind) {
    throw new McpToolError(
      `A full recon is already queued for this project (job ${sameKind.id}, status ` +
      `"${sameKind.status}"). Queueing a second would run the same scan twice. ` +
      (sameKind.status === 'needs_review'
        ? 'That job is parked awaiting a person (the project settings changed after it was ' +
          'queued, or its start got no answer), and nothing on this surface can re-confirm it.'
        : 'Wait for it, or cancel it first.'),
      'already_queued'
    )
  }

  if (active.length >= MAX_ACTIVE_PER_PROJECT) {
    throw new McpToolError(
      `This project already has ${active.length} jobs waiting, which is the limit. Wait for one ` +
      `to run or cancel one first.`,
      'busy'
    )
  }

  const result = await enqueueJob({ projectId, userId: ctx.token.userId, kind: KIND })
  if (!result.ok || !result.id) {
    throw new McpToolError(result.error || 'The scan could not be queued.', 'enqueue_failed')
  }

  const row = await prisma.jobQueue.findUnique({
    where: { id: result.id },
    select: {
      id: true, kind: true, status: true, priority: true,
      blockedCode: true, blockedReason: true, enqueuedAt: true, envelopeBytes: true,
    },
  })

  return {
    projectId,
    job: row ? describeJob(row) : { jobId: result.id, kind: KIND, status: 'queued' },
    notes: JOB_NOTES,
  }
}

/**
 * Cancel a job this token (or anyone) queued on this project.
 *
 * It must NOT copy the browser route's bug. That route's `updateMany` ignores
 * its `count`, so a job that flipped to `running` in the race window still
 * answers `{ok: true}` with nothing cancelled - and the caller believes it
 * stopped a scan that is in fact running. The guarded `where` is deliberate and
 * correct (every dispatch write is guarded the same way so a cancel landing
 * mid-dispatch is not resurrected); reading the count is the missing half.
 */
export async function cancelQueuedScan(ctx: McpContext, projectId: string, jobId: string) {
  requireScope(ctx.token, 'recon:queue')
  enforceRate(ctx, 'write')

  const job = await assertJobInProject(ctx.token, projectId, jobId)

  if (!(CANCELLABLE as readonly string[]).includes(job.status)) {
    throw new McpToolError(
      job.status === 'running'
        ? `Job ${jobId} has already started. Use stop_recon to stop the running scan.`
        : `Job ${jobId} is "${job.status}" and cannot be cancelled.`,
      'not_cancellable'
    )
  }

  const { count } = await prisma.jobQueue.updateMany({
    where: { id: jobId, status: { in: [...CANCELLABLE] } },
    data: { status: 'canceled', finishedAt: new Date(), blockedCode: '', blockedReason: '' },
  })

  if (count === 0) {
    // It changed state between the read and the write. Reporting success here
    // would tell the caller it stopped a scan that is now running.
    throw new McpToolError(
      `Job ${jobId} could not be cancelled: it had already started or finished. Re-read it ` +
      `with get_project_activity, and use stop_recon if a scan is now running.`,
      'lost_race'
    )
  }

  return {
    projectId,
    jobId,
    cancelled: true,
    priorStatus: job.status,
  }
}

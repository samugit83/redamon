/**
 * Tradecraft 2.0 ingestion jobs, the webapp's side (TD-8, phase 1 "Jobs and the pipeline").
 *
 * The webapp writes the job row with a start lease and claims the resource for it in one
 * transaction, then asks the agent to run it. The agent renews the lease of every job it holds,
 * queued or running; an unfinished job whose lease expired, or that never had one, runs nowhere,
 * so it no longer holds the claim (D-42, the `TriageRun` rule of triageRun.ts): the next start
 * fails it `agent_lost` and takes the resource. A cancel is a database flag the agent reads
 * between pages, so it reaches whichever copy of the agent runs the job.
 *
 * Nothing here starts a job on a timer: every job comes from a person's action (R-096).
 */
import type { Prisma, TradecraftIngestionJob, UserTradecraftResource } from '@prisma/client'
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { now } from '@/lib/authz/clock'
import type { AuditActor } from '@/lib/auditActor'
import { safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import {
  AGENT_ROUTES, Credentials, JobStartAnswer, JobStartBatch, UNFINISHED_JOB_STATUSES,
  type ErrorCode, type JobStartRequest,
} from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { ingestionHash } from './staleness'
import { SETTINGS_CONSTANTS } from './settingsSpec'
import { lockOwnResource } from './resourceAccess'

export const START_LEASE_MS: number = SETTINGS_CONSTANTS.jobStartLeaseSec * 1000

/** The kinds a person's click on one resource starts; Save & refresh all starts `bulk` ones (`startBulkJobs`). */
export const MANUAL_JOB_KINDS = ['add', 'refresh', 'reingest', 'regenerate_summary'] as const
export type ManualJobKind = (typeof MANUAL_JOB_KINDS)[number]

/** The agent only queues the job: a start that takes longer is a timeout, not a refusal. */
const START_TIMEOUT_MS = 15_000
const CANCEL_TIMEOUT_MS = 5_000

/** The person who started a job, and the administrator acting as them (D-08). */
export interface JobActor {
  actorUserId: string
  realActorUserId: string | null
}

/** The job's people from the request's audit actor; null without a signed-in person. */
export function jobActorOf(actor: AuditActor): JobActor | null {
  if (!actor.actorId) return null
  return actor.onBehalfOfUserId
    ? { actorUserId: actor.onBehalfOfUserId, realActorUserId: actor.actorId }
    : { actorUserId: actor.actorId, realActorUserId: null }
}

type JobRow = Pick<TradecraftIngestionJob,
  'id' | 'kind' | 'status' | 'stage' | 'progress' | 'errorCode' | 'cancelRequested' | 'leaseUntil' | 'createdAt' | 'startedAt' | 'finishedAt'>

export interface JobView {
  id: string
  kind: string
  status: string
  stage: string
  progress: unknown
  errorCode: string
  cancelRequested: boolean
  createdAt: string
  startedAt: string | null
  finishedAt: string | null
}

export function isUnfinished(status: string): boolean {
  return (UNFINISHED_JOB_STATUSES as readonly string[]).includes(status)
}

function leaseLive(job: Pick<JobRow, 'leaseUntil'>, at: Date): boolean {
  return job.leaseUntil !== null && job.leaseUntil.getTime() >= at.getTime()
}

/** Whether the job still holds its resource's claim: unfinished, with a live lease. */
export function holdsClaim(job: Pick<JobRow, 'status' | 'leaseUntil'>, at: Date = now()): boolean {
  return isUnfinished(job.status) && leaseLive(job, at)
}

/** The job as the browser sees it: an unfinished job no agent renews reads as failed `agent_lost`. */
export function jobView(job: JobRow, at: Date = now()): JobView {
  const lost = isUnfinished(job.status) && !leaseLive(job, at)
  return {
    id: job.id,
    kind: job.kind,
    status: lost ? 'failed' : job.status,
    stage: job.stage,
    progress: job.progress,
    errorCode: lost ? 'agent_lost' : job.errorCode,
    cancelRequested: job.cancelRequested,
    createdAt: job.createdAt.toISOString(),
    startedAt: job.startedAt?.toISOString() ?? null,
    finishedAt: job.finishedAt?.toISOString() ?? null,
  }
}

/** The account's latest job of a resource (the running one, or the one that ended last). */
export async function latestJob(ownerId: string, resourceId: string): Promise<JobView | null> {
  await sweepLostJobs(ownerId)
  const job = await prisma.tradecraftIngestionJob.findFirst({ where: { resourceId, userId: ownerId }, orderBy: { createdAt: 'desc' } })
  return job ? jobView(job) : null
}

type EndedJob = Pick<TradecraftIngestionJob, 'id' | 'kind' | 'resourceId'>

/** The 1.x `lastError` of a job that ended without a swap, in the 1.x format (agentLastError.ts). */
export function legacyErrorText(kind: string, code: string, upstreamStatus?: number): string {
  const action = kind === 'add' ? 'verify' : 'refresh'
  if (code === 'cancelled') return `${action} cancelled`
  return `${action} failed (${code}${upstreamStatus ? `, agent HTTP ${upstreamStatus}` : ''})`
}

/**
 * Ends a job that will not swap, inside the caller's transaction: closes it while it is still
 * unfinished (and, with `where`, only while that holds too), frees its resource's claim, and
 * writes the 1.x columns as a failed 1.x verify or refresh would (TD-18, D-25): the error, and a
 * verification time when the resource never had one, so the 1.x tab of an account that turned
 * 2.0 off shows the failure instead of "verifying" forever. Everything else stays as it was.
 * Only the writer that closed the job writes, so the agent's own close and this one never both
 * do. Answers whether this call closed it.
 */
async function endWithoutSwap(
  tx: Prisma.TransactionClient, job: EndedJob, status: 'failed' | 'cancelled', errorCode: ErrorCode, at: Date,
  opts: { where?: Prisma.TradecraftIngestionJobWhereInput; cancelRequested?: boolean; upstreamStatus?: number } = {},
): Promise<boolean> {
  const { count } = await tx.tradecraftIngestionJob.updateMany({
    where: { id: job.id, status: { in: [...UNFINISHED_JOB_STATUSES] }, ...opts.where },
    data: { status, errorCode, finishedAt: at, ...(opts.cancelRequested ? { cancelRequested: true } : {}) },
  })
  if (count !== 1) return false
  if (!job.resourceId) return true
  await tx.userTradecraftResource.updateMany({ where: { id: job.resourceId, activeJobId: job.id }, data: { activeJobId: null } })
  await tx.userTradecraftResource.updateMany({
    where: { id: job.resourceId }, data: { lastError: legacyErrorText(job.kind, errorCode, opts.upstreamStatus) },
  })
  await tx.userTradecraftResource.updateMany({ where: { id: job.resourceId, lastVerifiedAt: null }, data: { lastVerifiedAt: at } })
  return true
}

const LEASE_GONE = (at: Date): Prisma.TradecraftIngestionJobWhereInput => ({ OR: [{ leaseUntil: null }, { leaseUntil: { lt: at } }] })

/**
 * Fails the account's unfinished jobs that no agent renews (`agent_lost`), as the reads that
 * would show them run: the `TriageRun` rule (triageRun.ts), one call both answers and cleans up
 * after a lost agent. Best effort: a failure is logged and the read goes on. Answers how many it
 * ended.
 */
export async function sweepLostJobs(ownerId: string, at: Date = now()): Promise<number> {
  try {
    const lost = await prisma.tradecraftIngestionJob.findMany({
      where: { userId: ownerId, status: { in: [...UNFINISHED_JOB_STATUSES] }, ...LEASE_GONE(at) },
      select: { id: true, kind: true, resourceId: true },
    })
    let ended = 0
    for (const job of lost) {
      if (await prisma.$transaction(tx => endWithoutSwap(tx, job, 'failed', 'agent_lost', at, { where: LEASE_GONE(at) }))) ended += 1
    }
    return ended
  } catch (err) {
    console.error(`[tradecraft] job_sweep_failed user=${ownerId} code=${safeErrorCode(err)}`)
    return 0
  }
}

export type StartOutcome =
  | { kind: 'started'; job: JobView; delivery: 'accepted' | 'refused' | 'timeout' | 'unconfirmed' }
  | { kind: 'job_running'; job: JobView }
  | { kind: 'not_found' }
  | { kind: 'agent_unreachable'; job: JobView; upstreamStatus?: number; cause?: string }
  | { kind: 'bad_request'; job: JobView }

class NotFound extends Error {}
class ClaimHeld extends Error {
  constructor(readonly job: TradecraftIngestionJob) { super('job_running') }
}

/** The resource's running job, if one holds the claim; read inside a transaction that locked the row. */
export async function claimHolder(
  tx: Prisma.TransactionClient, resource: Pick<UserTradecraftResource, 'activeJobId'>, at: Date = now(),
): Promise<TradecraftIngestionJob | null> {
  if (!resource.activeJobId) return null
  const job = await tx.tradecraftIngestionJob.findUnique({ where: { id: resource.activeJobId } })
  return job && holdsClaim(job, at) ? job : null
}

/** Ends a job that will not run (see endWithoutSwap). */
async function closeJob(job: EndedJob, errorCode: ErrorCode, upstreamStatus?: number): Promise<void> {
  const at = now()
  await prisma.$transaction(tx => endWithoutSwap(tx, job, 'failed', errorCode, at, { upstreamStatus }))
}

export function buildJobRequest(
  job: Pick<TradecraftIngestionJob, 'id' | 'kind' | 'bulkId' | 'actorUserId' | 'realActorUserId'>,
  resource: UserTradecraftResource,
  user: { ingestion?: unknown } | null,
  accountGithubToken: string,
): JobStartRequest {
  const settings = effectiveSettings({ user, resource: resource.overrides })
  const githubToken = resource.githubTokenOverride || accountGithubToken
  return {
    job_id: job.id,
    user_id: resource.userId,
    resource_id: resource.id,
    kind: job.kind as JobStartRequest['kind'],
    actor_user_id: job.actorUserId ?? '',
    real_actor_user_id: job.realActorUserId,
    bulk_id: job.bulkId,
    settings: settings.values,
    settings_snapshot: { values: settings.values, provenance: settings.provenance },
    settings_hash: ingestionHash(settings.hash, {
      forcedType: resource.forcedType, focus: resource.focus, credentials: resource.credentials, githubTokenOverride: resource.githubTokenOverride,
    }),
    resource: {
      url: resource.url,
      slug: resource.slug,
      name: resource.name,
      storage_mode: resource.storageMode as JobStartRequest['resource']['storage_mode'],
      forced_type: resource.forcedType as JobStartRequest['resource']['forced_type'],
      type_options: (resource.typeOptions ?? {}) as Record<string, unknown>,
      focus: (resource.focus ?? {}) as Record<string, unknown>,
      summary: resource.summary,
      summary_source: resource.summarySource as JobStartRequest['resource']['summary_source'],
      summary_locked: resource.summaryLocked,
      model: resource.llmModel,
    },
    secrets: {
      github_token: githubToken || null,
      credentials: resource.hasLogin ? Credentials.parse(resource.credentials ?? {}) : null,
    },
  }
}

/**
 * The job row (with its start lease) and the claim, in one transaction under the resource's row
 * lock; a claim no agent renews is taken over, its job failed `agent_lost`.
 */
async function claimNewJob(input: {
  ownerId: string
  resourceId: string
  kind: ManualJobKind | 'bulk'
  actor: JobActor
  bulkId: string | null
  at: Date
}): Promise<{ job: TradecraftIngestionJob; resource: UserTradecraftResource }> {
  const { ownerId, resourceId, kind, actor, at } = input
  return prisma.$transaction(async (tx) => {
    if (!(await lockOwnResource(tx, ownerId, resourceId))) throw new NotFound()
    const row = await tx.userTradecraftResource.findUnique({ where: { id: resourceId } })
    if (!row) throw new NotFound()
    const holder = await claimHolder(tx, row, at)
    if (holder) throw new ClaimHeld(holder)
    const created = await tx.tradecraftIngestionJob.create({
      data: {
        userId: ownerId,
        resourceId,
        kind,
        status: 'queued',
        leaseUntil: new Date(at.getTime() + START_LEASE_MS),
        bulkId: input.bulkId,
        targetGeneration: row.generation + 1,
        actorUserId: actor.actorUserId,
        realActorUserId: actor.realActorUserId,
      },
    })
    const claim = await tx.userTradecraftResource.updateMany({
      where: { id: resourceId, userId: ownerId, activeJobId: row.activeJobId },
      data: { activeJobId: created.id },
    })
    if (claim.count !== 1) throw new Error('startJob: the claim changed under the row lock')
    // The claim it took over, if any: a job whose lease expired or never existed runs nowhere.
    const lost = await tx.tradecraftIngestionJob.findMany({
      where: { resourceId, id: { not: created.id }, status: { in: [...UNFINISHED_JOB_STATUSES] }, ...LEASE_GONE(at) },
      select: { id: true, kind: true, resourceId: true },
    })
    for (const job of lost) await endWithoutSwap(tx, job, 'failed', 'agent_lost', at, { where: LEASE_GONE(at) })
    return { job: created, resource: row }
  })
}

type Claimed = { job: TradecraftIngestionJob; resource: UserTradecraftResource }
type Delivered = Exclude<StartOutcome, { kind: 'job_running' } | { kind: 'not_found' }>

/**
 * Sends the claimed jobs to the agent in one `jobs` request (the agent's per-owner token bucket is
 * spent once, D-49) and answers each job's outcome in order. A claim is released at once when
 * the request was not delivered (refused connection, an error answer); after a timeout it is
 * kept, and the start lease frees it if the agent never took the job.
 */
async function deliverJobs(ownerId: string, claimed: Claimed[]): Promise<Delivered[]> {
  const [userSettings, account] = await Promise.all([
    prisma.tradecraftUserSettings.findUnique({ where: { userId: ownerId }, select: { ingestion: true } }),
    prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } }),
  ])
  const failedView = (job: TradecraftIngestionJob, code: ErrorCode) => jobView({ ...job, status: 'failed', errorCode: code, finishedAt: now() })
  const jobsList = claimed.map(c => c.job)
  const ids = jobsList.map(j => j.id).join(',')
  let batch: ReturnType<typeof JobStartBatch.safeParse>
  try {
    batch = JobStartBatch.safeParse({ jobs: claimed.map(c => buildJobRequest(c.job, c.resource, userSettings, account?.githubAccessToken ?? '')) })
  } catch {
    batch = JobStartBatch.safeParse(null)
  }
  if (!batch.success) {
    // The request carries secrets: log the jobs and the paths that failed, never the values.
    console.error(`[tradecraft] job_request_invalid job=${ids} paths=${batch.error.issues.map(i => i.path.join('.')).join(',')}`)
    for (const job of jobsList) await closeJob(job, 'internal_error')
    return jobsList.map(job => ({ kind: 'bad_request', job: failedView(job, 'internal_error') }))
  }

  let resp: Response
  try {
    resp = await agentFetch(AGENT_ROUTES.jobs, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(batch.data),
    }, { timeoutMs: START_TIMEOUT_MS })
  } catch (err) {
    const failure = upstreamFailure('agent', err instanceof AgentUnreachableError ? err.cause_ : err, '')
    if (failure.status === 504) {
      console.error(`[tradecraft] job_start_timeout job=${ids}`)
      return jobsList.map(job => ({ kind: 'started', job: jobView(job), delivery: 'timeout' }))
    }
    const cause = failure.body.cause
    console.error(`[tradecraft] job_start_unreachable job=${ids}${cause ? ` cause=${cause}` : ''}`)
    for (const job of jobsList) await closeJob(job, 'agent_unreachable')
    return jobsList.map(job => ({ kind: 'agent_unreachable', job: failedView(job, 'agent_unreachable'), ...(cause ? { cause } : {}) }))
  }
  if (!resp.ok) {
    console.error(`[tradecraft] job_start_refused job=${ids} status=${resp.status}`)
    for (const job of jobsList) await closeJob(job, 'agent_unreachable', resp.status)
    return jobsList.map(job => ({ kind: 'agent_unreachable', job: failedView(job, 'agent_unreachable'), upstreamStatus: resp.status }))
  }
  const answer = JobStartAnswer.safeParse(await resp.json().catch(() => null))
  if (!answer.success) return jobsList.map(job => ({ kind: 'started', job: jobView(job), delivery: 'unconfirmed' }))
  const out: Delivered[] = []
  for (const job of jobsList) {
    const refusal = answer.data.refused.find(r => r.job_id === job.id)
    if (refusal) {
      console.error(`[tradecraft] job_refused job=${job.id} code=${refusal.code}`)
      await closeJob(job, refusal.code)
      out.push({ kind: 'started', job: failedView(job, refusal.code), delivery: 'refused' })
    } else {
      out.push({ kind: 'started', job: jobView(job), delivery: 'accepted' })
    }
  }
  return out
}

/** Starts one job on the account's resource: the claim (`claimNewJob`), then one `jobs` request. */
export async function startJob(input: {
  ownerId: string
  resourceId: string
  kind: ManualJobKind
  actor: JobActor
  bulkId?: string | null
}): Promise<StartOutcome> {
  const { ownerId, resourceId, kind, actor } = input
  if (!(MANUAL_JOB_KINDS as readonly string[]).includes(kind)) throw new Error(`startJob: ${kind} is not started by a person here`)
  const at = now()
  let claimed: Claimed
  try {
    claimed = await claimNewJob({ ownerId, resourceId, kind, actor, bulkId: input.bulkId ?? null, at })
  } catch (err) {
    if (err instanceof NotFound) return { kind: 'not_found' }
    if (err instanceof ClaimHeld) return { kind: 'job_running', job: jobView(err.job, at) }
    throw err
  }
  return (await deliverJobs(ownerId, [claimed]))[0]
}

export type BulkSkip = { resourceId: string; reason: 'job_running' | 'not_found' }

/**
 * Save & refresh all (§3.2, T6.10): one `bulk` job per resource, all with `bulkId`, claimed one
 * by one (a resource already running is skipped, never queued behind itself), then started with
 * one `jobs` request. The agent runs them one at a time and stops the batch when the daily model
 * budget is spent (R-027).
 */
export async function startBulkJobs(input: {
  ownerId: string
  resourceIds: readonly string[]
  actor: JobActor
  bulkId: string
}): Promise<{ started: { resourceId: string; outcome: Delivered }[]; skipped: BulkSkip[] }> {
  const { ownerId, actor, bulkId } = input
  const at = now()
  const claimed: Claimed[] = []
  const skipped: BulkSkip[] = []
  for (const resourceId of input.resourceIds) {
    try {
      claimed.push(await claimNewJob({ ownerId, resourceId, kind: 'bulk', actor, bulkId, at }))
    } catch (err) {
      if (err instanceof NotFound) skipped.push({ resourceId, reason: 'not_found' })
      else if (err instanceof ClaimHeld) skipped.push({ resourceId, reason: 'job_running' })
      else throw err
    }
  }
  if (claimed.length === 0) return { started: [], skipped }
  const outcomes = await deliverJobs(ownerId, claimed)
  return { started: claimed.map((c, i) => ({ resourceId: c.resource.id, outcome: outcomes[i] })), skipped }
}

/** The answer of a route whose only work is the job (Refresh, Verify). */
export function jobStartResponse(outcome: StartOutcome, okStatus = 202, extra: Record<string, unknown> = {}): NextResponse {
  switch (outcome.kind) {
    case 'started':
      return NextResponse.json({ ...extra, job: outcome.job }, { status: okStatus })
    case 'job_running':
      return NextResponse.json({ ...extra, error: 'A job is already running for this resource: cancel it first', code: 'job_running', job: outcome.job }, { status: 409 })
    case 'not_found':
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    case 'agent_unreachable':
      return NextResponse.json({
        ...extra, error: 'The agent could not start the job', code: 'agent_unreachable', job: outcome.job,
        ...(outcome.upstreamStatus ? { upstreamStatus: outcome.upstreamStatus } : {}), ...(outcome.cause ? { cause: outcome.cause } : {}),
      }, { status: 503 })
    case 'bad_request':
      return NextResponse.json({ ...extra, error: 'The job request did not satisfy the agent contract', code: 'internal_error', job: outcome.job }, { status: 500 })
  }
}

/**
 * The job part of a write's answer (an add, a URL change) whose write succeeded: the write keeps
 * its status, the job shows how it started, and `jobError` says why it did not, so the screen
 * shows a saved resource with a failed job rather than a failed save.
 */
export function startedJobFields(outcome: StartOutcome): { job: JobView | null; jobError?: string } {
  switch (outcome.kind) {
    case 'started': return { job: outcome.job }
    case 'job_running': return { job: outcome.job, jobError: 'job_running' }
    case 'agent_unreachable': return { job: outcome.job, jobError: 'agent_unreachable' }
    case 'bad_request': return { job: outcome.job, jobError: 'internal_error' }
    case 'not_found': return { job: null, jobError: 'resource_deleted' }
  }
}

async function notifyCancel(jobId: string): Promise<void> {
  try {
    const resp = await agentFetch(AGENT_ROUTES.cancelJob(jobId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, { timeoutMs: CANCEL_TIMEOUT_MS })
    if (!resp.ok) console.error(`[tradecraft] job_cancel_refused job=${jobId} status=${resp.status}`)
  } catch {
    // The flag is the cancel; the call only makes the agent see it sooner.
    console.error(`[tradecraft] job_cancel_unreachable job=${jobId}`)
  }
}

/**
 * Cancels the resource's unfinished job: sets the flag the agent reads between pages. A job no
 * agent renews would never see the flag, so it ends here and frees the claim. `found` is false
 * when the account has no such resource; `job` is null when nothing was running.
 */
export async function cancelJob(ownerId: string, resourceId: string): Promise<{ found: boolean; job: JobView | null }> {
  const at = now()
  const result = await prisma.$transaction(async (tx) => {
    if (!(await lockOwnResource(tx, ownerId, resourceId))) return null
    const row = await tx.userTradecraftResource.findUnique({ where: { id: resourceId }, select: { activeJobId: true } })
    const job = row?.activeJobId ? await tx.tradecraftIngestionJob.findUnique({ where: { id: row.activeJobId } }) : null
    if (!job || !isUnfinished(job.status)) return { job: null, notify: false }
    if (leaseLive(job, at)) {
      return { job: await tx.tradecraftIngestionJob.update({ where: { id: job.id }, data: { cancelRequested: true } }), notify: true }
    }
    await endWithoutSwap(tx, job, 'cancelled', 'cancelled', at, { cancelRequested: true })
    return { job: await tx.tradecraftIngestionJob.findUnique({ where: { id: job.id } }), notify: false }
  })
  if (result === null) return { found: false, job: null }
  if (result.notify && result.job) await notifyCancel(result.job.id)
  return { found: true, job: result.job ? jobView(result.job, at) : null }
}

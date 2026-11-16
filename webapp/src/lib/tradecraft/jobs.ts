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
import { upstreamFailure } from '@/lib/routeErrors'
import {
  AGENT_ROUTES, Credentials, JobStartAnswer, JobStartBatch, UNFINISHED_JOB_STATUSES,
  type ErrorCode, type JobStartRequest,
} from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { SETTINGS_CONSTANTS } from './settingsSpec'
import { lockOwnResource } from './resourceAccess'

export const START_LEASE_MS: number = SETTINGS_CONSTANTS.jobStartLeaseSec * 1000

/** The kinds a person's action starts in this phase; T4.5 and T6.10 add theirs. */
export const MANUAL_JOB_KINDS = ['add', 'refresh', 'reingest'] as const
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
  const job = await prisma.tradecraftIngestionJob.findFirst({ where: { resourceId, userId: ownerId }, orderBy: { createdAt: 'desc' } })
  return job ? jobView(job) : null
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

/** Ends a job that will not run, and frees its resource's claim if it still holds it. */
async function closeJob(jobId: string, resourceId: string, status: 'failed' | 'cancelled', errorCode: ErrorCode): Promise<void> {
  const at = now()
  await prisma.$transaction([
    prisma.tradecraftIngestionJob.updateMany({ where: { id: jobId, status: { in: [...UNFINISHED_JOB_STATUSES] } }, data: { status, errorCode, finishedAt: at } }),
    prisma.userTradecraftResource.updateMany({ where: { id: resourceId, activeJobId: jobId }, data: { activeJobId: null } }),
  ])
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
    settings_hash: settings.hash,
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
 * Starts one job on the account's resource: the job row (with its start lease) and the claim in
 * one transaction under the row lock, then one `jobs` request to the agent. The claim is
 * released at once when the request was not delivered (refused connection, an error answer);
 * after a timeout it is kept, and the start lease frees it if the agent never took the job.
 */
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
  let job: TradecraftIngestionJob
  let resource: UserTradecraftResource
  try {
    ;({ job, resource } = await prisma.$transaction(async (tx) => {
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
          bulkId: input.bulkId ?? null,
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
      await tx.tradecraftIngestionJob.updateMany({
        where: {
          resourceId, id: { not: created.id }, status: { in: [...UNFINISHED_JOB_STATUSES] },
          OR: [{ leaseUntil: null }, { leaseUntil: { lt: at } }],
        },
        data: { status: 'failed', errorCode: 'agent_lost', finishedAt: at },
      })
      return { job: created, resource: row }
    }))
  } catch (err) {
    if (err instanceof NotFound) return { kind: 'not_found' }
    if (err instanceof ClaimHeld) return { kind: 'job_running', job: jobView(err.job, at) }
    throw err
  }

  const [userSettings, account] = await Promise.all([
    prisma.tradecraftUserSettings.findUnique({ where: { userId: ownerId }, select: { ingestion: true } }),
    prisma.userSettings.findUnique({ where: { userId: ownerId }, select: { githubAccessToken: true } }),
  ])
  const failedView = (code: ErrorCode) => jobView({ ...job, status: 'failed', errorCode: code, finishedAt: now() })
  let batch: ReturnType<typeof JobStartBatch.safeParse>
  try {
    batch = JobStartBatch.safeParse({ jobs: [buildJobRequest(job, resource, userSettings, account?.githubAccessToken ?? '')] })
  } catch {
    batch = JobStartBatch.safeParse(null)
  }
  if (!batch.success) {
    // The request carries secrets: log the job and the paths that failed, never the values.
    console.error(`[tradecraft] job_request_invalid job=${job.id} paths=${batch.error.issues.map(i => i.path.join('.')).join(',')}`)
    await closeJob(job.id, resourceId, 'failed', 'internal_error')
    return { kind: 'bad_request', job: failedView('internal_error') }
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
      console.error(`[tradecraft] job_start_timeout job=${job.id}`)
      return { kind: 'started', job: jobView(job), delivery: 'timeout' }
    }
    const cause = failure.body.cause
    console.error(`[tradecraft] job_start_unreachable job=${job.id}${cause ? ` cause=${cause}` : ''}`)
    await closeJob(job.id, resourceId, 'failed', 'agent_unreachable')
    return { kind: 'agent_unreachable', job: failedView('agent_unreachable'), ...(cause ? { cause } : {}) }
  }
  if (!resp.ok) {
    console.error(`[tradecraft] job_start_refused job=${job.id} status=${resp.status}`)
    await closeJob(job.id, resourceId, 'failed', 'agent_unreachable')
    return { kind: 'agent_unreachable', job: failedView('agent_unreachable'), upstreamStatus: resp.status }
  }
  const answer = JobStartAnswer.safeParse(await resp.json().catch(() => null))
  if (!answer.success) return { kind: 'started', job: jobView(job), delivery: 'unconfirmed' }
  const refusal = answer.data.refused.find(r => r.job_id === job.id)
  if (refusal) {
    console.error(`[tradecraft] job_refused job=${job.id} code=${refusal.code}`)
    await closeJob(job.id, resourceId, 'failed', refusal.code)
    return { kind: 'started', job: failedView(refusal.code), delivery: 'refused' }
  }
  return { kind: 'started', job: jobView(job), delivery: 'accepted' }
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
    const ended = await tx.tradecraftIngestionJob.update({
      where: { id: job.id }, data: { cancelRequested: true, status: 'cancelled', errorCode: 'cancelled', finishedAt: at },
    })
    await tx.userTradecraftResource.updateMany({ where: { id: resourceId, activeJobId: job.id }, data: { activeJobId: null } })
    return { job: ended, notify: false }
  })
  if (result === null) return { found: false, job: null }
  if (result.notify && result.job) await notifyCancel(result.job.id)
  return { found: true, job: result.job ? jobView(result.job, at) : null }
}

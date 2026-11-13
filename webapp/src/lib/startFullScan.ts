/**
 * The one full-scan start path (Scan Timeline Sections 3 + 7.2).
 *
 * Extracted so a SCHEDULED scan takes exactly the same route as a manual one:
 * same activation-lock check, same freeze-before-start, same orchestrator call
 * (which is where the RoE time window / excluded hosts / hard guardrail and the
 * admission ledger live), same ScanJob history. The only difference is who asked.
 *
 * Callers own authorization.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanStartFields } from '@/lib/scanJobCredential'
import { isActivationInProgress } from '@/lib/activationLock'
import {
  GRAPH_LOCK_HOLDER_PHRASE,
  CurrentVersionMovedError,
  withGraphStartLock,
  type GraphLockHolder,
} from '@/lib/projectGraphLock'
import { describeScanWriters } from '@/lib/graphWriters'
import { currentAuthorization, loadEngagement } from '@/lib/engagement'
import { settingsFingerprint } from '@/lib/jobQueue'
import { normalizeOrchestratorStartError, type NormalizedStartError } from '@/lib/orchestratorError'
import { classifyStartFailure } from '@/lib/scanStartOutcome'
import { applyRetentionSafe } from '@/lib/scanRetention'
import { upstreamFailure } from '@/lib/routeErrors'
import type { InvalidEntry } from '@/lib/domainBatch'
import { IP_HOSTNAME_SELECT, scopeStartProblem } from '@/lib/scopeGroups'
import {
  prepareVersionsForFullScan,
  rollbackPreparedVersions,
  createScanJob,
  SnapshotFreezeError,
  type PrepareResult,
  type ScanMode,
  type ScanTrigger,
} from '@/lib/scanTimeline'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

export interface StartFullScanInput {
  projectId: string
  mode: ScanMode
  trigger: ScanTrigger
  actorUserId?: string | null
  scheduleId?: string | null
  /**
   * Set by the headless callers (the queue, the scheduler), which retry a
   * transient refusal: no failed ScanJob is recorded for one, or every
   * attempt would leave a failed run in the history.
   */
  quietTransient?: boolean
}

export interface StartFullScanSuccess {
  ok: true
  state: Record<string, unknown>
  versionId: string
  versionSeq: number
  versionLabel: string
  frozenVersionId: string | null
  frozenNodeCount: number
  scanJobId: string | null
}

export interface StartFullScanFailure {
  ok: false
  status: number
  error: string
  /** Structured memory-governor payload, when the rejection was an admission limit. */
  limit?: Record<string, unknown>
  /** True when the graph could not be frozen (nothing was started, nothing lost). */
  snapshotFailed?: boolean
  /** True when the project's graph is mid-activation (retry later). */
  activationInProgress?: boolean
  /** What is already rewriting the graph, when the start was refused for that. */
  busy?: string
  scanJobId?: string | null
  /**
   * 'unknown' when the orchestrator call threw (timeout, connection reset): the
   * container may or may not have been spawned, so the caller must poll status
   * before retrying. Absent means the orchestrator gave a definitive answer.
   */
  startOutcome?: 'unknown'
  /**
   * 'scope_invalid' when the saved scope holds entries the current rules refuse
   * (a public-suffix update can do that to a stored list). Permanent and 422,
   * never 409: the queue requeues a 409 forever as "busy". Otherwise the
   * orchestrator's own code, e.g. 'spawn_failed' (the container could not be
   * created; permanent).
   */
  code?: 'scope_invalid' | string
  invalidEntries?: InvalidEntry[]
  /** The orchestrator's own HTTP status, when it answered with an error. */
  upstreamStatus?: number
  /** The errno of a call that got no answer (ECONNREFUSED, ENOTFOUND). */
  cause?: string
}

export type StartFullScanResult = StartFullScanSuccess | StartFullScanFailure

/**
 * Errnos raised before a request is sent: a refused connection, an unknown
 * host, no route. The orchestrator never saw the start, so nothing runs. A
 * timeout or a reset can come after it acted, so those stay "unknown".
 */
const NEVER_DELIVERED = new Set(['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH'])

export interface OrchestratorStartThrow {
  /** 503 for no connection, 504 for a timeout. */
  status: 503 | 504
  /** `orchestrator_unreachable` or `orchestrator_timeout`. */
  code: string
  cause?: string
  /** False only when the request certainly never reached the orchestrator. */
  outcomeUnknown: boolean
}

/** What a start call that got no HTTP answer means for the scan it asked for. */
export function classifyOrchestratorThrow(err: unknown): OrchestratorStartThrow {
  const { status, body } = upstreamFailure('orchestrator', err, '')
  return {
    status,
    code: body.code,
    ...(body.cause ? { cause: body.cause } : {}),
    outcomeUnknown: !(body.cause && NEVER_DELIVERED.has(body.cause)),
  }
}

/**
 * The settings digest for a directly-started run.
 *
 * Never throws: provenance is a side effect of starting a scan, and failing to
 * record it must not fail the start an operator asked for. A null hash reads as
 * "not recorded", which is honest; a failed start would not be.
 */
async function fingerprintProjectSettings(projectId: string): Promise<string | null> {
  try {
    const row = await prisma.project.findUnique({ where: { id: projectId } })
    if (!row) return null
    return settingsFingerprint('full_recon', row as unknown as Record<string, unknown>)
  } catch (err) {
    console.error('[scanTimeline] could not fingerprint settings for provenance:', err)
    return null
  }
}

async function currentAuthorizationId(projectId: string): Promise<string | null> {
  try {
    return (await currentAuthorization(projectId))?.id ?? null
  } catch (err) {
    console.error('[scanTimeline] could not read the current authorization:', err)
    return null
  }
}

interface Refusal {
  status: number
  norm: NormalizedStartError
  /** The reason recorded on the failed ScanJob. */
  ramReason: string | null
  upstreamStatus?: number
  cause?: string
}

/** A start that certainly did not begin: nothing was spawned. */
async function refuseStart(
  input: StartFullScanInput,
  prepared: PrepareResult,
  roeTextSha256: string | null,
  r: Refusal,
): Promise<StartFullScanFailure> {
  const { projectId, mode, trigger } = input
  const { status, norm } = r
  const isLimit = !!norm.limit?.limitType

  // Undo the freeze rather than leave a minted version and a duplicate
  // snapshot behind (P0-2).
  const rolledBack = await rollbackPreparedVersions(projectId, prepared)
  const versionId = rolledBack ? prepared.frozenVersionId : prepared.currentVersion.id

  // Record the attempt so the timeline shows why it did not run, unless the
  // caller retries it: then it is recorded once, when the refusal is final.
  const retried = input.quietTransient && classifyStartFailure(
    status, { error: norm.error, code: norm.code, limit: norm.limit }, { orchestratorAnswered: true },
  ).kind === 'transient'
  const job = retried ? null : await createScanJob({
    projectId,
    versionId,
    trigger,
    mode,
    status: norm.limit?.limitType === 'ram' ? 'deferred_ram' : 'failed',
    initiatedByUserId: input.actorUserId ?? null,
    roeTextSha256,
    scheduleId: input.scheduleId ?? null,
    ramReason: r.ramReason,
  }).catch(err => {
    console.error('[scanTimeline] could not record failed scan job:', err)
    return null
  })

  return {
    ok: false,
    status,
    error: norm.error,
    ...(isLimit ? { limit: norm.limit as Record<string, unknown> } : {}),
    ...(norm.code ? { code: norm.code } : {}),
    ...(r.upstreamStatus ? { upstreamStatus: r.upstreamStatus } : {}),
    ...(r.cause ? { cause: r.cause } : {}),
    scanJobId: job?.id ?? null,
  }
}

function activationRefusal(): StartFullScanFailure {
  return {
    ok: false,
    status: 409,
    activationInProgress: true,
    error: 'A version activation is in progress for this project - the graph is being swapped. ' +
      'Try again once it finishes.',
  }
}

/** A start refused because a version save or an activation holds the project's graph lock. */
export function graphLockedStartRefusal(holder: GraphLockHolder): StartFullScanFailure {
  if (holder === 'activation') return activationRefusal()
  const busy = GRAPH_LOCK_HOLDER_PHRASE[holder]
  return { ok: false, status: 409, busy, error: `Cannot start a scan while ${busy} for this project. Try again once it finishes.` }
}

/**
 * Every start path (the button, the scheduler, the queue dispatcher, MCP) comes
 * through here, holding the project's graph lock from the activation check to
 * the orchestrator's answer (projectGraphLock.ts).
 */
export async function startFullScan(input: StartFullScanInput): Promise<StartFullScanResult> {
  const held = await withGraphStartLock(input.projectId, () => startFullScanLocked(input))
  return held.acquired ? held.value : graphLockedStartRefusal(held.heldBy)
}

async function startFullScanLocked(input: StartFullScanInput): Promise<StartFullScanResult> {
  const { projectId, mode, trigger } = input

  // 4A.3: never start a scan into an in-flight graph swap. The graph lock keeps
  // out an activation in this process; the row still answers for one that a
  // crashed webapp left mid-swap, until its TTL.
  if (await isActivationInProgress(projectId)) return activationRefusal()

  // Risk 1 + Section 3.3: reject a start while a scan or partial recon is already
  // rewriting the graph, BEFORE we freeze it. The orchestrator refuses the
  // duplicate spawn anyway, but only after we would have snapshotted a mid-write
  // graph and minted a version for a scan that never happens.
  const busy = await describeScanWriters(projectId)
  if (busy) {
    return {
      ok: false,
      status: 409,
      error: `Cannot start a scan while ${busy} for this project. Stop it first.`,
      busy,
    }
  }

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true, targetDomain: true, ipMode: true, targetIps: true,
      domainBatchMode: true, domainBatchHosts: true, subdomainList: true,
      engagementKind: true, ...IP_HOSTNAME_SELECT,
    },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  if (project.ipMode) {
    if (!project.targetIps || project.targetIps.length === 0) {
      return { ok: false, status: 400, error: 'Project has no target IPs configured' }
    }
    // The hostname policy recon would refuse at load (an unconfirmed scan_all, a
    // record_filter with no include entry) is refused here, before a version is
    // frozen, so a schedule or the queue gets the reason instead of a failed run.
    const problem = scopeStartProblem(project)
    if (problem) {
      return { ok: false, status: 422, code: 'scope_invalid', invalidEntries: problem.invalid, error: problem.message }
    }
  } else if (!project.domainBatchMode && !project.targetDomain) {
    return { ok: false, status: 400, error: 'Project has no target domain configured' }
  } else {
    // Fail closed: a headless start (a schedule, the queue) has nobody to show
    // the form to, and the orchestrator would refuse the start anyway.
    const problem = scopeStartProblem(project)
    if (problem) {
      return {
        ok: false,
        status: 422,
        code: 'scope_invalid',
        invalidEntries: problem.invalid,
        error: problem.invalid.length > 0 ? `${problem.message} Edit the target list before scanning.` : problem.message,
      }
    }
  }

  // A third-party engagement must carry a rate ceiling AND the record of what
  // authorized it. Checked HERE rather than in the MCP tool, because an
  // agent-facing rule that only applies when an agent is present is not a
  // control: the scheduler and the queue dispatcher reach this same function.
  //
  // It refuses rather than downgrading. A scan that quietly ran without its
  // ceiling is the exact failure this exists to prevent, and the operator would
  // find out from the target.
  const engagement = await loadEngagement(projectId)
  if (engagement.blockers.length > 0) {
    // 422, not 409: the queue would requeue a 409 forever as "busy", and only a
    // person adding the ceiling or the record can fix this.
    return {
      ok: false,
      status: 422,
      error:
        'This is a third-party engagement and it is not startable: ' +
        engagement.blockers.join(' ') +
        ' Use preflight_scope_check to see the whole picture.',
    }
  }

  // Before the versions rotate: a failed quota read must leave nothing half-prepared.
  const jobFields = await scanStartFields(projectId, project.userId, input.actorUserId)

  // Freeze/rotate versions BEFORE starting. Fail closed: the graph is never
  // destroyed unsaved (Risk 4).
  let prepared
  try {
    prepared = await prepareVersionsForFullScan(projectId, mode, input.actorUserId ?? null)
  } catch (err) {
    if (err instanceof SnapshotFreezeError) {
      console.error('[scanTimeline] aborting scan start:', err.message)
      return { ok: false, status: 500, error: err.message, snapshotFailed: true }
    }
    if (err instanceof CurrentVersionMovedError) {
      return { ok: false, status: 409, busy: 'the current version changed', error: err.message }
    }
    throw err
  }

  let response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        ...jobFields,
        webapp_api_url: WEBAPP_URL,
        // Telemetry/history only - the pipeline behaves identically either way.
        mode,
      }),
    })
  } catch (err) {
    console.error(`[scanTimeline] orchestrator start call failed for project ${projectId}:`, err)
    const thrown = classifyOrchestratorThrow(err)
    if (!thrown.outcomeUnknown) {
      return refuseStart(input, prepared, engagement.documentTextSha256, {
        status: thrown.status,
        norm: { error: 'The orchestrator could not be reached, so the scan was not started.', code: thrown.code },
        ramReason: 'the orchestrator could not be reached',
        ...(thrown.cause ? { cause: thrown.cause } : {}),
      })
    }
    // A timeout or a reset is NOT a refusal: the orchestrator may already have
    // spawned the container. Rolling the versions back could therefore discard
    // the snapshot of a graph a live scan is about to overwrite, so the prepared
    // version stays and the caller is told the outcome is unknown.
    const job = await createScanJob({
      projectId,
      versionId: prepared.currentVersion.id,
      trigger,
      mode,
      status: 'failed',
      initiatedByUserId: input.actorUserId ?? null,
      roeTextSha256: engagement.documentTextSha256,
      scheduleId: input.scheduleId ?? null,
      ramReason: 'start outcome unknown: the orchestrator did not answer',
    }).catch(jobErr => {
      console.error('[scanTimeline] could not record unknown-outcome scan job:', jobErr)
      return null
    })

    return {
      ok: false,
      status: thrown.status,
      startOutcome: 'unknown',
      code: thrown.code,
      ...(thrown.cause ? { cause: thrown.cause } : {}),
      error:
        'The orchestrator did not answer, so it is unknown whether the scan started. ' +
        'Check the scan status before retrying.',
      scanJobId: job?.id ?? null,
    }
  }

  // An orchestrator from before plan 12.9 answered a container it could not
  // create with 200 and `status: error`. That is a refusal like any other:
  // nothing runs, so no retention and no running ScanJob.
  const accepted = response.ok ? await response.json().catch(() => ({})) : null
  const spawnFailed = accepted && (accepted as { status?: unknown }).status === 'error'

  if (!response.ok || spawnFailed) {
    const errorData = spawnFailed
      ? { detail: { detail: String((accepted as { error?: unknown }).error ?? 'The scan container could not be started'),
          code: 'spawn_failed' } }
      : await response.json().catch(() => ({}))
    // Single source of truth for turning a structured governor detail into a safe
    // string + limit object (Scan Queue Phase 0.4). Never render the raw object.
    const norm = normalizeOrchestratorStartError(errorData, 'Failed to start recon')
    return refuseStart(input, prepared, engagement.documentTextSha256, {
      status: spawnFailed ? 500 : response.status,
      norm,
      ramReason: norm.limit?.limitType ? String(norm.limit?.detail ?? norm.error) : (spawnFailed ? norm.error : null),
      ...(spawnFailed ? {} : { upstreamStatus: response.status }),
    })
  }

  const state = accepted as Record<string, unknown>

  // The scan is accepted, so the version it minted is real and the timeline can
  // be trimmed to policy. Retention deletes the oldest unpinned versions, which
  // is why it must never run for a start that did not begin (P0-2).
  await applyRetentionSafe(projectId)

  const job = await createScanJob({
    projectId,
    versionId: prepared.currentVersion.id,
    trigger,
    mode,
    // Provenance, so a graph node can be traced back to the configuration that
    // produced it and the document that permitted looking. JobQueue.settingsHash
    // is the only other settings fingerprint anywhere and it is deleted with the
    // queue row the moment the job dispatches.
    settingsHash: await fingerprintProjectSettings(projectId),
    authorizationId: await currentAuthorizationId(projectId),
    status: 'running',
    initiatedByUserId: input.actorUserId ?? null,
    roeTextSha256: engagement.documentTextSha256,
    scheduleId: input.scheduleId ?? null,
  }).catch(err => {
    console.error('[scanTimeline] could not record scan job:', err)
    return null
  })

  return {
    ok: true,
    state,
    versionId: prepared.currentVersion.id,
    versionSeq: prepared.currentVersion.seq,
    versionLabel: prepared.currentVersion.label,
    frozenVersionId: prepared.frozenVersionId,
    frozenNodeCount: prepared.frozenNodeCount,
    scanJobId: job?.id ?? null,
  }
}

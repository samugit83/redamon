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
import { isActivationInProgress } from '@/lib/activationLock'
import { describeScanWriters } from '@/lib/graphWriters'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import {
  prepareVersionsForFullScan,
  createScanJob,
  SnapshotFreezeError,
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
}

export type StartFullScanResult = StartFullScanSuccess | StartFullScanFailure

export async function startFullScan(input: StartFullScanInput): Promise<StartFullScanResult> {
  const { projectId, mode, trigger } = input

  // 4A.3: never start a scan into an in-flight graph swap.
  if (await isActivationInProgress(projectId)) {
    return {
      ok: false,
      status: 409,
      activationInProgress: true,
      error: 'A version activation is in progress for this project - the graph is being swapped. ' +
        'Try again once it finishes.',
    }
  }

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
      domainBatchMode: true, domainBatchGroups: true,
    },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  if (project.ipMode) {
    if (!project.targetIps || project.targetIps.length === 0) {
      return { ok: false, status: 400, error: 'Project has no target IPs configured' }
    }
  } else if (project.domainBatchMode) {
    // A batch's scope lives in its derived groups, not targetDomain. Fail closed:
    // an empty group list means the list was never saved, not that there is
    // nothing to scan, and the orchestrator would refuse the start anyway.
    const groups = Array.isArray(project.domainBatchGroups) ? project.domainBatchGroups : []
    if (groups.length === 0) {
      return {
        ok: false,
        status: 400,
        error: 'Project has no valid domain groups. Re-save its hostname list before scanning.',
      }
    }
  } else if (!project.targetDomain) {
    return { ok: false, status: 400, error: 'Project has no target domain configured' }
  }

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
    throw err
  }

  const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      // Telemetry/history only - the pipeline behaves identically either way.
      mode,
    }),
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    // Single source of truth for turning a structured governor detail into a safe
    // string + limit object (Scan Queue Phase 0.4). Never render the raw object.
    const norm = normalizeOrchestratorStartError(errorData, 'Failed to start recon')
    const isLimit = !!norm.limit?.limitType

    // Record the attempt so the timeline shows why it did not run.
    const job = await createScanJob({
      projectId,
      versionId: prepared.currentVersion.id,
      trigger,
      mode,
      status: norm.limit?.limitType === 'ram' ? 'deferred_ram' : 'failed',
      initiatedByUserId: input.actorUserId ?? null,
      scheduleId: input.scheduleId ?? null,
      ramReason: isLimit ? String(norm.limit?.detail ?? norm.error) : null,
    }).catch(err => {
      console.error('[scanTimeline] could not record failed scan job:', err)
      return null
    })

    return {
      ok: false,
      status: response.status,
      error: norm.error,
      ...(isLimit ? { limit: norm.limit as Record<string, unknown> } : {}),
      scanJobId: job?.id ?? null,
    }
  }

  const state = await response.json()

  const job = await createScanJob({
    projectId,
    versionId: prepared.currentVersion.id,
    trigger,
    mode,
    status: 'running',
    initiatedByUserId: input.actorUserId ?? null,
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

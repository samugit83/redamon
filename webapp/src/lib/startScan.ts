/**
 * One dispatch entry point that routes a JobQueue `kind` to the SAME start path
 * the user's button uses (Scan Queue plan, R2). The queue dispatcher never spawns
 * a container: it asks the webapp, and the webapp re-runs the identical start path,
 * so RoE, guardrails, the activation lock, target validation, the version freeze
 * and admission all re-run at dispatch, hours after enqueue.
 *
 * full_recon goes through lib/startFullScan.ts (the shared full-scan path with the
 * version freeze). Every other kind forwards to its orchestrator start endpoint,
 * mirroring its /api/.../start route body exactly.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { resolveTrufflehogStart } from '@/lib/trufflehogStart'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanJobCredential } from '@/lib/scanJobCredential'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { classifyOrchestratorThrow, graphLockedStartRefusal, startFullScan } from '@/lib/startFullScan'
import { withGraphStartLock } from '@/lib/projectGraphLock'
import { parseScanMode, recordScanStart, type ScanTrigger } from '@/lib/scanTimeline'
import { legacyGraphDomains, legacyGraphRefusal } from '@/lib/legacyGraph'
import { IP_HOSTNAME_SELECT, ipHostnameStartProblem, resolveScopeGroups } from '@/lib/scopeGroups'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

export interface DispatchStartResult {
  ok: boolean
  status: number
  error?: string
  limit?: Record<string, unknown>
  activationInProgress?: boolean
  busy?: string
  state?: unknown
  scanJobId?: string | null
  runId?: string
  /** 'unknown' when the orchestrator call threw: the scan may or may not have started. */
  startOutcome?: 'unknown'
  /** The webapp could not freeze the graph, so nothing was started. */
  snapshotFailed?: boolean
  /** The orchestrator's (or startFullScan's) reason code, e.g. 'spawn_failed'. */
  code?: string
  /** The orchestrator's own HTTP status, when it answered with an error. */
  upstreamStatus?: number
  /** The errno of a start call that got no answer. */
  cause?: string
}

export type StartScanPayload = Record<string, unknown>

/** Kinds whose orchestrator start body is just {project_id, user_id, webapp_api_url}. */
const SIMPLE_KIND_ENDPOINT: Record<string, { path: (p: string) => string; fallback: string }> = {
  gvm: { path: p => `/gvm/${p}/start`, fallback: 'Failed to start GVM scan' },
  github_hunt: { path: p => `/github-hunt/${p}/start`, fallback: 'Failed to start GitHub Secret Hunt' },
  supply_chain: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
  // A per-repo batch item runs the supply-chain container; its repo config is
  // applied by the env-override layer in scanners/supply_chain_scan/project_settings.py.
  supply_chain_repo: { path: p => `/supply-chain/${p}/start`, fallback: 'Failed to start Supply-Chain scan' },
}

function runId(state: unknown): string {
  if (state && typeof state === 'object') {
    const s = state as Record<string, unknown>
    const v = s.run_id ?? s.runId
    if (typeof v === 'string') return v
  }
  return ''
}

/** Orchestrator stop endpoint per kind. Run-based kinds need the run id. */
const STOP_ENDPOINT: Record<string, (p: string, r: string) => string | null> = {
  full_recon: p => `/recon/${p}/stop`,
  gvm: p => `/gvm/${p}/stop`,
  github_hunt: p => `/github-hunt/${p}/stop`,
  // Run-keyed: the run id is the source. A project-level stop would kill
  // whichever source the orchestrator happened to pick, or nothing at all.
  trufflehog: (p, r) => (r ? `/trufflehog/${p}/${encodeURIComponent(r)}/stop` : null),
  supply_chain: p => `/supply-chain/${p}/stop`,
  supply_chain_repo: p => `/supply-chain/${p}/stop`,
  ai_attack: (p, r) => (r ? `/ai-attack-surface/${p}/${r}/stop` : null),
  partial_recon: (p, r) => (r ? `/recon/${p}/partial/${r}/stop` : null),
}

/**
 * Best-effort stop of a scan that was just started. Used when a job is canceled in
 * the narrow window between dispatch claiming it and marking it running (Finding 1):
 * the scan already began, so we tell the orchestrator to stop it. Never throws.
 */
export async function stopScan(kind: string, projectId: string, runId = ''): Promise<void> {
  const build = STOP_ENDPOINT[kind]
  const path = build ? build(projectId, runId) : null
  if (!path) return
  try {
    await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, { method: 'POST' })
  } catch (e) {
    console.warn(`[jobQueue] best-effort stop of ${kind} for ${projectId} failed:`, e)
  }
}

/** A start route's refusal response, in the shape the queue classifies. */
async function routeRefusal(res: NextResponse): Promise<DispatchStartResult> {
  const body = (await res.json().catch(() => ({}))) as { error?: unknown; activationInProgress?: unknown }
  return {
    ok: false,
    status: res.status,
    ...(typeof body.error === 'string' ? { error: body.error } : {}),
    ...(body.activationInProgress === true ? { activationInProgress: true } : {}),
  }
}

/**
 * The checks the start buttons make before a run may write the live graph.
 * Every kind waits out a version activation swapping the graph; a partial recon
 * also waits out a mute-rule apply, which it would race for the same findings.
 * Both are 409s the queue reads as a capacity wait: requeued, never started.
 */
async function graphBusyRefusal(kind: string, projectId: string): Promise<DispatchStartResult | null> {
  const activating = await assertGraphNotActivating(projectId)
  if (activating) return routeRefusal(activating)
  if (kind !== 'partial_recon') return null
  const applying = await describeNodeFilterWriter(projectId)
  if (!applying) return null
  return {
    ok: false,
    status: 409,
    busy: applying,
    error: `Cannot start a partial recon while ${applying}. Try again when it finishes.`,
  }
}

/**
 * The run id each kind's start button records its ScanJob under, which is how
 * the reconcile matches a row to its run. supply_chain_repo has no button and
 * no ScanJob: its history is the queue row.
 */
const HISTORY_RUN_ID: Partial<Record<string, (state: unknown, body: Record<string, unknown>) => string>> = {
  partial_recon: state => runId(state),
  ai_attack: state => runId(state),
  trufflehog: (_state, body) => (typeof body.source === 'string' ? body.source : ''),
  gvm: () => '',
  github_hunt: () => '',
  supply_chain: () => '',
}

/** The roots the orchestrator granted a partial recon, as its route records them. */
function grantedRoots(state: unknown): string[] {
  const roots = (state as { roots?: unknown } | null)?.roots
  return Array.isArray(roots) ? roots.filter((r): r is string => typeof r === 'string') : []
}

export async function dispatchStart(
  kind: string,
  projectId: string,
  opts: { actorUserId?: string | null; payload?: StartScanPayload } = {},
): Promise<DispatchStartResult> {
  const payload = opts.payload ?? {}

  // full_recon: the shared full-scan path (version freeze + ScanJob history).
  if (kind === 'full_recon') {
    const mode = parseScanMode(payload.mode) ?? 'new'
    const trigger: ScanTrigger = 'scheduled'
    // quietTransient: the queue retries a transient refusal, so the start path
    // must not record a failed ScanJob for each attempt.
    const r = await startFullScan({
      projectId, mode, trigger, actorUserId: opts.actorUserId ?? null, quietTransient: true,
    })
    if (r.ok) {
      return { ok: true, status: 200, state: r.state, scanJobId: r.scanJobId ?? null, runId: runId(r.state) }
    }
    return {
      ok: false,
      status: r.status,
      error: r.error,
      limit: r.limit,
      activationInProgress: r.activationInProgress,
      busy: r.busy,
      scanJobId: r.scanJobId ?? null,
      ...(r.startOutcome ? { startOutcome: r.startOutcome } : {}),
      ...(r.snapshotFailed ? { snapshotFailed: true } : {}),
      ...(r.code ? { code: r.code } : {}),
      ...(r.upstreamStatus ? { upstreamStatus: r.upstreamStatus } : {}),
      ...(r.cause ? { cause: r.cause } : {}),
    }
  }

  // S-4: every other kind writes the live graph too (graphWriters.ts counts each
  // as a writer), so like its button it holds the project's graph lock.
  const held = await withGraphStartLock(projectId, () => dispatchOtherStart(kind, projectId, opts))
  if (held.acquired) return held.value
  const refused = graphLockedStartRefusal(held.heldBy)
  return {
    ok: false,
    status: refused.status,
    error: refused.error,
    ...(refused.activationInProgress ? { activationInProgress: true } : {}),
    ...(refused.busy ? { busy: refused.busy } : {}),
  }
}

/**
 * Run a start button's route holding the project's graph lock
 * (projectGraphLock.ts), for a scan whose run writes the live graph: from the
 * route's activation check through the orchestrator's answer, after which an
 * activation's or a version save's writer check sees the run. Without it an
 * activation could begin swapping the graph between the check and the start,
 * and the run would write into the half-restored graph; a save could freeze
 * the graph while the run writes into it. A save or an activation holding the
 * lock refuses the start with 409.
 */
export async function startUnderGraphLock(
  projectId: string,
  start: () => Promise<NextResponse>,
): Promise<NextResponse> {
  const held = await withGraphStartLock(projectId, start)
  if (held.acquired) return held.value
  const refused = graphLockedStartRefusal(held.heldBy)
  return NextResponse.json(
    {
      error: refused.error,
      ...(refused.activationInProgress ? { activationInProgress: true } : {}),
      ...(refused.busy ? { busy: refused.busy } : {}),
    },
    { status: refused.status },
  )
}

async function dispatchOtherStart(
  kind: string,
  projectId: string,
  opts: { actorUserId?: string | null; payload?: StartScanPayload },
): Promise<DispatchStartResult> {
  const payload = opts.payload ?? {}

  const graphBusy = await graphBusyRefusal(kind, projectId)
  if (graphBusy) return graphBusy

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true, supplyChainInputMode: true,
      targetDomain: true, subdomainList: true, ipMode: true, domainBatchMode: true, domainBatchHosts: true,
      engagementKind: true, ...IP_HOSTNAME_SELECT,
    },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  // A partial run loads the project settings as a full one does, and recon
  // refuses an IP-mode hostname policy it may not run (an unconfirmed scan_all,
  // a record_filter with no include entry). The queue gets the reason now.
  if (kind === 'partial_recon' && project.ipMode) {
    const problem = ipHostnameStartProblem(project)
    if (problem) return { ok: false, status: 422, error: problem }
  }

  // The writers that attach to Domain nodes refuse an old-model graph
  // (§4.11.6). 422, not the routes' 409: the queue reads a 409 as "busy" and
  // would requeue the job until a full recon happened to run.
  if (kind === 'partial_recon' || kind === 'gvm' || kind === 'ai_attack') {
    const legacy = await legacyGraphDomains(project.userId, projectId, resolveScopeGroups(project).groups)
    if (legacy && legacy.length > 0) {
      return { ok: false, status: 422, error: legacyGraphRefusal(legacy).error }
    }
  }

  // The engagement rule applies to the OTHER scanners too, and it has to be
  // checked here rather than only in startFullScan: GVM sweeps ports, the
  // GitHub hunt reads an organization's repositories, and the supply-chain scan
  // clones one. All three reach somebody else's estate.
  //
  // The queue dispatcher and the scheduler both arrive through this function
  // with nobody watching, which is exactly why the check is server-side: an
  // agent-facing rule that only applies when an agent is present is not a
  // control. The refusal is the manual routes': 422 and the full start's
  // message. A 409 would read as "busy" to the queue and requeue this until a
  // person fixed the engagement record.
  const engagementBlocked = await assertEngagementStartable(projectId)
  if (engagementBlocked) return routeRefusal(engagementBlocked)

  // 'org' is not an input this scan can read: it means "enumerate the account
  // and queue one scan per repo", which is a different kind (supply_chain_repo).
  // Dispatching it anyway would spawn a container that dies looking for an SBOM.
  if (kind === 'supply_chain' && project.supplyChainInputMode === 'org') {
    return {
      ok: false,
      status: 400,
      error: 'This project scans a GitHub organization. Queue the org batch from Other Scans '
        + 'instead, or set an SBOM/repository input in project settings.',
    }
  }

  let path: string
  let body: Record<string, unknown>
  let fallback: string

  const simple = SIMPLE_KIND_ENDPOINT[kind]
  if (simple) {
    path = simple.path(projectId)
    fallback = simple.fallback
    body = { project_id: projectId, user_id: project.userId, webapp_api_url: WEBAPP_URL }
    // A supply_chain_repo (org-batch) item carries its target repo in the payload;
    // forward it as a per-repo override so the container scans THIS repo, not the
    // project's default supply-chain config (Phase 6).
    if (kind === 'supply_chain_repo') {
      body.repo_override_url = typeof payload.repo_url === 'string' ? payload.repo_url : ''
      // Empty = github.com. Set for a GitHub Enterprise batch so the container
      // clones from that host and asks for the matching credential.
      body.repo_override_host = typeof payload.host === 'string' ? payload.host : ''
      body.repo_override_ref = typeof payload.ref === 'string' ? payload.ref : ''
      body.repo_override_scope = typeof payload.scope === 'string' ? payload.scope : ''
      body.repo_override_deep = !!payload.deep_analysis
    }
  } else if (kind === 'trufflehog') {
    // A dedicated branch, not the simple one: a queued TruffleHog job carries
    // its source (and the profile that defines the target) in the payload, and
    // the simple branch forwards no payload at all — the job would dispatch with
    // no source and run the wrong config.
    const resolved = await resolveTrufflehogStart(projectId, {
      profileId: typeof payload.profile_id === 'string' ? payload.profile_id : undefined,
      source: typeof payload.source === 'string' ? payload.source : undefined,
      webappUrl: WEBAPP_URL,
    })
    if (!resolved.ok) return { ok: false, status: resolved.status, error: resolved.error }
    path = `/trufflehog/${projectId}/start`
    fallback = 'Failed to start Secret Multiscanner scan'
    body = resolved.body as unknown as Record<string, unknown>
  } else if (kind === 'ai_attack') {
    path = `/ai-attack-surface/${projectId}/start`
    fallback = 'Failed to start AI Attack Surface scan'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool: payload.tool ?? 'garak',
      targets: payload.targets ?? [],
      bounds: payload.bounds ?? {},
      roe_confirmed: payload.roe_confirmed ?? false,
      dry_run: payload.dry_run ?? false,
      probes: payload.probes ?? [],
      strategies: payload.strategies ?? [],
      objective: payload.objective ?? '',
      target_model: payload.target_model ?? '',
      target_purpose: payload.target_purpose ?? '',
      // The GitHub token / api_key is never carried in a queue payload (see the
      // enqueue guard: ai_attack with a non-empty api_key is not queueable).
      api_key: payload.api_key ?? '',
      auth_header: payload.auth_header ?? '',
      auth_scheme: payload.auth_scheme ?? '',
    }
  } else if (kind === 'partial_recon') {
    path = `/recon/${projectId}/partial`
    fallback = 'Failed to start partial recon'
    body = {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: WEBAPP_URL,
      tool_id: payload.tool_id,
      graph_inputs: payload.graph_inputs,
      user_inputs: payload.user_inputs ?? [],
      user_targets: payload.user_targets ?? null,
      include_graph_targets: payload.include_graph_targets ?? true,
      settings_overrides: payload.settings_overrides ?? {},
    }
  } else {
    return { ok: false, status: 400, error: `Unknown scan kind: ${kind}` }
  }

  body = { ...body, ...scanJobCredential(projectId, project.userId) }

  const historyRunId = HISTORY_RUN_ID[kind]
  // Read before the start, as the routes do, so a RoE replaced mid-start cannot
  // misattribute the run.
  const roeTextSha256 = historyRunId ? await currentRoeTextSha256(projectId) : null

  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch (err) {
    console.error(`[jobQueue] orchestrator start call for ${kind} on ${projectId} failed:`, err)
    const thrown = classifyOrchestratorThrow(err)
    const why = { code: thrown.code, ...(thrown.cause ? { cause: thrown.cause } : {}) }
    if (!thrown.outcomeUnknown) {
      return { ok: false, status: thrown.status, error: 'The orchestrator could not be reached, so the scan was not started.', ...why }
    }
    // A timeout or a reset is not a refusal: the orchestrator may have spawned
    // the container anyway, and partial recon and AI attack allow parallel
    // runs, so a blind retry could start a duplicate.
    return {
      ok: false,
      status: thrown.status,
      startOutcome: 'unknown',
      error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
      ...why,
    }
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    const { error, limit, code } = normalizeOrchestratorStartError(errorData, fallback)
    return {
      ok: false,
      status: response.status,
      error,
      ...(limit ? { limit: limit as Record<string, unknown> } : {}),
      ...(code ? { code } : {}),
      upstreamStatus: response.status,
    }
  }

  const state = await response.json().catch(() => ({}))
  const scanJobId = historyRunId
    ? await recordScanStart({
        projectId,
        kind,
        runId: historyRunId(state, body),
        initiatedByUserId: opts.actorUserId ?? null,
        // As for the queue's full recon: nobody pressed a button for this run.
        trigger: 'scheduled',
        targets: kind === 'partial_recon' ? grantedRoots(state) : [],
        roeTextSha256,
      })
    : null
  return { ok: true, status: 200, state, runId: runId(state), scanJobId }
}

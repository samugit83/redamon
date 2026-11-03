/**
 * What is happening on ONE project right now, for the inbound MCP surface.
 *
 * The question "is anything writing this graph?" already had an answer in
 * `graphWriters.ts`, but only by asking the orchestrator once per scan kind:
 * up to seven sequential round trips. `graph_summary` sits in the 120/min read
 * bucket, so it could not afford that and checked only two of the seven kinds -
 * reporting `stable` (documented as "the counts are trustworthy") while a GVM,
 * GitHub Secret Hunt, TruffleHog, supply-chain or AI attack-surface scan was
 * inserting finding nodes.
 *
 * `GET /system/active-scans` answers all seven in ONE in-memory read, and its
 * active-status set is at least as conservative as every per-kind set the
 * webapp keeps. It is also cross-project, which is the thing to be careful
 * about: it returns every user's scans, so the filter below runs before any of
 * it is returned or counted.
 *
 * FAIL CLOSED. A source that cannot be read sets `unknown`, never "nothing is
 * running". The webapp's own Activity view swallows this failure and renders an
 * empty list, which is right for a UI with database fallbacks and wrong here:
 * on this surface it becomes a false negative in a security tool.
 */
import { orchestratorFetch } from '@/lib/orchestrator'
import { isActivationInProgress } from '@/lib/activationLock'
import { findLiveTriageRun } from '@/lib/triageRun'
import { findLiveNodeFilterRun } from '@/lib/nodeFilterRun'
import { agentLoopWaiting, checkAgentSessions } from '@/lib/agentSessions'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

/**
 * Short on purpose. This is one in-memory read on the orchestrator, and it sits
 * on the critical path of the most-called tool on the surface; waiting the
 * orchestrator default of 30s would turn a hung dependency into a hung tool
 * call, which a caller cannot tell from a slow answer.
 */
const ACTIVE_SCANS_TIMEOUT_MS = 10_000

/** One in-flight scan, projected. The owning project id is deliberately absent. */
export interface ActiveScan {
  /** full_recon | gvm | github_hunt | supply_chain | trufflehog | partial_recon | ai_attack */
  kind: string
  runId: string
  toolId: string
  status: string
  currentPhase: string | null
  currentGroup: string | null
  groupNumber: number | null
  totalGroups: number | null
  startedAt: string | null
}

export interface ProjectActivity {
  /** Only this project's scans. Another project's work is never included. */
  scans: ActiveScan[]
  agentSession: boolean
  /** The running chat is an Agent in the Loop run waiting for its external agent. */
  waitingForExternalAgent?: boolean
  triageRun: boolean
  /** Mutes and unmutes findings page by page, so counts move while it runs. */
  muteRulesApply: boolean
  activating: boolean
  /** True when a source could not be read. NEVER reported as "nothing running". */
  unknown: boolean
  unknownReason?: string
}

interface RawScan {
  kind?: unknown
  project_id?: unknown
  run_id?: unknown
  tool_id?: unknown
  status?: unknown
  current_phase?: unknown
  current_group?: unknown
  group_number?: unknown
  total_groups?: unknown
  started_at?: unknown
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const strOrNull = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)
const numOrNull = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

function projectScan(raw: RawScan): ActiveScan {
  return {
    kind: str(raw.kind) || 'unknown',
    runId: str(raw.run_id),
    toolId: str(raw.tool_id),
    status: str(raw.status) || 'unknown',
    currentPhase: strOrNull(raw.current_phase),
    currentGroup: strOrNull(raw.current_group),
    groupNumber: numOrNull(raw.group_number),
    totalGroups: numOrNull(raw.total_groups),
    startedAt: strOrNull(raw.started_at),
  }
}

/**
 * Every in-flight scan for ONE project, plus the two non-scan writers.
 *
 * Never throws: a caller deciding whether to trust a count needs an answer, and
 * `unknown` is that answer. The reason is a fixed phrase, never upstream error
 * text, which would carry host paths onto this surface.
 */
export async function readProjectActivity(projectId: string): Promise<ProjectActivity> {
  const out: ProjectActivity = {
    scans: [],
    agentSession: false,
    triageRun: false,
    muteRulesApply: false,
    activating: false,
    unknown: false,
  }
  const unreadable = (reason: string) => {
    out.unknown = true
    // First reason wins: it is the earliest thing that went wrong.
    out.unknownReason ??= reason
  }

  try {
    const resp = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/system/active-scans`,
      {},
      { timeoutMs: ACTIVE_SCANS_TIMEOUT_MS }
    )
    if (!resp.ok) {
      console.error(`[mcp] active-scans returned ${resp.status}`)
      unreadable('the scan state could not be read')
    } else {
      const body = (await resp.json()) as { scans?: unknown }
      if (!Array.isArray(body?.scans)) {
        // A 200 carrying a shape we do not recognise is NOT "nothing is
        // running". Substituting an empty list here reported the graph settled
        // during a live scan, which is the false negative this whole module
        // exists to prevent - reached through schema drift rather than through
        // a scan kind nobody checked. The other sources are still read below,
        // so an activation in flight is still named precisely.
        console.error('[mcp] active-scans returned an unexpected shape')
        unreadable('the scan state could not be read')
      } else {
        // The FILTER, before anything is returned or counted. This endpoint is
        // cross-project by design: the operator's Activity view deliberately
        // shows a count of other people's running scans, which on a token
        // surface is cross-tenant metadata. Never echo another project's id,
        // and never report how many of them there are.
        out.scans = (body.scans as RawScan[])
          .filter(s => str(s.project_id) === projectId)
          .map(projectScan)
      }
    }
  } catch (err) {
    console.error('[mcp] active-scans unreachable:', err)
    unreadable('the orchestrator could not be reached')
  }

  try {
    out.activating = await isActivationInProgress(projectId)
  } catch (err) {
    console.error('[mcp] activation state unreadable:', err)
    unreadable('the version-activation state could not be read')
  }

  try {
    out.triageRun = Boolean(await findLiveTriageRun(projectId))
  } catch (err) {
    console.error('[mcp] triage run state unreadable:', err)
    unreadable('the triage run state could not be read')
  }

  try {
    out.muteRulesApply = Boolean(await findLiveNodeFilterRun(projectId))
  } catch (err) {
    console.error('[mcp] mute rules apply state unreadable:', err)
    unreadable('the Mute Rules apply state could not be read')
  }

  try {
    // 'unverified' (a flag set, the agent unreachable) counts as a session: this
    // report must never read as settled when it cannot tell.
    out.agentSession = (await checkAgentSessions(projectId)) !== 'idle'
  } catch (err) {
    console.error('[mcp] agent session state unreadable:', err)
    unreadable('the agent session state could not be read')
  }

  if (out.agentSession) {
    // Best-effort detail: the session is already counted either way.
    try {
      out.waitingForExternalAgent = await agentLoopWaiting(projectId)
    } catch {
      out.waitingForExternalAgent = false
    }
  }

  return out
}

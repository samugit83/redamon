/**
 * "Is anything writing this project's live graph right now?" (Section 4A.3).
 *
 * Activation deletes and rebuilds the live graph, so it must be mutually
 * exclusive with the four things that write it:
 *   - a full recon scan          (orchestrator recon status)
 *   - a partial recon run        (orchestrator partial-run list)
 *   - an agent / LATS session    (Conversation.agentRunning - the agent writes
 *                                 AttackChain-family nodes and reasons over the
 *                                 graph; swapping it mid-run changes its world)
 *   - a triage run               (TriageRun.status running|publishing with a
 *                                 fresh heartbeat - it reads the whole graph,
 *                                 then writes the ranking back at the end)
 *
 * FAIL CLOSED: if the orchestrator cannot be reached we report "busy" rather than
 * assume idle, because guessing wrong here means swapping the graph under a
 * running scan.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { findLiveTriageRun } from '@/lib/triageRun'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

const ACTIVE_RECON_STATUSES = new Set(['running', 'starting', 'paused', 'stopping'])
const ACTIVE_PARTIAL_STATUSES = new Set(['running', 'starting', 'stopping'])
// GVM / GitHub-secret / TruffleHog share one status enum; these are the states in
// which the scan is still writing (or about to write) finding nodes into the live
// graph. 'paused' counts: a paused scan holds its place and will resume writing.
const ACTIVE_SECONDARY_STATUSES = new Set(['running', 'starting', 'paused', 'stopping'])

/**
 * Returns a human phrase describing what is holding the live graph
 * (e.g. "a full recon scan is running"), or null when the graph is free.
 * Used by ACTIVATION, which is exclusive with all three writers.
 */
export async function describeLiveGraphWriters(projectId: string): Promise<string | null> {
  // A triage run is the fourth writer. It reads the whole graph in memory and
  // publishes at the end, so swapping the graph mid-run makes it write a
  // ranking of findings that no longer exist. Checked first: it is a plain DB
  // read, and a stale heartbeat is swept here so a crashed agent does not lock
  // the project.
  try {
    const triage = await findLiveTriageRun(projectId)
    if (triage) return 'a triage run is in progress'
  } catch (err) {
    console.error('[graphWriters] triage-run check failed (treating as busy):', err)
    return 'the triage run state could not be verified'
  }

  // Agent sessions next: also a plain DB read, no network.
  try {
    const agent = await prisma.conversation.findFirst({
      where: { projectId, agentRunning: true },
      select: { id: true },
    })
    if (agent) return 'an agent session is running'
  } catch (err) {
    console.error('[graphWriters] agent-session check failed (treating as busy):', err)
    return 'the agent session state could not be verified'
  }

  const scan = await describeScanWriters(projectId)
  if (scan) return scan

  // GVM / GitHub-secret / TruffleHog also write finding nodes into the live graph
  // (Section 9A graph WRITERS). Activation deletes+rebuilds that graph, so it must
  // wait for these too - otherwise a swap can half-delete a scan's findings or graft
  // a newer scan's findings onto the restored older version.
  return describeSecondaryScanWriters(projectId)
}

// AI attack surface runs are enumerated (like partial recon), not exposed as one
// project-level status. These are the states in which a run still writes findings.
const ACTIVE_AI_ATTACK_STATUSES = new Set(['running', 'starting', 'stopping'])

/**
 * The GVM / GitHub-secret / TruffleHog / supply-chain / AI-attack-surface subset.
 * Each runs in its own container and writes findings into the live graph keyed by
 * project_id. Used by ACTIVATION only (a full scan legitimately runs alongside
 * these today, same as an agent session, so describeScanWriters deliberately omits
 * them).
 *
 * Supply chain and AI attack surface were missing from this list (C-2): both write
 * into the live graph, so activation could delete+rebuild the graph out from under
 * a running supply-chain or AI-attack scan.
 *
 * FAIL CLOSED: an unverifiable status is reported as busy, never assumed idle.
 */
export async function describeSecondaryScanWriters(projectId: string): Promise<string | null> {
  const checks: Array<{ path: string; label: string }> = [
    { path: `/gvm/${projectId}/status`, label: 'a GVM vulnerability scan is running' },
    { path: `/github-hunt/${projectId}/status`, label: 'a GitHub Secret Hunt is running' },
    { path: `/supply-chain/${projectId}/status`, label: 'a supply-chain scan is running' },
  ]

  for (const { path, label } of checks) {
    try {
      const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })
      if (!res.ok) return `${label.replace(' is running', '')} status could not be verified`
      const status = (await res.json())?.status
      if (status && ACTIVE_SECONDARY_STATUSES.has(status)) return label
    } catch (err) {
      console.error(`[graphWriters] ${path} check failed (treating as busy):`, err)
      return `${label.replace(' is running', '')} status could not be verified`
    }
  }

  // TruffleHog: run-keyed since the multi-source migration, so the /all listing
  // is the only view that sees every source. A project-level status would report
  // one of N parallel runs and the graph would be rebuilt out from under the rest.
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/all`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!res.ok) return 'the Secret Multiscanner scan status could not be verified'
    const data = await res.json()
    const runs: Array<{ status?: string }> = Array.isArray(data?.runs) ? data.runs : []
    if (runs.some(r => r.status && ACTIVE_SECONDARY_STATUSES.has(r.status))) {
      return 'a Secret Multiscanner scan is running'
    }
  } catch (err) {
    console.error('[graphWriters] trufflehog check failed (treating as busy):', err)
    return 'the Secret Multiscanner scan status could not be verified'
  }

  // AI attack surface: run-list shaped, so check each run like partial recon.
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/all`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!res.ok) return 'the AI attack-surface scan status could not be verified'
    const data = await res.json()
    const runs: Array<{ status?: string }> = Array.isArray(data?.runs) ? data.runs : []
    if (runs.some(r => r.status && ACTIVE_AI_ATTACK_STATUSES.has(r.status))) {
      return 'an AI attack-surface scan is running'
    }
  } catch (err) {
    console.error('[graphWriters] ai-attack-surface check failed (treating as busy):', err)
    return 'the AI attack-surface scan status could not be verified'
  }

  return null
}

/**
 * The SCAN subset: a full recon or a partial recon that is rewriting the graph
 * right now. Used before taking a snapshot (Risk 1: a capture must never read a
 * mid-write graph) and before starting another full scan.
 *
 * Deliberately excludes agent sessions: an agent legitimately runs alongside a
 * scan today, and blocking one on the other would be a behavior regression.
 */
export async function describeScanWriters(projectId: string): Promise<string | null> {
  let reconStatus: string | undefined
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!res.ok) return 'the scan status could not be verified'
    reconStatus = (await res.json())?.status
  } catch (err) {
    console.error('[graphWriters] recon status check failed (treating as busy):', err)
    return 'the scan status could not be verified'
  }
  if (reconStatus && ACTIVE_RECON_STATUSES.has(reconStatus)) {
    return 'a full recon scan is running'
  }

  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/all`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!res.ok) return 'the partial-recon status could not be verified'
    const data = await res.json()
    const runs: Array<{ status?: string }> = Array.isArray(data?.runs) ? data.runs : []
    if (runs.some(r => r.status && ACTIVE_PARTIAL_STATUSES.has(r.status))) {
      return 'a partial recon run is active'
    }
  } catch (err) {
    console.error('[graphWriters] partial recon check failed (treating as busy):', err)
    return 'the partial-recon status could not be verified'
  }

  return null
}

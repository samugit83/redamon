/**
 * The other six scanners' status, read-only.
 *
 * `graph_summary` can say a label is absent. It cannot say the scan that
 * PRODUCES that label is running right now, which is the same
 * clean-versus-never-scanned distinction one layer further out - so this is a
 * read, not an afterthought.
 *
 * STARTING these is deliberately still out. GVM and the GitHub hunt both need
 * a prior recon JSON on disk, supply-chain refuses org input mode, and the AI
 * attack-surface start takes an inline api_key and an roe_confirmed flag in its
 * body, which is a non-starter on a credentialed surface.
 */
import { orchestratorFetch } from '@/lib/orchestrator'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const STATUS_TIMEOUT_MS = 15_000

/** How many runs a run-list scanner reports. Plenty; bounded anyway. */
const MAX_RUNS = 50

interface ScannerSpec {
  /** `/…/{projectId}/…` */
  path: (projectId: string) => string
  /** A single ReconState, or a `{runs: [...]}` list. */
  shape: 'state' | 'runs'
  label: string
}

export const SCANNERS: Record<string, ScannerSpec> = {
  gvm: {
    path: id => `/gvm/${id}/status`,
    shape: 'state',
    label: 'GVM vulnerability scan',
  },
  github_hunt: {
    path: id => `/github-hunt/${id}/status`,
    shape: 'state',
    label: 'GitHub Secret Hunt',
  },
  supply_chain: {
    path: id => `/supply-chain/${id}/status`,
    shape: 'state',
    label: 'supply-chain scan',
  },
  trufflehog: {
    path: id => `/trufflehog/${id}/all`,
    shape: 'runs',
    label: 'Secret Multiscanner',
  },
  ai_attack: {
    path: id => `/ai-attack-surface/${id}/all`,
    shape: 'runs',
    label: 'AI attack-surface scan',
  },
  partial_recon: {
    path: id => `/recon/${id}/partial/all`,
    shape: 'runs',
    label: 'partial recon run',
  },
}

export const SCANNER_NAMES = Object.keys(SCANNERS)

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)
const numOrNull = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null

/**
 * Mask exactly as `projectReconState` does.
 *
 * The raw state carries `container_id` and an `error` populated with raw
 * exception text: a Docker SDK failure embeds the deployment's absolute host
 * paths and image names. A boolean is actionable; the exception is
 * reconnaissance about the host, placed straight into a model's context.
 */
function maskState(raw: unknown): Record<string, unknown> {
  const s = (raw ?? {}) as Record<string, unknown>
  return {
    status: str(s.status) ?? 'unknown',
    currentPhase: str(s.current_phase) ?? str(s.currentPhase),
    startedAt: str(s.started_at) ?? str(s.startedAt),
    completedAt: str(s.completed_at) ?? str(s.completedAt),
    ...(numOrNull(s.findings_count) !== null ? { findingsCount: numOrNull(s.findings_count) } : {}),
    ...(str(s.tool_id) ? { toolId: str(s.tool_id) } : {}),
    ...(str(s.run_id) ? { runId: str(s.run_id) } : {}),
    failed: s.status === 'error' || Boolean(s.error),
  }
}

export async function getScanStatus(ctx: McpContext, projectId: string, scanner: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const spec = SCANNERS[scanner]
  if (!spec) {
    throw new McpToolError(
      `Unknown scanner '${scanner}'. One of: ${SCANNER_NAMES.join(', ')}. For the full recon ` +
      `pipeline use get_recon_status.`,
      'bad_args'
    )
  }

  let resp: Response
  try {
    resp = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}${spec.path(projectId)}`,
      {},
      { timeoutMs: STATUS_TIMEOUT_MS }
    )
  } catch (err) {
    console.error(`[mcp] ${scanner} status unreachable:`, err)
    // NEVER "idle". Reporting "not running" for "cannot tell" is the false
    // negative this whole surface exists to avoid.
    throw new McpToolError(
      `The ${spec.label} status is unknown: the orchestrator is unreachable.`,
      'status_unknown'
    )
  }
  if (!resp.ok) {
    console.error(`[mcp] ${scanner} status returned ${resp.status}`)
    throw new McpToolError(`The ${spec.label} status is unknown.`, 'status_unknown')
  }

  const body = (await resp.json().catch(() => null)) as Record<string, unknown> | null
  if (!body) {
    throw new McpToolError(`The ${spec.label} status is unknown.`, 'status_unknown')
  }

  if (spec.shape === 'state') {
    return { projectId, scanner, scan: maskState(body) }
  }

  // A 200 whose `runs` key is absent or the wrong type is NOT zero runs: that
  // would answer "no scan is running" during one, which is the distinction this
  // tool exists to draw.
  if (!Array.isArray(body.runs)) {
    console.error(`[mcp] ${scanner} returned an unexpected shape`)
    throw new McpToolError(`The ${spec.label} status is unknown.`, 'status_unknown')
  }
  const runs = body.runs
  return {
    projectId,
    scanner,
    runs: runs.slice(0, MAX_RUNS).map(maskState),
    returned: Math.min(runs.length, MAX_RUNS),
    total: runs.length,
    ...(runs.length > MAX_RUNS ? { truncated: true } : {}),
  }
}

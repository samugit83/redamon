/**
 * Pure helpers for the scan queue (Scan Queue plan Phase 1). No I/O, no Prisma,
 * no globals: every function is deterministic given its arguments, so it is unit
 * testable without a database.
 *
 *   - envelopeForKind:    the enqueue-time memory estimate stored on the row. The
 *                         real admission authority is the orchestrator ledger at
 *                         dispatch; this is only a hint for ordering + display.
 *   - settingsFingerprint: sha256 over the scan-relevant project settings for a
 *                         kind (C-4). Recomputed at dispatch; a mismatch means the
 *                         config changed under the operator and the job must go to
 *                         needs_review instead of silently running the new config.
 *   - orderCandidates:    priority desc, then oldest-first. The dispatcher walks
 *                         this order and head-of-line reserves (see the dispatcher).
 *   - nextBackoff:        deterministic exponential backoff for a deferred retry.
 */
import { createHash } from 'crypto'

export type JobKind =
  | 'full_recon'
  | 'partial_recon'
  | 'gvm'
  | 'github_hunt'
  | 'trufflehog'
  | 'supply_chain'
  | 'supply_chain_repo'
  | 'ai_attack'

/**
 * Mirror of recon_orchestrator/resource_profile.default.json scan_job_envelope_bytes.
 * The ledger is the authority at dispatch; keep this in sync for a sane estimate.
 * supply_chain_repo shares the supply_chain envelope (same container shape).
 */
export const SCAN_JOB_ENVELOPE_BYTES: Record<string, number> = {
  full_recon: 2147483648,
  partial_recon: 805306368,
  ai_attack: 1073741824,
  gvm: 2684354560,
  github_hunt: 805306368,
  trufflehog: 805306368,
  // Source-qualified, mirroring the orchestrator: docker and huggingface
  // decompress remote blobs and peak well above the git-based sources.
  'trufflehog:docker': 1610612736,
  'trufflehog:huggingface': 1610612736,
  'trufflehog:s3': 1207959552,
  'trufflehog:gcs': 1207959552,
  supply_chain: 1879048192,
  supply_chain_repo: 1879048192,
  _default: 2147483648,
}

export function envelopeForKind(kind: string): number {
  const exact = SCAN_JOB_ENVELOPE_BYTES[kind]
  if (exact !== undefined) return exact
  // A qualified kind ('trufflehog:github') with no entry of its own falls back
  // to its BASE kind, not to _default — mirroring scan_job_envelope() in
  // resource_governor.py. Without this, a source we deliberately left on the
  // family envelope would be estimated at the 2 GB unknown-type figure here and
  // at 768 MB by the ledger, and the queue would order jobs by a number the
  // admission gate disagrees with.
  if (kind.includes(':')) {
    const base = SCAN_JOB_ENVELOPE_BYTES[kind.split(':')[0]]
    if (base !== undefined) return base
  }
  return SCAN_JOB_ENVELOPE_BYTES._default
}

/**
 * The scan-relevant project-settings subset per kind (C-4). A change to ANY of
 * these between enqueue and dispatch must block the run for re-confirmation, so
 * the fingerprint covers exactly the fields that steer where/what a job scans.
 */
export const FINGERPRINT_FIELDS: Record<string, readonly string[]> = {
  full_recon: ['targetDomain', 'ipMode', 'targetIps', 'scanModules', 'targetGuardrailEnabled', 'stealthMode'],
  partial_recon: ['targetDomain', 'ipMode', 'targetIps', 'scanModules', 'targetGuardrailEnabled', 'stealthMode'],
  // gvmPortList steers WHAT is scanned: swapping the top-1000 UDP list for the
  // full IANA sweep turns a minutes-long scan into an hours-long one. Omitting it
  // would let that change slip past the C-4 re-confirmation guard.
  gvm: ['targetDomain', 'ipMode', 'targetIps', 'gvmScanConfig', 'gvmScanTargets', 'gvmPortList'],
  github_hunt: ['githubTargetOrg', 'githubTargetRepos', 'githubScanMembers', 'githubScanGists', 'githubScanCommits'],
  // Only the SHARED options still live on Project; the per-source targets moved
  // to TrufflehogScanProfile and are folded in by the caller through `extra`
  // (see resolveTrufflehogFingerprintExtra). Listing the old
  // trufflehogGithubOrg/Repos columns here would hash a CONSTANT — the fields no
  // longer exist, settingsFingerprint skips undefined ones, and the C-4
  // re-confirmation guard would be silently disabled.
  trufflehog: ['trufflehogNoVerification', 'trufflehogResultTypes', 'trufflehogIncludeDetectors', 'trufflehogExcludeDetectors'],
  supply_chain: ['supplyChainInputMode', 'supplyChainSbomFile', 'supplyChainRepoUrl', 'supplyChainRepoRef', 'supplyChainRepoScope', 'supplyChainDeepAnalysisEnabled'],
  supply_chain_repo: ['supplyChainInputMode', 'supplyChainSbomFile', 'supplyChainRepoUrl', 'supplyChainRepoRef', 'supplyChainRepoScope', 'supplyChainDeepAnalysisEnabled'],
  ai_attack: [],
}

/** Stable JSON: sorted object keys, sorted primitive arrays, so equal settings
 * always serialize identically regardless of field or array order. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    const mapped = value.map(canonicalize)
    // Sort arrays of primitives for order-independence (e.g. targetIps). Leave
    // arrays of objects in place (order may be meaningful and rarely occurs here).
    if (mapped.every(v => v === null || typeof v !== 'object')) {
      return [...mapped].sort((a, b) => String(a).localeCompare(String(b)))
    }
    return mapped
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

/**
 * sha256 hex over the kind's scan-relevant settings subset. `project` is any
 * object carrying the fields (typically a Prisma Project row); unknown/absent
 * fields are simply omitted, so a not-yet-added column never throws.
 */
export function settingsFingerprint(
  kind: string,
  project: Record<string, unknown>,
  /** Extra scan-steering settings that do not live on the Project row. Merged in
   *  before hashing. TruffleHog needs this: its targets moved to a per-source
   *  profile, and without them the hash covers only the shared options — so
   *  re-pointing a Docker scan at a different namespace would not invalidate the
   *  queued job. */
  extra?: Record<string, unknown>,
): string {
  const fields = FINGERPRINT_FIELDS[kind] ?? []
  const subset: Record<string, unknown> = {}
  for (const f of fields) {
    if (project[f] !== undefined) subset[f] = project[f]
  }
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (v !== undefined) subset[k] = v
    }
  }
  const canonical = JSON.stringify({ kind, settings: canonicalize(subset) })
  return createHash('sha256').update(canonical).digest('hex')
}

export interface OrderableCandidate {
  priority: number
  enqueuedAt: Date | string | number
}

function ms(t: Date | string | number): number {
  return t instanceof Date ? t.getTime() : new Date(t).getTime()
}

/**
 * Dispatch order: higher priority first (manual 10 > scheduled 0 > batch -10),
 * ties broken by oldest enqueue first. Returns a new sorted array; does not
 * mutate the input.
 */
export function orderCandidates<T extends OrderableCandidate>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority
    return ms(a.enqueuedAt) - ms(b.enqueuedAt)
  })
}

export const BACKOFF_BASE_MS = 30_000
export const BACKOFF_MAX_MS = 1_800_000 // 30 minutes

/**
 * Deterministic exponential backoff for a deferred retry: 30s, 60s, 120s, ...
 * capped at 30 minutes. `attempts` is the number of attempts already made.
 * Returns milliseconds; the caller adds it to `now` to set notBefore.
 */
export function nextBackoff(attempts: number): number {
  const n = Math.max(0, Math.floor(attempts))
  const raw = BACKOFF_BASE_MS * Math.pow(2, n)
  return Math.min(raw, BACKOFF_MAX_MS)
}

/**
 * Short, FIXED re-check delay for a job that is only WAITING FOR CAPACITY (a slot,
 * memory, or the project's turn) rather than failing. Aligned to roughly one
 * dispatcher tick (~20s) so a freed slot is picked up promptly instead of after
 * an escalating exponential backoff. Capacity waits must NOT use nextBackoff():
 * that couples the wait to an attempt counter, which both delays a legitimate
 * promotion once a slot frees and eventually fails a job that did nothing wrong.
 */
export const CAPACITY_RECHECK_MS = 20_000

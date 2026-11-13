/**
 * One engine, two doors: every Priority Board action the UI routes and the MCP
 * tools share.
 *
 * Each action exists ONCE, in the agent and the graph mixin; this module is the
 * webapp half of it, parameterised by the door it was called through (`app` or
 * `mcp`). The doors keep only what is theirs: authentication, argument shapes,
 * and how an error is presented.
 *
 * Three rules every write here enforces, so neither door can forget one:
 *
 * 1. **Not during a version switch (B19).** Activation freezes the graph,
 *    clears it and restores it; a write committed after the freeze is deleted by
 *    the clear, after a 200. Every write checks before it runs AND after it
 *    returns, and a switch that started meanwhile turns its success into an
 *    error the caller cannot mistake for one.
 * 2. **The graph's view is refreshed (C18).** `invalidateCache` after a write,
 *    as the mute route does, so the drawer and "Ask agent" do not serve
 *    pre-write values for ten seconds.
 * 3. **An MCP write during a live run needs a layered agent.** Such an agent
 *    re-reads decisions and reviews under the node lock when the run publishes,
 *    so the write is honoured. An older agent would let the publish re-file the
 *    finding from its pre-write analysis, so without its acknowledgement
 *    (`layered_publish`) the write is refused: version skew fails closed.
 */
import { createHash } from 'crypto'
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { isActivationInProgress } from '@/lib/activationLock'
import { writeAudit } from '@/lib/audit'
import { invalidateCache } from '@/app/api/graph/cache'

export type TriageChannel = 'app' | 'mcp'

export interface TriageTenant {
  userId: string
  projectId: string
}

/** The finding labels a single-finding action may be narrowed to. */
export const FINDING_LABELS = [
  'Vulnerability', 'JsReconFinding', 'Secret', 'MultiscannerFinding',
  'GithubSecret', 'GithubSensitiveFile', 'MalPackageFinding', 'ExploitGvm',
] as const

/** A finding id as the board and MCP send it: the stored `id` / `finding_id`. */
export const FINDING_ID_RE = /^[A-Za-z0-9_.:-]{1,200}$/

export const DECIDED_BY = ['person', 'review', 'rules'] as const
export const REVIEWED_VIA = ['builtin', 'mcp', 'none'] as const
export const REVIEW_CURRENT = ['current', 'stale', 'none'] as const

export interface BoardFilters {
  decidedBy?: (typeof DECIDED_BY)[number]
  reviewedVia?: (typeof REVIEWED_VIA)[number]
  reviewCurrent?: (typeof REVIEW_CURRENT)[number]
}

/**
 * A refusal or a failure, with a stable `code` each door maps to its own shape
 * (an HTTP status for the UI, a `Refused (<code>): ...` message for MCP).
 */
export class TriageActionError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status: number,
    public readonly details: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = 'TriageActionError'
  }
}

const READ_TIMEOUT_MS = 60_000
/** The agent's own write transaction times out at 15 s; this covers the trip. */
const WRITE_TIMEOUT_MS = 30_000

/** Transport errors that happen before the request leaves: nothing was written. */
const REFUSED_BEFORE_SENDING = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
])

function refusedBeforeSending(err: unknown): boolean {
  const e = err as { code?: unknown; cause?: { code?: unknown } } | null
  const code = e?.cause?.code ?? e?.code
  return typeof code === 'string' && REFUSED_BEFORE_SENDING.has(code)
}

const ERRNO = /^(E[A-Z0-9_]{2,40}|UND_ERR_[A-Z_]{2,40})$/
const AGENT_CODE = /^[a-z][a-z0-9_]{0,63}$/
const AGENT_CLASS = /^[A-Za-z_][A-Za-z0-9_.]{0,79}$/

/** The errno or timeout class of a transport failure, which tells a stopped
 *  agent (ECONNREFUSED) from a hung one (TimeoutError); `{}` when there is none. */
function transportCause(err: unknown): { cause?: string } {
  const e = err as { name?: unknown; code?: unknown; cause?: { code?: unknown } } | null
  const code = e?.cause?.code ?? e?.code
  if (typeof code === 'string' && ERRNO.test(code)) return { cause: code }
  return e?.name === 'TimeoutError' || e?.name === 'AbortError' ? { cause: String(e.name) } : {}
}

/** What the agent said about a failure it answered: its status, its own code
 *  and the exception class it reported, never its message. */
function agentFailureFacts(status: number, body: Record<string, unknown> | null): Record<string, unknown> {
  const agentCode = typeof body?.code === 'string' && AGENT_CODE.test(body.code) ? body.code : undefined
  const errorClass = typeof body?.error_class === 'string' && AGENT_CLASS.test(body.error_class)
    ? body.error_class : undefined
  return {
    upstreamStatus: status,
    ...(agentCode ? { agentCode } : {}),
    ...(errorClass ? { errorClass } : {}),
  }
}

interface CallOptions {
  channel: TriageChannel
  write?: boolean
  path?: string
}

/**
 * One call into the agent, as data. `source: 'mcp'` opts an MCP call into the
 * agent's MCP concurrency ceiling; the UI's calls leave it unset.
 */
export async function agentTriage(
  op: string,
  tenant: TriageTenant,
  extra: Record<string, unknown>,
  opts: CallOptions,
): Promise<Record<string, unknown>> {
  const path = opts.path ?? '/graph/triage'
  const payload = path === '/graph/triage'
    ? { op, user_id: tenant.userId, project_id: tenant.projectId,
        ...(opts.channel === 'mcp' ? { source: 'mcp' } : {}), ...extra }
    : { ...extra }
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}${path}`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(opts.write ? WRITE_TIMEOUT_MS : READ_TIMEOUT_MS),
    })
  } catch (err) {
    console.error(`[triage] ${op} transport error:`, err)
    if (opts.write && !refusedBeforeSending(err)) {
      throw new TriageActionError(
        'The request was sent but its answer was lost, so it may or may not have been applied. ' +
          'Re-read the finding before trying again.',
        'outcome_unknown', 502, transportCause(err))
    }
    throw new TriageActionError('The findings service is unavailable.', 'agent_unreachable', 503,
                                transportCause(err))
  }
  const body = (await resp.json().catch(() => null)) as Record<string, unknown> | null
  if (!resp.ok) {
    const message = typeof body?.error === 'string' ? body.error : ''
    if (resp.status === 503 && (body?.code === 'busy' || body?.code === 'retry')) {
      throw new TriageActionError(message || 'The graph is busy; nothing was changed.', 'busy', 503)
    }
    if (resp.status === 400 && /unknown op/i.test(message)) {
      throw new TriageActionError(
        'The findings service is older than this RedAmon build and does not know this ' +
          'operation, so nothing was done. The operator must rebuild the agent image.',
        'agent_outdated', 502)
    }
    if (resp.status === 400) {
      throw new TriageActionError(message || 'The request was refused.', 'bad_args', 400)
    }
    if (resp.status === 409) {
      throw new TriageActionError(message || 'Refused.', String(body?.code || 'busy'), 409)
    }
    console.error(`[triage] ${op} failed (${resp.status})`, message)
    const facts = agentFailureFacts(resp.status, body)
    // The agent's own sentence for a deployment it refuses to serve
    // (INTERNAL_API_KEY unset) says what to do; nothing else is forwarded.
    if (facts.agentCode === 'not_configured' && message) {
      throw new TriageActionError(message, 'agent_failed', 502, facts)
    }
    throw new TriageActionError('The findings service failed.', 'agent_failed', 502, facts)
  }
  if (!body || typeof body !== 'object') {
    if (opts.write) {
      throw new TriageActionError('The answer was lost; re-read the finding.', 'outcome_unknown', 502)
    }
    throw new TriageActionError('The findings could not be read.', 'agent_failed', 502)
  }
  return body
}

/** Refuse while a version switch is in progress. An unreadable lock refuses too. */
async function refuseDuringActivation(projectId: string): Promise<void> {
  let activating: boolean
  try {
    activating = await isActivationInProgress(projectId)
  } catch (err) {
    console.error('[triage] activation state unreadable:', err)
    throw new TriageActionError(
      'Whether a version switch is in progress could not be determined, so nothing was written.',
      'busy', 503)
  }
  if (activating) {
    throw new TriageActionError(
      'A version switch is in progress on this project; nothing was written. Retry once it has finished.',
      'busy', 409)
  }
}

/** After a successful write: a switch that started meanwhile has deleted it. */
async function confirmNoActivationStarted(projectId: string): Promise<void> {
  let activating = true
  try {
    activating = await isActivationInProgress(projectId)
  } catch {
    activating = true
  }
  if (activating) {
    throw new TriageActionError(
      'An activation started while this was saved; re-check the finding after the switch.',
      'activation_changed', 409)
  }
}

/**
 * Every MCP write needs an agent that enforces the layered rules: one that
 * refuses to change a decision made in the app (`decided_in_app`) and honours
 * a write made during a run at publish. An older agent does neither, and the
 * webapp alone cannot tell, so the probe is an op only such an agent knows.
 * A confirmation is trusted for a few minutes, so a rollback is caught soon.
 */
const LAYERED_CONFIRM_TTL_MS = 5 * 60 * 1000
let layeredConfirmedAt = 0

/** Test seam: start with the agent confirmed, or not. */
export function __setLayeredAgentConfirmed(confirmed: boolean): void {
  layeredConfirmedAt = confirmed ? Date.now() : 0
}

async function requireLayeredAgent(tenant: TriageTenant, findingId: string): Promise<void> {
  if (Date.now() - layeredConfirmedAt < LAYERED_CONFIRM_TTL_MS) return
  let body: Record<string, unknown> | null = null
  try {
    body = await agentTriage('finding_detail', tenant, { node_id: findingId }, { channel: 'mcp' })
  } catch {
    body = null
  }
  if (body?.layered_publish !== true) {
    throw new TriageActionError(
      'The findings service could not confirm it enforces the rules an agent\'s write needs ' +
        '(it may be older than this RedAmon build), so nothing was written. The operator ' +
        'must rebuild the agent image.',
      'agent_outdated', 502)
  }
  layeredConfirmedAt = Date.now()
}

function filterArgs(filters: BoardFilters): Record<string, string> {
  const out: Record<string, string> = {}
  if (filters.decidedBy) out.decided_by = filters.decidedBy
  if (filters.reviewedVia) out.reviewed_via = filters.reviewedVia
  if (filters.reviewCurrent) out.review_current = filters.reviewCurrent
  return out
}

/** The board: findings (capped) and the exact total of the filtered set. */
export async function listFindings(
  tenant: TriageTenant,
  opts: { limit?: number; filters?: BoardFilters; channel: TriageChannel },
): Promise<{ findings: Array<Record<string, unknown>>; total: number | undefined }> {
  const body = await agentTriage('list_findings', tenant, {
    ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
    ...filterArgs(opts.filters ?? {}),
  }, { channel: opts.channel })
  const findings = Array.isArray(body.findings) ? (body.findings as Array<Record<string, unknown>>) : null
  if (!findings) throw new TriageActionError('The findings could not be read.', 'agent_failed', 502)
  return { findings, total: typeof body.total === 'number' ? body.total : undefined }
}

/** Uncapped counts behind the filters. Null when they cannot be read: display only. */
export async function triageFacets(
  tenant: TriageTenant, channel: TriageChannel,
): Promise<Record<string, unknown> | null> {
  try {
    const body = await agentTriage('triage_facets', tenant, {}, { channel })
    const { layered_publish: _a, mcp_gated: _b, ...facets } = body
    return facets
  } catch (err) {
    console.error('[triage] facets unavailable:', err)
    return null
  }
}

function notFoundOrAmbiguous(body: Record<string, unknown>): TriageActionError {
  if (Array.isArray(body.ambiguous) || Array.isArray(body.labels)) {
    const labels = (body.ambiguous ?? body.labels) as string[]
    return new TriageActionError(
      `The id matches findings of more than one kind (${labels.join(', ')}); pass label to pick one.`,
      'ambiguous', 409, { labels })
  }
  return new TriageActionError(
    'No such finding in this project: a wrong id, another project\'s id, or a muted finding.',
    'not_found', 404)
}

/** Everything behind one finding's place on the board. */
export async function readFinding(
  tenant: TriageTenant, findingId: string, label: string | undefined, channel: TriageChannel,
): Promise<Record<string, unknown>> {
  const body = await agentTriage('finding_detail', tenant,
    { node_id: findingId, ...(label ? { label } : {}) }, { channel })
  if (body.found !== true) throw notFoundOrAmbiguous(body)
  return body
}

/** What a reviewer reads: the redacted evidence bundle, its hash and the rules. */
export async function readEvidence(
  tenant: TriageTenant, findingId: string, label: string | undefined, channel: TriageChannel,
): Promise<Record<string, unknown>> {
  const body = await agentTriage('finding_evidence', tenant,
    { node_id: findingId, ...(label ? { label } : {}) }, { channel })
  if (body.found !== true) throw notFoundOrAmbiguous(body)
  return body
}

export const VERDICT_STATUSES = ['confirmed', 'likely_noise', 'unreviewed'] as const
export type VerdictStatus = (typeof VERDICT_STATUSES)[number]

export interface VerdictInput {
  findingId: string
  status: VerdictStatus
  reason?: string
  label?: string
  channel: TriageChannel
  verdictBy?: string
  tokenPrefix?: string
}

export interface WriteResult {
  label: string | null
  rescored: boolean
  rescoreReason?: string
  before: Record<string, unknown> | null
  after: Record<string, unknown> | null
  row: Record<string, unknown> | null
}

/** A person's decision (Real / False positive / Reset), rescored at once. */
export async function recordVerdict(tenant: TriageTenant, input: VerdictInput): Promise<WriteResult> {
  await refuseDuringActivation(tenant.projectId)
  if (input.channel === 'mcp') await requireLayeredAgent(tenant, input.findingId)

  const body = await agentTriage('human_verdict', tenant, {
    node_id: input.findingId,
    status: input.status,
    reason: (input.reason ?? '').slice(0, 500),
    ...(input.label ? { label: input.label } : {}),
    ...(input.verdictBy ? { verdict_by: input.verdictBy } : {}),
    ...(input.channel === 'mcp' && input.tokenPrefix ? { token_prefix: input.tokenPrefix } : {}),
  }, { channel: input.channel, write: true })

  if (body.updated !== true) {
    const reason = typeof body.reason === 'string' ? body.reason : ''
    if (reason === 'muted') {
      throw new TriageActionError('The finding is muted; nothing was written.', 'muted', 409)
    }
    if (reason === 'decided_in_app') {
      throw new TriageActionError(
        'A person decided this in the app, and that decision can only be changed in the app. ' +
          'Nothing was written.', 'decided_in_app', 409)
    }
    if (reason && reason !== 'not_found' && reason !== 'ambiguous') {
      throw new TriageActionError(`The verdict was not recorded (${reason}).`, 'not_updated', 409)
    }
    throw notFoundOrAmbiguous(body)
  }

  await confirmNoActivationStarted(tenant.projectId)
  invalidateCache(tenant.projectId)
  return writeResult(body)
}

function writeResult(body: Record<string, unknown>): WriteResult {
  return {
    label: typeof body.label === 'string' ? body.label : null,
    rescored: body.rescored === true,
    ...(typeof body.rescore_reason === 'string' ? { rescoreReason: body.rescore_reason } : {}),
    before: (body.before as Record<string, unknown>) ?? null,
    after: (body.after as Record<string, unknown>) ?? null,
    row: (body.row as Record<string, unknown>) ?? null,
  }
}

export interface ReviewInput {
  findingId: string
  label?: string
  evidenceHash: string
  verdict: string
  evidenceQuote?: string
  disputedFacts?: Array<{ fact: string; quote: string }>
  impactMultiplier?: number
  impactQuote?: string
  why?: string
  fixLever?: string
  tokenId: string
  tokenPrefix: string
  actorUserId: string
}

/** What `submit_review` refuses with, in words an agent can act on. */
const REVIEW_REFUSALS: Record<string, string> = {
  not_found: 'No such finding in this project (or it is muted).',
  out_of_triage_scope: 'The finding is not one the Priority Board ranks, so it cannot be reviewed.',
  not_scored: 'The finding has not been ranked by a triage run yet; there is nothing to correct.',
  decided_by_person: 'A person decided this finding; a review can never override that.',
  proven: 'The finding is proven (an exploit ran or a credential validated); a review may not lower it.',
  not_open: 'The finding is fixed, gone or inactive, so it is not ranked.',
  source_not_reviewed: 'Findings from this source are facts or advisories and are not reviewed.',
  no_evidence: 'The finding carries no evidence to review.',
  evidence_changed: 'The evidence changed since it was read. Read it again with get_finding_evidence.',
  bad_verdict: 'Unknown verdict.',
}

/** An external agent's review (MCP only). */
export async function submitReview(tenant: TriageTenant, input: ReviewInput) {
  await refuseDuringActivation(tenant.projectId)
  await requireLayeredAgent(tenant, input.findingId)

  const review = {
    verdict: input.verdict,
    evidence_quote: input.evidenceQuote ?? '',
    disputed_facts: input.disputedFacts ?? [],
    impact_multiplier: input.impactMultiplier ?? 1.0,
    impact_quote: input.impactQuote ?? '',
    why: input.why ?? '',
    fix_lever: input.fixLever ?? '',
  }
  const body = await agentTriage('submit_review', tenant, {
    node_id: input.findingId,
    ...(input.label ? { label: input.label } : {}),
    evidence_hash: input.evidenceHash,
    token_prefix: input.tokenPrefix,
    review,
  }, { channel: 'mcp', write: true })

  if (body.written !== true) {
    const reason = typeof body.reason === 'string' ? body.reason : 'not_found'
    if (reason === 'ambiguous') throw notFoundOrAmbiguous(body)
    throw new TriageActionError(REVIEW_REFUSALS[reason] ?? `Refused: ${reason}.`, reason,
                                reason === 'not_found' ? 404 : 409)
  }

  await confirmNoActivationStarted(tenant.projectId)
  invalidateCache(tenant.projectId)

  const result = writeResult(body)
  const accepted = (body.accepted as Record<string, unknown>) ?? {}
  // Forensic matching without storing target text: a hash of what was said.
  const textSha256 = createHash('sha256')
    .update([review.why, review.evidence_quote, review.impact_quote, review.fix_lever,
             ...review.disputed_facts.map((d) => d.quote)].join('\u0000'))
    .digest('hex')
  void writeAudit({
    actorId: input.actorUserId,
    action: 'triage.review',
    targetType: 'finding',
    targetId: input.findingId,
    after: {
      projectId: tenant.projectId,
      findingId: input.findingId,
      label: result.label,
      verdict: accepted.verdict ?? null,
      disputes: accepted.disputed_facts ?? [],
      multiplier: accepted.impact_multiplier ?? null,
      before: result.before,
      after: result.after,
      tokenId: input.tokenId,
      tokenPrefix: input.tokenPrefix,
      textSha256,
    },
    source: 'mcp',
  })
  return {
    ...result,
    accepted,
    dropped: Array.isArray(body.dropped) ? body.dropped : [],
    reviewSurvivesRescan: body.review_survives_rescan !== false,
  }
}

/** Start (or attach to) a run with no browser attached. */
export async function startRun(
  tenant: TriageTenant,
  opts: { trigger: TriageChannel; tokenId?: string; realActorUserId?: string | null;
          maxReviewBudget?: number;
          /** The person the run is for when not the owner (a collaborator over MCP, step 5.10). */
          actorUserId?: string },
): Promise<{ runId: string | null; attached: boolean }> {
  const body = await agentTriage('start', tenant, {
    user_id: tenant.userId,
    project_id: tenant.projectId,
    trigger: opts.trigger,
    ...(opts.actorUserId ? { actor_user_id: opts.actorUserId } : {}),
    ...(opts.tokenId ? { token_id: opts.tokenId } : {}),
    ...(opts.realActorUserId ? { real_actor_user_id: opts.realActorUserId } : {}),
    ...(opts.maxReviewBudget !== undefined ? { max_review_budget: opts.maxReviewBudget } : {}),
  }, { channel: opts.trigger, write: true, path: '/triage/runs' })
  return { runId: typeof body.runId === 'string' ? body.runId : null, attached: body.attached === true }
}

/** Stop a run. Refused by the agent while it publishes (`reason: 'publishing'`). */
export async function stopRun(
  tenant: TriageTenant, channel: TriageChannel,
): Promise<{ stopped: boolean; reason?: string; runId?: string }> {
  const body = await agentTriage('stop', tenant, { project_id: tenant.projectId },
    { channel, write: true, path: '/triage/runs/stop' })
  return {
    stopped: body.stopped === true,
    ...(typeof body.reason === 'string' ? { reason: body.reason } : {}),
    ...(typeof body.runId === 'string' ? { runId: body.runId } : {}),
  }
}

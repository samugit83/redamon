/**
 * One answer per finding to "can this go in a report?" (plan 10, read-side).
 *
 *   reportable  proven (an exploit or a validator showed it), or a person confirmed it
 *   candidate   might be real; its `blocker` says what is missing
 *   info        no impact, even if real
 *   excluded    a person judged it a false positive, or a rule resolved it
 *
 * A Priority Board run (score model v3.10+) stores the answer on the node,
 * `triage_disposition` and `triage_blocker`, and every reader shows that. For a
 * node no such run has rescored, the same rules run here on what the board
 * already stores, in this order, so the first rule that matches wins. An AI
 * review alone decides none of them: its false positive stays a candidate with
 * a blocker that says so, because the reviewer reads target-controlled text
 * (see reportable.ts). Unknown or missing values make a candidate "not triaged
 * yet", never a reportable finding.
 *
 * "Excluded" is always reportable.ts's own bucket, read live before any stored
 * answer, and the public-key test is publicClientKeys.ts's, so a finding's
 * disposition can never disagree with the report's "not counted" lines or its
 * public-key list.
 *
 * A candidate's blocker is the first of the four gates (reachable now,
 * attributed, controlled, impactful) its run found failing, else the first it
 * could not tell, else its tier rule. score_model.disposition_of is the stored
 * half; agentic/tests/test_disposition_parity.py runs it over the vector files
 * this half is tested on.
 *
 * Both halves here are built from the same constants: the board and MCP decide
 * in TypeScript, the report and Insights group in Cypher. The live parity check
 * over the shared vectors is disposition.integration.test.ts. The Cypher half
 * cannot read the gates inside the stored tier inputs (a JSON string), and needs
 * not: a run writes them together with the stored answer it prefers. Neither
 * Cypher half names the `Muted` label or binds a parameter, so any query can
 * carry it.
 */
import { reportBucket, reportBucketCypher, reportCountable, type ReportTriageProps } from './reportable'
import { agentCandidateConfirmedOrNA, notMuted } from '@/lib/graphMute'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'
import { isPublicClientKey, publicClientKeyCypher } from '@/lib/secrets/publicClientKeys'

export const DISPOSITIONS = ['reportable', 'candidate', 'info', 'excluded'] as const
export type Disposition = (typeof DISPOSITIONS)[number]

export const DISPOSITION_LABELS: Record<Disposition, string> = {
  reportable: 'Reportable',
  candidate: 'Candidate',
  info: 'Info',
  excluded: 'Excluded',
}

/** What each disposition means, for a tooltip or a legend. */
export const DISPOSITION_MEANINGS: Record<Disposition, string> = {
  reportable: 'Proven (an exploit or a validator showed it), or a person confirmed it.',
  candidate: 'Might be real. Verify it before reporting it.',
  info: 'No impact, even if real.',
  excluded: 'A person judged it a false positive, or it was resolved (fixed, gone, inactive).',
}

/** The heading the severity breakdowns carry: a scanner's severity is a claim. */
export const SCANNER_SEVERITY_LABEL = 'Scanner severity (not yet verified)'

/** The tier rules read here, exactly as `score_model.tier_rule` returns them. */
export const TIER_RULE_PROVEN = 'proven'
export const TIER_RULE_NO_IMPACT = 'nothing here has any impact'

export const BLOCKER_NOT_TRIAGED = 'not triaged yet'
export const BLOCKER_AI_FALSE_POSITIVE = 'AI review: likely false positive'

/** The four gates, in the order a blocker names them (score_model.GATES). */
export const GATES = ['reachable_now', 'attributed', 'controlled', 'impactful'] as const
export type Gate = (typeof GATES)[number]

/** Each gate's blocker when it fails, and when the run could not tell. */
export const GATE_BLOCKERS: Record<Gate, { failed: string; unknown: string }> = {
  reachable_now: { failed: 'not reachable now', unknown: 'unknown: reachable now' },
  attributed: { failed: 'shared edge', unknown: 'unknown: attributed' },
  controlled: { failed: 'failed its control check', unknown: 'unknown: controlled' },
  impactful: { failed: 'no impact shown', unknown: 'unknown: impactful' },
}

/** The board's own info-level severities (the triage mixin's severity rank). */
export const INFO_SEVERITIES = ['info', 'informational', 'none'] as const

export interface DispositionResult {
  disposition: Disposition
  /** Set for a candidate only. */
  blocker: string | null
}

/** A finding's property bag, or a Priority Board row. */
export interface DispositionProps extends ReportTriageProps {
  triage_tier_rule?: unknown
  severity?: unknown
  public_client_key?: unknown
  secret_type?: unknown
  /** JSON: the run's tier inputs, with its `gates` and `public_client_key`. */
  triage_tier_inputs?: unknown
  /** The answer a run stored, preferred when it is whole. */
  triage_disposition?: unknown
  triage_blocker?: unknown
}

/** The answers a run may store; "excluded" is always decided live. */
const STORED = ['reportable', 'candidate', 'info'] as const

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/

function quoted(values: readonly string[]): string {
  return `[${values.map((v) => `'${v}'`).join(', ')}]`
}

function tierRuleOf(p: DispositionProps): string {
  return typeof p.triage_tier_rule === 'string' ? p.triage_tier_rule : ''
}

/** As `evidence.person_decided` reads a Real: a legacy or unattributed one is not a person's. */
function personConfirmed(p: DispositionProps): boolean {
  return p.triage_status === 'confirmed' && p.triage_source === 'human'
}

function infoSeverity(p: DispositionProps): boolean {
  return typeof p.severity === 'string' &&
    (INFO_SEVERITIES as readonly string[]).includes(p.severity.trim().toLowerCase())
}

interface StoredInputs {
  gates: Record<Gate, boolean | null> | null
  publicClientKey: boolean
}

/** The run's tier inputs, as score_model.TierInputs.from_dict reads them. */
function storedInputs(p: DispositionProps): StoredInputs {
  let raw: unknown = p.triage_tier_inputs
  if (typeof raw === 'string') {
    try { raw = JSON.parse(raw) } catch { raw = null }
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { gates: null, publicClientKey: false }
  const inputs = raw as Record<string, unknown>
  const g = inputs.gates
  const gates = g && typeof g === 'object' && !Array.isArray(g)
    ? Object.fromEntries(GATES.map((k) => {
      const v = (g as Record<string, unknown>)[k]
      return [k, typeof v === 'boolean' ? v : null]
    })) as Record<Gate, boolean | null>
    : null
  return { gates, publicClientKey: inputs.public_client_key === true }
}

/** The first gate that failed, else the first unknown one; null if all passed or none was measured. */
function gateBlocker(gates: Record<Gate, boolean | null> | null): string | null {
  if (!gates) return null
  for (const g of GATES) if (gates[g] === false) return GATE_BLOCKERS[g].failed
  for (const g of GATES) if (gates[g] === null) return GATE_BLOCKERS[g].unknown
  return null
}

function storedDisposition(p: DispositionProps): DispositionResult | null {
  const d = p.triage_disposition
  if (!(STORED as readonly unknown[]).includes(d)) return null
  if (d !== 'candidate') return { disposition: d as Disposition, blocker: null }
  const b = p.triage_blocker
  return typeof b === 'string' && b !== '' ? { disposition: 'candidate', blocker: b } : null
}

/**
 * The rules on their own, ignoring a stored answer: what a reader shows for a
 * node no v3.10 run has rescored, and what a run's stored answer must equal.
 */
export function readSideDisposition(p: DispositionProps): DispositionResult {
  const bucket = reportBucket(p)
  if (bucket === 'resolved' || bucket === 'person_false_positive') {
    return { disposition: 'excluded', blocker: null }
  }
  const rule = tierRuleOf(p)
  if (rule === TIER_RULE_PROVEN || personConfirmed(p)) {
    return { disposition: 'reportable', blocker: null }
  }
  const inputs = storedInputs(p)
  if (rule === TIER_RULE_NO_IMPACT || isPublicClientKey(p.public_client_key, p.secret_type) ||
      inputs.publicClientKey || (rule === '' && infoSeverity(p))) {
    return { disposition: 'info', blocker: null }
  }
  if (bucket === 'ai_flagged') return { disposition: 'candidate', blocker: BLOCKER_AI_FALSE_POSITIVE }
  return { disposition: 'candidate', blocker: gateBlocker(inputs.gates) || rule || BLOCKER_NOT_TRIAGED }
}

export function disposition(p: DispositionProps): DispositionResult {
  const bucket = reportBucket(p)
  if (bucket === 'resolved' || bucket === 'person_false_positive') {
    return { disposition: 'excluded', blocker: null }
  }
  return storedDisposition(p) ?? readSideDisposition(p)
}

/** Null when there are no props to read: a reader then shows nothing, never a default. */
export function readDisposition(props: unknown): DispositionResult | null {
  if (!props || typeof props !== 'object' || Array.isArray(props)) return null
  return disposition(props as DispositionProps)
}

/** "Candidate, blocked by <blocker>", in the words every surface uses. */
export function dispositionText(r: DispositionResult): string {
  const label = DISPOSITION_LABELS[r.disposition]
  if (r.disposition !== 'candidate' || !r.blocker) return label
  if (r.blocker === BLOCKER_NOT_TRIAGED) return `${label}, ${BLOCKER_NOT_TRIAGED}`
  return `${label}, blocked by ${r.blocker}`
}

function checked(v: string): string {
  if (!IDENTIFIER.test(v)) throw new Error(`not a Cypher identifier: ${v}`)
  return v
}

function tierRuleCypher(v: string): string {
  return `coalesce(${v}.triage_tier_rule, '')`
}

/**
 * The stored answer is whole: an answer a run may store, and a candidate names
 * its blocker. `> ''` is null, so false, for a missing or non-string blocker,
 * where trim() would fail the whole query.
 */
function storedCypher(v: string): string {
  return (
    `(${v}.triage_disposition IN ${quoted(STORED.filter((d) => d !== 'candidate'))} ` +
    `OR (${v}.triage_disposition = 'candidate' AND ${v}.triage_blocker > ''))`
  )
}

/** A Cypher expression yielding the `Disposition` of the finding bound to `v`. */
export function dispositionCypher(v: string): string {
  checked(v)
  const rule = tierRuleCypher(v)
  return (
    `CASE WHEN NOT (${reportCountable(v)}) THEN 'excluded' ` +
    `WHEN ${storedCypher(v)} THEN ${v}.triage_disposition ` +
    `WHEN ${rule} = '${TIER_RULE_PROVEN}' ` +
    `OR (coalesce(${v}.triage_status, '') = 'confirmed' AND coalesce(${v}.triage_source, '') = 'human') ` +
    `THEN 'reportable' ` +
    `WHEN ${rule} = '${TIER_RULE_NO_IMPACT}' OR ${publicClientKeyCypher(v)} ` +
    `OR (${rule} = '' AND toLower(trim(toString(coalesce(${v}.severity, '')))) IN ${quoted(INFO_SEVERITIES)}) ` +
    `THEN 'info' ELSE 'candidate' END`
  )
}

/** A Cypher expression yielding the blocker of the finding bound to `v`: null unless a candidate. */
export function blockerCypher(v: string): string {
  checked(v)
  const rule = tierRuleCypher(v)
  return (
    `CASE WHEN ${dispositionCypher(v)} = 'candidate' THEN ` +
    `CASE WHEN ${storedCypher(v)} THEN ${v}.triage_blocker ` +
    `WHEN ${reportBucketCypher(v)} = 'ai_flagged' THEN '${BLOCKER_AI_FALSE_POSITIVE}' ` +
    `WHEN ${rule} <> '' THEN ${v}.triage_tier_rule ELSE '${BLOCKER_NOT_TRIAGED}' END END`
  )
}

/**
 * A WHERE fragment for the severity breakdowns: a finding with no impact (info)
 * says nothing about how severe the open work is, so they count reportable and
 * candidate findings only. ANDed with `reportCountable`, which already drops
 * the excluded ones.
 */
export function inSeverityBreakdown(v: string): string {
  return `${dispositionCypher(v)} IN ['reportable', 'candidate']`
}

export interface DispositionSummary {
  reportable: number
  candidate: number
  info: number
  excluded: number
  /** Candidates by blocker, largest first. */
  blockers: { blocker: string; count: number }[]
}

/** How many blockers a summary names before it sums the rest. */
export const TOP_BLOCKERS = 5

export function topBlockers(blockers: DispositionSummary['blockers']) {
  const top = blockers.slice(0, TOP_BLOCKERS)
  const rest = blockers.slice(TOP_BLOCKERS)
  return { top, otherCount: rest.reduce((s, b) => s + b.count, 0), otherBlockers: rest.length }
}

function toCount(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/**
 * Every unmuted finding of a project, by disposition, for the headline of the
 * report and Insights. The same finding set as `queryJudgedFindings`. Null,
 * never zeros, when the query fails: "0 reportable" would be a claim.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function queryDispositionSummary(session: any, pid: string, uid?: string): Promise<DispositionSummary | null> {
  try {
    const tenantWhere = uid ? 'n.user_id = $uid AND n.project_id = $pid' : 'n.project_id = $pid'
    const params = uid ? { pid, uid } : { pid }
    const res = await session.run(
      `MATCH (n:${MUTEABLE_FINDING_LABELS.join('|')})
       WHERE ${tenantWhere} AND ${notMuted('n')} AND ${agentCandidateConfirmedOrNA('n')}
       WITH ${dispositionCypher('n')} AS disposition, ${blockerCypher('n')} AS blocker
       RETURN disposition, blocker, count(*) AS total`,
      params
    )
    const summary: DispositionSummary = { reportable: 0, candidate: 0, info: 0, excluded: 0, blockers: [] }
    const byBlocker = new Map<string, number>()
    for (const r of res.records) {
      const d = r.get('disposition')
      if (!(DISPOSITIONS as readonly unknown[]).includes(d)) continue
      const total = toCount(r.get('total'))
      summary[d as Disposition] += total
      const blocker = r.get('blocker')
      if (d === 'candidate' && typeof blocker === 'string') {
        byBlocker.set(blocker, (byBlocker.get(blocker) ?? 0) + total)
      }
    }
    summary.blockers = [...byBlocker.entries()]
      .map(([blocker, count]) => ({ blocker, count }))
      .sort((a, b) => b.count - a.count || a.blocker.localeCompare(b.blocker))
    return summary
  } catch (e) {
    console.warn('[triage] disposition counts could not be read:', e)
    return null
  }
}

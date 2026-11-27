/**
 * Which findings the deliverable surfaces COUNT, once the Priority Board has
 * judged them: the client report, Insights and the MCP analytics tools.
 *
 * A finding drops out of their counts only when a PERSON judged it a false
 * positive, or a rule resolved it (fixed, gone, inactive). An AI review alone
 * never removes one. The reviewers, builtin and MCP, read target-controlled
 * evidence, so an injected sentence in a JS file or a response body can make
 * them answer `false_positive`; such a finding stays counted and is reported
 * on its own line instead.
 *
 * "A person" is `triage_status = 'likely_noise'` WITH `triage_source = 'human'`,
 * as `evidence.person_decided` reads it: a v3.1 node can still carry an AI's
 * `likely_noise` under `triage_source = 'ai'` until the next publish retires
 * it. A resolved state wins over everything, as in `combine_layers` and the
 * board's `_section_of`, which keeps the buckets disjoint.
 *
 * A missing or unknown `triage_state` is open: an unrecognised value is never
 * read as a judgement.
 *
 * Neither Cypher half names the `Muted` label or binds a parameter, so the MCP
 * analytics Cypher (which `scope_query` refuses for either) can carry it too.
 */
import { agentCandidateConfirmedOrNA, notMuted } from '@/lib/graphMute'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'

export const RESOLVED_TRIAGE_STATES = ['fixed', 'gone', 'inactive'] as const

export type ReportBucket = 'counted' | 'ai_flagged' | 'person_false_positive' | 'resolved'

/** A finding's property bag; only the three triage fields are read. */
export interface ReportTriageProps {
  triage_state?: unknown
  triage_status?: unknown
  triage_source?: unknown
  [property: string]: unknown
}

const RESOLVED_LIST = `[${RESOLVED_TRIAGE_STATES.map((s) => `'${s}'`).join(', ')}]`

function stateOf(p: ReportTriageProps): string {
  return typeof p.triage_state === 'string' && p.triage_state !== '' ? p.triage_state : 'open'
}

export function reportBucket(p: ReportTriageProps): ReportBucket {
  const state = stateOf(p)
  if ((RESOLVED_TRIAGE_STATES as readonly string[]).includes(state)) return 'resolved'
  if (p.triage_status === 'likely_noise' && p.triage_source === 'human') return 'person_false_positive'
  // Whatever false_positive state survives the person test was set by a review.
  if (state === 'false_positive' || (p.triage_status === 'likely_noise' && p.triage_source === 'ai')) {
    return 'ai_flagged'
  }
  return 'counted'
}

export function isReportCountable(p: ReportTriageProps): boolean {
  const bucket = reportBucket(p)
  return bucket === 'counted' || bucket === 'ai_flagged'
}

function resolvedCypher(v: string): string {
  return `coalesce(${v}.triage_state, 'open') IN ${RESOLVED_LIST}`
}

function personFalsePositiveCypher(v: string): string {
  return `coalesce(${v}.triage_status, '') = 'likely_noise' AND coalesce(${v}.triage_source, '') = 'human'`
}

/** A WHERE fragment: the finding bound to `v` is counted. ANDed with `notMuted`. */
export function reportCountable(v: string): string {
  return `NOT (${personFalsePositiveCypher(v)}) AND NOT ${resolvedCypher(v)}`
}

/** A Cypher expression yielding the `ReportBucket` of the finding bound to `v`. */
export function reportBucketCypher(v: string): string {
  return (
    `CASE WHEN ${resolvedCypher(v)} THEN 'resolved' ` +
    `WHEN ${personFalsePositiveCypher(v)} THEN 'person_false_positive' ` +
    `WHEN coalesce(${v}.triage_state, 'open') = 'false_positive' ` +
    `OR (coalesce(${v}.triage_status, '') = 'likely_noise' AND coalesce(${v}.triage_source, '') = 'ai') ` +
    `THEN 'ai_flagged' ELSE 'counted' END`
  )
}

export interface JudgedFindingCounts {
  personFalsePositive: number
  resolved: number
  aiFlagged: number
}

function toCount(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/**
 * How many unmuted findings of a project the board judged, by bucket, for the
 * report's and Insights' "not counted above" lines. A muted finding is only
 * ever counted as suppressed, never twice. Null, never zeros, when the query
 * fails: a reader must not take "could not count" for "none".
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function queryJudgedFindings(session: any, pid: string, uid?: string): Promise<JudgedFindingCounts | null> {
  try {
    const res = await session.run(
      `MATCH (n:${MUTEABLE_FINDING_LABELS.join('|')})
       WHERE ${uid ? 'n.user_id = $uid AND ' : ''}n.project_id = $pid AND ${notMuted('n')} AND ${agentCandidateConfirmedOrNA('n')}
       WITH ${reportBucketCypher('n')} AS bucket
       WHERE bucket <> 'counted'
       RETURN bucket, count(*) AS total`,
      uid ? { uid, pid } : { pid }
    )
    const counts: JudgedFindingCounts = { personFalsePositive: 0, resolved: 0, aiFlagged: 0 }
    for (const r of res.records) {
      const total = toCount(r.get('total'))
      const bucket = r.get('bucket')
      if (bucket === 'person_false_positive') counts.personFalsePositive += total
      else if (bucket === 'resolved') counts.resolved += total
      else if (bucket === 'ai_flagged') counts.aiFlagged += total
    }
    return counts
  } catch (e) {
    console.warn('[triage] judged-finding counts could not be read:', e)
    return null
  }
}

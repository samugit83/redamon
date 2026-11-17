'use client'

import type { IngestionReport as Report } from '@/lib/tradecraft/agentContract'
import css from './mapView.module.css'

const SKIP_WORDS: ReadonlyArray<[keyof Report['skipped'], string]> = [
  ['excluded', 'excluded'], ['outOfScope', 'out of scope'], ['tooLittleText', 'too little text'],
  ['robots', 'robots.txt'], ['outsideFocus', 'outside the focus'],
]

/** The crawl's stop codes in words; Auto's own line ("auto: robots (21 pages)") is already words. */
const STOP_WORDS: Readonly<Record<string, string>> = {
  max_pages: 'the page limit', max_llm_calls: 'the model call limit', time_budget: 'the time limit',
  max_map_entries: 'the map entry limit', frontier_empty: 'every link was visited', no_llm: 'no model to guide the crawl',
  llm_stop: 'the model said stop', llm_error: 'a model call failed', llm_parse_error: "the model's answer was unreadable",
  cancelled: 'cancelled', sitemap: 'the sitemap was read',
}

const READINESS_WORDS: ReadonlyArray<[string, string]> = [
  ['realTitlesPct', 'real titles'], ['headingsPct', 'headings'], ['descriptionPct', 'descriptions'], ['taggedPct', 'tagged'],
]

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const n = (v: number) => v.toLocaleString('en-US')

export function stopText(code: string): string {
  return STOP_WORDS[code] ? `${STOP_WORDS[code]} (${code})` : code
}

function bytesText(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

/**
 * The report in one line: the accordion row's "40 visited, 31 kept, 9 LLM calls, 61 s, stopped: …";
 * `short`, the card's "40 visited, 31 kept, stopped: …", its calls and time one click away.
 */
export function reportSummary(report: Partial<Report>, short = false): string {
  const parts = [`${n(num(report.visited) ?? 0)} visited`, `${n(num(report.kept) ?? 0)} kept`]
  const calls = num(report.llmCalls)
  if (calls !== null && !short) parts.push(`${n(calls)} LLM calls`)
  const secs = num(report.durationSec)
  if (secs !== null && !short) parts.push(`${Math.round(secs)} s`)
  return `${parts.join(', ')}${report.stopReason ? `, stopped: ${report.stopReason}` : ''}`
}

/** What the focus did (§6.14 "Transparency"): "focus kept 120 of 4,800 pages". */
export function focusText(focus: Report['focus'] | undefined): string {
  if (!focus || Object.keys(focus).length === 0) return ''
  const mode = focus.mode === 'tag_only' || focus.mode === 'tagOnly' ? 'Tag only' : focus.mode === 'focused' ? 'Focused' : String(focus.mode ?? '')
  const kept = num(focus.kept)
  const dropped = num(focus.dropped)
  if (kept === null || dropped === null) return mode ? `${mode}: nothing dropped` : ''
  const maybe = num(focus.maybe) ?? 0
  return `${mode}: focus kept ${n(kept)} of ${n(kept + dropped)} pages${maybe ? `, ${n(maybe)} of them as maybe` : ''}`
}

/** Q4's readiness line, with the fix the agent suggests when a share is low. */
export function readinessText(readiness: Report['readiness'] | undefined): { line: string; suggestion: string } {
  if (!readiness) return { line: '', suggestion: '' }
  const line = READINESS_WORDS.filter(([k]) => num(readiness[k]) !== null).map(([k, w]) => `${readiness[k]}% ${w}`).join(', ')
  const suggestion = readiness.suggestStored
    ? 'Few pages have headings or a description: Stored mode keeps a copy that gives every page both.'
    : readiness.suggestContentChecks
      ? 'Few pages have a description: a focus with content checks writes one for each page it checks.'
      : ''
  return { line, suggestion }
}

/**
 * The full ingestion report (§3.3): the one-line summary, opening to every count the agent wrote:
 * pages visited and kept, skipped by reason, the stop reason, model calls, duration, what was
 * stored and what was not, the focus counts, readiness and errors by code. Counts and codes only:
 * the report never holds a URL or page text.
 */
export function IngestionReport({ report, testId, short = false }: { report: Partial<Report>; testId?: string; short?: boolean }) {
  const skipped = report.skipped
  const skips = skipped ? SKIP_WORDS.filter(([k]) => (num(skipped[k]) ?? 0) > 0).map(([k, w]) => `${n(skipped[k])} ${w}`) : []
  const stored = report.stored
  const focus = focusText(report.focus)
  const ready = readinessText(report.readiness)
  const errors = report.errors ?? []
  return (
    <details className={css.report}>
      <summary data-testid={testId}>{reportSummary(report, short)}</summary>
      <dl className={css.reportList} data-testid="tc-report-full">
        <dt>Pages visited</dt><dd>{n(num(report.visited) ?? 0)}</dd>
        <dt>Pages kept</dt><dd>{n(num(report.kept) ?? 0)}</dd>
        <dt>Skipped</dt><dd>{skips.length ? skips.join(', ') : 'none'}</dd>
        <dt>Stop reason</dt><dd>{report.stopReason ? stopText(report.stopReason) : 'none'}</dd>
        <dt>Model calls</dt><dd>{n(num(report.llmCalls) ?? 0)}</dd>
        <dt>Duration</dt><dd>{Math.round(num(report.durationSec) ?? 0)} s</dd>
        <dt>Stored copy</dt>
        <dd>
          {stored && (num(stored.pages) ?? 0) > 0 ? `${n(stored.pages)} pages, ${bytesText(num(stored.bytes) ?? 0)}` : 'no page stored'}
          {stored && (num(stored.notStoredQuota) ?? 0) > 0 ? `; ${n(stored.notStoredQuota)} not stored (storage quota)` : ''}
          {stored && (num(stored.notStoredSize) ?? 0) > 0 ? `; ${n(stored.notStoredSize)} not stored (page too large)` : ''}
        </dd>
        {focus && <><dt>Focus</dt><dd>{focus}</dd></>}
        {ready.line && <><dt>Readiness</dt><dd>{ready.line}{ready.suggestion && <span className={css.hint}> {ready.suggestion}</span>}</dd></>}
        {errors.length > 0 && <><dt>Errors</dt><dd>{errors.map(e => `${e.code} × ${n(e.count)}`).join(', ')}</dd></>}
      </dl>
    </details>
  )
}

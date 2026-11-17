/** The full ingestion report (§3.3, T6.8): every count the agent writes, and its one-line summary. */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { IngestionReport, focusText, readinessText, reportSummary, stopText } from './IngestionReport'
import type { IngestionReport as Report } from '@/lib/tradecraft/agentContract'

afterEach(cleanup)

const REPORT: Report = {
  visited: 4800, kept: 120, skipped: { excluded: 12, outOfScope: 3, tooLittleText: 40, robots: 2, outsideFocus: 4680 },
  stopReason: 'max_pages', llmCalls: 57, durationSec: 183.4,
  stored: { pages: 118, bytes: 3_145_728, notStoredQuota: 1, notStoredSize: 1 },
  focus: { mode: 'focused', kept: 120, maybe: 9, dropped: 4680 },
  readiness: { realTitlesPct: 92, headingsPct: 40, descriptionPct: 30, taggedPct: 88, suggestContentChecks: 1 },
  errors: [{ code: 'page_too_large', count: 2 }, { code: 'fetch_failed', count: 1 }],
}

describe('IngestionReport', () => {
  test('report_fields: visited, kept, skipped by reason, stop reason, model calls, duration, stored and not stored, focus, readiness, errors', () => {
    render(<IngestionReport report={REPORT} testId="r" />)
    expect(screen.getByTestId('r')).toHaveTextContent('4,800 visited, 120 kept, 57 LLM calls, 183 s, stopped: max_pages')
    fireEvent.click(screen.getByTestId('r'))
    const full = within(screen.getByTestId('tc-report-full'))
    const rows = Object.fromEntries([...screen.getByTestId('tc-report-full').querySelectorAll('dt')].map(dt => [dt.textContent, dt.nextElementSibling?.textContent]))
    expect(rows).toEqual({
      'Pages visited': '4,800',
      'Pages kept': '120',
      Skipped: '12 excluded, 3 out of scope, 40 too little text, 2 robots.txt, 4,680 outside the focus',
      'Stop reason': 'the page limit (max_pages)',
      'Model calls': '57',
      Duration: '183 s',
      'Stored copy': '118 pages, 3.0 MB; 1 not stored (storage quota); 1 not stored (page too large)',
      Focus: 'Focused: focus kept 120 of 4,800 pages, 9 of them as maybe',
      Readiness: '92% real titles, 40% headings, 30% descriptions, 88% tagged Few pages have a description: a focus with content checks writes one for each page it checks.',
      Errors: 'page_too_large × 2, fetch_failed × 1',
    })
    expect(full.queryByText(/https?:/)).toBeNull()
  })

  test('an empty report: no reasons, nothing stored, no focus or readiness line', () => {
    render(<IngestionReport report={{ ...REPORT, skipped: { excluded: 0, outOfScope: 0, tooLittleText: 0, robots: 0, outsideFocus: 0 }, stored: { pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0 }, focus: {}, readiness: {}, errors: [], stopReason: '' }} />)
    const dts = [...screen.getByTestId('tc-report-full').querySelectorAll('dt')].map(d => d.textContent)
    expect(dts).toEqual(['Pages visited', 'Pages kept', 'Skipped', 'Stop reason', 'Model calls', 'Duration', 'Stored copy'])
    expect(screen.getByText('no page stored')).toBeInTheDocument()
  })

  test('the summary leaves out what a report does not hold; stop codes in words; Auto\'s own line kept', () => {
    expect(reportSummary({ visited: 40, kept: 31, stopReason: 'frontier_empty' })).toBe('40 visited, 31 kept, stopped: frontier_empty')
    expect(reportSummary({ ...REPORT, stopReason: 'max_pages' }, true)).toBe('4,800 visited, 120 kept, stopped: max_pages')
    expect(stopText('frontier_empty')).toBe('every link was visited (frontier_empty)')
    expect(stopText('auto: robots (21 pages)')).toBe('auto: robots (21 pages)')
    expect(focusText({ mode: 'tag_only' })).toBe('Tag only: nothing dropped')
    expect(focusText({})).toBe('')
    expect(readinessText({ realTitlesPct: 20, headingsPct: 10, descriptionPct: 5, taggedPct: 60, suggestStored: 1 }).suggestion).toMatch(/Stored mode/)
  })
})

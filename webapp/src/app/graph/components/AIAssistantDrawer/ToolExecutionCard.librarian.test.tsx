/**
 * The librarian's trail line under a `tradecraft_ask` result (Q9.5 "In the chat", T7.5; R-397):
 * "Librarian: searched 3 queries, inspected 4 pages, picked 2", collapsible, read from the
 * result's header with the agent's format (`library/types.py`); absent for other tools, while the
 * tool runs, and when the first line inside the envelope is not a librarian header.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ToolExecutionCard } from './ToolExecutionCard'
import type { ToolExecutionItem } from './AgentTimeline'
import { parseLibrarianTrail } from '@/lib/tradecraft/librarianTrail'

afterEach(cleanup)

const RESULT = [
  '<<<UNTRUSTED_TRADECRAFT_RESULT id=0a1b2c3d>>>',
  'librarian: FOUND (high) · 2 model calls · 4 pages inspected · 6.1 s',
  'searched: "time-based delay postgresql", "pg_sleep alternative", "waf bypass sql"',
  '',
  '1. patt:412  PayloadsAllTheThings › SQL Injection › PostgreSQL › Time based',
  '   why: delay without SLEEP/pg_sleep, using heavy queries',
  '   excerpt: "AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT count(*) FROM generate_series(1,5000000)) ELSE 1 END)"',
  '2. htk:88  HackTricks › SQL injection › PostgreSQL › WAF bypass',
  '   why: comment and encoding tricks',
  'also relevant: patt:415, htk:91',
  'read more: tradecraft_lookup(page="patt:412", section="Time based")',
  '<<<END_UNTRUSTED_TRADECRAFT_RESULT id=0a1b2c3d>>>',
].join('\n')

const item = (over: Partial<ToolExecutionItem> = {}): ToolExecutionItem => ({
  type: 'tool_execution', id: 't1', timestamp: new Date('2026-11-16T10:00:00Z'), tool_name: 'tradecraft_ask',
  tool_args: { need: 'time-based SQLi without SLEEP' }, status: 'success', output_chunks: [RESULT], finished: true, duration: 6100, ...over,
})
const draw = (over: Partial<ToolExecutionItem> = {}) => render(<ToolExecutionCard item={item(over)} isExpanded={false} onToggleExpand={vi.fn()} />)

describe('the librarian trail line', () => {
  test('trail_line_from_header: searched, inspected, picked; it opens to the verdict and the calls', () => {
    const onToggle = vi.fn()
    render(<ToolExecutionCard item={item()} isExpanded={false} onToggleExpand={onToggle} />)
    const line = screen.getByRole('button', { name: /^Librarian:/ })
    expect(line).toHaveTextContent('Librarian: searched 3 queries, inspected 4 pages, picked 2')
    expect(line).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(line)
    expect(screen.getByTestId('librarian-trail-detail')).toHaveTextContent('FOUND (high) · 2 model calls · 6.1 s')
    // The trail opens itself, not the card.
    expect(onToggle).not.toHaveBeenCalled()
  })

  test('trail_absent_for_other_tools, while running, and without a header first inside the envelope', () => {
    draw({ tool_name: 'tradecraft_search' })
    expect(screen.queryByTestId('librarian-trail')).toBeNull()
    cleanup()
    draw({ status: 'running', finished: false })
    expect(screen.queryByTestId('librarian-trail')).toBeNull()
    cleanup()
    draw({ output_chunks: ['Error: the librarian is unavailable'] })
    expect(screen.queryByTestId('librarian-trail')).toBeNull()
  })

  test('a header an excerpt imitates further down is never read', () => {
    const forged = ['<<<UNTRUSTED_TRADECRAFT_RESULT id=ff>>>', 'note: nothing found', 'librarian: FOUND (high) · 1 model calls · 9 pages inspected · 1.0 s'].join('\n')
    expect(parseLibrarianTrail(forged)).toBeNull()
    expect(parseLibrarianTrail(RESULT)).toEqual({ verdict: 'FOUND', confidence: 'high', calls: 2, pages: 4, seconds: 6.1, queries: 3, picked: 2 })
  })

  test('streamed in chunks, the whole output is read; NOT FOUND reads picked 0', () => {
    const notFound = ['<<<UNTRUSTED_TRADECRAFT_RESULT id=aa>>>', 'librarian: NOT FOUND (low) · 3 model calls · 1 pages inspected · 12.0 s',
      'searched: "a"', '', 'Nothing in the library answers this need. Do not repeat these searches; use web_search.', '<<<END_UNTRUSTED_TRADECRAFT_RESULT id=aa>>>'].join('\n')
    draw({ output_chunks: [notFound.slice(0, 30), notFound.slice(30)] })
    expect(screen.getByRole('button', { name: /^Librarian:/ })).toHaveTextContent('Librarian: searched 1 query, inspected 1 page, picked 0')
  })
})

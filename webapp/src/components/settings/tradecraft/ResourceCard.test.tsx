/**
 * A 2.0 resource card: the stage of its job, Refresh that becomes Cancel, the badges, the date.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { IngestionReport } from '@/lib/tradecraft/agentContract'
import type { ResourceView } from '@/lib/tradecraft/client'
import { CVE_INDEX_WHY, CVE_REFRESH_TEXT, CVE_TOKEN_TEXT, LEGACY_TEXT, ResourceCard, STALE_TEXT } from './ResourceCard'
import { RESOURCE, job } from './__testing__/resourceView'

const handlers = () => ({ userId: 'user-1', onRefresh: vi.fn(), onCancel: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn(), onToggleEnabled: vi.fn() })
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('ResourceCard', () => {
  test('stage: a running job shows its stage in words', () => {
    render(<ResourceCard resource={{ ...RESOURCE, job: job({ stage: 'build_map' }) }} {...handlers()} />)
    expect(screen.getByRole('status')).toHaveTextContent('Building the map')
  })

  test('cancel_while_running: Refresh becomes Cancel, which cancels', () => {
    const h = handlers()
    render(<ResourceCard resource={{ ...RESOURCE, job: job({ status: 'queued' }) }} {...h} />)
    expect(screen.queryByRole('button', { name: /Refresh/ })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Cancel/ }))
    expect(h.onCancel).toHaveBeenCalledWith(expect.objectContaining({ id: 'r1' }))
  })

  test('with no job running the card offers Refresh', () => {
    const h = handlers()
    render(<ResourceCard resource={RESOURCE} {...h} />)
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    expect(h.onRefresh).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: /Cancel/ })).toBeNull()
  })

  test('stale_badge: "Ingested with older settings" with a Refresh link (R-029)', () => {
    const h = handlers()
    render(<ResourceCard resource={{ ...RESOURCE, stale: true }} {...h} />)
    const badge = screen.getByText(STALE_TEXT)
    expect(STALE_TEXT).toBe('Ingested with older settings')
    fireEvent.click(within(badge).getByRole('button', { name: 'Refresh' }))
    expect(h.onRefresh).toHaveBeenCalledTimes(1)
  })

  test('legacy_badge: a resource converted from 1.x says what a refresh adds (R-216)', () => {
    render(<ResourceCard resource={{ ...RESOURCE, mapVersion: 2 }} {...handlers()} />)
    expect(screen.getByText(LEGACY_TEXT)).toBeInTheDocument()
    expect(LEGACY_TEXT).toBe('Ingested before 2.0: refresh for headings, descriptions and search inside pages')
    cleanup()
    render(<ResourceCard resource={RESOURCE} {...handlers()} />)
    expect(screen.queryByText(LEGACY_TEXT)).toBeNull()
  })

  test('last_refreshed: when it was last refreshed, or never (R-099)', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-11-16T10:00:00Z'))
    render(<ResourceCard resource={{ ...RESOURCE, lastRefreshedAt: '2026-11-13T09:00:00.000Z' }} {...handlers()} />)
    expect(screen.getByText('Last refreshed 3d ago')).toBeInTheDocument()
    cleanup()
    render(<ResourceCard resource={RESOURCE} {...handlers()} />)
    expect(screen.getByText('Last refreshed never')).toBeInTheDocument()
  })

  test('map_button: Map opens the resource\'s Map view (§6.10); the card shows the full report (§3.3)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ entries: [], total: 0, nextCursor: null }), { status: 200 })))
    render(<ResourceCard resource={{ ...RESOURCE, report: { visited: 40, kept: 31, stopReason: 'max_pages', llmCalls: 3, durationSec: 9 } as never }} {...handlers()} />)
    // The card's line keeps its words (T4.x, the e2e specs); calls and time are in the full report.
    expect(screen.getByTestId('tc-report').textContent).toBe('40 visited, 31 kept, stopped: max_pages')
    expect(screen.getByTestId('tc-report-full')).toHaveTextContent('Model calls3')
    expect(screen.getByTestId('tc-report-full')).toHaveTextContent('the page limit (max_pages)')
    fireEvent.click(screen.getByRole('button', { name: 'Map of Lab Wiki' }))
    expect(await screen.findByText('No pages in the map yet: refresh the resource to build it.')).toBeInTheDocument()
    expect(vi.mocked(fetch)).toHaveBeenCalledWith('/api/users/user-1/tradecraft-resources/r1/map?status=kept', undefined)
    vi.unstubAllGlobals()
  })

  test('a failed ingestion is no refresh: its 1.x verification time is not shown as one; a clean 1.x verify is', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-11-16T10:00:00Z'))
    render(<ResourceCard resource={{ ...RESOURCE, mapVersion: 1, lastVerifiedAt: '2026-11-16T09:59:30.000Z', lastError: 'fetch_failed' }} {...handlers()} />)
    expect(screen.getByText('Last refreshed never')).toBeInTheDocument()
    cleanup()
    render(<ResourceCard resource={{ ...RESOURCE, mapVersion: 1, lastVerifiedAt: '2026-11-13T09:00:00.000Z', lastError: '' }} {...handlers()} />)
    expect(screen.getByText('Last refreshed 3d ago')).toBeInTheDocument()
    cleanup()
    render(<ResourceCard resource={{ ...RESOURCE, mapVersion: 3, lastRefreshedAt: '2026-11-13T09:00:00.000Z', lastVerifiedAt: '2026-11-16T09:59:30.000Z', lastError: 'fetch_failed' }} {...handlers()} />)
    expect(screen.getByText('Last refreshed 3d ago')).toBeInTheDocument()
  })
})

// The agent's reports as an archive's ingestion writes them (agentic/tradecraft/ingest/builders.py, index_cve).
const OLD_ARCHIVE_REPORT = IngestionReport.parse({ visited: 1, kept: 0, llmCalls: 1 })
const NEEDS_TOKEN_REPORT = IngestionReport.parse({
  visited: 1, kept: 0, llmCalls: 1, stopReason: 'cve index: add a GitHub token to index this archive',
  errors: [{ code: 'cve_index_needs_token', count: 1 }],
})
const INDEXED_REPORT = IngestionReport.parse({ visited: 1, kept: 20000, llmCalls: 1, stopReason: 'cve index: largest 20000 of 183523 files' })
const ARCHIVE: ResourceView = { ...RESOURCE, name: 'trickest/cve', url: 'https://github.com/trickest/cve', resourceType: 'cve-poc-db', entryCount: 0 }

describe('ResourceCard: a CVE archive with no index (NQ-9)', () => {
  const hints = () => screen.queryAllByTestId('tc-cve-index-hint')

  test('the wording', () => {
    expect(CVE_REFRESH_TEXT).toBe('Refresh to index this archive')
    expect(CVE_TOKEN_TEXT).toBe(
      'Add a GitHub token to index this archive: the GitHub Access Token in Global Settings > API Keys, or the GitHub token override in Edit > Access, then refresh',
    )
    expect(CVE_INDEX_WHY).toBe('An index lets search and Library now find the CVEs this archive holds; without one, a CVE is read only by its id.')
  })

  test('a report from before the index (no "cve index" stop reason) asks for a refresh, as a notice', () => {
    render(<ResourceCard resource={{ ...ARCHIVE, report: OLD_ARCHIVE_REPORT }} {...handlers()} />)
    const hint = screen.getByText(CVE_REFRESH_TEXT)
    expect(hint.className).toMatch(/badgeInfo/)
    expect(hint.className).not.toMatch(/badgeWarn/)
    expect(hint).toHaveAttribute('title', expect.stringContaining('search and Library now find the CVEs'))
    expect(screen.queryByText(CVE_TOKEN_TEXT)).toBeNull()
    // Not stale: the old archive's settings hash is unchanged, so this is the only sign.
    expect(screen.queryByText(STALE_TEXT)).toBeNull()
  })

  test('a report with cve_index_needs_token asks for a GitHub token, and says where one goes in its visible text', () => {
    render(<ResourceCard resource={{ ...ARCHIVE, report: NEEDS_TOKEN_REPORT }} {...handlers()} />)
    const hint = screen.getByTestId('tc-cve-index-hint')
    // In the text, not only in the tooltip: a keyboard or touch user never sees a title.
    expect(hint.textContent).toBe(CVE_TOKEN_TEXT)
    expect(hint.textContent).toMatch(/GitHub Access Token in Global Settings > API Keys.*GitHub token override in Edit > Access/)
    expect(hint).toHaveAttribute('title', CVE_INDEX_WHY)
    expect(hint.className).toMatch(/badgeInfo/)
    expect(screen.queryByText(CVE_REFRESH_TEXT)).toBeNull()
  })

  test('a token set on the resource since that report: a refresh indexes it', () => {
    render(<ResourceCard resource={{ ...ARCHIVE, githubTokenOverride: 'set', stale: true, report: NEEDS_TOKEN_REPORT }} {...handlers()} />)
    expect(screen.getByText(CVE_REFRESH_TEXT)).toBeInTheDocument()
    expect(screen.queryByText(CVE_TOKEN_TEXT)).toBeNull()
  })

  test.each([
    ['indexed', INDEXED_REPORT],
    ['indexed with folders unread', IngestionReport.parse({ kept: 3, stopReason: 'cve index: 3 of 3 files, 2 folders unread' })],
    ['an empty index', IngestionReport.parse({ kept: 0, stopReason: 'cve index: 0 of 0 files' })],
  ])('%s: no hint', (_name, report) => {
    render(<ResourceCard resource={{ ...ARCHIVE, report }} {...handlers()} />)
    expect(hints()).toEqual([])
  })

  test('not an archive: no hint, whatever its report says', () => {
    for (const report of [OLD_ARCHIVE_REPORT, NEEDS_TOKEN_REPORT]) {
      render(<ResourceCard resource={{ ...RESOURCE, report }} {...handlers()} />)
      expect(hints()).toEqual([])
      cleanup()
    }
    // The type the person forced wins over the detected one, as on the type badge.
    render(<ResourceCard resource={{ ...ARCHIVE, forcedType: 'github-repo', report: OLD_ARCHIVE_REPORT }} {...handlers()} />)
    expect(hints()).toEqual([])
    cleanup()
    render(<ResourceCard resource={{ ...RESOURCE, resourceType: 'github-repo', forcedType: 'cve-poc-db', report: OLD_ARCHIVE_REPORT }} {...handlers()} />)
    expect(screen.getByText(CVE_REFRESH_TEXT)).toBeInTheDocument()
  })

  test('an archive with no report yet (its first ingestion, or converted from 1.x): no hint', () => {
    render(<ResourceCard resource={{ ...ARCHIVE, report: null }} {...handlers()} />)
    expect(hints()).toEqual([])
    cleanup()
    render(<ResourceCard resource={{ ...ARCHIVE, mapVersion: 2, report: null }} {...handlers()} />)
    expect(hints()).toEqual([])
    expect(screen.getByText(LEGACY_TEXT)).toBeInTheDocument()
  })

  test('the hint is no button and leaves the card\'s Refresh the only one', () => {
    const h = handlers()
    render(<ResourceCard resource={{ ...ARCHIVE, report: OLD_ARCHIVE_REPORT }} {...h} />)
    expect(screen.getByTestId('tc-cve-index-hint')).toHaveTextContent(CVE_REFRESH_TEXT)
    expect(screen.getAllByRole('button', { name: /Refresh/ })).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    expect(h.onRefresh).toHaveBeenCalledWith(expect.objectContaining({ id: 'r1' }))
  })
})

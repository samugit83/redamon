/**
 * A 2.0 resource card: the stage of its job, Refresh that becomes Cancel, the badges, the date.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { LEGACY_TEXT, ResourceCard, STALE_TEXT } from './ResourceCard'
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
    expect(screen.getByTestId('tc-report')).toHaveTextContent('40 visited, 31 kept, 3 LLM calls, 9 s, stopped: max_pages')
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

/**
 * The accordion's Pages (§3.4, T6.8): the owner's expanded row opens the Map view read-only, on the
 * owner's account; the row shows the full ingestion report; nobody else gets Pages.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { TradecraftResourcesAccordion } from './TradecraftResourcesAccordion'
import type { ProjectTradecraftView } from '@/lib/tradecraft/projectView'

const ROW = {
  id: 'r1', name: 'HackTricks', type: 'mkdocs-wiki', storageMode: 'stored', pages: 2, lastRefreshedAt: null,
  enabledGlobally: true, offInProject: false, ownerOnly: false, locked: false,
  details: {
    url: 'https://wiki.tc-fixture.test/', mapVersion: 3, stale: false, focus: {}, summary: 'Offensive wiki.', summarySource: 'generated',
    report: { visited: 40, kept: 31, skipped: { excluded: 0, outOfScope: 0, tooLittleText: 0, robots: 0, outsideFocus: 9 }, stopReason: 'frontier_empty', llmCalls: 9, durationSec: 61, stored: { pages: 31, bytes: 1, notStoredQuota: 0, notStoredSize: 0 }, focus: {}, readiness: {}, errors: [] },
    ingestedWith: {}, hasLogin: true, lastError: '',
  },
}
let view: ProjectTradecraftView
let pageAnswer: () => Response
const urls: string[] = []
beforeEach(() => {
  urls.length = 0
  view = { v2: true, viewerIsOwner: true, ownerId: 'owner-1', resources: [ROW] as ProjectTradecraftView['resources'], counts: null }
  pageAnswer = () => new Response(JSON.stringify({ pageId: 'hacktricks:1', url: 'https://wiki.tc-fixture.test/a', title: 'A', blocked: false, stored: true, text: 'payload text', fetchedAt: null, storageMode: 'stored' }), { status: 200 })
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    urls.push(url)
    if (url === '/api/projects/p1/tradecraft') return new Response(JSON.stringify(view), { status: 200 })
    if (url.includes('/map?')) {
      return new Response(JSON.stringify({ entries: [{ id: '1', pageId: 'hacktricks:1', title: 'A', url: 'https://wiki.tc-fixture.test/a', topics: ['xss'], kinds: [], technologies: [], description: 'd', source: 'sitemap', status: 'kept', reason: '', pinned: false, renamed: false, stored: true }], total: 1, nextCursor: null }), { status: 200 })
    }
    if (url.includes('/pages/')) return pageAnswer()
    return new Response('{}', { status: 500 })
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const draw = () => render(<TradecraftResourcesAccordion projectId="p1" offIds={[]} onChange={vi.fn()} />)

describe('TradecraftResourcesAccordion Pages', () => {
  test('pages_read_only: Pages opens the read-only Map view on the owner\'s account (R-045)', async () => {
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    fireEvent.click(within(screen.getByTestId('details-r1')).getByRole('button', { name: 'Pages' }))
    const map = await screen.findByTestId('tc-map-view')
    expect(await within(map).findByText('A')).toBeInTheDocument()
    expect(urls).toContain('/api/users/owner-1/tradecraft-resources/r1/map?status=kept')
    expect(within(map).queryByRole('button', { name: /^Block|^Pin$|^Rename$|^Restore$|^Unblock/ })).toBeNull()
    expect(within(map).getByRole('button', { name: 'Read now' })).toBeInTheDocument()
  })

  test('the expanded row shows the full report', async () => {
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    expect(within(screen.getByTestId('details-r1')).getByTestId('tc-report-full')).toHaveTextContent('9 outside the focus')
  })

  test('act as on a login resource: the page text is refused in the accordion too (R-067)', async () => {
    pageAnswer = () => new Response(JSON.stringify({ error: 'Not available while acting as Ada', code: 'not_while_acting_as', action: 'use_site_logins' }), { status: 403 })
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    fireEvent.click(screen.getByRole('button', { name: 'Pages' }))
    const map = await screen.findByTestId('tc-map-view')
    fireEvent.click(await within(map).findByRole('button', { name: 'View' }))
    expect(await within(map).findByRole('alert')).toHaveTextContent('Not available while acting as Ada')
    expect(within(map).queryByText('payload text')).toBeNull()
  })

  test('no ownerId in the view (anyone but the owner): no Pages', async () => {
    view = { ...view, ownerId: undefined }
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    expect(within(screen.getByTestId('details-r1')).queryByRole('button', { name: 'Pages' })).toBeNull()
  })
})

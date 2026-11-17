/**
 * The Map view (§6.10, T6.8): search, count, source, tags, descriptions; View as plain text; Open on
 * the site; Read now; Pin; Block one, the ticked ones, or all matching with the count confirmed;
 * the Blocked filter with Unblock; Rename; the Dropped filter with Restore; the read-only mode of
 * a project's Pages (§3.4).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within, waitFor } from '@testing-library/react'
import { MapView, BLOCK_NOTE, READ_NOW_NOTE } from './MapView'
import type { MapEntryView } from '@/lib/tradecraft/client'

const BASE = '/api/users/user-1/tradecraft-resources/r1'
const RESOURCE = { id: 'r1', name: 'Lab Wiki', url: 'https://wiki.tc-fixture.test/', storageMode: 'stored' }

const entry = (over: Partial<MapEntryView>): MapEntryView => ({
  id: '1', pageId: 'lab-wiki:1', title: 'SQL injection', url: 'https://wiki.tc-fixture.test/sqli', topics: ['sql_injection'], kinds: ['payloads'],
  technologies: [], description: 'Union and blind payloads.', source: 'sitemap', status: 'kept', reason: '', pinned: false, renamed: false, stored: true,
  ...over,
})
const KEPT = [
  entry({}),
  entry({ id: '2', pageId: 'lab-wiki:2', title: 'Tag: news', url: 'https://wiki.tc-fixture.test/tag/news', topics: [], kinds: [], description: '', source: 'crawl', stored: false }),
]
const DROPPED = [entry({ id: '3', pageId: 'lab-wiki:3', title: 'Theory', url: 'https://wiki.tc-fixture.test/theory', status: 'dropped', reason: 'theory without payloads' })]
const BLOCKED = [entry({ id: '', pageId: '', title: '', url: 'https://wiki.tc-fixture.test/tag/old', status: 'blocked', topics: [], kinds: [], description: '', source: '' })]

type Call = { url: string; method: string; body: unknown }
let calls: Call[]
let respond: (c: Call) => Response | undefined
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

function mapAnswer(url: URL): Response {
  const status = url.searchParams.get('status') ?? 'kept'
  const q = url.searchParams.get('query') ?? ''
  const tag = url.searchParams.get('tag') ?? ''
  const list = status === 'dropped' ? DROPPED : status === 'blocked' ? BLOCKED : KEPT
  const found = list.filter(e => (!q || e.url.includes(q) || e.title.includes(q)) && (!tag || [...e.topics, ...e.kinds].includes(tag)))
  return json({ entries: found, total: found.length, nextCursor: null })
}

beforeEach(() => {
  calls = []
  respond = () => undefined
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    const c: Call = { url: input, method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(c)
    const custom = respond(c)
    if (custom) return custom
    const url = new URL(input, 'http://x')
    if (c.method === 'GET' && url.pathname === `${BASE}/map`) return mapAnswer(url)
    if (c.method === 'POST' && url.pathname === `${BASE}/map`) return json({ op: (c.body as { op: string }).op, count: 1 })
    return json({ error: 'unexpected' }, 500)
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const draw = (readOnly = false) => render(<MapView userId="user-1" resource={RESOURCE} readOnly={readOnly} onClose={vi.fn()} />)
const item = (url: string) => within(document.querySelector(`[data-entry="${url}"]`) as HTMLElement)
const posts = () => calls.filter(c => c.method === 'POST').map(c => ({ url: c.url, body: c.body }))

describe('MapView', () => {
  test('lists the map: title, URL, page ID, source, tags, description, the count and the sources', async () => {
    draw()
    expect(await screen.findByText('SQL injection')).toBeInTheDocument()
    const first = item(KEPT[0].url)
    for (const text of ['https://wiki.tc-fixture.test/sqli', 'lab-wiki:1', 'source: sitemap', 'sql_injection', 'payloads', 'Union and blind payloads.', 'stored']) {
      expect(first.getByText(text)).toBeInTheDocument()
    }
    expect(screen.getByTestId('tc-map-count')).toHaveTextContent('2 pages · from sitemap, crawl')
  })

  test('search: by title or URL, sent to the route; a tag chip filters by its tag', async () => {
    draw()
    await screen.findByText('SQL injection')
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: '/tag/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(screen.queryByText('SQL injection')).toBeNull())
    expect(screen.getByTestId('tc-map-count')).toHaveTextContent('1 page match')
    expect(calls.some(c => c.url.includes('query=%2Ftag%2F'))).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Filter by the tag payloads' }))
    await waitFor(() => expect(calls.some(c => c.url.includes('tag=payloads'))).toBe(true))
    expect(await screen.findByRole('button', { name: 'Clear the tag payloads' })).toBeInTheDocument()
  })

  test('plain_text: View shows the stored text in a <pre> as text, with its date; HTML in it never renders', async () => {
    respond = c => c.url === `${BASE}/pages/lab-wiki:1` ? json({
      pageId: 'lab-wiki:1', url: KEPT[0].url, title: 'SQL injection', blocked: false, stored: true,
      text: '<script>alert(1)</script><b>bold</b> UNION SELECT', fetchedAt: '2026-11-15T08:30:00.000Z', storageMode: 'stored',
    }) : undefined
    draw()
    await screen.findByText('SQL injection')
    fireEvent.click(item(KEPT[0].url).getByRole('button', { name: 'View' }))
    const pre = await screen.findByTestId('tc-page-text')
    expect(pre.tagName).toBe('PRE')
    expect(pre.textContent).toBe('<script>alert(1)</script><b>bold</b> UNION SELECT')
    expect(pre.querySelector('script, b')).toBeNull()
    expect(screen.getByText(/downloaded 2026-11-15 08:30 UTC/)).toBeInTheDocument()
  })

  test('a page not stored offers Read now, which shows the cleaned text once and keeps nothing', async () => {
    respond = c => {
      if (c.method === 'GET' && c.url === `${BASE}/pages/lab-wiki:2`) {
        return json({ pageId: 'lab-wiki:2', url: KEPT[1].url, title: 'Tag: news', blocked: false, stored: false, text: '', fetchedAt: null, storageMode: 'stored' })
      }
      if (c.method === 'POST' && c.url === `${BASE}/pages/lab-wiki:2`) {
        return json({ result: { text: 'Fresh <i>text</i>', source: 'live_not_stored', fetched_at: '', truncated: true, error_code: '' } })
      }
      return undefined
    }
    draw()
    await screen.findByText('Tag: news')
    fireEvent.click(item(KEPT[1].url).getByRole('button', { name: 'View' }))
    expect(await screen.findByText(/Not stored \(beyond the storage limits\)/)).toBeInTheDocument()
    fireEvent.click(within(screen.getByTestId('tc-page-panel')).getByRole('button', { name: 'Read now' }))
    const pre = await screen.findByTestId('tc-read-now-text')
    expect(pre.textContent).toBe('Fresh <i>text</i>')
    expect(screen.getByText(new RegExp(READ_NOW_NOTE))).toHaveTextContent('cut at the read limit')
    // Read now sends no body: the route takes the URL from the entry and the login from the row.
    expect(calls.find(c => c.method === 'POST')?.body).toBeUndefined()
  })

  test('Open on the site: a new tab with no opener; an address that is not a web URL is no link', async () => {
    respond = c => c.url.includes('/map') && c.method === 'GET'
      ? json({ entries: [KEPT[0], entry({ id: '9', pageId: 'lab-wiki:9', url: 'javascript:alert(1)', title: 'Odd' })], total: 2, nextCursor: null })
      : undefined
    draw()
    await screen.findByText('SQL injection')
    const link = item(KEPT[0].url).getByRole('link', { name: /Open on the site/ })
    expect(link).toHaveAttribute('href', KEPT[0].url)
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(item('javascript:alert(1)').queryByRole('link')).toBeNull()
  })

  test('block_all_matching_confirms_count: the confirmation names the count, the request carries it', async () => {
    draw()
    await screen.findByText('SQL injection')
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: '/tag/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(screen.getByTestId('tc-map-count')).toHaveTextContent('1 page match'))
    fireEvent.click(screen.getByRole('button', { name: 'Block all matching the search' }))
    const dialog = screen.getByRole('alertdialog', { name: 'Confirm the block' })
    expect(dialog).toHaveTextContent(`Block 1 page matching "/tag/"? ${BLOCK_NOTE}`)
    expect(posts()).toEqual([])
    fireEvent.click(within(dialog).getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(posts()).toEqual([{ url: `${BASE}/map`, body: { op: 'block', matching: { query: '/tag/', status: 'kept' }, expectedCount: 1 } }]))
    expect(await screen.findByRole('status')).toHaveTextContent('Blocked 1 page')
  })

  test('a count that changed meanwhile is refused (409): the new count is shown and confirmed again', async () => {
    let first = true
    respond = c => {
      if (c.method !== 'POST' || !first) return undefined
      first = false
      return json({ error: 'The search now matches 3 pages, not 1: check them again', code: 'count_changed', count: 3 }, 409)
    }
    draw()
    await screen.findByText('SQL injection')
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: '/tag/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(screen.getByTestId('tc-map-count')).toHaveTextContent('1 page match'))
    fireEvent.click(screen.getByRole('button', { name: 'Block all matching the search' }))
    fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Block' }))
    const again = await screen.findByText(/now matches 3 pages, not 1/)
    expect(again.closest('[role="alertdialog"]')).toHaveTextContent('Block 3 pages matching "/tag/"?')
    fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(posts()).toHaveLength(2))
    expect((posts()[1].body as { expectedCount: number }).expectedCount).toBe(3)
  })

  test('Block selected: the ticked entries, after a confirmation with their number', async () => {
    draw()
    await screen.findByText('SQL injection')
    expect(screen.getByRole('button', { name: 'Block selected (0)' })).toBeDisabled()
    fireEvent.click(item(KEPT[0].url).getByRole('checkbox'))
    fireEvent.click(item(KEPT[1].url).getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Block selected (2)' }))
    expect(screen.getByRole('alertdialog')).toHaveTextContent('Block 2 pages?')
    fireEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Block' }))
    await waitFor(() => expect(posts()).toEqual([{ url: `${BASE}/map`, body: { op: 'block', urls: [KEPT[0].url, KEPT[1].url] } }]))
  })

  test('unblock_filter: the Blocked filter lists blocked pages, even one gone from the map; Unblock one or the ticked ones', async () => {
    draw()
    await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: 'Blocked' }))
    await waitFor(() => expect(calls.some(c => c.url.includes('status=blocked'))).toBe(true))
    const gone = item(BLOCKED[0].url)
    expect(gone.getByText('(no title)')).toBeInTheDocument()
    // No page ID: it left the map, so there is no text to view or read.
    expect(gone.queryByRole('button', { name: 'View' })).toBeNull()
    expect(gone.queryByRole('button', { name: 'Read now' })).toBeNull()
    expect(gone.queryByRole('button', { name: 'Block' })).toBeNull()
    fireEvent.click(gone.getByRole('button', { name: 'Unblock' }))
    await waitFor(() => expect(posts()).toEqual([{ url: `${BASE}/map`, body: { op: 'unblock', urls: [BLOCKED[0].url] } }]))
    expect(await screen.findByRole('status')).toHaveTextContent('Unblocked 1 page: back in the map at the next refresh')
    fireEvent.click(item(BLOCKED[0].url).getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Unblock selected (1)' }))
    await waitFor(() => expect(posts()).toHaveLength(2))
  })

  test('restore: the Dropped filter shows each reason; Restore pins it', async () => {
    draw()
    await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: 'Dropped' }))
    expect(await screen.findByText('dropped: theory without payloads')).toBeInTheDocument()
    fireEvent.click(item(DROPPED[0].url).getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(posts()).toEqual([{ url: `${BASE}/map`, body: { op: 'restore', url: DROPPED[0].url } }]))
    expect(await screen.findByRole('status')).toHaveTextContent('Restored and pinned: Theory')
  })

  test('Rename gives a clearer title; an empty one clears it; Pin adds a typed URL, its refusal shown', async () => {
    respond = c => c.method === 'POST' && (c.body as { op: string }).op === 'pin'
      ? json({ error: 'Private or internal addresses are not allowed', code: 'private_address', field: 'url' }, 400)
      : undefined
    draw()
    await screen.findByText('SQL injection')
    fireEvent.click(item(KEPT[0].url).getByRole('button', { name: 'Rename' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'New title' }), { target: { value: '  SQLi payloads  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save title' }))
    await waitFor(() => expect(posts()[0].body).toEqual({ op: 'rename', url: KEPT[0].url, title: 'SQLi payloads' }))
    fireEvent.change(await screen.findByRole('textbox', { name: 'Pin a URL' }), { target: { value: 'http://10.0.0.5/x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Pin' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Private or internal addresses are not allowed')
    expect(posts()[1].body).toEqual({ op: 'pin', url: 'http://10.0.0.5/x' })
  })

  test('read_only_mode: search, tags, descriptions, View, Open and Read now only; no Pin, Block, Unblock, Rename, Restore', async () => {
    draw(true)
    await screen.findByText('SQL injection')
    const first = item(KEPT[0].url)
    for (const name of ['View', 'Read now']) expect(first.getByRole('button', { name })).toBeInTheDocument()
    expect(first.getByRole('link', { name: /Open on the site/ })).toBeInTheDocument()
    expect(first.getByText('Union and blind payloads.')).toBeInTheDocument()
    expect(first.getByRole('button', { name: 'Filter by the tag payloads' })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Search the map' })).toBeInTheDocument()
    for (const name of [/^Pin$/, /^Block/, /^Unblock/, /^Rename$/, /^Restore$/, /^Dropped$/, /^Blocked$/]) {
      expect(screen.queryByRole('button', { name })).toBeNull()
    }
    expect(screen.queryByRole('textbox', { name: 'Pin a URL' })).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  test('act as on a login resource: View answers the refusal in its own words', async () => {
    respond = c => c.url === `${BASE}/pages/lab-wiki:1`
      ? json({ error: 'Not available while acting as Ada: using their saved site logins', code: 'not_while_acting_as', action: 'use_site_logins' }, 403)
      : undefined
    draw(true)
    await screen.findByText('SQL injection')
    fireEvent.click(item(KEPT[0].url).getByRole('button', { name: 'View' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Not available while acting as Ada')
    expect(screen.queryByTestId('tc-page-text')).toBeNull()
  })

  test('Load more reads the next page by its cursor', async () => {
    respond = c => {
      if (c.method !== 'GET' || !c.url.includes('/map')) return undefined
      return c.url.includes('cursor=1')
        ? json({ entries: [KEPT[1]], total: 2, nextCursor: null })
        : json({ entries: [KEPT[0]], total: 2, nextCursor: '1' })
    }
    draw()
    await screen.findByText('SQL injection')
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('Tag: news')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  })
})

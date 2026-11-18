/**
 * The locators of `testing/e2e/tests/tradecraftMap.spec.ts` (T6.12), held to Playwright's rules on
 * the components the spec drives (M3's failure: `{ name: 'Search' }` without `exact` also matched
 * "Block all matching the search", a strict-mode violation). Playwright matches a role's name as a
 * case-insensitive substring unless `exact: true`, and refuses an action on a locator that resolves
 * to more than one element; `pw` does the same over the accessible names, so each locator the spec
 * acts on must resolve to exactly one element in every state the spec reaches it in.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, queryAllByRole } from '@testing-library/react'

vi.mock('@/components/shared/ModelPicker', () => ({
  ModelPicker: ({ value, onChange }: { value: string; onChange: (v: string) => void }) =>
    <input aria-label="Model" value={value} onChange={e => onChange(e.target.value)} />,
}))

import { AlertProvider } from '@/components/ui'
import { MapView } from './MapView'
import { ResourceFormV2 } from './form/ResourceFormV2'
import { ResourceCard } from './ResourceCard'
import { RESOURCE } from './__testing__/resourceView'
import type { MapEntryView } from '@/lib/tradecraft/client'

type Name = string | RegExp | null
/** Playwright's `getByRole(role, { name, exact })`: the elements it resolves to (`null`: no name given). */
function pw(root: HTMLElement, role: string, name: Name, exact = false): HTMLElement[] {
  if (name === null) return queryAllByRole(root, role)
  // Testing Library hands a function matcher the accessible name it computed.
  return queryAllByRole(root, role, {
    name: (accessible: string) => {
      const n = accessible.replace(/\s+/g, ' ').trim()
      if (name instanceof RegExp) return name.test(n)
      return exact ? n === name : n.toLowerCase().includes(name.toLowerCase())
    },
  })
}
/** Playwright's `getByLabel(text, { exact })` over label elements and aria-label. */
function pwLabel(root: HTMLElement, text: string, exact = false): HTMLElement[] {
  const ok = (n: string) => (exact ? n.replace(/\s+/g, ' ').trim() === text : n.toLowerCase().includes(text.toLowerCase()))
  const byLabel = [...root.querySelectorAll('label')].filter(l => ok(l.textContent ?? ''))
    .map(l => (l.htmlFor ? root.querySelector(`#${CSS.escape(l.htmlFor)}`) : l.querySelector('input, textarea, select')))
  const byAria = [...root.querySelectorAll('[aria-label]')].filter(el => ok(el.getAttribute('aria-label') ?? ''))
  return [...new Set([...byLabel, ...byAria].filter((el): el is HTMLElement => el instanceof HTMLElement))]
}
const one = (found: HTMLElement[], what: string) => {
  expect(found.length, `${what} resolves to ${found.length} elements`).toBe(1)
  return found[0]
}

const LIB = 'https://library.tc-e2e.test/'
const entry = (over: Partial<MapEntryView>): MapEntryView => ({
  id: '1', pageId: 'tc-map-library:1', title: 'SQL injection', url: `${LIB}sqli/`, topics: ['sql_injection'], kinds: ['payloads'],
  technologies: [], description: 'Union and blind payloads.', source: 'sitemap', status: 'kept', reason: '', pinned: false, renamed: false, stored: true,
  ...over,
})
// The seed's Map library (webapp/scripts/e2e-tradecraft-seed.mjs).
const KEPT = [
  entry({}),
  entry({ id: '2', pageId: 'tc-map-library:2', title: 'Cross-site scripting', url: `${LIB}xss/`, topics: ['xss'] }),
  entry({ id: '3', pageId: 'tc-map-library:3', title: 'Tag: news', url: `${LIB}tag/news`, topics: [], kinds: [], description: '', source: 'crawl' }),
  entry({ id: '4', pageId: 'tc-map-library:4', title: 'Tag: events', url: `${LIB}tag/events`, topics: [], kinds: [], description: '', source: 'crawl' }),
]
const DROPPED = [entry({ id: '5', pageId: 'tc-map-library:5', title: 'Injection theory', url: `${LIB}theory/`, status: 'dropped', reason: 'theory without payloads', stored: false })]

let blocked: MapEntryView[]
beforeEach(() => {
  blocked = []
  vi.stubGlobal('fetch', vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(input, 'http://x')
    if (url.pathname.endsWith('/map') && (init?.method ?? 'GET') === 'POST') {
      const body = JSON.parse(String(init!.body))
      if (body.op === 'block') blocked = KEPT.filter(e => e.url.includes('/tag/')).map(e => ({ ...e, status: 'blocked' as const }))
      if (body.op === 'unblock') blocked = blocked.filter(e => !body.urls.includes(e.url))
      return new Response(JSON.stringify({ op: body.op, count: body.op === 'block' ? 2 : 1 }), { status: 200 })
    }
    if (url.pathname.endsWith('/map')) {
      const status = url.searchParams.get('status') ?? 'kept'
      const q = url.searchParams.get('query') ?? ''
      const list = status === 'blocked' ? blocked : status === 'dropped' ? DROPPED : KEPT.filter(e => !blocked.some(b => b.url === e.url))
      const found = list.filter(e => !q || e.url.includes(q) || e.title.includes(q))
      return new Response(JSON.stringify({ entries: found, total: found.length, nextCursor: null }), { status: 200 })
    }
    if (url.pathname.includes('/pages/')) {
      return new Response(JSON.stringify({ pageId: 'tc-map-library:2', url: `${LIB}xss/`, title: 'x', blocked: false, stored: true, text: 'text', fetchedAt: null, storageMode: 'stored' }), { status: 200 })
    }
    return new Response('{}', { status: 200 })
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const view = () => screen.getByTestId('tc-map-view')
const entryEl = (path: string) => view().querySelector(`[data-entry="${LIB}${path}"]`) as HTMLElement
async function search(text: string) {
  fireEvent.change(one(pw(view(), 'textbox', 'Search the map', true), 'textbox "Search the map"'), { target: { value: text } })
  fireEvent.click(one(pw(view(), 'button', 'Search', true), 'button "Search" (exact)'))
}

describe('the Map spec\'s locators resolve to one element each (Playwright\'s rules)', () => {
  test('tests 1-3: search, View, Block all matching, the confirmation, Blocked, Unblock, Dropped, Restore, In the map', async () => {
    render(<MapView userId="u1" resource={{ id: 'r1', name: 'TC Map Library', url: LIB, storageMode: 'stored' }} onClose={vi.fn()} />)
    await screen.findByText('SQL injection')
    await search('scripting')
    await waitFor(() => expect(screen.queryByText('SQL injection')).toBeNull())
    fireEvent.click(one(pw(entryEl('xss/'), 'button', 'View', true), 'entry xss/ button "View"'))
    await screen.findByTestId('tc-page-text')
    one(pw(entryEl('xss/'), 'link', /Open on the site/), 'entry xss/ link /Open on the site/')

    await search('/tag/')
    await waitFor(() => expect(screen.getByTestId('tc-map-count')).toHaveTextContent(/^2 pages match/))
    // M3's failure: the old locator matched two buttons here.
    expect(pw(view(), 'button', 'Search').length).toBe(2)
    one(pw(view(), 'button', 'Search', true), 'button "Search" (exact) with a search set')
    fireEvent.click(one(pw(view(), 'button', 'Block all matching the search', true), 'button "Block all matching the search"'))
    const confirm = one(pw(view(), 'alertdialog', 'Confirm the block', true), 'alertdialog "Confirm the block"')
    fireEvent.click(one(pw(confirm, 'button', 'Block', true), 'confirmation button "Block"'))
    await waitFor(() => expect(one(pw(view(), 'status', null), 'the notice (role status)')).toHaveTextContent('Blocked 2 pages'))

    await search('')
    await waitFor(() => expect(screen.getByTestId('tc-map-count')).toHaveTextContent(/^2 pages( ·|$)/))
    fireEvent.click(one(pw(view(), 'button', 'Blocked', true), 'tab "Blocked"'))
    await waitFor(() => expect(screen.getByTestId('tc-map-count')).toHaveTextContent(/^2 pages( ·|$)/))
    fireEvent.click(one(pw(entryEl('tag/news'), 'button', 'Unblock', true), 'entry tag/news button "Unblock"'))
    await waitFor(() => expect(one(pw(view(), 'status', null), 'the notice')).toHaveTextContent('Unblocked 1 page: back in the map at the next refresh'))

    fireEvent.click(one(pw(view(), 'button', 'Dropped', true), 'tab "Dropped"'))
    await screen.findByText('dropped: theory without payloads')
    fireEvent.click(one(pw(entryEl('theory/'), 'button', 'Restore', true), 'entry theory/ button "Restore"'))
    await waitFor(() => expect(one(pw(view(), 'status', null), 'the notice')).toHaveTextContent(/^Restored and pinned/))
    fireEvent.click(one(pw(view(), 'button', 'In the map', true), 'tab "In the map"'))
  })

  test('test 4: the read-only view has none of the curation buttons; View resolves to one', async () => {
    render(<MapView userId="u1" resource={{ id: 'r1', name: 'TC Map Library', url: LIB, storageMode: 'stored' }} readOnly onClose={vi.fn()} />)
    await screen.findByText('SQL injection')
    for (const name of [/^Block/, /^Pin$/, /^Rename$/, /^Restore$/, /^Unblock/, /^Dropped$/, /^Blocked$/]) expect(pw(view(), 'button', name)).toHaveLength(0)
    one(pw(entryEl('sqli/'), 'button', 'View', true), 'entry sqli/ button "View"')
  })

  test('the card buttons and the form: "Map of <name>", "Edit <name>", /^Access/ and the "Cookies" label', async () => {
    const h = { userId: 'u1', onRefresh: vi.fn(), onCancel: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn(), onToggleEnabled: vi.fn() }
    const { container } = render(<div>
      <ResourceCard resource={{ ...RESOURCE, id: 'lib', name: 'TC Map Library' }} {...h} />
      <ResourceCard resource={{ ...RESOURCE, id: 'kb', name: 'TC Map KB' }} {...h} />
    </div>)
    for (const name of ['Map of TC Map Library', 'Map of TC Map KB', 'Edit TC Map KB']) one(pw(container, 'button', name, true), `button "${name}"`)
    cleanup()
    render(<AlertProvider><ResourceFormV2 userId="u1" onSaved={vi.fn()} onCancel={vi.fn()}
      resource={{ ...RESOURCE, name: 'TC Map KB', hasLogin: true, credentials: { cookie: 'set', headers: [], basic_auth: null } }} /></AlertProvider>)
    fireEvent.click(one(pw(document.body, 'button', /^Access/), 'button /^Access/'))
    one(pwLabel(document.body, 'Cookies', true), 'label "Cookies" (exact)')
  })
})

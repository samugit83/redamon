/**
 * The Map view's list and the person's curation of a resource's map (§6.10, T6.7; R-165, R-167,
 * R-169, AC-39, D-54): browse the live generation by search, status and tag with a cursor; pin a
 * URL that passes the resource URL check; block chosen URLs or every entry matching a search
 * whose count the person confirmed (409 when it changed), deleting their stored text and
 * sections at once; unblock; rename; restore a dropped page, which is pinned.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as never)[k] }) }))

import { curate, readMap, type MapResource } from './curation'

const R1 = { id: 'r1', userId: 'owner', slug: 'wiki', url: 'https://wiki.example.test/', generation: 2, hasLogin: false, credentials: {} }
const row = (id = 'r1') => h.db.rows('userTradecraftResource', { id })[0] as unknown as MapResource
const entry = (url: string, generation = 2) => h.db.rows('tradecraftEntry', { resourceId: 'r1', url, generation })[0]
const curation = (url: string) => h.db.rows('tradecraftCuration', { resourceId: 'r1', url })[0]

function seedEntry(n: number, over: Record<string, unknown> = {}) {
  return h.db.seed('tradecraftEntry', {
    id: BigInt(n), userId: 'owner', resourceId: 'r1', generation: 2, pageId: n, url: `https://wiki.example.test/p${n}`, title: `Page ${n}`,
    status: 'kept', source: 'sitemap', topics: [], kinds: [], technologies: [], description: '', ...over,
  })
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.db.seed('userTradecraftResource', {
    ...R1, name: 'Wiki', storageMode: 'stored', ingestionReport: { visited: 5, kept: 4, stored: { pages: 3, bytes: 30, notStoredQuota: 0, notStoredSize: 0 } },
  })
  h.db.seed('userTradecraftResource', { id: 'r2', userId: 'owner', name: 'Blog', slug: 'blog', url: 'https://blog.example.test/', generation: 1 })
  seedEntry(1, { title: 'SQL injection payloads', topics: ['sql_injection'], kinds: ['payloads'], storedText: 'union select', storedBytes: 12 })
  seedEntry(2, { title: 'SQLi filter bypass', topics: ['sql_injection'], kinds: ['bypasses'], storedText: 'bypass text', storedBytes: 11 })
  seedEntry(3, { title: 'XSS cheat sheet', topics: ['xss'], kinds: ['payloads'], storedText: 'xss text', storedBytes: 8 })
  seedEntry(4, { title: 'Company news', status: 'dropped', dropReason: 'news' })
  // An older generation and another resource never show.
  seedEntry(90, { generation: 1, url: 'https://wiki.example.test/old', title: 'SQL old' })
  h.db.seed('tradecraftEntry', { id: BigInt(500), userId: 'owner', resourceId: 'r2', generation: 1, pageId: 500, url: 'https://blog.example.test/sqli', title: 'SQL blog' })
  for (const [id, entryId] of [[1, 1], [2, 1], [3, 2], [4, 3]]) {
    h.db.seed('tradecraftSection', { id: BigInt(id), entryId: BigInt(entryId), resourceId: 'r1', userId: 'owner', generation: 2, ord: id, level: 1, text: 't' })
  }
})

describe('readMap (R-165)', () => {
  test('bigint_as_string: the live generation\'s kept entries, ids and page ids as strings, the total', async () => {
    const map = await readMap(row(), {})
    expect(map.total).toBe(3)
    expect(map.entries.map(e => e.id)).toEqual(['1', '2', '3'])
    expect(map.entries[0]).toEqual({
      id: '1', pageId: 'wiki:1', title: 'SQL injection payloads', url: 'https://wiki.example.test/p1', topics: ['sql_injection'], kinds: ['payloads'],
      technologies: [], description: '', source: 'sitemap', status: 'kept', reason: '', pinned: false, renamed: false, stored: true,
    })
    expect(JSON.stringify(map)).not.toMatch(/union select/)
  })

  test('search over title and URL (any case), status and tag filters; dropped entries keep their reason', async () => {
    expect((await readMap(row(), { query: 'sql' })).entries.map(e => e.id)).toEqual(['1', '2'])
    expect((await readMap(row(), { query: 'P3' })).entries.map(e => e.id)).toEqual(['3'])
    expect((await readMap(row(), { tag: 'payloads' })).entries.map(e => e.id)).toEqual(['1', '3'])
    expect((await readMap(row(), { status: 'dropped' })).entries).toEqual([expect.objectContaining({ id: '4', status: 'dropped', reason: 'news' })])
  })

  test('a cursor pages through the entries', async () => {
    const first = await readMap(row(), { limit: 2 })
    expect(first.entries.map(e => e.id)).toEqual(['1', '2'])
    expect(first.nextCursor).toBe('2')
    const second = await readMap(row(), { limit: 2, cursor: first.nextCursor })
    expect(second.entries.map(e => e.id)).toEqual(['3'])
    expect(second.nextCursor).toBeNull()
  })

  test('a blocked page leaves the kept list for the blocked one; a rename shows at once', async () => {
    await curate(row(), { op: 'block', urls: ['https://wiki.example.test/p2'] }, 'owner')
    await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p1', title: 'Union payloads' }, 'owner')
    const kept = await readMap(row(), {})
    expect(kept.entries.map(e => [e.id, e.title, e.renamed])).toEqual([['1', 'Union payloads', true], ['3', 'XSS cheat sheet', false]])
    expect((await readMap(row(), { status: 'blocked' })).entries).toEqual([expect.objectContaining({ url: 'https://wiki.example.test/p2', status: 'blocked', title: 'SQLi filter bypass' })])
  })
})

describe('curate (R-167)', () => {
  test('block_deletes_text_now: the stored text and sections go at once, the curation row stays, the report counts follow', async () => {
    const r = await curate(row(), { op: 'block', urls: ['https://wiki.example.test/p1'] }, 'owner')
    expect(r).toEqual({ ok: true, op: 'block', count: 1 })
    expect(entry('https://wiki.example.test/p1')).toMatchObject({ storedText: null, storedBytes: 0 })
    expect(h.db.rows('tradecraftSection', { entryId: BigInt(1) })).toEqual([])
    expect(h.db.rows('tradecraftSection')).toHaveLength(2)
    expect(curation('https://wiki.example.test/p1')).toMatchObject({ blocked: true, pinned: false, createdById: 'owner' })
    expect((row() as unknown as { ingestionReport: { stored: { pages: number; bytes: number } } }).ingestionReport.stored).toMatchObject({ pages: 2, bytes: 18 })
  })

  test('block_matching_exact (AC-39): every entry matching the search, when the confirmed count still holds; 409 when it changed', async () => {
    expect(await curate(row(), { op: 'block', matching: { query: 'sql' }, expectedCount: 3 }, 'owner'))
      .toMatchObject({ ok: false, status: 409, code: 'count_changed', count: 2 })
    expect(h.db.rows('tradecraftCuration')).toEqual([])
    expect(await curate(row(), { op: 'block', matching: { query: 'sql' }, expectedCount: 2 }, 'owner')).toEqual({ ok: true, op: 'block', count: 2 })
    expect(h.db.rows('tradecraftCuration').map(c => c.url).sort()).toEqual(['https://wiki.example.test/p1', 'https://wiki.example.test/p2'])
    // The older generation and the other resource were never touched.
    expect(entry('https://wiki.example.test/old', 1).title).toBe('SQL old')
    expect(h.db.rows('tradecraftCuration', { resourceId: 'r2' })).toEqual([])
    expect(entry('https://wiki.example.test/p3').storedText).toBe('xss text')
  })

  test('unblock: the page leaves the blocked list; a row holding nothing else goes', async () => {
    await curate(row(), { op: 'block', urls: ['https://wiki.example.test/p1', 'https://wiki.example.test/p3'] }, 'owner')
    await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p3', title: 'XSS' }, 'owner')
    expect(await curate(row(), { op: 'unblock', urls: ['https://wiki.example.test/p1', 'https://wiki.example.test/p3'] }, 'owner')).toEqual({ ok: true, op: 'unblock', count: 2 })
    expect(curation('https://wiki.example.test/p1')).toBeUndefined()
    expect(curation('https://wiki.example.test/p3')).toMatchObject({ blocked: false, renamedTitle: 'XSS' })
    expect((await readMap(row(), { status: 'blocked' })).entries).toEqual([])
  })

  test('rename: kept across refreshes in the curation row; an empty title clears it; limits refused', async () => {
    expect(await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p3', title: '  XSS polyglots ' }, 'owner')).toEqual({ ok: true, op: 'rename', count: 1 })
    expect(curation('https://wiki.example.test/p3').renamedTitle).toBe('XSS polyglots')
    expect(entry('https://wiki.example.test/p3').title).toBe('XSS cheat sheet')
    await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p3', title: '' }, 'owner')
    expect(curation('https://wiki.example.test/p3')).toBeUndefined()
    expect(await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p3', title: 't'.repeat(301) }, 'owner')).toMatchObject({ ok: false, status: 400, field: 'title' })
    expect(await curate(row(), { op: 'rename', url: 'https://wiki.example.test/p3', title: 'a\nb' }, 'owner')).toMatchObject({ ok: false, status: 400 })
    expect(await curate(row(), { op: 'rename', url: 'https://wiki.example.test/nowhere', title: 'x' }, 'owner')).toMatchObject({ ok: false, status: 404 })
  })

  test('restore_pins (AC-14): a dropped page is kept at once and pinned, so it survives refreshes; a kept one is a 409', async () => {
    expect(await curate(row(), { op: 'restore', url: 'https://wiki.example.test/p4' }, 'owner')).toEqual({ ok: true, op: 'restore', count: 1 })
    expect(entry('https://wiki.example.test/p4')).toMatchObject({ status: 'kept', dropReason: '' })
    expect(curation('https://wiki.example.test/p4')).toMatchObject({ pinned: true, restoredFromDrop: true })
    expect((await readMap(row(), {})).entries.find(e => e.id === '4')).toMatchObject({ pinned: true })
    expect(await curate(row(), { op: 'restore', url: 'https://wiki.example.test/p1' }, 'owner')).toMatchObject({ ok: false, status: 409, code: 'not_dropped' })
  })

  test('pin: a URL the person typed is recorded for the next refresh; a pin lifts a block', async () => {
    expect(await curate(row(), { op: 'pin', url: 'https://wiki.example.test/new-page' }, 'owner')).toEqual({ ok: true, op: 'pin', count: 1 })
    expect(curation('https://wiki.example.test/new-page')).toMatchObject({ pinned: true, blocked: false })
    await curate(row(), { op: 'block', urls: ['https://wiki.example.test/p2'] }, 'owner')
    await curate(row(), { op: 'pin', url: 'https://wiki.example.test/p2' }, 'owner')
    expect(curation('https://wiki.example.test/p2')).toMatchObject({ pinned: true, blocked: false })
  })

  test('pin_url_checked: a private address, a login in the URL, and another host on a resource with a login are refused', async () => {
    for (const url of ['http://127.0.0.1/admin', 'https://u:p@wiki.example.test/x', 'ftp://wiki.example.test/x', 'not a url']) {
      expect(await curate(row(), { op: 'pin', url }, 'owner'), url).toMatchObject({ ok: false, status: 400, field: 'url' })
    }
    Object.assign(h.db.rows('userTradecraftResource', { id: 'r1' })[0], { hasLogin: true, credentials: { cookie: 'session=fake' } })
    expect(await curate(row(), { op: 'pin', url: 'https://evil.example.test/steal' }, 'owner')).toMatchObject({ ok: false, status: 400, code: 'other_host' })
    expect((await curate(row(), { op: 'pin', url: 'https://wiki.example.test/private' }, 'owner')).ok).toBe(true)
    // A public resource may pin a page of another host (a mirror), as a crawl may follow one.
    expect((await curate(h.db.rows('userTradecraftResource', { id: 'r2' })[0] as unknown as MapResource, { op: 'pin', url: 'https://mirror.example.test/a' }, 'owner')).ok).toBe(true)
    expect(h.db.rows('tradecraftCuration', { url: 'https://evil.example.test/steal' })).toEqual([])
  })

  test('a bad body is a 400; a resource deleted meanwhile a 404', async () => {
    for (const body of [{}, { op: 'drop' }, { op: 'block' }, { op: 'block', urls: [] }, { op: 'block', urls: ['x'], matching: { query: 'a' }, expectedCount: 1 },
      { op: 'block', matching: { query: 'a' } }, { op: 'unblock', urls: 'x' }, { op: 'block', urls: Array.from({ length: 501 }, (_, i) => `https://wiki.example.test/${i}`) }]) {
      expect(await curate(row(), body, 'owner'), JSON.stringify(body).slice(0, 80)).toMatchObject({ ok: false, status: 400 })
    }
    const gone = { ...row(), id: 'gone' }
    expect(await curate(gone, { op: 'pin', url: 'https://wiki.example.test/a' }, 'owner')).toMatchObject({ ok: false, status: 404 })
  })
})

describe('the live generation is the one the row lock finds (review C; AC-39, D-46)', () => {
  /** The row as a caller read it before a refresh's swap moved the live generation from 2 to 3. */
  function swapped(): MapResource {
    const before = { ...row() }
    const live = h.db.rows('userTradecraftResource', { id: 'r1' })[0]
    live.generation = 3
    for (const [n, title, status] of [[11, 'SQL union', 'kept'], [12, 'SQL blind', 'kept'], [13, 'SQL time based', 'kept'], [14, 'Old news', 'dropped']] as const) {
      seedEntry(n, { generation: 3, url: `https://wiki.example.test/g3-${n}`, title, status })
    }
    return before
  }

  test('block all matching counts the live map, not the one read before the lock: the old count is a 409', async () => {
    const stale = swapped()
    expect(stale.generation).toBe(2)
    expect(await curate(stale, { op: 'block', matching: { query: 'sql' }, expectedCount: 2 }, 'owner')).toMatchObject({ ok: false, status: 409, code: 'count_changed', count: 3 })
    expect(await curate(stale, { op: 'block', matching: { query: 'sql' }, expectedCount: 3 }, 'owner')).toEqual({ ok: true, op: 'block', count: 3 })
    expect(h.db.rows('tradecraftCuration').map(c => c.url).sort()).toEqual([11, 12, 13].map(n => `https://wiki.example.test/g3-${n}`))
  })

  test('restore and rename act on the live generation', async () => {
    const stale = swapped()
    expect(await curate(stale, { op: 'restore', url: 'https://wiki.example.test/g3-14' }, 'owner')).toEqual({ ok: true, op: 'restore', count: 1 })
    expect(h.db.rows('tradecraftEntry', { url: 'https://wiki.example.test/g3-14' })[0].status).toBe('kept')
    // A page only the dead generation has is no longer in the map.
    expect(await curate(stale, { op: 'restore', url: 'https://wiki.example.test/p4' }, 'owner')).toMatchObject({ ok: false, status: 404 })
    expect(await curate(stale, { op: 'rename', url: 'https://wiki.example.test/p1', title: 'x' }, 'owner')).toMatchObject({ ok: false, status: 404 })
  })

  test('readMap reads the live generation in the same snapshot as its entries', async () => {
    const stale = swapped()
    const map = await readMap(stale, {})
    expect(map.entries.map(e => e.title)).toEqual(['SQL union', 'SQL blind', 'SQL time based'])
    expect(map.total).toBe(3)
  })
})

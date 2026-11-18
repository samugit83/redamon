/**
 * The 2.0 list: no map, no secret value, counts, the latest job, the stale flag.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { setNowForTests } from '@/lib/authz/clock'
import { effectiveSettings } from '../effectiveSettings'
import { ingestionHash } from '../staleness'
import { bulkRefreshOffer, legacyEntryCount, listResourcesV2, resourceViewOf } from './list'

const T0 = Date.parse('2026-11-16T10:00:00Z')
const USER = { ingestion: { 'crawl.maxPages': 90 } }
// r-v3 as a 2.0 ingestion left it: its token override and its login are part of what it was ingested with (§6.13).
const currentHash = (overrides: Record<string, unknown> = {}) => ingestionHash(effectiveSettings({ user: USER, resource: overrides }).hash, {
  credentials: { cookie: 'session=fake-session' }, githubTokenOverride: 'ghp_SECRET_fake_1',
})

beforeEach(() => {
  h.db = createTradecraftDb()
  setNowForTests(() => new Date(T0))
  h.db.seed('tradecraftUserSettings', { userId: 'owner', ...USER })
  h.db.seed('userTradecraftResource', {
    id: 'r-v3', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', mapVersion: 3, generation: 2,
    githubTokenOverride: 'ghp_SECRET_fake_1', credentials: { cookie: 'session=fake-session' }, hasLogin: true,
    sitemap: { nav: [{ title: 'MAPENTRY', path: '/a' }] }, settingsHash: currentHash(), createdAt: new Date(T0 - 3000),
    ingestionReport: { visited: 40, kept: 31, stopReason: 'frontier_empty' },
  })
  h.db.seed('userTradecraftResource', {
    id: 'r-v1', userId: 'owner', name: 'Old', slug: 'old', url: 'https://old.example.test/', mapVersion: 1,
    sitemap: { nav: [1, 2], pages: [3], links: [4, 5, 6] }, createdAt: new Date(T0 - 2000),
  })
  h.db.seed('userTradecraftResource', { id: 'r-other', userId: 'other', name: 'Theirs', slug: 'theirs', url: 'https://theirs.example.test/' })
  for (const [i, generation, status] of [[1, 2, 'kept'], [2, 2, 'kept'], [3, 2, 'dropped'], [4, 1, 'kept']] as const) {
    h.db.seed('tradecraftEntry', { id: `e${i}`, userId: 'owner', resourceId: 'r-v3', generation, pageId: i, url: `https://wiki.example.test/${i}`, status })
  }
  h.db.seed('tradecraftIngestionJob', { id: 'j-old', userId: 'owner', resourceId: 'r-v3', kind: 'add', status: 'succeeded', createdAt: new Date(T0 - 9000) })
  h.db.seed('tradecraftIngestionJob', { id: 'j-new', userId: 'owner', resourceId: 'r-v3', kind: 'refresh', status: 'running', leaseUntil: new Date(T0 + 9000), stage: 'build_map', createdAt: new Date(T0 - 1000) })
})
afterEach(() => setNowForTests(null))

describe('listResourcesV2', () => {
  test("the account's resources, oldest first, nobody else's", async () => {
    expect((await listResourcesV2('owner')).map(r => r.id)).toEqual(['r-v3', 'r-v1'])
  })

  test('no_secret_values: a secret reads as set, never as its value', async () => {
    const list = await listResourcesV2('owner')
    const text = JSON.stringify(list)
    expect(text).not.toMatch(/SECRET|fake-session/)
    expect(list[0]).toMatchObject({ githubTokenOverride: 'set', hasLogin: true })
    // The login reads masked (T6.5): what is set, header names, never a value.
    expect(list[0].credentials).toEqual({ cookie: 'set', headers: [], basic_auth: null })
    expect(list[1].githubTokenOverride).toBe('')
  })

  test('no_sitemap: no map, no snapshot, no override in the answer', async () => {
    const list = await listResourcesV2('owner')
    expect(JSON.stringify(list)).not.toContain('MAPENTRY')
    for (const key of ['sitemap', 'settingsSnapshot', 'settingsHash', 'activeJobId', 'generation']) expect(list[0]).not.toHaveProperty(key)
  })

  test('counts: kept entries of the live generation; a 1.x map counted as the 1.x list counts it', async () => {
    const [v3, v1] = await listResourcesV2('owner')
    expect(v3.entryCount).toBe(2)
    expect(v1.entryCount).toBe(6)
    expect(legacyEntryCount({ tree: [1], junk: [1, 2] })).toBe(1)
    expect(legacyEntryCount(null)).toBe(0)
  })

  test('stale_when_hash_differs: the snapshot hash against today’s effective settings (R-029, R-192)', async () => {
    expect((await resourceViewOf('owner', 'r-v3'))?.stale).toBe(false)
    h.db.rows('userTradecraftResource', { id: 'r-v3' })[0].overrides = { 'crawl.maxPages': 10 }
    expect((await resourceViewOf('owner', 'r-v3'))?.stale).toBe(true)
    h.db.rows('userTradecraftResource', { id: 'r-v3' })[0].settingsHash = currentHash({ 'crawl.maxPages': 10 })
    expect((await resourceViewOf('owner', 'r-v3'))?.stale).toBe(false)
    h.db.rows('tradecraftUserSettings', { userId: 'owner' })[0].ingestion = { 'crawl.maxPages': 91 }
    expect((await resourceViewOf('owner', 'r-v3'))?.stale).toBe(false)
    h.db.rows('tradecraftUserSettings', { userId: 'owner' })[0].ingestion = { 'fetching.requestTimeoutSec': 50 }
    expect((await resourceViewOf('owner', 'r-v3'))?.stale).toBe(true)
  })

  test('a resource 2.0 never ingested is not stale: it shows the 1.x map version instead', async () => {
    const v1 = await resourceViewOf('owner', 'r-v1')
    expect(v1).toMatchObject({ stale: false, mapVersion: 1, job: null, report: null })
  })

  test('the latest job and the one-line report', async () => {
    const v3 = await resourceViewOf('owner', 'r-v3')
    expect(v3?.job).toMatchObject({ id: 'j-new', status: 'running', stage: 'build_map' })
    expect(v3?.report).toMatchObject({ visited: 40, kept: 31, stopReason: 'frontier_empty' })
  })

  test("resourceViewOf: another account's resource is null", async () => {
    expect(await resourceViewOf('owner', 'r-other')).toBeNull()
    expect(await listResourcesV2('nobody')).toEqual([])
  })
})

describe('overrides in the view', () => {
  test("the resource's own settings travel to its Edit form; an unreadable value reads as none", async () => {
    h.db.rows('userTradecraftResource', { id: 'r-v1' })[0].overrides = { 'crawl.maxPages': 40 }
    h.db.rows('userTradecraftResource', { id: 'r-v3' })[0].overrides = ['not', 'a', 'map']
    const list = await listResourcesV2('owner')
    expect(list.find(r => r.id === 'r-v1')!.overrides).toEqual({ 'crawl.maxPages': 40 })
    expect(list.find(r => r.id === 'r-v3')!.overrides).toEqual({})
  })
})

describe('bulkRefreshOffer (T9.1, §7.2)', () => {
  test('offered while a converted resource (map version 2) exists, until the person answered once', async () => {
    expect(await bulkRefreshOffer('owner')).toBe(false)
    h.db.seed('userTradecraftResource', { id: 'r-v2', userId: 'owner', name: 'Converted', slug: 'conv', url: 'https://conv.example.test/', mapVersion: 2 })
    expect(await bulkRefreshOffer('owner')).toBe(true)
    expect(await bulkRefreshOffer('other')).toBe(false)
    h.db.rows('tradecraftUserSettings', { userId: 'owner' })[0].bulkRefreshOfferedAt = new Date(T0)
    expect(await bulkRefreshOffer('owner')).toBe(false)
  })

  test('an account with no settings row is offered too (a conversion needs no row)', async () => {
    h.db.seed('userTradecraftResource', { id: 'r-v2b', userId: 'other', name: 'Converted', slug: 'conv', url: 'https://conv.example.test/', mapVersion: 2 })
    expect(await bulkRefreshOffer('other')).toBe(true)
  })
})

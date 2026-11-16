/**
 * The run catalog's one policy (TD-9): active resources, the login rule, the GitHub token as
 * today, and the 1.x payload with the 1.x columns only.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { LEGACY_RESOURCE_COLUMNS, LegacyCatalog, V2Catalog, type V2Catalog as V2 } from './agentContract'
import { effectiveSettings } from './effectiveSettings'
import { activeResourcesFor, isOwnerRun, legacyCatalog, runCatalog, v2Catalog } from './catalog'

const T = (n: number) => new Date(Date.parse('2026-11-16T10:00:00Z') + n * 1000)
const OWNER_RUN = { ownerId: 'owner', projectId: 'p1', personId: 'owner', actorId: null }

beforeEach(() => {
  h.db = createTradecraftDb()
  const r = (id: string, extra: Record<string, unknown>, n: number) => h.db.seed('userTradecraftResource', {
    id, userId: 'owner', name: id, slug: id, url: `https://${id}.example.test/`, createdAt: T(n), mapVersion: 3, generation: 7,
    sitemap: { nav: [{ title: 'MAPENTRY' }] }, ...extra,
  })
  r('public', { githubTokenOverride: 'ghp_override_fake', resourceType: 'mkdocs-wiki' }, 1)
  r('private', { hasLogin: true, credentials: { cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key' }] } }, 2)
  r('disabled', { enabled: false }, 3)
  r('off-in-p1', {}, 4)
  h.db.seed('userTradecraftResource', { id: 'theirs', userId: 'other', name: 'theirs', slug: 'theirs', url: 'https://theirs.example.test/' })
  h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: 'off-in-p1' })
  h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true, ingestion: { 'fetching.requestTimeoutSec': 42 }, search: { 'search.results': 7 } })
})

const ids = async (parties: Parameters<typeof activeResourcesFor>[0]) => (await activeResourcesFor(parties)).map(r => r.id)

describe('activeResourcesFor', () => {
  test('active_rule: enabled and not turned off here, the owner\'s only, oldest first (R-060)', async () => {
    expect(await ids(OWNER_RUN)).toEqual(['public', 'private'])
  })

  test('off_in_one_project: a resource turned off in one project stays active in the others (AC-23)', async () => {
    expect(await ids({ ...OWNER_RUN, projectId: 'p2' })).toEqual(['public', 'private', 'off-in-p1'])
  })

  test.each([
    ["the owner's own run", { personId: 'owner', actorId: null }, true],
    ["a collaborator's run", { personId: 'collab', actorId: null }, false],
    ['the owner, acted on by an administrator', { personId: 'owner', actorId: 'admin-1' }, false],
    ['no person given', { personId: null, actorId: null }, false],
  ])('login_rule: %s', async (_name, who, listsLogin) => {
    expect((await ids({ ...OWNER_RUN, ...who })).includes('private')).toBe(listsLogin)
    expect(isOwnerRun({ ownerId: 'owner', ...who })).toBe(listsLogin)
  })
})

describe('the 2.0 catalog', () => {
  test('the owner\'s run: the login with its values; every resource with its read settings', async () => {
    const c = await v2Catalog(OWNER_RUN) as V2
    expect(c).toMatchObject({ v2: true, owner_id: 'owner', person_id: 'owner', actor_id: null })
    const priv = c.resources.find(r => r.id === 'private')!
    expect(priv).toMatchObject({ has_login: true, credentials: { cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key' }], basic_auth: null } })
    const pub = c.resources.find(r => r.id === 'public')!
    expect(pub).toMatchObject({ type: 'mkdocs-wiki', storage_mode: 'live', map_version: 3, credentials: null })
    expect(pub.read_settings['fetching.requestTimeoutSec']).toBe(42)
    expect(Object.keys(pub.read_settings).every(k => /^(fetching|content)\./.test(k))).toBe(true)
  })

  test("login_rule in a collaborator's run: the resource is not listed at all, and no login travels", async () => {
    const c = await v2Catalog({ ...OWNER_RUN, personId: 'collab' }) as V2
    expect(c.resources.map(r => r.id)).toEqual(['public'])
    expect(JSON.stringify(c)).not.toMatch(/fake-session|fake-key/)
  })

  test("github_token_owner_shared: the resource's override travels in every run, as in 1.x (R-156)", async () => {
    for (const personId of ['owner', 'collab']) {
      const c = await v2Catalog({ ...OWNER_RUN, personId }) as V2
      expect(c.resources.find(r => r.id === 'public')!.github_token).toBe('ghp_override_fake')
    }
  })

  test('no_maps_in_payload and no_generation_in_payload (TD-9, R-219)', async () => {
    const text = JSON.stringify(await v2Catalog(OWNER_RUN))
    expect(text).not.toContain('MAPENTRY')
    expect(text).not.toMatch(/"sitemap"|"generation"/)
  })

  test("read settings: the values the resource was ingested with, when it has a snapshot", async () => {
    h.db.rows('userTradecraftResource', { id: 'public' })[0].settingsSnapshot = { values: { 'fetching.requestTimeoutSec': 11, 'crawl.maxPages': 3 }, provenance: {} }
    const c = await v2Catalog(OWNER_RUN) as V2
    expect(c.resources.find(r => r.id === 'public')!.read_settings).toEqual({ 'fetching.requestTimeoutSec': 11 })
  })

  test("the account's search settings", async () => {
    const c = await v2Catalog(OWNER_RUN) as V2
    expect(c.search).toEqual(effectiveSettings({ user: { search: { 'search.results': 7 } }, scope: 'search' }).values)
  })

  test('the payload satisfies the contract after the JSON hop', async () => {
    expect(V2Catalog.safeParse(JSON.parse(JSON.stringify(await v2Catalog({ ...OWNER_RUN, personId: 'collab', actorId: 'admin-1' })))).success).toBe(true)
  })
})

describe('the 1.x payload (switch off)', () => {
  test("runCatalog follows the owner's switch", async () => {
    expect((await runCatalog(OWNER_RUN)).v2).toBe(true)
    h.db.rows('tradecraftUserSettings', { userId: 'owner' })[0].v2Enabled = false
    expect((await runCatalog(OWNER_RUN)).v2).toBe(false)
  })

  test('legacy_payload_has_no_2x_column: a row with a login set carries the 1.x columns only (D-44)', async () => {
    const c = await legacyCatalog('owner')
    expect(LegacyCatalog.safeParse(c).success).toBe(true)
    if (c.v2) throw new Error('expected the 1.x payload')
    expect(c.legacy.map(r => r.id)).toEqual(['public', 'private', 'disabled', 'off-in-p1'])
    for (const r of c.legacy) expect(Object.keys(r).sort()).toEqual([...LEGACY_RESOURCE_COLUMNS].sort())
    expect(JSON.stringify(c)).not.toMatch(/fake-session|fake-key|hasLogin|credentials/)
  })
})

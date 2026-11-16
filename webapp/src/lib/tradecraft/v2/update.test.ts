/**
 * Editing a 2.0 resource: what acts at once, what waits for a running job, what only makes it stale.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'
import { refused, stubAgent } from '../__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, actingAs: false }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))

import { setNowForTests } from '@/lib/authz/clock'
import { JobStartBatch } from '../agentContract'
import { effectiveSettings } from '../effectiveSettings'
import { ingestionHash } from '../staleness'
import { updateResourceV2 } from './update'

const T0 = Date.parse('2026-11-16T10:00:00Z')
let t = new Date(T0)
const ACTOR = { actorUserId: 'owner', realActorUserId: null }
const update = (body: Record<string, unknown>, resourceId = 'r1', ownerId = 'owner') => updateResourceV2({ ownerId, resourceId, body, actor: ACTOR })
const row = (id = 'r1') => h.db.rows('userTradecraftResource', { id })[0]

function runningJob(leaseUntil: Date | null) {
  h.db.seed('tradecraftIngestionJob', { id: 'j-run', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', leaseUntil })
  row().activeJobId = 'j-run'
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.actingAs = false
  t = new Date(T0)
  setNowForTests(() => t)
  h.db.clock.now = () => t
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o',
    storageMode: 'stored', githubTokenOverride: 'ghp_stored_fake', credentials: { cookie: 'session=fake-session' }, hasLogin: true, generation: 2,
  })
  h.db.seed('userTradecraftResource', { id: 'r2', userId: 'owner', name: 'Blog', slug: 'blog', url: 'https://blog.example.test/', storageMode: 'stored' })
  h.db.seed('tradecraftEntry', { id: 'e1', userId: 'owner', resourceId: 'r1', generation: 2, pageId: 1, url: 'https://wiki.example.test/a', storedText: 'page text', storedBytes: 9 })
  h.db.seed('tradecraftEntry', { id: 'e2', userId: 'owner', resourceId: 'r2', generation: 0, pageId: 2, url: 'https://blog.example.test/a', storedText: 'other text', storedBytes: 10 })
  h.db.seed('tradecraftSection', { id: 's1', userId: 'owner', resourceId: 'r1', entryId: 'e1', ord: 0, text: 'page text' })
  h.db.seed('tradecraftSection', { id: 's2', userId: 'owner', resourceId: 'r2', entryId: 'e2', ord: 0, text: 'other text' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('updateResourceV2', () => {
  test('url_checked: a new URL passes the address check (D-04); nothing written', async () => {
    const res = await update({ url: 'http://169.254.169.254/latest/' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ field: 'url', code: 'bad_url' })
    expect(row().url).toBe('https://wiki.example.test/')
  })

  test("duplicate_409: another of the account's resources has the URL (D-05); another account's does not count", async () => {
    stubAgent()
    h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.example.test/' })
    const res = await update({ url: 'https://blog.example.test/' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'duplicate' })
    expect(row().url).toBe('https://wiki.example.test/')
    expect((await update({ url: 'https://x.example.test/' })).status).toBe(200)
  })

  test('url_change_reingests: the new URL is saved and ingested again (R-195)', async () => {
    const agent = stubAgent()
    const res = await update({ url: 'https://wiki2.example.test/' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.job).toMatchObject({ kind: 'reingest', status: 'queued' })
    const [req] = JobStartBatch.parse(agent.calls.find(c => c.path === '/tradecraft/v2/jobs')!.body).jobs
    expect([req.kind, req.resource.url]).toEqual(['reingest', 'https://wiki2.example.test/'])
    expect(row().activeJobId).toBe(body.job.id)
  })

  test('a new URL saved while the agent is down: 200, the URL changed, the job failed and says why', async () => {
    stubAgent(() => refused())
    const res = await update({ url: 'https://wiki2.example.test/' })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ jobError: 'agent_unreachable', job: { status: 'failed' }, resource: { url: 'https://wiki2.example.test/' } })
    expect(row()).toMatchObject({ url: 'https://wiki2.example.test/', activeJobId: null })
  })

  test('the same URL sent back starts nothing', async () => {
    const agent = stubAgent()
    const res = await update({ url: 'https://wiki.example.test/', name: 'Wiki renamed' })
    expect((await res.json()).job).toBeNull()
    expect(agent.calls).toHaveLength(0)
    expect(row().name).toBe('Wiki renamed')
  })

  test("enabled_change_clears_choices: every project's choice for the resource goes, in the same write (R-062)", async () => {
    for (const [projectId, resourceId] of [['p1', 'r1'], ['p2', 'r1'], ['p1', 'r2']]) h.db.seed('tradecraftProjectChoice', { projectId, resourceId })
    await update({ enabled: true })
    expect(h.db.rows('tradecraftProjectChoice')).toHaveLength(3)
    await update({ enabled: false })
    expect(h.db.rows('tradecraftProjectChoice').map(c => [c.projectId, c.resourceId])).toEqual([['p1', 'r2']])
    expect(row().enabled).toBe(false)
  })

  test('stored_to_live_deletes_text: the stored pages and their sections go at once, other resources keep theirs', async () => {
    const res = await update({ storageMode: 'live' })
    expect(res.status).toBe(200)
    expect(row().storageMode).toBe('live')
    expect(h.db.rows('tradecraftEntry', { resourceId: 'r1' })[0]).toMatchObject({ storedText: null, storedBytes: 0 })
    expect(h.db.rows('tradecraftSection', { resourceId: 'r1' })).toHaveLength(0)
    expect(h.db.rows('tradecraftEntry', { resourceId: 'r2' })[0].storedText).toBe('other text')
    expect(h.db.rows('tradecraftSection', { resourceId: 'r2' })).toHaveLength(1)
  })

  test.each([
    ['a URL change', { url: 'https://wiki2.example.test/' }],
    ['Stored → Live', { storageMode: 'live' }],
    ['the login removed', { credentials: null }],
  ])('immediate_edits_refused_while_running (%s): 409 job_running, nothing written (D-45)', async (_name, body) => {
    runningJob(new Date(T0 + 30_000))
    const agent = stubAgent()
    const before = structuredClone(h.db.tables)
    const res = await update({ ...body, name: 'Renamed too' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'job_running', job: { id: 'j-run', status: 'running' } })
    expect(h.db.tables).toEqual(before)
    expect(agent.calls).toHaveLength(0)
  })

  test.each([
    ['a URL change', { url: 'https://wiki2.example.test/' }, (r: Record<string, unknown>) => r.url === 'https://wiki2.example.test/'],
    ['Stored → Live', { storageMode: 'live' }, (r: Record<string, unknown>) => r.storageMode === 'live'],
    ['the login removed', { credentials: null }, (r: Record<string, unknown>) => r.hasLogin === false && JSON.stringify(r.credentials) === '{}'],
  ])('immediate_edits_allowed_after_lease_expired (%s)', async (_name, body, applied) => {
    runningJob(new Date(T0 - 1))
    stubAgent()
    expect((await update(body)).status).toBe(200)
    expect(applied(row())).toBe(true)
  })

  test('other edits only make the resource stale: allowed while a job runs, no job started', async () => {
    runningJob(new Date(T0 + 30_000))
    const agent = stubAgent()
    const res = await update({ name: 'New name', llmModel: 'gpt-4o-mini', enabled: false })
    expect(res.status).toBe(200)
    expect(row()).toMatchObject({ name: 'New name', llmModel: 'gpt-4o-mini', enabled: false, activeJobId: 'j-run' })
    expect(agent.calls).toHaveLength(0)
  })

  test('the masked token keeps the stored one; an empty one clears it', async () => {
    await update({ githubTokenOverride: 'set' })
    expect(row().githubTokenOverride).toBe('ghp_stored_fake')
    await update({ githubTokenOverride: '' })
    expect(row().githubTokenOverride).toBe('')
  })

  test('a forced PDF type stores its pages', async () => {
    row().storageMode = 'live'
    await update({ forcedType: 'pdf', storageMode: 'live' })
    expect(row()).toMatchObject({ forcedType: 'pdf', storageMode: 'stored' })
  })

  test("another account's resource: 404, nothing written", async () => {
    expect((await update({ name: 'x' }, 'r1', 'other')).status).toBe(404)
    expect(row().name).toBe('Wiki')
  })

  test('act-as: a URL change would send the GitHub token, so it is refused before any write', async () => {
    h.actingAs = true
    const agent = stubAgent()
    expect((await update({ url: 'https://wiki2.example.test/' })).status).toBe(403)
    expect(row().url).toBe('https://wiki.example.test/')
    expect(agent.calls).toHaveLength(0)
    expect((await update({ name: 'Renamed' })).status).toBe(200)
  })

  test('the answer carries no secret value', async () => {
    const body = await (await update({ name: 'x' })).json()
    expect(JSON.stringify(body)).not.toMatch(/ghp_stored_fake|fake-session/)
    expect(body.resource).toMatchObject({ githubTokenOverride: 'set', hasLogin: true })
  })

  describe('editing_rules (§6.13, R-174): what is saved, what goes stale, what is ingested', () => {
    /** r1 as a 2.0 ingestion with today's settings left it: current, not stale. */
    function ingestedCurrent(over: Record<string, unknown> = {}) {
      Object.assign(row(), { mapVersion: 3, overrides: {}, forcedType: '', ingestionReport: { visited: 5, kept: 5, stored: { pages: 5, bytes: 50, notStoredQuota: 0, notStoredSize: 0 } }, ...over })
      const r = row()
      r.settingsHash = ingestionHash(effectiveSettings({ resource: r.overrides }).hash, r.forcedType as string)
    }
    const view = async (body: Record<string, unknown>) => {
      const res = await update(body)
      expect(res.status).toBe(200)
      return res.json() as Promise<{ resource: { stale: boolean }; job: unknown }>
    }

    test('the resource starts current', async () => {
      ingestedCurrent()
      stubAgent()
      expect((await view({})).resource.stale).toBe(false)
    })

    test('name, enabled, model: saved, no ingestion, not stale', async () => {
      ingestedCurrent()
      const agent = stubAgent()
      const body = await view({ name: 'Renamed', enabled: false, llmModel: 'gpt-4o-mini' })
      expect(body).toMatchObject({ job: null, resource: { stale: false } })
      expect(row()).toMatchObject({ name: 'Renamed', enabled: false, llmModel: 'gpt-4o-mini' })
      expect(agent.calls).toEqual([])
    })

    test('URL: saved and ingested again', async () => {
      ingestedCurrent()
      stubAgent()
      expect((await view({ url: 'https://wiki2.example.test/' })).job).toMatchObject({ kind: 'reingest' })
    })

    test('type: saved, stale, no ingestion', async () => {
      ingestedCurrent()
      const agent = stubAgent()
      const body = await view({ forcedType: 'mkdocs-wiki' })
      expect(body).toMatchObject({ job: null, resource: { stale: true } })
      expect(row().forcedType).toBe('mkdocs-wiki')
      expect(agent.calls).toEqual([])
      // Back to Auto: the hash matches again.
      expect((await view({ forcedType: '' })).resource.stale).toBe(false)
    })

    test.each([
      ['a crawl field', { 'crawl.maxPages': 50 }],
      ['a map field', { 'knownTypes.maxMapEntries.wiki': 500 }],
      ['a fetching field', { 'fetching.userAgent': 'Probe/1.0' }],
      ['a content field', { 'content.bodySelector': 'main' }],
      ['a type option', { 'type.github.branch': 'dev' }],
    ])('%s: saved (type options mirrored), stale, no ingestion', async (_name, overrides) => {
      ingestedCurrent()
      const agent = stubAgent()
      const body = await view({ overrides })
      expect(body).toMatchObject({ job: null, resource: { stale: true } })
      expect(row().overrides).toEqual(overrides)
      expect(row().typeOptions).toEqual(Object.fromEntries(Object.entries(overrides).filter(([k]) => k.startsWith('type.'))))
      expect(agent.calls).toEqual([])
      expect((await view({ overrides: {} })).resource.stale).toBe(false)
    })

    test('Live → Stored: saved, stale until an ingestion stores the pages', async () => {
      ingestedCurrent({ storageMode: 'live', ingestionReport: { visited: 5, kept: 5 } })
      stubAgent()
      expect((await view({ storageMode: 'stored' }))).toMatchObject({ job: null, resource: { stale: true } })
      expect(row().storageMode).toBe('stored')
    })

    test('Stored → Live: the stored text goes at once, and the resource is not stale', async () => {
      ingestedCurrent()
      stubAgent()
      expect((await view({ storageMode: 'live' })).resource.stale).toBe(false)
      expect(h.db.rows('tradecraftEntry', { resourceId: 'r1' })[0].storedText).toBeNull()
    })

    test('Stored → Live → Stored: nothing is stored any more, so the resource is stale again (§6.13)', async () => {
      ingestedCurrent()
      stubAgent()
      await view({ storageMode: 'live' })
      expect(row().ingestionReport).toMatchObject({ visited: 5, kept: 5, stored: { pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0 } })
      expect((await view({ storageMode: 'stored' }))).toMatchObject({ job: null, resource: { stale: true } })
    })

    test('a Stored ingestion the quota left without text stays current: Save & re-ingest could not clear the badge', async () => {
      ingestedCurrent({ ingestionReport: { visited: 5, kept: 5, stored: { pages: 0, bytes: 0, notStoredQuota: 5, notStoredSize: 0 } } })
      stubAgent()
      expect((await view({})).resource.stale).toBe(false)
    })

    test('the Resource ID is read-only: the same ID passes, another is refused and nothing is written (R-137)', async () => {
      stubAgent()
      expect((await update({ slug: 'wiki', name: 'Same id' })).status).toBe(200)
      const res = await update({ slug: 'renamed', name: 'Other id' })
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ field: 'slug', code: 'slug_read_only' })
      expect(row()).toMatchObject({ slug: 'wiki', name: 'Same id' })
    })

    test('a user-only override is refused, nothing written (R-133)', async () => {
      const res = await update({ overrides: { 'storage.userQuotaMb': 5 }, name: 'x' })
      expect(res.status).toBe(400)
      expect(row().name).toBe('Wiki')
    })
  })
})

/**
 * Adding a 2.0 resource: the row with the account's current settings, the cap, then an `add` job.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'
import { json, refused, stubAgent } from '../__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, permissions: false, actingAs: false }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/flags', () => ({ rbacFlags: () => ({ permissions: h.permissions }) }))
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => (h.actingAs ? NextResponse.json({ code: 'not_while_acting_as' }, { status: 403 }) : null)),
}))

import { setNowForTests } from '@/lib/authz/clock'
import { JobStartBatch } from '../agentContract'
import { effectiveSettings } from '../effectiveSettings'
import { MAX_RESOURCES_PER_USER, createResourceV2 } from './create'

const ACTOR = { actorUserId: 'owner', realActorUserId: null }
const BODY = { name: 'Team Wiki', url: 'https://wiki.example.test/', llmModel: 'gpt-4o' }
const create = (body: Record<string, unknown> = BODY, skipVerify = false) => createResourceV2({ ownerId: 'owner', body, actor: ACTOR, skipVerify })
const resources = () => h.db.rows('userTradecraftResource', { userId: 'owner' })
const jobRequests = (agent: ReturnType<typeof stubAgent>) => agent.calls.filter(c => c.path === '/tradecraft/v2/jobs').map(c => JobStartBatch.parse(c.body).jobs[0])

beforeEach(() => {
  h.db = createTradecraftDb()
  h.permissions = false
  h.actingAs = false
  setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

describe('createResourceV2', () => {
  test('201 with the resource view and its queued add job; the job runs in the background', async () => {
    const agent = stubAgent()
    const res = await create()
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.job).toMatchObject({ kind: 'add', status: 'queued' })
    expect(body.resource).toMatchObject({ name: 'Team Wiki', slug: 'team-wiki', url: 'https://wiki.example.test/', storageMode: 'live', mapVersion: 1, job: { id: body.job.id } })
    expect(resources()[0]).toMatchObject({ llmModel: 'gpt-4o', activeJobId: body.job.id, resourceType: 'agentic-crawl', forcedType: '' })
    expect(jobRequests(agent).map(r => [r.kind, r.resource.url])).toEqual([['add', 'https://wiki.example.test/']])
  })

  test("uses_current_effective_settings: the account's saved values travel with the first job (R-028)", async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', ingestion: { 'crawl.maxPages': 75, 'storage.defaultMode': 'stored' } })
    const agent = stubAgent()
    await create()
    const [req] = jobRequests(agent)
    expect(req.settings['crawl.maxPages']).toBe(75)
    expect(req.settings_hash).toBe(effectiveSettings({ user: { ingestion: { 'crawl.maxPages': 75, 'storage.defaultMode': 'stored' } } }).hash)
    expect(req.resource.storage_mode).toBe('stored')
    expect(resources()[0].storageMode).toBe('stored')
  })

  test('the storage the form picked wins over the default; a PDF is Stored and a CVE database Live whatever was picked', async () => {
    stubAgent()
    await create({ ...BODY, storageMode: 'stored' }, true)
    await create({ name: 'Paper', url: 'https://docs.example.test/a.pdf', llmModel: 'gpt-4o', forcedType: 'pdf', storageMode: 'live' }, true)
    await create({ name: 'CVE PoCs', url: 'https://cve.example.test/', llmModel: 'gpt-4o', forcedType: 'cve-poc-db', storageMode: 'stored' }, true)
    expect(resources().map(r => [r.name, r.storageMode, r.resourceType])).toEqual([
      ['Team Wiki', 'stored', 'agentic-crawl'], ['Paper', 'stored', 'pdf'], ['CVE PoCs', 'live', 'cve-poc-db'],
    ])
  })

  test('skipVerify: the row only, no job, no request', async () => {
    const agent = stubAgent()
    const res = await create(BODY, true)
    expect(res.status).toBe(201)
    expect((await res.json()).job).toBeNull()
    expect(agent.calls).toHaveLength(0)
    expect(h.db.rows('tradecraftIngestionJob')).toHaveLength(0)
  })

  test('resource_cap: the 200th resource is added, the 201st is refused with nothing written (D-12)', async () => {
    for (let i = 0; i < MAX_RESOURCES_PER_USER - 1; i++) h.db.seed('userTradecraftResource', { userId: 'owner', name: `r${i}`, slug: `r${i}`, url: `https://r${i}.example.test/` })
    h.db.seed('userTradecraftResource', { userId: 'other', name: 'x', slug: 'x', url: 'https://x.example.test/' })
    const agent = stubAgent()
    expect((await create()).status).toBe(201)
    const refusedAnswer = await create({ ...BODY, name: 'One more', url: 'https://more.example.test/' })
    expect(refusedAnswer.status).toBe(409)
    expect(await refusedAnswer.json()).toEqual({ error: 'An account holds at most 200 Tradecraft resources', code: 'resource_cap' })
    expect(resources()).toHaveLength(MAX_RESOURCES_PER_USER)
    expect(jobRequests(agent)).toHaveLength(1)
  })

  test('resource_cap holds for two adds at once: one passes, one is refused', async () => {
    for (let i = 0; i < MAX_RESOURCES_PER_USER - 1; i++) h.db.seed('userTradecraftResource', { userId: 'owner', name: `r${i}`, slug: `r${i}`, url: `https://r${i}.example.test/` })
    stubAgent()
    const statuses = (await Promise.all([
      create({ ...BODY, name: 'A', url: 'https://a.example.test/' }, true),
      create({ ...BODY, name: 'B', url: 'https://b.example.test/' }, true),
    ])).map(r => r.status).sort()
    expect(statuses).toEqual([201, 409])
    expect(resources()).toHaveLength(MAX_RESOURCES_PER_USER)
    expect(h.db.raw.filter(r => r.sql.includes('pg_advisory_xact_lock')).map(r => r.values)).toEqual([['tradecraft_resources:owner'], ['tradecraft_resources:owner']])
  })

  test('a URL the account already has is a 409, not a 500', async () => {
    stubAgent()
    await create(BODY, true)
    const res = await create({ ...BODY, name: 'Same site again' }, true)
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('duplicate')
  })

  test('a field the rules refuse is a 400 naming it, nothing written', async () => {
    const res = await create({ ...BODY, url: 'https://admin:pw@wiki.example.test/' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ field: 'url', code: 'userinfo_refused' })
    expect(resources()).toHaveLength(0)
  })

  test('the agent cannot be reached: the add is saved (201), its job failed, the answer says why', async () => {
    stubAgent(() => refused())
    const res = await create()
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body).toMatchObject({ jobError: 'agent_unreachable', job: { status: 'failed', errorCode: 'agent_unreachable' }, resource: { name: 'Team Wiki' } })
    expect(resources()[0].activeJobId).toBeNull()
  })

  test("act-as: the add job would send the account's GitHub token, so it is refused before any write", async () => {
    h.permissions = true
    h.actingAs = true
    h.db.seed('userSettings', { userId: 'owner', githubAccessToken: 'ghp_account_fake' })
    const agent = stubAgent()
    const res = await create()
    expect(res.status).toBe(403)
    expect(resources()).toHaveLength(0)
    expect(agent.calls).toHaveLength(0)
    expect((await create({ ...BODY, githubTokenOverride: 'ghp_own_fake' })).status).toBe(201)
  })

  test('the answer carries no secret value', async () => {
    stubAgent()
    const body = await (await create({ ...BODY, githubTokenOverride: 'ghp_SECRET_fake_9999' })).json()
    expect(JSON.stringify(body)).not.toContain('SECRET')
    expect(body.resource.githubTokenOverride).toBe('set')
  })
})

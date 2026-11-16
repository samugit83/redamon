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
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
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
  vi.mocked(refuseWhileActingAsOn).mockClear()
  // T7.1: while the librarian is in use an add needs its model; the tests below that are not about it have one.
  h.db.seed('userSettings', { userId: 'owner', featureModels: { tradecraft_librarian: 'gpt-4o-mini' } })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
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

  test.each([
    ['recommended, Auto type', 'recommended', '', 'live'],
    ['recommended, a website', 'recommended', 'agentic-crawl', 'stored'],
    ['recommended, a GitHub repository', 'recommended', 'github-repo', 'stored'],
    ['recommended, a wiki (size unknown before Check URL)', 'recommended', 'mkdocs-wiki', 'live'],
    ['recommended, a CVE archive', 'recommended', 'cve-poc-db', 'live'],
    ['live', 'live', 'agentic-crawl', 'live'],
  ])("the account's default %s: a mode a row and a job can hold", async (_name, defaultMode, forcedType, expected) => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', ingestion: { 'storage.defaultMode': defaultMode } })
    const agent = stubAgent()
    expect((await create({ ...BODY, forcedType })).status).toBe(201)
    expect(resources()[0].storageMode).toBe(expected)
    expect(jobRequests(agent)[0].resource.storage_mode).toBe(expected)
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
    h.db.rows('userSettings', { userId: 'owner' })[0].githubAccessToken = 'ghp_account_fake'
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

  test('slug_rules: the chosen Resource ID is kept; a taken one is a 409 naming the field, nothing written (R-137)', async () => {
    stubAgent()
    expect((await create({ ...BODY, slug: 'my-wiki' })).status).toBe(201)
    expect(resources()[0].slug).toBe('my-wiki')
    const res = await create({ ...BODY, url: 'https://other.example.test/', slug: 'my-wiki' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ field: 'slug', code: 'slug_taken' })
    expect(resources()).toHaveLength(1)
    // Without one, the name's slug, suffixed when taken.
    await create({ ...BODY, name: 'My Wiki', url: 'https://third.example.test/' })
    expect(resources().map(r => r.slug)).toEqual(['my-wiki', 'my-wiki-2'])
  })

  test('another account may use the same Resource ID', async () => {
    stubAgent()
    h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'my-wiki', url: 'https://x.example.test/' })
    expect((await create({ ...BODY, slug: 'my-wiki' })).status).toBe(201)
  })

  test('the overrides are stored, their type.* keys mirrored, and they reach the first job; the preset is recorded', async () => {
    const agent = stubAgent()
    const overrides = { 'crawl.maxPages': 40, 'type.github.branch': 'dev' }
    await create({ ...BODY, forcedType: 'github-repo', overrides, presetKey: 'payloadsallthethings' })
    expect(resources()[0]).toMatchObject({ overrides, typeOptions: { 'type.github.branch': 'dev' }, presetKey: 'payloadsallthethings', forcedType: 'github-repo' })
    const [req] = jobRequests(agent)
    expect(req.settings).toMatchObject({ 'crawl.maxPages': 40, 'type.github.branch': 'dev' })
    expect(req.resource.type_options).toEqual({ 'type.github.branch': 'dev' })
    expect(req.settings_snapshot.provenance['crawl.maxPages']).toBe('resource')
  })

  test('the focus is stored and reaches the first job; its hash carries it (T5.5)', async () => {
    const agent = stubAgent()
    const focus = { mode: 'focused', recipe: 'web_payload_library', topics: ['xss'], kinds: ['payloads'], keep: 'XSS payloads', skip: '', skipMode: 'replace', strictness: 'loose' }
    expect((await create({ ...BODY, focus })).status).toBe(201)
    expect(resources()[0].focus).toEqual(focus)
    const [req] = jobRequests(agent)
    expect(req.resource.focus).toEqual(focus)
    expect(req.settings_hash).not.toBe(effectiveSettings({}).hash)
  })

  test('foreign_skill_refused: a focus on another account\'s skill is a 400, nothing written', async () => {
    h.db.seed('userAttackSkill', { id: 'theirs', userId: 'other', name: 'Theirs' })
    const agent = stubAgent()
    const res = await create({ ...BODY, focus: { mode: 'focused', topics: ['user_skill:theirs'] } })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ field: 'focus.topics', code: 'foreign_skill' })
    expect(resources()).toEqual([])
    expect(agent.calls).toEqual([])
  })

  describe('site logins (§6.6, T6.5)', () => {
    const LOGIN = { cookie: 'session=fake-session', headers: [{ name: 'X-Api-Key', value: 'fake-key-1' }], basic_auth: { username: 'bob', password: 'fake-pass' } }

    test('has_login_recomputed: a login typed at add is stored in the contract\'s shape, the flag set, its audit row names fields only', async () => {
      const agent = stubAgent()
      const res = await create({ ...BODY, credentials: LOGIN })
      expect(res.status).toBe(201)
      expect(resources()[0]).toMatchObject({ credentials: LOGIN, hasLogin: true })
      const audit = h.db.rows('auditLog')
      expect(audit).toEqual([expect.objectContaining({
        action: 'tradecraft.credentials_changed', actorId: 'owner', targetType: 'tradecraft_resource', targetId: resources()[0].id,
        before: { hasLogin: false }, after: { hasLogin: true, changed: ['cookie', 'header:X-Api-Key', 'basic_auth.username', 'basic_auth.password'] },
      })])
      expect(JSON.stringify(audit)).not.toMatch(/fake-/)
      // The owner's add job carries the login, to the agent only.
      expect(jobRequests(agent)[0].secrets.credentials).toEqual(LOGIN)
      const text = JSON.stringify(await res.json())
      expect(text).not.toMatch(/fake-/)
    })

    test('an add without a login writes no audit row and keeps the flag off', async () => {
      stubAgent()
      await create({ ...BODY, credentials: { cookie: '', headers: [] } })
      expect(resources()[0]).toMatchObject({ credentials: {}, hasLogin: false })
      expect(h.db.rows('auditLog')).toEqual([])
    })

    test('credential_writes_refused: acting as the account, an add with a login is refused as change_site_logins, nothing written', async () => {
      h.actingAs = true
      const agent = stubAgent()
      expect((await create({ ...BODY, credentials: LOGIN })).status).toBe(403)
      expect(vi.mocked(refuseWhileActingAsOn).mock.calls[0]).toEqual(['owner', 'change_site_logins'])
      expect(resources()).toEqual([])
      expect(agent.calls).toEqual([])
    })

    test('a failed audit insert adds nothing (the row and the login roll back together)', async () => {
      stubAgent()
      h.db.failNext('auditLog.create', new Error('audit down'))
      await expect(create({ ...BODY, credentials: LOGIN })).rejects.toThrow('audit down')
      expect(resources()).toEqual([])
    })

    test('a bad login is a 400 naming its field, nothing written', async () => {
      stubAgent()
      const res = await create({ ...BODY, credentials: { headers: [{ name: 'Host', value: 'evil.example.test' }] } })
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ field: 'credentials.headers[0].name', code: 'bad_credentials' })
      expect(resources()).toEqual([])
    })
  })

  describe('the librarian model gate (Q10, T7.1; R-013, R-404, AC-70)', () => {
    const noModel = () => { h.db.rows('userSettings', { userId: 'owner' })[0].featureModels = {} }

    test('model_required_without_librarian: while the librarian is in use, an add without its model opens the gate, nothing written', async () => {
      noModel()
      const agent = stubAgent()
      const res = await create()
      expect(res.status).toBe(409)
      expect(await res.json()).toEqual({ error: 'Choose a model for this feature first', code: 'model_required', featureId: 'tradecraft_librarian' })
      expect(resources()).toEqual([])
      expect(agent.calls).toEqual([])
      expect((await create(BODY, true)).status).toBe(409)
    })

    test('with the model saved (the gate saved it), the same add goes through', async () => {
      noModel()
      stubAgent()
      expect((await create()).status).toBe(409)
      h.db.rows('userSettings', { userId: 'owner' })[0].featureModels = { tradecraft_librarian: 'gpt-4o-mini' }
      expect((await create()).status).toBe(201)
    })

    test('search_only_asks_nothing: with Librarian use "Search only", no model is asked for', async () => {
      noModel()
      h.db.seed('tradecraftUserSettings', { userId: 'owner', search: { 'librarian.use': 'search_only' } })
      stubAgent()
      expect((await create()).status).toBe(201)
    })

    test('loop_model_refused_for_librarian: a saved Agent in the Loop model is no librarian model', async () => {
      h.db.rows('userSettings', { userId: 'owner' })[0].featureModels = { tradecraft_librarian: 'loop/mcp' }
      stubAgent()
      expect(await (await create()).json()).toMatchObject({ code: 'model_required', featureId: 'tradecraft_librarian' })
    })

    test('a field the rules refuse is still a 400 first', async () => {
      noModel()
      expect((await create({ ...BODY, url: 'http://127.0.0.1/' })).status).toBe(400)
    })
  })

  test('a user-only override is refused before anything is written', async () => {
    const agent = stubAgent()
    const res = await create({ ...BODY, overrides: { 'storage.userQuotaMb': 5 } })
    expect(res.status).toBe(400)
    expect(resources()).toEqual([])
    expect(agent.calls).toEqual([])
  })
})

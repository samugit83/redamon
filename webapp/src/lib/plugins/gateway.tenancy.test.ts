/**
 * The Gateway frame (TD-06, R-06, R-68): whose data a call may reach. The project and
 * the session a token names must still belong to its user, whatever ACCESS_ENFORCE says:
 * ownership is always enforced. A foreign or missing resource is a 404, as everywhere
 * else in the webapp (anti-enumeration).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
// The real policy unless a test answers for it (step 5.10: a share's level and toggles).
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const actual = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import {
  ALICE,
  ALICE_OTHER_PROJECT,
  ALICE_OTHER_SESSION,
  ALICE_PROJECT,
  ALICE_SESSION,
  ALICE_CONV,
  BOB,
  BOB_PROJECT,
  BOB_SESSION,
  CALL_SECRET,
  answer,
  echoManifest,
  gatewayRequest,
  seedWorld,
  token,
  type TokenInput,
} from './__testing__/gatewayHarness'
import { withGateway, type GatewayContext } from './gateway'
import * as store from './dataStore'
import { POST as dataGet } from '@/app/api/plugin-gateway/v1/data/get/route'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { ownsScope, scopeRefusal } from './changeSetAccess'

let db: FakePrisma

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.stubEnv('ACCESS_ENFORCE', '')
})
afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const handler = vi.fn(async () => ({ ok: true }))
const status = async (over: TokenInput) => {
  handler.mockClear()
  const res = await withGateway(gatewayRequest('x', {}, { token: await token(over) }), { op: 'x' }, handler)
  return { ...(await answer(res)), ran: handler.mock.calls.length > 0 }
}

describe.each(['', '0', 'false'])('ACCESS_ENFORCE=%j: tenancy is strict either way', (enforce) => {
  beforeEach(() => vi.stubEnv('ACCESS_ENFORCE', enforce))

  test('control: Alice, her project, her session → 200', async () => {
    expect((await status({})).status).toBe(200)
  })

  test("another user's project: 404, handler not run", async () => {
    const r = await status({ prj: BOB_PROJECT, ses: undefined, conv: undefined })
    expect(r).toMatchObject({ status: 404, body: { code: 'not_found' }, ran: false })
  })

  test('a project that no longer exists: 404', async () => {
    const t = await token({ ses: undefined, conv: undefined })
    await db.project.delete({ where: { id: ALICE_PROJECT } })
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: t }), { op: 'x' }, handler))
    expect(r.status).toBe(404)
  })

  test("another user's session, inside Alice's project claim: 404", async () => {
    expect((await status({ ses: BOB_SESSION, conv: undefined })).status).toBe(404)
  })

  test("Alice's session of another of her projects: 404", async () => {
    expect((await status({ ses: ALICE_OTHER_SESSION, conv: undefined })).status).toBe(404)
  })

  test('an unknown session: 404', async () => {
    expect((await status({ ses: 'session-nobody', conv: undefined })).status).toBe(404)
  })

  test('a session without a project: 404 (it cannot be checked)', async () => {
    expect((await status({ prj: undefined, conv: undefined })).status).toBe(404)
  })

  test('a conversation id that is not the session’s: 404', async () => {
    expect((await status({ conv: 'conv-bob' })).status).toBe(404)
  })

  test('a session that moved to another user since the token was minted: 404', async () => {
    const t = await token()
    await db.conversation.update({ where: { sessionId: ALICE_SESSION }, data: { userId: BOB } })
    const r = await answer(await withGateway(gatewayRequest('x', {}, { token: t }), { op: 'x' }, handler))
    expect(r.status).toBe(404)
  })
})

describe('data owners come from the token only', () => {
  beforeEach(async () => {
    await store.put({ pluginId: 'echo' }, { type: 'project', id: ALICE_PROJECT }, 'notes', 'k1', 'alice project')
    await store.put({ pluginId: 'echo' }, { type: 'project', id: BOB_PROJECT }, 'notes', 'k1', 'bob project')
    await store.put({ pluginId: 'echo' }, { type: 'user', id: ALICE }, 'notes', 'k1', 'alice')
    await store.put({ pluginId: 'echo' }, { type: 'user', id: BOB }, 'notes', 'k1', 'bob')
  })

  const get = async (body: Record<string, unknown>, over: TokenInput = {}) =>
    answer(await dataGet(gatewayRequest('data/get', body, { token: await token(over) })))

  test('owner user is the token user', async () => {
    expect((await get({ collection: 'notes', key: 'k1', owner: 'user' })).body).toEqual({ found: true, value: 'alice' })
  })

  test("owner project is the token's project; a projectId in the body is ignored", async () => {
    const r = await get({ collection: 'notes', key: 'k1', owner: 'project', projectId: BOB_PROJECT })
    expect(r.body).toEqual({ found: true, value: 'alice project' })
  })

  test('owner project outside a project: 400 invalid_owner with the contract message', async () => {
    const r = await get({ collection: 'notes', key: 'k1', owner: 'project' }, { prj: undefined, ses: undefined, conv: undefined })
    expect(r).toEqual({ status: 400, body: { error: 'This action was not started from a project.', code: 'invalid_owner' } })
  })

  test.each([undefined, 'admin', 'global', 7])('owner %j: 400 invalid_owner', async (owner) => {
    const r = await get({ collection: 'notes', key: 'k1', owner })
    expect(r.status).toBe(400)
    expect(r.body.code).toBe('invalid_owner')
  })

  test("Bob's token never reads Alice's rows", async () => {
    const r = await get(
      { collection: 'notes', key: 'k1', owner: 'project' },
      { sub: BOB, prj: BOB_PROJECT, ses: BOB_SESSION, conv: 'conv-bob' },
    )
    expect(r.body).toEqual({ found: true, value: 'bob project' })
  })

  test('a token for another of Alice’s projects reads that project only', async () => {
    const r = await get({ collection: 'notes', key: 'k1', owner: 'project' }, { prj: ALICE_OTHER_PROJECT, ses: undefined, conv: undefined })
    expect(r.body).toEqual({ found: false })
  })
})

// Step 5.10 (SH-35): a plugin run for a collaborator on a project shared with them. The token names
// the person (`sub`) and the project's owner (`ten`); the Gateway asks projectAccess() for the
// person at the levels the plugin's permissions need (Read + Write, and Use AI agent for a plugin
// that may call a model; the owner's alone for one that declares none), checks the owner is still
// the token's tenant, and opens a conversation only to its author, never on project access alone.
describe('a project shared with the token user (step 5.10)', () => {
  const BOB_ON_ALICE = 'session-bob-on-alice'
  const policy = vi.mocked(projectAccess)
  const shared = (level: 'read' | 'write', toggles: Partial<ProjectAccessToggles> = {}, via: ProjectAccess['via'] = 'share'): ProjectAccess =>
    Object.freeze({
      project: Object.freeze({ id: ALICE_PROJECT, userId: ALICE }),
      level,
      toggles: Object.freeze({ rawData: level === 'write', ...toggles }),
      via,
    }) as ProjectAccess
  const editor = (toggles: Partial<ProjectAccessToggles> = {}) => shared('write', toggles)
  const BOB_TOKEN: TokenInput = { sub: BOB, prj: ALICE_PROJECT, ses: BOB_ON_ALICE, conv: 'conv-bob-on-alice' }

  let seen: GatewayContext | null
  const capture = vi.fn(async (ctx: GatewayContext) => {
    seen = ctx
    return { ok: true }
  })
  const call = async (over: TokenInput) => {
    seen = null
    capture.mockClear()
    const res = await withGateway(gatewayRequest('x', {}, { token: await token(over) }), { op: 'x' }, capture)
    return { ...(await answer(res)), ran: capture.mock.calls.length > 0 }
  }

  beforeEach(async () => {
    db.seed('conversation', [{ id: 'conv-bob-on-alice', sessionId: BOB_ON_ALICE, userId: BOB, projectId: ALICE_PROJECT }])
    policy.mockReset()
  })
  afterEach(async () => {
    const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
    policy.mockImplementation(actual.projectAccess)
  })

  test('collaborator with access served: Read + Write with Use AI agent runs a model-calling plugin, as the person, for the owner', async () => {
    policy.mockResolvedValue(editor({ useAgent: true }))
    const r = await call(BOB_TOKEN)
    expect(r).toMatchObject({ status: 200, ran: true })
    expect(seen).toMatchObject({ userId: BOB, tenantId: ALICE, projectId: ALICE_PROJECT, sessionId: BOB_ON_ALICE })
    expect(seen!.access).toMatchObject({ level: 'write', via: 'share' })
    expect(seen!.conversation).toMatchObject({ id: 'conv-bob-on-alice', userId: BOB })
    expect(policy).toHaveBeenCalledWith({ userId: BOB }, ALICE_PROJECT)
  })

  test("collaborator with access served: the project's plugin data is the project's, whoever runs it", async () => {
    await store.put({ pluginId: 'echo' }, { type: 'project', id: ALICE_PROJECT }, 'notes', 'k1', 'alice project')
    policy.mockResolvedValue(editor({ useAgent: true }))
    const r = await answer(await dataGet(gatewayRequest('data/get', { collection: 'notes', key: 'k1', owner: 'project' }, { token: await token(BOB_TOKEN) })))
    expect(r).toEqual({ status: 200, body: { found: true, value: 'alice project' } })
  })

  test('a plugin that may call a model needs Use AI agent: without it every call is a 404, the handler not run', async () => {
    policy.mockResolvedValue(editor({ useAgent: false }))
    expect(await call(BOB_TOKEN)).toMatchObject({ status: 404, body: { code: 'not_found' }, ran: false })
  })

  test('a plugin that calls no model runs at Read + Write without Use AI agent', async () => {
    await db.pluginInstall.update({
      where: { pluginId: 'echo' },
      data: { grantedPermissions: ['session:read', 'override:skill.text'] },
    })
    policy.mockResolvedValue(editor())
    expect(await call(BOB_TOKEN)).toMatchObject({ status: 200, ran: true })
  })

  test('a permission declared but not granted counts for nothing; one granted but not declared neither', async () => {
    // llm:invoke granted but no longer declared (an update dropped it): the run needs Read + Write only.
    await db.pluginInstall.update({
      where: { pluginId: 'echo' },
      data: { manifest: echoManifest({ permissions: ['session:read', 'override:skill.text'], llmFeature: undefined }) },
    })
    policy.mockResolvedValue(editor())
    expect(await call(BOB_TOKEN)).toMatchObject({ status: 200, ran: true })
  })

  test("a plugin that declares no permission stays the owner's: a co-owner with every toggle is refused, the owner served", async () => {
    await db.pluginInstall.update({ where: { pluginId: 'echo' }, data: { grantedPermissions: [], manifest: echoManifest({ permissions: [], llmFeature: undefined, actions: [{ id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 }] }) } })
    policy.mockResolvedValue(editor({ useAgent: true, runScans: true, exploit: true, manage: true }))
    expect(await call({ ...BOB_TOKEN, ses: undefined, conv: undefined })).toMatchObject({ status: 404, ran: false })
    const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
    policy.mockImplementation(actual.projectAccess)
    expect(await call({ ses: undefined, conv: undefined })).toMatchObject({ status: 200, ran: true })
  })

  test.each([
    ['a read share', shared('read')],
    ['a read share with Raw data & files', shared('read', { rawData: true })],
    ['oversight', shared('read', {}, 'oversight')],
    ['break-glass', shared('read', { rawData: true }, 'break_glass')],
  ])('%s never runs a plugin: 404', async (_what, access) => {
    policy.mockResolvedValue(access)
    expect(await call({ ...BOB_TOKEN, ses: undefined, conv: undefined })).toMatchObject({ status: 404, ran: false })
  })

  test("transcript only for author or share: the owner's session is a 404 to a co-owner, project access alone never opens it", async () => {
    policy.mockResolvedValue(editor({ useAgent: true, runScans: true, exploit: true, manage: true }))
    expect(await call({ sub: BOB, prj: ALICE_PROJECT, ses: ALICE_SESSION, conv: ALICE_CONV })).toMatchObject({ status: 404, ran: false })
    expect(await call({ sub: BOB, prj: ALICE_PROJECT, ses: ALICE_SESSION, conv: undefined })).toMatchObject({ status: 404, ran: false })
  })

  test('transcript only for author or share: the collaborator reaches their own session on the shared project', async () => {
    policy.mockResolvedValue(editor({ useAgent: true }))
    const r = await call(BOB_TOKEN)
    expect(r.status).toBe(200)
    expect(seen!.conversation).toMatchObject({ sessionId: BOB_ON_ALICE, userId: BOB, projectId: ALICE_PROJECT })
  })

  test('a token whose tenant no longer owns the project (a transfer since it was minted) is a 404', async () => {
    policy.mockResolvedValue(editor({ useAgent: true }))
    expect(await call({ ...BOB_TOKEN, ten: BOB })).toMatchObject({ status: 404, ran: false })
    expect(await call({ ...BOB_TOKEN, ten: 'user-admin' })).toMatchObject({ status: 404, ran: false })
  })

  test("a token minted before the tenant claim reads as its user's: a collaborator's is refused, the owner's served", async () => {
    policy.mockResolvedValue(editor({ useAgent: true }))
    expect(await call({ ...BOB_TOKEN, ten: undefined })).toMatchObject({ status: 404, ran: false })
    const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
    policy.mockImplementation(actual.projectAccess)
    expect(await call({ ten: undefined })).toMatchObject({ status: 200, ran: true })
  })

  test('outside a project the tenant is the user: any other tenant is a 404', async () => {
    expect(await call({ prj: undefined, ses: undefined, conv: undefined })).toMatchObject({ status: 200, ran: true })
    expect(seen).toMatchObject({ tenantId: ALICE, access: null })
    expect(await call({ prj: undefined, ses: undefined, conv: undefined, ten: BOB })).toMatchObject({ status: 404, ran: false })
    expect(policy).not.toHaveBeenCalled()
  })

  test('an admin acting as the person: the share is asked as acted (read at most, D-22)', async () => {
    policy.mockResolvedValue(shared('read'))
    expect(await call({ ...BOB_TOKEN, act: 'user-admin' })).toMatchObject({ status: 404, ran: false })
    expect(policy).toHaveBeenCalledWith({ userId: BOB }, ALICE_PROJECT, { actingAs: true })
  })

  test('the access is asked on every call: a toggle withdrawn mid-action ends the next call', async () => {
    const t = await token(BOB_TOKEN)
    policy.mockResolvedValueOnce(editor({ useAgent: true }))
    expect((await withGateway(gatewayRequest('x', {}, { token: t }), { op: 'x' }, capture)).status).toBe(200)
    policy.mockResolvedValueOnce(editor({ useAgent: false }))
    expect((await withGateway(gatewayRequest('x', {}, { token: t }), { op: 'x' }, capture)).status).toBe(404)
  })

  test('override approval needs Manage: a project scope is decided at M, a user scope stays its own', async () => {
    policy.mockResolvedValue(editor({ useAgent: true, runScans: true, exploit: true }))
    expect(await scopeRefusal({ type: 'project', id: ALICE_PROJECT }, BOB)).toBe('level')
    expect(await ownsScope({ type: 'project', id: ALICE_PROJECT }, BOB)).toBe(false)
    policy.mockResolvedValue(editor({ manage: true }))
    expect(await scopeRefusal({ type: 'project', id: ALICE_PROJECT }, BOB)).toBeNull()
    policy.mockResolvedValue(shared('read', { rawData: true }, 'oversight'))
    expect(await scopeRefusal({ type: 'project', id: ALICE_PROJECT }, BOB)).toBe('not_found')
    policy.mockResolvedValue(null)
    expect(await scopeRefusal({ type: 'project', id: ALICE_PROJECT }, BOB)).toBe('not_found')
    policy.mockResolvedValue(editor({ manage: true }))
    expect(await scopeRefusal({ type: 'user', id: ALICE }, BOB)).toBe('not_found')
    expect(await scopeRefusal({ type: 'project', id: ALICE_PROJECT }, BOB, { actingAs: true })).toBeNull()
    expect(policy).toHaveBeenLastCalledWith({ userId: BOB }, ALICE_PROJECT, { actingAs: true })
  })
})

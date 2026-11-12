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

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import {
  ALICE,
  ALICE_OTHER_PROJECT,
  ALICE_OTHER_SESSION,
  ALICE_PROJECT,
  ALICE_SESSION,
  BOB,
  BOB_PROJECT,
  BOB_SESSION,
  CALL_SECRET,
  answer,
  gatewayRequest,
  seedWorld,
  token,
  type TokenInput,
} from './__testing__/gatewayHarness'
import { withGateway } from './gateway'
import * as store from './dataStore'
import { POST as dataGet } from '@/app/api/plugin-gateway/v1/data/get/route'

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

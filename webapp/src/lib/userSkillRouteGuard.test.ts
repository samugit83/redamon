/**
 * requireOwnBrowserRequest: the routes only the upload dialog calls accept a same-origin
 * request that passes the account's write rule (HD-23): the REAL signed-in user owns the
 * id, or an admin is acting as a passwordless managed owner. An admin acting as an owner
 * who can sign in is refused, and the internal key, which requireUserAccess lets through,
 * is no login here. The real session helpers run over signed tokens; only the cookie
 * store and Prisma are mocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  auth: undefined as string | undefined,
  actAs: undefined as string | undefined,
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.auth) return { value: h.auth }
      if (name === 'redamon-act-as' && h.actAs) return { value: h.actAs }
      return undefined
    },
  })),
}))
const USERS: Record<string, { role: string; password: string }> = {
  alice: { role: 'standard', password: 'hash' },
  carol: { role: 'standard', password: '' },
  managed: { role: 'standard', password: '' },
  root: { role: 'admin', password: 'hash' },
}
vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => USERS[where.id]
        ? { id: where.id, email: `${where.id}@e2e.local`, createdAt: new Date(0), ...USERS[where.id] }
        : null,
    },
  },
}))

import { requireOwnBrowserRequest } from './userSkillRouteGuard'
import { createActAsToken, createToken } from './auth'

const request = (headers: Record<string, string> = {}, id = 'alice') =>
  new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills/batch`, {
    method: 'POST', headers: { host: 'localhost:3000', ...headers },
  })

async function status(req: NextRequest, id = 'alice') {
  const out = await requireOwnBrowserRequest(req, id)
  return out instanceof NextResponse ? { status: out.status, body: await out.json() } : { status: 0, eff: out }
}

beforeEach(async () => {
  vi.stubEnv('AUTH_SECRET', 'g'.repeat(64))
  vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')
  h.auth = await createToken('alice', 'standard')
  h.actAs = undefined
})
afterEach(() => vi.unstubAllEnvs())

describe('requireOwnBrowserRequest', () => {
  test('the owner from the same origin passes with the effective user', async () => {
    expect(await status(request({ origin: 'http://localhost:3000' }))).toEqual({ status: 0, eff: { userId: 'alice' } })
  })

  test('a foreign Origin is 403 cross_origin, before the session is read', async () => {
    h.auth = undefined
    const out = await status(request({ origin: 'https://evil.example.com' }))
    expect(out).toMatchObject({ status: 403, body: { code: 'cross_origin' } })
  })

  test('no session is 401', async () => {
    h.auth = undefined
    expect((await status(request())).status).toBe(401)
  })

  test("another user's id is 403", async () => {
    expect((await status(request({}, 'carol'), 'carol')).status).toBe(403)
  })

  test('an admin acting as an owner who can sign in is refused; an admin not acting is refused (HD-23)', async () => {
    h.auth = await createToken('root', 'admin')
    h.actAs = await createActAsToken('root', 'alice')
    expect(await status(request())).toMatchObject({ status: 403, body: { code: 'own_account_only' } })
    h.actAs = undefined
    expect(await status(request())).toMatchObject({ status: 403, body: { code: 'own_account_only' } })
  })

  test('an admin acting as a passwordless managed owner passes', async () => {
    h.auth = await createToken('root', 'admin')
    h.actAs = await createActAsToken('root', 'managed')
    expect(await status(request({}, 'managed'), 'managed')).toEqual({ status: 0, eff: { userId: 'managed' } })
  })

  test('a stale tab whose act-as user changed cannot act for the previous one', async () => {
    h.auth = await createToken('root', 'admin')
    h.actAs = await createActAsToken('root', 'carol')
    expect((await status(request({}, 'managed'), 'managed')).status).toBe(403)
  })

  test('a request carrying only x-internal-key is 401', async () => {
    h.auth = undefined
    vi.stubEnv('INTERNAL_API_KEY', 'k'.repeat(32))
    expect((await status(request({ 'x-internal-key': 'k'.repeat(32) }))).status).toBe(401)
  })
})

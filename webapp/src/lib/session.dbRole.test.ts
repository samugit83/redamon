/**
 * The session helpers decide role and existence from the database, not from the
 * 7-day login JWT (HD-10, F-09): a demoted or deleted account loses its powers on
 * its next request. Real tokens are signed; only the cookie store and Prisma are mocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'd'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-dbrole')

let authCookie: string | undefined
let actAsCookie: string | undefined

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && authCookie) return { value: authCookie }
      if (name === 'redamon-act-as' && actAsCookie) return { value: actAsCookie }
      return undefined
    },
  })),
}))

/** The users table as the database has it now: id -> role. Absent = deleted. */
const dbRoles = new Map<string, string>()
const findUnique = vi.fn(async (args: { where: { id: string } }) => {
  const role = dbRoles.get(args.where.id)
  if (!role) return null
  return { id: args.where.id, email: `${args.where.id}@e2e.local`, role, password: 'hash', createdAt: new Date(0) }
})
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (args: { where: { id: string } }) => findUnique(args) } },
}))

import { getSession, getEffectiveUser, requireAdmin, requireSession, requireUserAccess } from './session'
import { createToken, createActAsToken } from './auth'

function req(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://x/api/users/someone/settings', { headers })
}

beforeEach(() => {
  authCookie = undefined
  actAsCookie = undefined
  dbRoles.clear()
  findUnique.mockClear()
})

describe('role and existence from the database', () => {
  test('a valid token of a deleted user is no session', async () => {
    authCookie = await createToken('gone', 'admin')
    expect(await getSession()).toBeNull()
    expect(await getEffectiveUser()).toBeNull()
    expect(((await requireSession()) as NextResponse).status).toBe(401)
    expect(((await requireAdmin()) as NextResponse).status).toBe(401)
    expect(((await requireUserAccess(req(), 'gone')) as NextResponse).status).toBe(401)
  })

  test('a token claiming admin for a demoted user is not admin', async () => {
    dbRoles.set('demoted', 'standard')
    authCookie = await createToken('demoted', 'admin')
    expect(await getSession()).toEqual({ userId: 'demoted', role: 'standard' })
    expect(((await requireUserAccess(req(), 'victim')) as NextResponse).status).toBe(403)
    expect(await requireUserAccess(req(), 'demoted')).toBeNull()
  })

  test('a token claiming standard for a promoted user is admin', async () => {
    dbRoles.set('promoted', 'admin')
    authCookie = await createToken('promoted', 'standard')
    expect(await getSession()).toEqual({ userId: 'promoted', role: 'admin' })
    const admin = await requireAdmin()
    expect(admin).not.toBeInstanceOf(NextResponse)
    expect(await requireUserAccess(req(), 'victim')).toBeNull()
  })

  test('an act-as cookie minted by a demoted admin is ignored', async () => {
    dbRoles.set('demoted', 'standard')
    dbRoles.set('victim', 'standard')
    authCookie = await createToken('demoted', 'admin')
    actAsCookie = await createActAsToken('demoted', 'victim')
    expect(await getEffectiveUser()).toEqual({ userId: 'demoted' })
  })

  test('an act-as cookie naming a deleted user is ignored', async () => {
    dbRoles.set('admin-1', 'admin')
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'gone')
    expect(await getEffectiveUser()).toEqual({ userId: 'admin-1' })
  })

  test('an admin acting as an existing user still gets that user', async () => {
    dbRoles.set('admin-1', 'admin')
    dbRoles.set('victim', 'standard')
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'victim')
    expect(await getEffectiveUser()).toEqual({ userId: 'victim' })
  })

  test('requireAdmin answers 403 for a demoted admin', async () => {
    dbRoles.set('demoted', 'standard')
    authCookie = await createToken('demoted', 'admin')
    const res = await requireAdmin()
    expect(res).toBeInstanceOf(NextResponse)
    expect((res as NextResponse).status).toBe(403)
  })

  test('the internal key needs no account read', async () => {
    expect(await requireUserAccess(req({ 'x-internal-key': 'internal-key-dbrole' }), 'victim')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('one query per call', async () => {
    dbRoles.set('admin-1', 'admin')
    dbRoles.set('victim', 'standard')
    authCookie = await createToken('admin-1', 'admin')
    const calls: [string, () => Promise<unknown>][] = [
      ['getSession', () => getSession()],
      ['requireSession', () => requireSession()],
      ['requireAdmin', () => requireAdmin()],
      ['requireUserAccess', () => requireUserAccess(req(), 'victim')],
      ['getEffectiveUser', () => getEffectiveUser()],
    ]
    for (const [name, call] of calls) {
      findUnique.mockClear()
      await call()
      expect(findUnique, name).toHaveBeenCalledTimes(1)
      expect(findUnique.mock.calls[0][0].where, name).toEqual({ id: 'admin-1' })
    }
    // Acting as someone adds exactly one read: the target's existence.
    actAsCookie = await createActAsToken('admin-1', 'victim')
    findUnique.mockClear()
    await getEffectiveUser()
    expect(findUnique.mock.calls.map(c => c[0].where.id)).toEqual(['admin-1', 'victim'])
  })

  test('no cookie reads nothing', async () => {
    expect(await getSession()).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a failed account read never admits: getSession throws, requireSession and requireAdmin answer a coded 500', async () => {
    authCookie = await createToken('admin-1', 'admin')
    const down = Object.assign(new Error('connect ECONNREFUSED'), { code: 'P1001' })
    findUnique.mockRejectedValue(down)
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      await expect(getSession()).rejects.toThrow()
      await expect(getEffectiveUser()).rejects.toThrow()
      for (const res of [await requireSession(), await requireAdmin()]) {
        expect(res).toBeInstanceOf(NextResponse)
        expect((res as NextResponse).status).toBe(500)
        const body = await (res as NextResponse).json()
        expect(body.code).toBe('P1001')
        expect(JSON.stringify(body)).not.toContain('ECONNREFUSED')
      }
    } finally {
      err.mockRestore()
      findUnique.mockReset()
    }
  })
})

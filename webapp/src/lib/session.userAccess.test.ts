/**
 * Unit tests for the REAL requireUserAccess ownership gate (STRIDE I1 closure) and its
 * two modes (HD-23, F-19): `read` keeps the internal key and the admin bypass (every
 * secret is masked for a browser caller); `write` needs the account's own session, the
 * internal key, or an admin acting as a passwordless managed account (OQ-49).
 *
 * Real tokens are signed; only the cookie store and Prisma are mocked.
 *
 * Run: npx vitest run src/lib/session.userAccess.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-xyz')

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

// getSession reads role and existence from the database (HD-10). `managed` has no
// password: it can never sign in, an admin runs it through act-as.
const DB: Record<string, { role: string; password: string }> = {
  'victim': { role: 'standard', password: 'h' },
  'attacker': { role: 'standard', password: 'h' },
  'admin-1': { role: 'admin', password: 'h' },
  'admin-2': { role: 'admin', password: 'h' },
  'managed': { role: 'standard', password: '' },
}
const findUnique = vi.fn(async ({ where }: { where: { id: string } }) =>
  DB[where.id]
    ? { id: where.id, email: `${where.id}@e2e.local`, role: DB[where.id].role, password: DB[where.id].password, createdAt: new Date(0) }
    : null)
vi.mock('@/lib/prisma', () => ({ default: { user: { findUnique: (a: { where: { id: string } }) => findUnique(a) } } }))

import { requireAccountWrite, requireUserAccess } from './session'
import { createActAsToken, createToken } from './auth'

function req(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('http://x/api/users/victim/settings', { headers })
}
const READ = { mode: 'read' } as const
const WRITE = { mode: 'write' } as const

async function body(r: NextResponse | null) {
  return r ? { status: r.status, ...(await r.json()) } : null
}

beforeEach(() => {
  authCookie = undefined
  actAsCookie = undefined
  findUnique.mockClear()
})

describe('requireUserAccess', () => {
  test('internal-key caller -> allowed (null), no session needed', async () => {
    const r = await requireUserAccess(req({ 'x-internal-key': 'internal-key-xyz' }), 'victim', READ)
    expect(r).toBeNull()
  })

  test('no session, no key -> 401', async () => {
    const r = await requireUserAccess(req(), 'victim', READ)
    expect((r as NextResponse).status).toBe(401)
  })

  test('owner -> allowed (null)', async () => {
    authCookie = await createToken('victim', 'standard')
    const r = await requireUserAccess(req(), 'victim', READ)
    expect(r).toBeNull()
  })

  test('EXPLOIT: standard user requesting another user -> 403', async () => {
    authCookie = await createToken('attacker', 'standard')
    const r = await requireUserAccess(req(), 'victim', READ)
    expect((r as NextResponse).status).toBe(403)
  })

  test('admin requesting another user -> allowed (masked-read convenience preserved)', async () => {
    authCookie = await createToken('admin-1', 'admin')
    const r = await requireUserAccess(req(), 'victim', READ)
    expect(r).toBeNull()
  })
})

describe('read and write modes (HD-23)', () => {
  test('an admin reads another account masked', async () => {
    authCookie = await createToken('admin-1', 'admin')
    expect(await requireUserAccess(req(), 'victim', READ)).toBeNull()
    expect(await requireUserAccess(req(), 'admin-2', READ)).toBeNull()
    // the read never consults an act-as cookie
    expect(findUnique.mock.calls.map(c => c[0].where.id)).toEqual(['admin-1', 'admin-1'])
  })

  test('an admin cannot write another account', async () => {
    authCookie = await createToken('admin-1', 'admin')
    for (const target of ['victim', 'admin-2', 'managed']) {
      expect(await body(await requireUserAccess(req(), target, WRITE)), target)
        .toMatchObject({ status: 403, code: 'own_account_only' })
    }
  })

  test('an admin acting as a member cannot write the member', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'victim')
    expect(await body(await requireUserAccess(req(), 'victim', WRITE)))
      .toMatchObject({ status: 403, code: 'own_account_only' })
    // acting as an admin target changes nothing either
    actAsCookie = await createActAsToken('admin-1', 'admin-2')
    expect((await requireUserAccess(req(), 'admin-2', WRITE))?.status).toBe(403)
  })

  test('an admin acting as a passwordless managed account writes it', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-1', 'managed')
    expect(await requireUserAccess(req(), 'managed', WRITE)).toBeNull()
    // only the account it acts as: another account stays refused
    expect((await requireUserAccess(req(), 'victim', WRITE))?.status).toBe(403)
  })

  test('the managed exception needs the act-as cookie of THIS admin and an account that still exists', async () => {
    authCookie = await createToken('admin-1', 'admin')
    actAsCookie = await createActAsToken('admin-2', 'managed')
    expect((await requireUserAccess(req(), 'managed', WRITE))?.status).toBe(403)
    actAsCookie = await createActAsToken('admin-1', 'gone')
    expect((await requireUserAccess(req(), 'gone', WRITE))?.status).toBe(403)
  })

  test('a member holding an act-as cookie for a managed account cannot write it', async () => {
    authCookie = await createToken('attacker', 'standard')
    actAsCookie = await createActAsToken('attacker', 'managed')
    expect(await body(await requireUserAccess(req(), 'managed', WRITE))).toMatchObject({ status: 403, error: 'Forbidden' })
  })

  test('the internal key still writes', async () => {
    expect(await requireUserAccess(req({ 'x-internal-key': 'internal-key-xyz' }), 'victim', WRITE)).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('the account itself writes', async () => {
    authCookie = await createToken('victim', 'standard')
    expect(await requireUserAccess(req(), 'victim', WRITE)).toBeNull()
    authCookie = await createToken('admin-1', 'admin')
    expect(await requireUserAccess(req(), 'admin-1', WRITE)).toBeNull()
  })

  test('a write with no session is 401', async () => {
    expect((await requireUserAccess(req(), 'victim', WRITE))?.status).toBe(401)
  })

  test('requireAccountWrite never admits the internal key: it is session only', async () => {
    expect((await requireAccountWrite('victim'))?.status).toBe(401)
    authCookie = await createToken('victim', 'standard')
    expect(await requireAccountWrite('victim')).toBeNull()
  })

  test('the role comes from the database: a token claiming admin for a member writes nothing else', async () => {
    authCookie = await createToken('attacker', 'admin')
    actAsCookie = await createActAsToken('attacker', 'managed')
    expect((await requireUserAccess(req(), 'managed', WRITE))?.status).toBe(403)
  })
})

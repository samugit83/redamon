/**
 * The Edge middleware and device sessions (step 6.10). The middleware cannot read the database (T2),
 * so it never checks `sid`; but its idle refresh re-signs an admin's login token with `lat` moved,
 * and that token must keep naming the same device session, or the refresh would sign the browser out
 * at its next API call. Same claims, same expiry; a member's token is never re-signed.
 *
 * Run: npx vitest run --no-file-parallelism src/middleware.deviceSessions.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { SignJWT, decodeJwt } from 'jose'

vi.stubEnv('AUTH_SECRET', 'k'.repeat(64))

import { middleware } from './middleware'
import { setFlagsForTests } from './lib/authz/flags'
import { setNowForTests } from './lib/authz/clock'

const KEY = new TextEncoder().encode('k'.repeat(64))
const T0 = Math.floor(Date.now() / 1000)

const sign = (claims: Record<string, unknown>) => new SignJWT({ sub: 'a1', role: 'admin', sv: 2, ...claims })
  .setProtectedHeader({ alg: 'HS256' }).setIssuedAt(T0).setExpirationTime(T0 + 12 * 3600).sign(KEY)
const req = (cookie: string) => new NextRequest('http://localhost:3000/api/projects', { headers: { cookie: `redamon-auth=${cookie}` } })
const reissued = (res: Response) => {
  const header = res.headers.getSetCookie?.().find((c) => c.startsWith('redamon-auth=')) ?? null
  return header ? header.slice('redamon-auth='.length).split(';')[0] : null
}

beforeEach(() => setFlagsForTests({ identity: true, permissions: true, governance: true }))
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('sid kept on refresh', () => {
  test('an admin token refreshed for activity names the same device session, with the same expiry', async () => {
    setNowForTests(() => new Date((T0 + 120) * 1000))
    const res = await middleware(req(await sign({ adm: 1, idl: 60, lat: T0, sid: 'ckdevice01' })))
    const token = reissued(res)
    expect(token).not.toBeNull()
    const claims = decodeJwt(token!)
    expect(claims).toMatchObject({ sub: 'a1', role: 'admin', sv: 2, adm: 1, idl: 60, sid: 'ckdevice01', lat: T0 + 120, exp: T0 + 12 * 3600 })
  })

  test('a member token with a sid passes untouched (no idle claims, nothing re-signed)', async () => {
    setNowForTests(() => new Date((T0 + 120) * 1000))
    const res = await middleware(req(await sign({ role: 'standard', sid: 'ckdevice02' })))
    expect(res.status).toBe(200)
    expect(reissued(res)).toBeNull()
  })
})

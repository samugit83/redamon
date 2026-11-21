/**
 * Regression for GHSA-wgxp-vq94-73h8: "Authenticated users can read other users' tunnel
 * credentials".
 *
 * From 4.0.0 to 7.7.2 the handler of GET /api/global/tunnel-config read the first user
 * row holding a tunnel credential and answered it in clear, with no check of its own. The
 * route is on the middleware's INTERNAL_ALLOWLIST, which looks like protection but only
 * says where a valid X-Internal-Key may go: a request without the key falls through to
 * the cookie check, so any signed-in account reached the handler and got the operator's
 * ngrok authtoken, chisel server URL and chisel user:pass.
 *
 * These tests replay the reporter's proof of concept through the real middleware and the
 * real handler, with real signed tokens and Prisma mocked: account A configured the
 * tunnel (synthetic values), unrelated member B asks the route with their own cookie. The
 * middleware still lets B through, which is why the handler's isInternalRequest check is
 * the control and must stay; B gets 404 and no row is read. The positive control proves
 * the fixture holds A's values for the one legitimate caller, the agent's chisel lookup
 * (agentic/utils.py), so each 404 is the gate and not an empty table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const INTERNAL_KEY = 'internal-key-ghsa-wgxp'
const SCANNER_KEY = 'scanner-key-ghsa-wgxp'
vi.stubEnv('AUTH_SECRET', 'g'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', INTERNAL_KEY)
vi.stubEnv('SCANNER_API_KEY', SCANNER_KEY)

// Synthetic values in the advisory's shape. Each carries MARK so one substring check
// catches any of them in an answer body.
const MARK = 'GHSA-WGXP-MARK'
const A_VALUES = {
  ngrokAuthtoken: `NGROK-TEST-${MARK}-a`,
  chiselServerUrl: `http://chisel-${MARK.toLowerCase()}-a.example.test:9090`,
  chiselAuth: `a:CHISEL-TEST-${MARK}-a`,
}
const INSTANCE_VALUES = {
  ngrokAuthtoken: `NGROK-TEST-${MARK}-instance`,
  chiselServerUrl: `http://chisel-${MARK.toLowerCase()}-instance.example.test:9090`,
  chiselAuth: `root:CHISEL-TEST-${MARK}-instance`,
}

interface SettingsRow {
  id: string
  userId: string
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
  tunnelsEnabled: boolean
  updatedAt: Date
}

let userRows: SettingsRow[] = []

/** The route's query over userRows: any credential set, then the first row (the PoC has one). */
const settingsFindFirst = vi.fn(async (args: { select: Record<string, true> }) => {
  const hit = userRows.find(r => r.ngrokAuthtoken !== '' || r.chiselServerUrl !== '')
  if (!hit) return null
  return Object.fromEntries(Object.keys(args.select).map(k => [k, hit[k as keyof SettingsRow]]))
})
const instanceFindUnique = vi.fn(async () => ({ id: 'singleton', tunnelsEnabled: true, ...INSTANCE_VALUES }))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findFirst: (a: Parameters<typeof settingsFindFirst>[0]) => settingsFindFirst(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
  },
}))

import { middleware } from '@/middleware'
import { GET } from './route'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'

const ROUTE_URL = 'http://localhost:3000/api/global/tunnel-config'

/**
 * The request the handler receives after the middleware passes one on: the original
 * headers, replaced by the set the middleware forwards when it rewrites them (Next.js
 * encodes that set as x-middleware-override-headers + x-middleware-request-<name>).
 */
function forwarded(original: NextRequest, mw: Response): NextRequest {
  const override = mw.headers.get('x-middleware-override-headers')
  if (!override) return original
  const headers = new Headers()
  for (const name of override.split(',')) {
    const value = mw.headers.get(`x-middleware-request-${name}`)
    if (value !== null) headers.set(name, value)
  }
  return new NextRequest(ROUTE_URL, { headers })
}

type Outcome = { stoppedBy: 'middleware' | 'handler'; res: Response; forwardedUser: string | null }

/** One browser or service request, through the middleware and then the handler. */
async function send(opts: { cookie?: string; headers?: Record<string, string> } = {}): Promise<Outcome> {
  const headers = new Headers(opts.headers ?? {})
  if (opts.cookie) headers.set('cookie', `redamon-auth=${opts.cookie}`)
  const req = new NextRequest(ROUTE_URL, { headers })
  const mw = await middleware(req)
  if (mw.headers.get('x-middleware-next') !== '1') {
    return { stoppedBy: 'middleware', res: mw, forwardedUser: null }
  }
  const forwardedUser = mw.headers.get('x-middleware-request-x-user-id')
  return { stoppedBy: 'handler', res: await GET(forwarded(req, mw)), forwardedUser }
}

const row = (id: string, userId: string, over: Partial<SettingsRow> = {}): SettingsRow => ({
  id, userId, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', tunnelsEnabled: false,
  updatedAt: new Date('2026-11-01T00:00:00Z'), ...over,
})

let warnSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  // Step 1 of the PoC: A saved tunnel values; B, a separate standard account, saved none.
  userRows = [row('settings-a', 'user-a', A_VALUES), row('settings-b', 'user-b')]
  settingsFindFirst.mockClear()
  instanceFindUnique.mockClear()
  // The middleware logs the scanner key's refused route; the tests assert outcomes instead.
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  warnSpy.mockRestore()
})

const SWITCH_STATES = [
  { identity: false, source: 'the user row', values: A_VALUES },
  { identity: true, source: 'the instance settings row', values: INSTANCE_VALUES },
] as const

describe.each(SWITCH_STATES)('GHSA-wgxp-vq94-73h8, identity switch $identity (credentials in $source)', ({ identity, values }) => {
  beforeEach(() => setFlagsForTests({ identity }))

  const expectNoRowRead = () => {
    expect(settingsFindFirst).not.toHaveBeenCalled()
    expect(instanceFindUnique).not.toHaveBeenCalled()
  }

  test("the PoC: member B's session reaches the handler, which answers 404 with none of the tunnel values", async () => {
    const out = await send({ cookie: await createToken('user-b', 'standard') })

    // The allowlist entry does not keep a session out: the handler is the control.
    expect(out.stoppedBy).toBe('handler')
    expect(out.forwardedUser).toBe('user-b')

    expect(out.res.status).toBe(404)
    const body = await out.res.text()
    expect(JSON.parse(body)).toEqual({ error: 'Not found' })
    expect(body).not.toContain(MARK)
    for (const v of Object.values(values)) expect(body).not.toContain(v)
    expectNoRowRead()
  })

  test("an admin's session is refused the same way: no browser ever needs the plaintext", async () => {
    const out = await send({ cookie: await createToken('admin-1', 'admin') })
    expect(out.stoppedBy).toBe('handler')
    expect(out.res.status).toBe(404)
    expect(await out.res.text()).not.toContain(MARK)
    expectNoRowRead()
  })

  test('B adding a wrong internal key, or the scan containers\' scanner key, still gets 404', async () => {
    const cookie = await createToken('user-b', 'standard')
    for (const key of ['not-the-internal-key', SCANNER_KEY]) {
      const out = await send({ cookie, headers: { 'x-internal-key': key } })
      expect(out.stoppedBy).toBe('handler')
      expect(out.res.status).toBe(404)
      expect(await out.res.text()).not.toContain(MARK)
    }
    expectNoRowRead()
  })

  test('the scanner key without a session is stopped by the middleware', async () => {
    const out = await send({ headers: { 'x-internal-key': SCANNER_KEY } })
    expect(out.stoppedBy).toBe('middleware')
    expect(out.res.status).toBe(401)
    expectNoRowRead()
  })

  test('no cookie and no key: 401 at the middleware, nothing read', async () => {
    const out = await send()
    expect(out.stoppedBy).toBe('middleware')
    expect(out.res.status).toBe(401)
    expectNoRowRead()
  })

  test("positive control: the agent's internal-key lookup still gets the values, and only the three fields", async () => {
    const out = await send({ headers: { 'x-internal-key': INTERNAL_KEY } })
    expect(out.stoppedBy).toBe('handler')
    expect(out.res.status).toBe(200)
    expect(await out.res.json()).toEqual(values)
  })
})

/**
 * Unit tests for the tunnel-config sync trigger route (STRIDE I19, F-23).
 *
 * Only the kali-sandbox may call it (F-23, ID-33, whatever the identity switch): it sends
 * `Authorization: Bearer <TUNNEL_AUTH_TOKEN>`, compared in constant time, and an unset
 * token refuses every call, as the tunnel manager it pushes to does. Accepted, on worker
 * boot it FORCES tunnels down (clears tunnelsEnabled, in the instance settings row too with
 * the identity switch on, and pushes an empty/stop config) so a restart never silently
 * re-exposes internal listeners to the internet. prisma + global fetch are mocked.
 *
 * Run: npx vitest run "src/app/api/global/tunnel-config/sync/route.test.ts"
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockUpdateMany = vi.fn()
const mockInstanceUpdateMany = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      updateMany: (...args: unknown[]) => mockUpdateMany(...args),
    },
    instanceSettings: {
      updateMany: (...args: unknown[]) => mockInstanceUpdateMany(...args),
    },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'
const TOKEN = 'fake-tunnel-token-0123456789'

const sync = (authorization?: string) => POST(new NextRequest('http://webapp:3000/api/global/tunnel-config/sync', {
  method: 'POST',
  headers: authorization ? { authorization } : {},
}))

let fetchSpy: ReturnType<typeof vi.fn>

beforeEach(() => {
  mockUpdateMany.mockReset().mockResolvedValue({ count: 0 })
  mockInstanceUpdateMany.mockReset().mockResolvedValue({ count: 0 })
  vi.stubEnv('TUNNEL_AUTH_TOKEN', TOKEN)
  fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
  vi.stubGlobal('fetch', fetchSpy)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST /api/global/tunnel-config/sync — only the sandbox (F-23)', () => {
  test.each([
    ['no bearer', undefined],
    ['a wrong bearer', `Bearer ${TOKEN.slice(0, -1)}x`],
    ['the token with another scheme', `Basic ${TOKEN}`],
    ['an empty bearer', 'Bearer '],
  ])('%s: 401, nothing written, nothing pushed', async (_name, header) => {
    const res = await sync(header)
    expect(res.status).toBe(401)
    expect(mockUpdateMany).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  test('unset token 401: every call refused, as the tunnel manager refuses its pushes', async () => {
    vi.stubEnv('TUNNEL_AUTH_TOKEN', '')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const header of [undefined, 'Bearer ', 'Bearer anything']) {
      expect((await sync(header)).status).toBe(401)
    }
    expect(mockUpdateMany).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledWith('[rbac] tunnel sync refused code=tunnel_token_unset: TUNNEL_AUTH_TOKEN is not set')
  })

  test('bearer accepted (any case of the scheme)', async () => {
    expect((await sync(`Bearer ${TOKEN}`)).status).toBe(200)
    expect((await sync(`bearer ${TOKEN}`)).status).toBe(200)
  })
})

describe('POST /api/global/tunnel-config/sync — I19', () => {
  test('forces tunnels down: clears tunnelsEnabled and pushes an EMPTY config', async () => {
    const res = await sync(`Bearer ${TOKEN}`)
    expect(await res.json()).toEqual({ ok: true, configured: false })

    // Disabled every enabled row.
    expect(mockUpdateMany).toHaveBeenCalledWith({
      where: { tunnelsEnabled: true },
      data: { tunnelsEnabled: false },
    })

    // Pushed a stop (empty) config — never re-activates on boot.
    const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(WORKER_URL)
    expect(JSON.parse(opts.body as string)).toEqual({
      ngrokAuthtoken: '',
      chiselServerUrl: '',
      chiselAuth: '',
    })
  })

  test('presents the TUNNEL_AUTH_TOKEN to the tunnel manager', async () => {
    await sync(`Bearer ${TOKEN}`)
    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect((opts.headers as Record<string, string>)['Authorization']).toBe(`Bearer ${TOKEN}`)
  })

  test('identity switch on: the instance settings row is turned off too; off, it is not touched', async () => {
    setFlagsForTests({ identity: true })
    await sync(`Bearer ${TOKEN}`)
    expect(mockInstanceUpdateMany).toHaveBeenCalledWith({
      where: { id: 'instance', tunnelsEnabled: true },
      data: { tunnelsEnabled: false },
    })
    setFlagsForTests({ identity: false })
    mockInstanceUpdateMany.mockClear()
    await sync(`Bearer ${TOKEN}`)
    expect(mockInstanceUpdateMany).not.toHaveBeenCalled()
  })

  test('worker push failure is swallowed: returns ok:false, HTTP 200', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    fetchSpy.mockRejectedValue(new Error('connect ECONNREFUSED'))

    const res = await sync(`Bearer ${TOKEN}`)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: false })
  })
})

describe('the sandbox\'s boot call (mcp/kali-sandbox/entrypoint.sh)', () => {
  const entrypoint = readFileSync(path.resolve(__dirname, '../../../../../../../mcp/kali-sandbox/entrypoint.sh'), 'utf8')
  const callLine = entrypoint.split('\n').find((l) => l.includes('/api/global/tunnel-config/sync'))!

  test('presents the tunnel bearer, through stdin so no command line shows it', () => {
    expect(callLine).toContain("printf 'Authorization: Bearer %s\\n' \"$TUNNEL_AUTH_TOKEN\" | curl")
    expect(callLine).toContain('-H @-')
    expect(entrypoint).not.toMatch(/curl[^\n]*Bearer \$\{?TUNNEL_AUTH_TOKEN/)
  })

  test('skips the call without a token: the webapp would refuse it, and no tunnel can be up', () => {
    expect(entrypoint).toMatch(/if \[ -z "\$\{TUNNEL_AUTH_TOKEN:-\}" \]; then/)
  })
})

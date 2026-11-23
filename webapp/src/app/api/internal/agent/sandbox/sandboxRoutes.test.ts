/**
 * The four internal routes the agent calls for a person's Kali sandbox (group 1, B.10, S13):
 * POST ensure, POST lease, POST release, GET list. The master key (isInternalRequest) is the only
 * way in: no key, a wrong key and the scanner key are 401 and reach nothing. Bodies are validated
 * against the contract before the gateway is asked. Errors keep the contract's codes, a memory
 * refusal its governor payload (B.6's `payload | {code}`), and the orchestrator out of reach is a 503.
 * The routes are on the middleware's internal-key allowlist, method and path exactly.
 *
 * Real routes, middleware, isInternalRequest and the gateway's answer mapping; the gateway's calls
 * are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/internal/agent/sandbox/sandboxRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
const SCANNER = 'scanner-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('SCANNER_API_KEY', SCANNER)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

const h = vi.hoisted(() => ({
  ensure: vi.fn(),
  lease: vi.fn(),
  release: vi.fn(),
  list: vi.fn(),
}))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/sandbox/gateway', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/gateway')>()),
  ensureSandbox: (...a: unknown[]) => h.ensure(...a),
  leaseSandbox: (...a: unknown[]) => h.lease(...a),
  releaseSandboxLease: (...a: unknown[]) => h.release(...a),
  agentSandboxList: (...a: unknown[]) => h.list(...a),
}))

import { POST as ensurePOST } from './ensure/route'
import { POST as leasePOST } from './lease/route'
import { POST as releasePOST } from './release/route'
import { GET as listGET } from './list/route'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'
import type { SandboxLimit } from '@/lib/sandbox/contract'

const TOKEN = 'per-instance-bearer-0123456789abcdef'
const INSTANCE = 'a1b2c3'
const LEASE = '0b9d7a52-5d0f-4b6f-9a39-6a1d2a0a7f10'
const RAM: SandboxLimit = {
  admitted: false, limitType: 'ram', resource: 'kali_sandbox', current: 1, ceiling: 2,
  settingName: null, detail: 'not enough memory',
}
const RUNNING = {
  user_id: 'bob', view: 'own', instance: INSTANCE, host: 'redamon-kali-x', token: TOKEN,
  tunnel_token: 'tun', ports: { network_recon: 8000 }, reverse_port: 4444, projects: ['PB'], state: 'running',
  fresh: false, stop_at: 1, stop_reason: null, warn: false,
}

type Handler = (req: NextRequest) => Promise<Response>
const ROUTES: Array<{ name: string; method: 'GET' | 'POST'; path: string; handler: Handler; body?: unknown }> = [
  { name: 'ensure', method: 'POST', path: '/api/internal/agent/sandbox/ensure', handler: ensurePOST, body: { userId: 'bob' } },
  { name: 'lease', method: 'POST', path: '/api/internal/agent/sandbox/lease', handler: leasePOST, body: { userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'run' } },
  { name: 'release', method: 'POST', path: '/api/internal/agent/sandbox/release', handler: releasePOST, body: { userId: 'bob', leaseId: LEASE } },
  { name: 'list', method: 'GET', path: '/api/internal/agent/sandbox/list', handler: listGET as Handler },
]

function req(method: string, p: string, body?: unknown, headers: Record<string, string> = { 'x-internal-key': KEY }): NextRequest {
  return new NextRequest(`http://localhost:3000${p}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
  })
}
const ensure = (body: unknown) => ensurePOST(req('POST', '/api/internal/agent/sandbox/ensure', body))
const lease = (body: unknown) => leasePOST(req('POST', '/api/internal/agent/sandbox/lease', body))
const release = (body: unknown) => releasePOST(req('POST', '/api/internal/agent/sandbox/release', body))
const answer = async (res: Response) => [res.status, res.status === 204 ? null : await res.json()] as const

beforeEach(() => {
  for (const f of Object.values(h)) f.mockReset()
  h.ensure.mockResolvedValue(RUNNING)
  h.lease.mockResolvedValue({ expires_at: 10, state: 'running', stop_at: 20, warn: false })
  h.release.mockResolvedValue(undefined)
  h.list.mockResolvedValue({ sandboxes: [] })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  vi.restoreAllMocks()
})

describe('the master key is the only way in', () => {
  test.each(ROUTES)('$name: no key, a wrong key and the scanner key are 401, and the gateway is never asked', async (route) => {
    const attempts: Record<string, string>[] = [{}, { 'x-internal-key': 'nope' }, { 'x-internal-key': SCANNER }, { 'x-internal-key': 'changeme' }]
    for (const headers of attempts) {
      const res = await route.handler(req(route.method, route.path, route.body, headers))
      expect([headers, res.status]).toEqual([headers, 401])
    }
    for (const f of Object.values(h)) expect(f).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('$name: on the internal-key allowlist with its method only, never on the scanner\'s', async (route) => {
    const { internalKeyRouteAllowed, scannerKeyRouteAllowed } = await import('@/middleware')
    expect(internalKeyRouteAllowed(route.method, route.path)).toBe(true)
    expect(internalKeyRouteAllowed(route.method === 'GET' ? 'POST' : 'GET', route.path)).toBe(false)
    expect(internalKeyRouteAllowed(route.method, `${route.path}/x`)).toBe(false)
    expect(internalKeyRouteAllowed(route.method, `${route.path}x`)).toBe(false)
    expect(scannerKeyRouteAllowed(route.method, route.path)).toBe(false)
  })

  test('with the allowlist enforced the middleware lets the agent through, and a near path not', async () => {
    vi.stubEnv('INTERNAL_KEY_ALLOWLIST_ENFORCE', 'true')
    vi.resetModules()
    const { middleware } = await import('@/middleware')
    const passed = await middleware(req('POST', '/api/internal/agent/sandbox/ensure', { userId: 'bob' }))
    expect(passed.headers.get('x-middleware-next')).toBe('1')
    const refused = await middleware(req('POST', '/api/internal/agent/sandbox/stop', { userId: 'bob' }))
    expect(refused.status).toBe(401)
    vi.unstubAllEnvs()
    vi.stubEnv('INTERNAL_API_KEY', KEY)
    vi.stubEnv('SCANNER_API_KEY', SCANNER)
    vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))
  })
})

describe('POST ensure', () => {
  test('a valid body is handed to ensureSandbox: the project id as a hint, wait and actingAs as given', async () => {
    expect(await answer(await ensure({ userId: 'bob' }))).toEqual([200, RUNNING])
    expect(h.ensure).toHaveBeenLastCalledWith('bob', { needProject: null, wait: true, actingAs: false })
    await ensure({ userId: 'bob', projectId: 'PC', wait: false, actingAs: true })
    expect(h.ensure).toHaveBeenLastCalledWith('bob', { needProject: 'PC', wait: false, actingAs: true })
    await ensure({ userId: 'bob', projectId: null })
    expect(h.ensure).toHaveBeenLastCalledWith('bob', { needProject: null, wait: true, actingAs: false })
  })

  test('a starting answer is a 202, a running one a 200', async () => {
    h.ensure.mockResolvedValueOnce({ state: 'starting', instance: INSTANCE, fresh: true })
    expect(await answer(await ensure({ userId: 'bob', wait: false }))).toEqual([202, { state: 'starting', instance: INSTANCE, fresh: true }])
    h.ensure.mockResolvedValueOnce(RUNNING)
    expect(await answer(await ensure({ userId: 'bob' }))).toEqual([200, RUNNING])
  })

  test('an invalid body is a 400 and reaches nothing', async () => {
    const bad: Array<[unknown, string]> = [
      ['not json', 'invalid_sandbox_request'],
      [[], 'invalid_sandbox_request'],
      [{}, 'invalid_user_id'],
      [{ userId: '../bob' }, 'invalid_user_id'],
      [{ userId: 'ensure' }, 'invalid_user_id'],
      [{ userId: 7 }, 'invalid_user_id'],
      [{ userId: 'x'.repeat(65) }, 'invalid_user_id'],
      [{ userId: 'bob', projectId: '..' }, 'invalid_project_id'],
      [{ userId: 'bob', projectId: '.staging' }, 'invalid_project_id'],
      [{ userId: 'bob', projectId: 5 }, 'invalid_project_id'],
      [{ userId: 'bob', wait: 'yes' }, 'invalid_sandbox_request'],
      [{ userId: 'bob', actingAs: 'true' }, 'invalid_sandbox_request'],
      [{ userId: 'bob', actingAs: 1 }, 'invalid_sandbox_request'],
    ]
    for (const [body, code] of bad) {
      const [status, json] = await answer(await ensure(body))
      expect([body, status, (json as { code: string }).code]).toEqual([body, 400, code])
    }
    expect(h.ensure).not.toHaveBeenCalled()
  })

  test('a refusal keeps its code; a memory refusal its governor payload, flat, as the orchestrator gives it', async () => {
    h.ensure.mockRejectedValueOnce(new SandboxError(403, 'sandbox_project_refused'))
    const [s1, refused] = await answer(await ensure({ userId: 'bob', projectId: 'PC' }))
    expect([s1, refused]).toEqual([403, { error: expect.any(String), code: 'sandbox_project_refused' }])
    h.ensure.mockRejectedValueOnce(new SandboxError(409, 'sandbox_ram', RAM))
    expect(await answer(await ensure({ userId: 'bob' }))).toEqual([409, { ...RAM, code: 'sandbox_ram' }])
    h.ensure.mockRejectedValueOnce(new SandboxError(504, 'sandbox_start_timeout'))
    expect((await answer(await ensure({ userId: 'bob' })))[0]).toBe(504)
  })

  test('the orchestrator unavailable is a 503 orchestrator_unavailable with no detail; any other failure a coded 500', async () => {
    h.ensure.mockRejectedValueOnce(new SandboxError(503, 'orchestrator_unavailable'))
    expect(await answer(await ensure({ userId: 'bob' }))).toEqual([503, { error: expect.any(String), code: 'orchestrator_unavailable' }])
    h.ensure.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    expect(await answer(await ensure({ userId: 'bob' }))).toEqual([500, { error: expect.any(String), code: 'P1001' }])
  })

  test('a lease or list call that cannot reach the orchestrator is a 503 orchestrator_unreachable', async () => {
    const cause = Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } })
    h.lease.mockRejectedValueOnce(new OrchestratorUnreachable(cause))
    const [status, json] = await answer(await lease({ userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'run' }))
    expect(status).toBe(503)
    expect(json).toMatchObject({ code: 'orchestrator_unreachable' })
  })

  test('nothing the route logs holds a token or the answer', async () => {
    await ensure({ userId: 'bob' })
    h.ensure.mockRejectedValueOnce(new SandboxError(409, 'sandbox_ram', RAM))
    await ensure({ userId: 'bob' })
    const logged = JSON.stringify([vi.mocked(console.warn).mock.calls, vi.mocked(console.error).mock.calls, vi.mocked(console.info).mock.calls])
    expect(logged).not.toContain(TOKEN)
  })
})

describe('POST lease', () => {
  test('a valid body takes or renews the lease', async () => {
    expect(await answer(await lease({ userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'hold' })))
      .toEqual([200, { expires_at: 10, state: 'running', stop_at: 20, warn: false }])
    expect(h.lease).toHaveBeenCalledWith('bob', { instance: INSTANCE, leaseId: LEASE, kind: 'hold' })
  })

  test('the instance is 6 hex, the lease id a UUID, the kind one of the contract\'s', async () => {
    const ok = { userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'run' }
    for (const body of [
      { ...ok, userId: 'stop-all' },
      { ...ok, instance: 'shared' },
      { ...ok, instance: 'A1B2C3' },
      { ...ok, instance: 'a1b2c3d' },
      { ...ok, leaseId: 'not-a-uuid' },
      { ...ok, leaseId: `${LEASE}\n` },
      { ...ok, kind: 'root' },
      { ...ok, kind: undefined },
    ]) {
      expect([body, (await lease(body)).status]).toEqual([body, 400])
    }
    expect(h.lease).not.toHaveBeenCalled()
  })

  test('the gateway\'s refusals keep their codes', async () => {
    h.lease.mockRejectedValueOnce(new SandboxError(409, 'sandbox_draining'))
    expect(await answer(await lease({ userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'run' })))
      .toEqual([409, { error: expect.any(String), code: 'sandbox_draining' }])
    h.lease.mockRejectedValueOnce(new SandboxError(403, 'sandbox_user_refused'))
    expect((await lease({ userId: 'bob', instance: INSTANCE, leaseId: LEASE, kind: 'run' })).status).toBe(403)
  })
})

describe('POST release and GET list', () => {
  test('a release is a 204', async () => {
    expect(await answer(await release({ userId: 'bob', leaseId: LEASE }))).toEqual([204, null])
    expect(h.release).toHaveBeenCalledWith('bob', LEASE)
    for (const body of [{ userId: 'bob' }, { userId: '../bob', leaseId: LEASE }, { userId: 'bob', leaseId: 'x' }]) {
      expect((await release(body)).status).toBe(400)
    }
    expect(h.release).toHaveBeenCalledTimes(1)
  })

  test('the list answers what the gateway gives the agent', async () => {
    const list = { sandboxes: [{ user_id: 'bob', view: 'own', instance: INSTANCE, host: 'h', token: TOKEN, state: 'running' }] }
    h.list.mockResolvedValueOnce(list)
    expect(await answer(await listGET(req('GET', '/api/internal/agent/sandbox/list')))).toEqual([200, list])
  })
})

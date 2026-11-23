/**
 * PUT /api/users/[id]/settings: a save that is stored but not applied.
 *
 * Two follow-up calls ride a settings save: the orchestrator's capture-proxy
 * start/stop (TrafficMind) and the tunnel push to the person's own Kali sandbox
 * (through the agent, group 1). Both used to be
 * awaited without reading the answer, so a proxy that never started or a tunnel
 * the sandbox refused read as "Settings saved". The save still answers 200 (the
 * row is written) and lists each failed follow-up in `warnings` with a code and
 * a status, never the service's own text (the orchestrator answers with
 * `str(exc)`). A non-admin's capture fields, which the route drops, are named in
 * `ignoredFields` so the TrafficMind modal cannot report them as applied.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
const sandbox = vi.hoisted(() => ({ ensureSandbox: vi.fn(), sandboxStatus: vi.fn(), agentFetch: vi.fn() }))
vi.mock('@/lib/sandbox/gateway', () => ({
  ensureSandbox: (...a: unknown[]) => sandbox.ensureSandbox(...a),
  sandboxStatus: (...a: unknown[]) => sandbox.sandboxStatus(...a),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig() as Record<string, unknown>),
  agentFetch: (...a: unknown[]) => sandbox.agentFetch(...a),
}))

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()
const mockOrchestratorFetch = vi.fn()
const mockGetSession = vi.fn()
const fetchMock = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
      updateMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
    apiKeyRotationConfig: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn(),
      update: vi.fn(),
      deleteMany: vi.fn(),
      upsert: vi.fn(),
    },
    // The tunnel gate reads the account getSession answered (sharedToolAccess, step 3.9).
    user: { findUnique: async ({ where }: { where: { id: string } }) => { const s = await mockGetSession(); return s && s.userId === where.id ? { id: s.userId, email: `${s.userId}@e2e.local`, role: s.role, password: 'x', createdAt: new Date(0), legacyGrants: [] } : null } },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: vi.fn().mockResolvedValue(null),
  isInternalRequest: vi.fn().mockReturnValue(false),
  isScannerRequest: vi.fn().mockReturnValue(false),
  getSession: (...a: unknown[]) => mockGetSession(...a),
  authzIdentityOf: vi.fn(async (s: unknown) => ({ session: s, principal: {}, actingAs: null })),
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a),
}))

import { GET, PUT } from './route'
import { AgentUnreachableError } from '@/lib/agentFetch'

const EXISTING = {
  userId: 'u1', captureProxyEnabled: false, captureProxyPort: 8888, captureProxyRedactSecrets: true,
  tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '',
}

function put(body: Record<string, unknown>): Promise<Response> {
  const req = new NextRequest('http://x/api/users/u1/settings', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return PUT(req, { params: Promise.resolve({ id: 'u1' }) })
}

function refused(code: string): TypeError {
  const err = new TypeError('fetch failed')
  ;(err as TypeError & { cause?: unknown }).cause = Object.assign(new Error(`connect ${code}`), { code })
  return err
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  mockGetSession.mockResolvedValue({ userId: 'u1', role: 'admin' })
  let row: Record<string, unknown> = { ...EXISTING }
  mockFindUnique.mockImplementation(async () => ({ ...row }))
  mockUpsert.mockImplementation(({ update }: { update: Record<string, unknown> }) => {
    row = { ...row, ...update }
    return Promise.resolve({ ...row })
  })
  sandbox.ensureSandbox.mockResolvedValue({ state: 'running', fresh: false, instance: 'a1b2c3' })
  sandbox.sandboxStatus.mockResolvedValue({ instances: [{ instance: 'a1b2c3', view: 'own', state: 'running' }] })
  sandbox.agentFetch.mockImplementation(async () => new Response('{}', { status: 200 }))
  mockOrchestratorFetch.mockImplementation(async () => new Response('{}', { status: 200 }))
  fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('settings PUT: follow-up failures become warnings', () => {
  test('every follow-up applied: a plain 200 with no warnings', async () => {
    const res = await put({ captureProxyEnabled: true, tunnelsEnabled: true, ngrokAuthtoken: 'tok' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.warnings).toBeUndefined()
    expect(body.ignoredFields).toBeUndefined()
  })

  test('the orchestrator refused to start the proxy: status and code, not its exception text', async () => {
    mockOrchestratorFetch.mockImplementation(async () =>
      new Response(JSON.stringify({ detail: 'port 8888 is already allocated by /run/secret' }), { status: 500 }))
    const res = await put({ captureProxyEnabled: true })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.warnings).toEqual([{
      service: 'orchestrator', message: 'The capture proxy was not started',
      code: 'orchestrator_error', upstreamStatus: 500,
    }])
    expect(JSON.stringify(body)).not.toContain('/run/secret')
    expect(body.captureProxyEnabled).toBe(true)
  })

  test('an orchestrator that never answered the stop: the errno', async () => {
    mockFindUnique.mockResolvedValue({ ...EXISTING, captureProxyEnabled: true })
    mockOrchestratorFetch.mockRejectedValue(refused('ECONNREFUSED'))
    const body = await (await put({ captureProxyEnabled: false })).json()
    expect(body.warnings).toEqual([{
      service: 'orchestrator', message: 'The capture proxy was not stopped',
      code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    }])
  })

  test('an orchestrator that timed out reads as a timeout', async () => {
    mockOrchestratorFetch.mockRejectedValue(new DOMException('The operation was aborted due to timeout', 'TimeoutError'))
    const body = await (await put({ captureProxyEnabled: true })).json()
    expect(body.warnings[0]).toMatchObject({ code: 'orchestrator_timeout' })
  })

  test('the agent refused the tunnel push to the person\'s sandbox: its status and code, never the configuration', async () => {
    sandbox.agentFetch.mockImplementation(async () => new Response(JSON.stringify({ error: 'unauthorized tok' }), { status: 401 }))
    const res = await put({ tunnelsEnabled: true, ngrokAuthtoken: 'tok' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.warnings).toEqual([{
      service: 'agent', message: 'The tunnel configuration was not applied',
      code: 'agent_401', upstreamStatus: 401,
    }])
    expect(JSON.stringify(body.warnings)).not.toContain('tok')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('both follow-ups failing are both listed', async () => {
    mockOrchestratorFetch.mockRejectedValue(refused('ECONNREFUSED'))
    sandbox.agentFetch.mockRejectedValue(new AgentUnreachableError(refused('ENOTFOUND')))
    const body = await (await put({ captureProxyEnabled: true, tunnelsEnabled: true })).json()
    expect(body.warnings.map((w: { code: string }) => w.code))
      .toEqual(['orchestrator_unreachable', 'agent_unreachable'])
  })
})

describe('settings PUT: a non-admin capture write', () => {
  test('the dropped capture fields are named, so the modal does not report them applied', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u1', role: 'standard' })
    const res = await put({ captureProxyPort: 9000, captureEgressBlockPrivate: false, shodanApiKey: 'k' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ignoredFields).toEqual(['captureProxyPort', 'captureEgressBlockPrivate'])
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('settings GET/PUT: a database failure answers its code', () => {
  test('GET', async () => {
    mockFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const res = await GET(new NextRequest('http://x/api/users/u1/settings'), { params: Promise.resolve({ id: 'u1' }) })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to fetch user settings', code: 'P1001' })
  })

  test('PUT', async () => {
    mockUpsert.mockRejectedValue(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' }))
    const res = await put({ shodanApiKey: 'k' })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to update user settings', code: 'P2024' })
  })
})

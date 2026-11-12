/**
 * The twenty routes the middleware's login check was all that guarded (HD-10,
 * 01_current_state.md §1.2). The middleware admits any validly signed cookie, so a
 * deleted account kept them until its 7-day cookie expired: each now reads the
 * account first and answers 401 without one, before it calls a service or touches
 * a file. One of them, /api/global/tunnel-config, has since become internal-key only
 * (HD-05, step 1.10): it answers 404 to every session and is checked separately below.
 * Real tokens are signed; the cookie store, Prisma and fetch are mocked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest } from 'next/server'
import { ROUTE_MANIFEST } from '@/lib/authz/routeManifest'

vi.hoisted(() => {
  // Read at import time by the templates route; a path that never exists.
  process.env.NUCLEI_TEMPLATES_PATH = '/nonexistent/rbac-login-only-templates'
})
vi.stubEnv('AUTH_SECRET', 'l'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-login-only')

let authCookie: string | undefined
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && authCookie ? { value: authCookie } : undefined),
  })),
}))

const dbRoles = new Map<string, string>()
const userFindUnique = vi.fn(async (args: { where: { id: string } }) => {
  const role = dbRoles.get(args.where.id)
  return role ? { id: args.where.id, email: `${args.where.id}@e2e.local`, role, password: 'h', createdAt: new Date(0) } : null
})
const settingsFindFirst = vi.fn(async () => ({ ngrokAuthtoken: 'fake-ngrok', chiselServerUrl: '', chiselAuth: '' }))
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    userSettings: { findFirst: () => settingsFindFirst() },
  },
}))

const fetchSpy = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }))
vi.stubGlobal('fetch', fetchSpy)

import { createToken } from '@/lib/auth'

type Handler = (req: NextRequest, ctx: { params: Promise<{ id: string }> }) => Promise<Response>
interface Case { path: string; load: () => Promise<Record<string, unknown>> }

const ROUTES: Case[] = [
  { path: '/api/agent/emergency-stop-all', load: () => import('./agent/emergency-stop-all/route') },
  { path: '/api/agent/health', load: () => import('./agent/health/route') },
  { path: '/api/agent/host-ip', load: () => import('./agent/host-ip/route') },
  { path: '/api/agent/jobs/[id]/kill', load: () => import('./agent/jobs/[id]/kill/route') },
  { path: '/api/agent/sessions', load: () => import('./agent/sessions/route') },
  { path: '/api/agent/sessions/[id]/interact', load: () => import('./agent/sessions/[id]/interact/route') },
  { path: '/api/agent/sessions/[id]/kill', load: () => import('./agent/sessions/[id]/kill/route') },
  { path: '/api/agent/tunnel-status', load: () => import('./agent/tunnel-status/route') },
  { path: '/api/community-skills', load: () => import('./community-skills/route') },
  { path: '/api/cypherfix/health', load: () => import('./cypherfix/health/route') },
  { path: '/api/gvm/available', load: () => import('./gvm/available/route') },
  { path: '/api/js-recon/trufflehog/available', load: () => import('./js-recon/trufflehog/available/route') },
  { path: '/api/mcp/manifest', load: () => import('./mcp/manifest/route') },
  { path: '/api/mcp/reload', load: () => import('./mcp/reload/route') },
  { path: '/api/nuclei-templates', load: () => import('./nuclei-templates/route') },
  { path: '/api/projects/defaults', load: () => import('./projects/defaults/route') },
  { path: '/api/skills', load: () => import('./skills/route') },
  { path: '/api/system/stats', load: () => import('./system/stats/route') },
  { path: '/api/ws', load: () => import('./ws/route') },
]
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const

function request(method: string, path: string, headers: Record<string, string> = {}): NextRequest {
  const url = `http://localhost:3000${path.replace('[id]', 'rbac-x')}`
  const init: { method: string; headers: Record<string, string>; body?: string } = { method, headers }
  if (method !== 'GET' && method !== 'DELETE') {
    init.body = '{"command":"id"}'
    init.headers = { 'content-type': 'application/json', ...headers }
  }
  return new NextRequest(url, init)
}

/** Every exported handler of every route, called as `who` would call it. */
async function callAll(headers: Record<string, string> = {}): Promise<{ label: string; status: number }[]> {
  const out: { label: string; status: number }[] = []
  for (const r of ROUTES) {
    const mod = await r.load()
    for (const m of METHODS) {
      const handler = mod[m] as Handler | undefined
      if (!handler) continue
      const res = await handler(request(m, r.path, headers), { params: Promise.resolve({ id: 'rbac-x' }) })
      out.push({ label: `${m} ${r.path}`, status: res.status })
    }
  }
  return out
}

const quiet = { error: vi.spyOn(console, 'error'), warn: vi.spyOn(console, 'warn') }

beforeEach(() => {
  authCookie = undefined
  dbRoles.clear()
  userFindUnique.mockClear()
  settingsFindFirst.mockClear()
  fetchSpy.mockClear()
  quiet.error.mockImplementation(() => {})
  quiet.warn.mockImplementation(() => {})
})
afterAll(() => {
  quiet.error.mockRestore()
  quiet.warn.mockRestore()
  vi.unstubAllGlobals()
})

describe('the former login-only routes read the account first', () => {
  test('the list is the twenty routes the manifest recorded as login-only: nineteen session-guarded, one internal', () => {
    const paths = ROUTES.map(r => r.path)
    expect(paths).toHaveLength(19)
    const byPath = new Map(ROUTE_MANIFEST.map(e => [e.path, e.guard]))
    // The MCP reload reads the account through a stronger guard since step 1.9 (HD-03, HD-15); the
    // MCP manifest asks self:mcp_servers through requirePermission, a session guard (step 3.9).
    const stronger: Record<string, string> = { '/api/mcp/reload': 'admin-jwt' }
    expect(paths.filter(p => byPath.get(p) !== (stronger[p] ?? 'session'))).toEqual([])
    expect(byPath.get('/api/global/tunnel-config')).toBe('internal')
  })

  test("each of the 19 session-guarded former login-only routes answers 401 for a deleted user's valid token", async () => {
    authCookie = await createToken('deleted-user', 'admin')
    const results = await callAll()
    expect(results.length).toBeGreaterThanOrEqual(21)
    expect(results.filter(r => r.status !== 401)).toEqual([])
    // Refused before any service call, file or settings read.
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('each answers 401 without a cookie', async () => {
    const results = await callAll()
    expect(results.filter(r => r.status !== 401)).toEqual([])
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test('a signed-in account still reaches every one of them', async () => {
    dbRoles.set('member', 'standard')
    authCookie = await createToken('member', 'standard')
    const results = await callAll()
    expect(results.filter(r => r.status === 401)).toEqual([])
  })

  test('the tunnel config still answers the internal key without a cookie (the agent chisel lookup)', async () => {
    const { GET } = await import('./global/tunnel-config/route')
    const res = await GET(request('GET', '/api/global/tunnel-config', { 'x-internal-key': 'internal-key-login-only' }))
    expect(res.status).toBe(200)
    expect(settingsFindFirst).toHaveBeenCalledTimes(1)
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('a wrong internal key on the tunnel config is refused (404, HD-05)', async () => {
    const { GET } = await import('./global/tunnel-config/route')
    const res = await GET(request('GET', '/api/global/tunnel-config', { 'x-internal-key': 'wrong' }))
    expect(res.status).toBe(404)
    expect(settingsFindFirst).not.toHaveBeenCalled()
  })

  test("the tunnel config answers a deleted user's token, and a live member's, with 404 and reads nothing", async () => {
    const { GET } = await import('./global/tunnel-config/route')
    authCookie = await createToken('deleted-user', 'admin')
    expect((await GET(request('GET', '/api/global/tunnel-config'))).status).toBe(404)
    dbRoles.set('member', 'standard')
    authCookie = await createToken('member', 'standard')
    expect((await GET(request('GET', '/api/global/tunnel-config'))).status).toBe(404)
    expect(settingsFindFirst).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })
})

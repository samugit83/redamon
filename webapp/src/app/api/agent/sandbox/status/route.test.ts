/**
 * GET /api/agent/sandbox/status (group 1, B.10, WI-S16-3; OQ-G1-9 default A): when the signed-in
 * person's own Kali sandbox stops and whether it warns, for the Sessions panel's banner.
 *
 * The person is the session's effective user, never a value of the request; the answer lists only
 * the view that person works in (`own`, or `act_as` for an admin acting as a member) and only
 * `state`, `stop_at`, `stop_reason` and `warn`: no token, host, instance, project hash or lease. A
 * failure is its code, never the orchestrator's text. agent:sessions is asked first (the family test
 * sessions.permissions.test.ts runs the real guard); the manifest names it.
 *
 * The guard and the orchestrator call (`sandboxStatus`) are doubles; the route and the failure
 * mapping (`sandboxFailureResponse`) are real.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({ guard: vi.fn(), status: vi.fn() }))
vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))
vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: (...a: unknown[]) => h.guard(...a),
}))
vi.mock('@/lib/sandbox/gateway', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/gateway')>()),
  sandboxStatus: (...a: unknown[]) => h.status(...a),
}))

import { GET } from './route'
import { forbiddenResponse } from '@/lib/authz/guards'
import { ROUTE_MANIFEST } from '@/lib/authz/routeManifest'
import { SESSION_ROUTE_STATUS } from '@/lib/sandbox/contract'
import { OrchestratorUnreachable, SandboxError } from '@/lib/sandbox/orchestratorClient'

function as(person: string, actingAsAdmin?: string) {
  const real = actingAsAdmin ?? person
  return {
    session: { userId: real, role: actingAsAdmin ? 'admin' : 'standard' },
    principal: { id: real },
    actingAs: actingAsAdmin ? { id: person } : null,
    effective: { userId: person },
    permission: 'agent:sessions',
    access: null,
  }
}

const instance = (over: Record<string, unknown>) => ({
  instance: 'aaaaa1', view: 'own', state: 'running', projects_hash: '0123456789abcdef', created_at: 1_790_000_000,
  last_used: 1_790_000_100, lease_kinds: ['hold'], stop_at: 1_790_028_900, stop_reason: null, warn: true, reverse_port: 4444, ...over,
})

const read = (query = '') => GET(new NextRequest(`http://x${SESSION_ROUTE_STATUS}${query}`))

beforeEach(() => {
  h.guard.mockReset().mockResolvedValue(as('alice'))
  h.status.mockReset().mockResolvedValue({
    instances: [instance({}), instance({ instance: 'aaaaa2', view: 'act_as', warn: false, stop_at: 1_790_001_300 })],
  })
})

describe('the person and the view come from the session', () => {
  test("the signed-in person's own view: state, stop time, reason and warning, nothing else", async () => {
    const res = await read()
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({
      instances: [{ state: 'running', stop_at: 1_790_028_900, stop_reason: null, warn: true }],
    })
    expect(h.status).toHaveBeenCalledWith('alice')
    expect(h.guard.mock.calls[0].slice(1)).toEqual(['agent:sessions'])
  })

  test('a person named in the request is ignored: never another person\'s sandbox', async () => {
    await read('?userId=bob&user_id=bob&sandbox=bbbbb1&view=act_as')
    expect(h.status).toHaveBeenCalledTimes(1)
    expect(h.status).toHaveBeenCalledWith('alice')
  })

  test('no token, host, instance, project hash, lease or port reaches the browser', async () => {
    h.status.mockResolvedValue({ instances: [{ ...instance({}), token: 'tok-secret', host: 'redamon-kali-x' }] })
    const text = await (await read()).text()
    for (const leak of ['tok-secret', 'redamon-kali', 'aaaaa1', '0123456789abcdef', 'hold', '4444', 'created_at', 'last_used']) {
      expect(text).not.toContain(leak)
    }
  })

  test("an admin acting as a member sees that member's act_as sandbox, the one the admin works in, and not the member's own", async () => {
    h.guard.mockResolvedValue(as('member-m', 'admin-x'))
    const body = await (await read()).json()
    expect(h.status).toHaveBeenCalledWith('member-m')
    expect(body.instances).toEqual([{ state: 'running', stop_at: 1_790_001_300, stop_reason: null, warn: false }])
  })

  test('no sandbox running: no instance, and no mode is named', async () => {
    h.status.mockResolvedValue({ mode: 'per_user', instances: [] })
    expect(await (await read()).json()).toEqual({ instances: [] })
  })
})

describe('refusals and failures', () => {
  test('without agent:sessions: the 403 naming it, the orchestrator not asked', async () => {
    h.guard.mockResolvedValue(forbiddenResponse('agent:sessions'))
    const res = await read()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'agent:sessions' })
    expect(h.status).not.toHaveBeenCalled()
  })

  test('signed out: 401', async () => {
    h.guard.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await read()).status).toBe(401)
    expect(h.status).not.toHaveBeenCalled()
  })

  test('the orchestrator out of reach: its code and status, never its text', async () => {
    h.status.mockRejectedValue(new OrchestratorUnreachable(Object.assign(new Error('connect ECONNREFUSED 10.9.9.9:8010'), { code: 'ECONNREFUSED' })))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await read()
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.code).toBe('orchestrator_unreachable')
    expect(JSON.stringify(body)).not.toContain('10.9.9.9')
  })

  test('an answer outside the contract: 502 orchestrator_error', async () => {
    h.status.mockRejectedValue(new SandboxError(502, 'orchestrator_error'))
    const res = await read()
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ code: 'orchestrator_error' })
  })
})

describe('the manifest', () => {
  test('the route is the contract path, a session guard asking agent:sessions for GET only', () => {
    expect(SESSION_ROUTE_STATUS).toBe('/api/agent/sandbox/status')
    const entry = ROUTE_MANIFEST.find(e => e.path === SESSION_ROUTE_STATUS)
    expect(entry).toMatchObject({ guard: 'session', methods: ['GET'], permission: 'agent:sessions' })
  })
})

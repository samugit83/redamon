/**
 * GET /api/agent/tunnel-status, the read-only tunnel indicator (group 1, S17, WI-S17-6).
 *
 * Each person has their own tunnel in their own sandbox, so the route asks the agent for the
 * signed-in person with the master key (agentFetch sends it), and nobody ever sees another person's
 * tunnel host. Under act-as it shows no tunnel: the acting admin's Kali work runs in the member's
 * `act_as` sandbox, which never runs one, and the member's own tunnel is not the admin's to see. The
 * guard stays the login check it was; an agent that cannot say reads as "no tunnel".
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/agent/tunnel-status/route.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  session: vi.fn(),
  identity: vi.fn(),
  agentFetch: vi.fn(),
}))

// getEffectiveUser (the acted-as member under act-as) and an orchestrator that names
// per-user mode are what a build that showed the member's tunnel to the acting admin read: the
// act-as test fails on it, not only on a missing mock.
const effectiveUser = async () => {
  const id = await h.identity()
  return id ? { userId: id.actingAs?.id ?? id.session.userId } : null
}
vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => h.session(...a),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  getEffectiveUser: () => effectiveUser(),
}))
vi.mock('@/lib/sandbox/gateway', async (orig) => ({
  ...(await orig() as Record<string, unknown>),
  sandboxMode: async () => 'per_user',
}))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agentFetch(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { instanceSettings: { updateMany: vi.fn() } } }))

import { GET } from './route'
import { resetTunnelEffectsForTests } from '@/lib/sharedSettingsEffects'

const INACTIVE = { ngrok: { active: false }, chisel: { active: false } }

beforeEach(() => {
  for (const fn of Object.values(h)) fn.mockReset()
  resetTunnelEffectsForTests()
  h.session.mockResolvedValue({ userId: 'member-1', role: 'standard' })
  h.identity.mockResolvedValue({ session: { userId: 'member-1' }, principal: { id: 'member-1' }, actingAs: null })
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: true, host: '0.tcp.ngrok.io', port: 12345 }, chisel: { active: false } })))
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('the tunnel indicator', () => {
  test('the agent is asked for the signed-in person, with the master key', async () => {
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ngrok: { active: true, host: '0.tcp.ngrok.io' } })
    expect(h.agentFetch).toHaveBeenCalledTimes(1)
    expect(h.agentFetch.mock.calls[0][0]).toBe('/tunnel-status?user_id=member-1')
  })

  test('the person id is encoded', async () => {
    h.identity.mockResolvedValue({ session: { userId: 'a b&c' }, principal: { id: 'a b&c' }, actingAs: null })
    await GET()
    expect(h.agentFetch.mock.calls[0][0]).toBe('/tunnel-status?user_id=a%20b%26c')
  })

  test('act-as: inactive, and the agent is not asked (never the member\'s own tunnel to the acting admin)', async () => {
    h.session.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    h.identity.mockResolvedValue({ session: { userId: 'admin-1' }, principal: { id: 'admin-1' }, actingAs: { id: 'member-1' } })
    expect(await (await GET()).json()).toEqual(INACTIVE)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('nobody asks the orchestrator for a mode, and nothing is sent to a fixed Kali address', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    await GET()
    expect(fetchSpy).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  test.each([
    ['the agent answers an error', async () => { h.agentFetch.mockResolvedValue(new Response('{}', { status: 502 })) }],
    ['the agent is out of reach', async () => { h.agentFetch.mockRejectedValue(new Error('down')) }],
    ['no session identity', async () => { h.identity.mockResolvedValue(null) }],
  ])('%s: inactive, never an error', async (_name, arrange) => {
    await arrange()
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(INACTIVE)
  })

  test('the guard stays the login check: no session, no agent call', async () => {
    h.session.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await GET()).status).toBe(401)
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.identity).not.toHaveBeenCalled()
  })
})

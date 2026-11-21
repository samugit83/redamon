/**
 * GET /api/agent/tunnel-status, the read-only tunnel indicator (group 1, S17, WI-S17-6).
 *
 * Shared mode is unchanged: the agent's /tunnel-status, the one instance tunnel. In per-user mode
 * each person has their own tunnel in their own sandbox, so the route asks the agent for the
 * signed-in EFFECTIVE person (the member under act-as) with the master key (agentFetch sends it),
 * and nobody ever sees another person's tunnel host. The guard stays the login check it was; an
 * agent that cannot say reads as "no tunnel".
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/agent/tunnel-status/route.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  session: vi.fn(),
  effective: vi.fn(),
  sandboxMode: vi.fn(),
  agentFetch: vi.fn(),
}))

vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => h.session(...a),
  getEffectiveUser: (...a: unknown[]) => h.effective(...a),
}))
vi.mock('@/lib/sandbox/gateway', () => ({ sandboxMode: (...a: unknown[]) => h.sandboxMode(...a) }))
vi.mock('@/lib/agentFetch', () => ({ agentFetch: (...a: unknown[]) => h.agentFetch(...a) }))
vi.mock('@/lib/prisma', () => ({ default: { instanceSettings: { updateMany: vi.fn() } } }))

import { GET } from './route'
import { resetTunnelEffectsForTests } from '@/lib/sharedSettingsEffects'

const INACTIVE = { ngrok: { active: false }, chisel: { active: false } }

beforeEach(() => {
  for (const fn of Object.values(h)) fn.mockReset()
  resetTunnelEffectsForTests()
  h.session.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
  h.effective.mockResolvedValue({ userId: 'member-1' })
  h.sandboxMode.mockResolvedValue('per_user')
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ngrok: { active: true, host: '0.tcp.ngrok.io', port: 12345 }, chisel: { active: false } })))
  // The flip push to the shared container on the first per_user answer.
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 200 })))
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('the tunnel indicator', () => {
  test('per-user mode: the agent is asked for the signed-in effective person, with the master key', async () => {
    const res = await GET()
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ngrok: { active: true, host: '0.tcp.ngrok.io' } })
    expect(h.agentFetch).toHaveBeenCalledTimes(1)
    expect(h.agentFetch.mock.calls[0][0]).toBe('/tunnel-status?user_id=member-1')
  })

  test('per-user mode: the person id is encoded', async () => {
    h.effective.mockResolvedValue({ userId: 'a b&c' })
    await GET()
    expect(h.agentFetch.mock.calls[0][0]).toBe('/tunnel-status?user_id=a%20b%26c')
  })

  test('a mode nobody named: inactive, and the agent is not asked (review F1)', async () => {
    h.sandboxMode.mockRejectedValue(new Error('orchestrator unreachable'))
    expect(await (await GET()).json()).toEqual(INACTIVE)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('shared mode: unchanged, the one instance tunnel', async () => {
    h.sandboxMode.mockResolvedValue('shared')
    await GET()
    expect(h.agentFetch.mock.calls[0][0]).toBe('/tunnel-status')
  })

  test.each([
    ['the agent answers an error', async () => { h.agentFetch.mockResolvedValue(new Response('{}', { status: 502 })) }],
    ['the agent is out of reach', async () => { h.agentFetch.mockRejectedValue(new Error('down')) }],
    ['no effective person', async () => { h.effective.mockResolvedValue(null) }],
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
    expect(h.sandboxMode).not.toHaveBeenCalled()
  })
})

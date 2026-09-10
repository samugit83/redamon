/**
 * BOLA + fail-closed coverage for the five /api/triage/* routes.
 *
 * Mute is the sharpest authorization surface in the feature: it does not just
 * expose data, it CHANGES WHAT THE AGENT CAN SEE for a whole project. Someone
 * who could mute across tenants could blind another user's agent to a real
 * finding, so these routes are held to a stricter rule than the rest of the app.
 *
 * Two properties are pinned here:
 *
 *  1. A caller who does not own the project gets 404 (never 403, which would
 *     confirm the project exists) and the agent is never called.
 *  2. The check does NOT honour `ACCESS_ENFORCE=0`. That log-only escape hatch
 *     exists so an ownership fix can be rolled out in observe mode, but a mute
 *     that "would have been blocked" still mutates the graph, so it must hard
 *     fail regardless of the flag. That is the regression this file exists for.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireEff = vi.fn()
const mockFindUnique = vi.fn()
const mockAgentFetch = vi.fn()

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
}))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (b: Record<string, string> = {}) => ({ ...b, 'x-internal-key': 'k' }),
}))

import { GET as getFindings } from './findings/route'
import { GET as getMuted } from './muted/route'
import { POST as postMute } from './mute/route'
import { POST as postUnmute } from './unmute/route'
import { POST as postVerdict } from './verdict/route'

const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

const OWNER = 'alice'
const ATTACKER = 'mallory'
const VICTIM_PROJECT = 'victim-project'

function getReq(path: string) {
  return new NextRequest(`http://x/api/triage/${path}?projectId=${VICTIM_PROJECT}`)
}
function postReq(body: unknown) {
  return new NextRequest('http://x/api/triage/mute', {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Every route, in the shape the BOLA assertions need. */
const ROUTES: { name: string; call: () => Promise<Response> }[] = [
  { name: 'GET findings', call: () => getFindings(getReq('findings')) },
  { name: 'GET muted', call: () => getMuted(getReq('muted')) },
  { name: 'POST mute', call: () => postMute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1' })) },
  { name: 'POST unmute', call: () => postUnmute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1' })) },
  {
    name: 'POST verdict',
    call: () =>
      postVerdict(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1', status: 'confirmed' })),
  },
]

const originalEnforce = process.env.ACCESS_ENFORCE

beforeEach(() => {
  vi.clearAllMocks()
  mockAgentFetch.mockResolvedValue(
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
  )
})

afterEach(() => {
  if (originalEnforce === undefined) delete process.env.ACCESS_ENFORCE
  else process.env.ACCESS_ENFORCE = originalEnforce
})

describe('a caller who does not own the project cannot reach the graph', () => {
  test.each(ROUTES)('EXPLOIT: $name with someone else\'s projectId -> 404', async ({ call }) => {
    mockRequireEff.mockResolvedValue({ userId: ATTACKER })
    mockFindUnique.mockResolvedValue({ id: VICTIM_PROJECT, userId: OWNER })

    const res = await call()

    expect(res.status).toBe(404)
    // 404 and not 403: a 403 would confirm the project id is real.
    await expect(res.json()).resolves.toEqual({ error: 'Not found' })
    // and nothing reached the graph
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('$name: a project that does not exist is also 404', async ({ call }) => {
    mockRequireEff.mockResolvedValue({ userId: ATTACKER })
    mockFindUnique.mockResolvedValue(null)

    const res = await call()

    expect(res.status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('$name: no session -> 401, project never looked up', async ({ call }) => {
    mockRequireEff.mockResolvedValue(UNAUTH)

    const res = await call()

    expect(res.status).toBe(401)
    expect(mockFindUnique).not.toHaveBeenCalled()
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})

describe('mute does not honour the ACCESS_ENFORCE log-only escape hatch', () => {
  // The rest of the app can be rolled out in observe mode. Mute cannot: a mute
  // that "would have been blocked" has still hidden a finding from the agent.
  test.each(['0', 'false'])('ACCESS_ENFORCE=%s still hard-blocks a cross-user mute', async flag => {
    process.env.ACCESS_ENFORCE = flag
    mockRequireEff.mockResolvedValue({ userId: ATTACKER })
    mockFindUnique.mockResolvedValue({ id: VICTIM_PROJECT, userId: OWNER })

    const res = await postMute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1' }))

    expect(res.status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('ACCESS_ENFORCE=0 also hard-blocks reading the muted table', async () => {
    process.env.ACCESS_ENFORCE = '0'
    mockRequireEff.mockResolvedValue({ userId: ATTACKER })
    mockFindUnique.mockResolvedValue({ id: VICTIM_PROJECT, userId: OWNER })

    const res = await getMuted(getReq('muted'))

    expect(res.status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})

describe('the owner is allowed, and the tenant is never body-supplied', () => {
  beforeEach(() => {
    mockRequireEff.mockResolvedValue({ userId: OWNER })
    mockFindUnique.mockResolvedValue({ id: VICTIM_PROJECT, userId: OWNER })
  })

  test('the owner can mute', async () => {
    const res = await postMute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1' }))
    expect(res.status).toBe(200)
    expect(mockAgentFetch).toHaveBeenCalledOnce()
  })

  test('the tenant sent to the agent comes from the PROJECT, not the request body', async () => {
    // A body claiming another user must not be able to redirect the write.
    await postMute(
      postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1', user_id: 'someone-else', project_id: 'other' }),
    )
    const sent = JSON.parse((mockAgentFetch.mock.calls[0][1] as RequestInit).body as string)
    expect(sent.user_id).toBe(OWNER)
    expect(sent.project_id).toBe(VICTIM_PROJECT)
  })

  test('the internal key is attached, so the agent endpoint is not open', async () => {
    await postMute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1' }))
    const headers = (mockAgentFetch.mock.calls[0][1] as RequestInit).headers as Record<string, string>
    expect(headers['x-internal-key']).toBe('k')
  })

  test('a missing nodeId is rejected before the agent is called', async () => {
    const res = await postMute(postReq({ projectId: VICTIM_PROJECT }))
    expect(res.status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a missing projectId is rejected before the project is looked up', async () => {
    const res = await postMute(postReq({ nodeId: 'v1' }))
    expect(res.status).toBe(400)
    expect(mockFindUnique).not.toHaveBeenCalled()
  })

  test('an unknown verdict status is rejected', async () => {
    const res = await postVerdict(
      postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1', status: 'delete_it' }),
    )
    expect(res.status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a long mute reason is truncated rather than passed through whole', async () => {
    await postMute(postReq({ projectId: VICTIM_PROJECT, nodeId: 'v1', reason: 'x'.repeat(5000) }))
    const sent = JSON.parse((mockAgentFetch.mock.calls[0][1] as RequestInit).body as string)
    expect(sent.reason).toHaveLength(500)
  })
})

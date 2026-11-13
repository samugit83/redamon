/**
 * P0-3: the NL -> Cypher proxy was a cross-tenant and LLM-spend hole.
 *
 * It forwarded `user_id` and `project_id` straight from the client body, added
 * no internal key and performed no ownership check. The agent endpoint behind
 * it spends the BODY-NAMED user's provider key, so any logged-in user could
 * generate Cypher against any project and bill any other user's key.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  eff: vi.fn(),
  access: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: (...a: unknown[]) => h.eff(...a),
  requireProjectAccess: (...a: unknown[]) => h.access(...a),
}))

import { NextResponse } from 'next/server'
import { POST } from './route'

const post = (body: unknown) =>
  POST({ json: async () => body } as never)

const agentCall = () => h.fetch.mock.calls[0]
const agentBody = () => JSON.parse(agentCall()[1].body)

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', h.fetch)
  vi.stubEnv('INTERNAL_API_KEY', 'master-key')
  h.eff.mockResolvedValue({ userId: 'owner' })
  h.access.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
  h.fetch.mockResolvedValue({ ok: true, json: async () => ({ cypher: 'MATCH (i:IP) RETURN i' }) })
})

describe('identity comes from the session, never the body', () => {
  test('a body-supplied user_id is overridden by the session identity', async () => {
    await post({ question: 'list ips', user_id: 'victim', project_id: 'p1' })
    expect(agentBody().user_id).toBe('owner')
  })

  test("the graph tenant and the key owner sent upstream are the project's owner; a body's tenant_user_id is ignored (step 4.6, NF-11)", async () => {
    await post({ question: 'q', project_id: 'p1', user_id: 'victim', tenant_user_id: 'victim' })
    expect(agentBody()).toMatchObject({ user_id: 'owner', tenant_user_id: 'owner', project_id: 'p1' })
  })

  test('the project id sent upstream is the one the access check resolved', async () => {
    h.access.mockResolvedValue({ project: { id: 'p1', userId: 'owner' } })
    await post({ question: 'q', project_id: 'p1' })
    expect(agentBody().project_id).toBe('p1')
  })

  test('an unauthenticated caller is rejected before the agent is called', async () => {
    h.eff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await post({ question: 'q', project_id: 'p1' })
    expect(res.status).toBe(401)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('ownership is enforced', () => {
  test("another user's projectId is refused and never reaches the agent", async () => {
    h.access.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await post({ question: 'q', project_id: 'someone-elses' })
    expect(res.status).toBe(404)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the ownership check runs against the session user', async () => {
    await post({ question: 'q', project_id: 'p1', user_id: 'victim' })
    expect(h.access).toHaveBeenCalledWith({ userId: 'owner' }, 'p1')
  })

  test('a missing project_id is refused, not forwarded as an empty tenant', async () => {
    h.access.mockResolvedValue(NextResponse.json({ error: 'projectId is required' }, { status: 400 }))
    const res = await post({ question: 'q' })
    expect(res.status).toBe(400)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('the agent call is authenticated', () => {
  test('the internal key is attached so the billed endpoint accepts it', async () => {
    await post({ question: 'q', project_id: 'p1' })
    expect(agentCall()[1].headers['x-internal-key']).toBe('master-key')
  })
})

describe('errors are normalised', () => {
  test('the agent error body is not passed through to the client', async () => {
    h.fetch.mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => 'Failed after 3 attempts: MATCH (x:Secret) ... anthropic 401',
    })
    const res = await post({ question: 'q', project_id: 'p1' })
    const json = await res.json()

    expect(res.status).toBe(422)
    expect(json.error).not.toMatch(/MATCH|anthropic|attempts/)
  })

  test('an unreachable agent gives a stable 503 agent_unreachable message', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:8080'))
    const res = await post({ question: 'q', project_id: 'p1' })
    const json = await res.json()

    expect(res.status).toBe(503)
    expect(json.code).toBe('agent_unreachable')
    expect(JSON.stringify(json)).not.toMatch(/10\.0\.0\.5/)
    expect(json.error).not.toMatch(/ECONNREFUSED|10\.0\.0\.5/)
  })

  test('the agent own sentence reaches the person, with its status (G-13)', async () => {
    h.fetch.mockResolvedValue(new Response(JSON.stringify({
      error: 'No LLM configured. Configure an AI model in project settings to use graph views.',
    }), { status: 400 }))
    const res = await post({ question: 'q', project_id: 'p1' })
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'No LLM configured. Configure an AI model in project settings to use graph views.',
      upstreamStatus: 400,
    })
  })

  test('the daily cap 429 detail is forwarded', async () => {
    h.fetch.mockResolvedValue(new Response(JSON.stringify({ detail: 'Daily LLM call cap exceeded' }), { status: 429 }))
    const res = await post({ question: 'q', project_id: 'p1' })
    expect(res.status).toBe(429)
    expect((await res.json()).error).toBe('Daily LLM call cap exceeded')
  })

  test('a failed model call carries its code and the provider class and status (G-14)', async () => {
    h.fetch.mockResolvedValue(new Response(JSON.stringify({
      error: 'The AI model call failed. Try again in a moment.', code: 'model_call_failed',
      error_class: 'RateLimitError', provider_status: 429,
    }), { status: 502 }))
    const res = await post({ question: 'q', project_id: 'p1' })
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'The AI model call failed. Try again in a moment.', code: 'model_call_failed',
      upstreamStatus: 502, errorClass: 'RateLimitError', providerStatus: 429,
    })
  })

  test('a malformed JSON body is a 400, not a 500', async () => {
    const res = await POST({
      json: async () => { throw new SyntaxError('Unexpected token') },
    } as never)
    expect(res.status).toBe(400)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('the happy path still works', () => {
  test('the generated cypher is returned to the caller', async () => {
    const res = await post({ question: 'list ips', project_id: 'p1' })
    expect(await res.json()).toEqual({ cypher: 'MATCH (i:IP) RETURN i' })
  })

  test('other body fields (for_graph_view) are preserved', async () => {
    await post({ question: 'q', project_id: 'p1', for_graph_view: false })
    expect(agentBody().for_graph_view).toBe(false)
  })
})

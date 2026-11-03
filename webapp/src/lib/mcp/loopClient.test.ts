/**
 * The MCP server's Agent in the Loop transport.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ fetch: vi.fn(), timeout: vi.fn() }))

vi.mock('@/lib/agentFetch', () => ({ agentBaseUrl: () => 'http://agent:8080' }))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (x?: object) => ({ 'x-internal-key': 'k', ...(x ?? {}) }),
}))

import { loopAnswer, loopGet, loopWait } from './loopClient'

const ID = { userId: 'u1', driverId: 'tok1', driverName: 'cc-amber', projectIds: ['p1', 'p2'] }
const STEP = 'a'.repeat(32)

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  vi.stubGlobal('fetch', h.fetch)
  vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms: number) => {
    h.timeout(ms)
    return new AbortController().signal
  })
  h.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ step: null, sessions: [], hint: 'x' }) })
})

const call = () => h.fetch.mock.calls[0] as [string, RequestInit]
const sent = () => JSON.parse(String(call()[1].body)) as Record<string, unknown>

describe('the wire', () => {
  test('wait: URL, internal key, snake_case body, long-poll timeout', async () => {
    await loopWait({ ...ID, sessionId: 'session_ab', waitSeconds: 50, delivery: 'dedup' })
    expect(call()[0]).toBe('http://agent:8080/loop/steps/wait')
    expect(call()[1].method).toBe('POST')
    expect(call()[1].headers).toEqual({ 'x-internal-key': 'k', 'Content-Type': 'application/json' })
    expect(sent()).toEqual({
      user_id: 'u1', driver_id: 'tok1', driver_name: 'cc-amber', project_ids: ['p1', 'p2'],
      session_id: 'session_ab', wait_seconds: 50, delivery: 'dedup',
    })
    expect(h.timeout).toHaveBeenCalledWith(60_000)
  })

  test('wait without a driver name or session sends neither', async () => {
    await loopWait({ userId: 'u1', driverId: 'tok1', projectIds: [], waitSeconds: 5, delivery: 'full' })
    expect(sent()).toEqual({ user_id: 'u1', driver_id: 'tok1', project_ids: [], wait_seconds: 5, delivery: 'full' })
    expect(h.timeout).toHaveBeenCalledWith(15_000)
  })

  test('get and answer use the short timeout and the step path', async () => {
    await loopGet({ ...ID, stepId: STEP, cursor: 40000, full: true })
    expect(call()[0]).toBe(`http://agent:8080/loop/steps/${STEP}/get`)
    expect(sent()).toMatchObject({ cursor: 40000, full: true, user_id: 'u1' })
    expect(h.timeout).toHaveBeenCalledWith(15_000)

    h.fetch.mockClear()
    await loopAnswer({ ...ID, stepId: STEP, answer: '{"a":1}',
      answeredBy: { tokenPrefix: 'rdmn_mcp_aaaa', tokenName: 'laptop' } })
    expect(call()[0]).toBe(`http://agent:8080/loop/steps/${STEP}/answer`)
    expect(sent()).toEqual({
      user_id: 'u1', driver_id: 'tok1', driver_name: 'cc-amber', project_ids: ['p1', 'p2'],
      answer: '{"a":1}', answered_by: { token_prefix: 'rdmn_mcp_aaaa', token_name: 'laptop' },
    })
  })

  test('a decline sends the reason and no answer', async () => {
    await loopAnswer({ ...ID, stepId: STEP, declined: true, reason: 'out of scope',
      answeredBy: { tokenPrefix: 'p', tokenName: 'n' } })
    expect(sent()).toMatchObject({ declined: true, reason: 'out of scope' })
    expect(sent()).not.toHaveProperty('answer')
  })
})

describe('failures become fixed sentences with codes', () => {
  const agentSays = (status: number, body: unknown) =>
    h.fetch.mockResolvedValue({ ok: false, status, json: async () => body })

  test.each([
    [404, { error: 'x', code: 'loop_disabled' }, 'disabled'],
    [404, { detail: 'Not Found' }, 'agent_outdated'],
    [404, { error: 'x', code: 'not_found' }, 'not_found'],
    [409, { error: 'x', code: 'step_closed' }, 'step_closed'],
    [413, { error: 'x', code: 'answer_too_large' }, 'answer_too_large'],
    [422, { error: 'x', code: 'bad_args' }, 'bad_args'],
    [429, {}, 'loop_too_many_steps'],
    [401, { detail: 'nope' }, 'agent_refused'],
    [503, { detail: 'INTERNAL_API_KEY is not configured' }, 'agent_failed'],
    [500, { detail: 'Traceback /opt/app/api.py' }, 'agent_failed'],
  ])('%s %j -> %s', async (status, body, code) => {
    agentSays(status, body)
    const err = await loopGet({ ...ID, stepId: STEP, cursor: 0, full: false }).catch((e) => e)
    expect(err.code).toBe(code)
    expect(String(err.message)).not.toMatch(/Traceback|api\.py|INTERNAL_API_KEY|nope/)
  })

  test('the outdated agent tells the operator what to do', async () => {
    agentSays(404, { detail: 'Not Found' })
    await expect(loopWait({ ...ID, waitSeconds: 1, delivery: 'full' }))
      .rejects.toThrow(/rebuild and restart the agent/)
  })

  test('a network failure or abort is agent_unreachable', async () => {
    h.fetch.mockRejectedValue(Object.assign(new Error('aborted'), { name: 'TimeoutError' }))
    const err = await loopWait({ ...ID, waitSeconds: 1, delivery: 'full' }).catch((e) => e)
    expect(err.code).toBe('agent_unreachable')
  })
})

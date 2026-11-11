/**
 * closeAgentSockets: the webapp's caller of the agent's master-key POST /ws/close (DV-21).
 * It never throws, since the access change it follows is already committed; a close the
 * agent did not confirm is logged `[rbac] socket-close failed` with a fixed reason.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { closeAgentSockets } from './agentSockets'

vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const fetchMock = vi.fn()
let errors: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  errors = vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('closeAgentSockets', () => {
  test('sends only the ids it was given, the kinds and the scope, with the master key', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ closed: 3, stopped_runs: 1 }), { status: 200 }))
    expect(await closeAgentSockets({ projectId: 'p-1', kinds: ['agent', 'kali-terminal'], scope: 'account' }))
      .toEqual({ ok: true, closed: 3, stoppedRuns: 1 })
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('http://agent.test:8080/ws/close')
    expect(JSON.parse(init.body)).toEqual({ project_id: 'p-1', kinds: ['agent', 'kali-terminal'], scope: 'account' })
    expect(init.headers['x-internal-key']).toBe('ik-test-master-0001')
    expect(errors).not.toHaveBeenCalled()
  })

  test('the scope defaults to access', async () => {
    fetchMock.mockResolvedValue(new Response('{"closed":0,"stopped_runs":0}', { status: 200 }))
    await closeAgentSockets({ userId: 'u-1', kinds: ['kali-terminal'] })
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ user_id: 'u-1', kinds: ['kali-terminal'], scope: 'access' })
  })

  test('an answer without counts reads as zero', async () => {
    fetchMock.mockResolvedValue(new Response('not json', { status: 200 }))
    expect(await closeAgentSockets({ userId: 'u-1', kinds: ['kali-terminal'] })).toEqual({ ok: true, closed: 0, stoppedRuns: 0 })
  })

  test('the agent unreachable or refusing: a fixed reason, logged, never thrown', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('fetch failed'))
    expect(await closeAgentSockets({ userId: 'u-1', kinds: ['kali-terminal'] })).toEqual({ ok: false, reason: 'agent_unreachable' })
    fetchMock.mockResolvedValueOnce(new Response('{"detail":"Unauthorized"}', { status: 401 }))
    expect(await closeAgentSockets({ userId: 'u-1', kinds: ['kali-terminal'] })).toEqual({ ok: false, reason: 'agent_http_401' })
    const lines = errors.mock.calls.map((c: unknown[]) => String(c[0]))
    expect(lines).toEqual([
      '[rbac] socket-close failed user=u-1 project=- kinds=kali-terminal: agent_unreachable',
      '[rbac] socket-close failed user=u-1 project=- kinds=kali-terminal: agent_http_401',
    ])
  })
})

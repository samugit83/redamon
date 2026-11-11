/**
 * The reload a member's MCP save asks of the agent (RBAC OQ-41, NF-06).
 *
 * The agent holds one user MCP toolset for the whole process. The save names whose
 * servers they are, so the agent can defer the reload while another owner's run is
 * live on a different set; the save still succeeds, and the servers load at the
 * member's next run start. A deferral reaches the person as a warning with its code.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

vi.mock('@/lib/mcp/userServerAccess', () => ({
  ownerRunsStdio: vi.fn(async () => false),
  serversForAgent: vi.fn((_owner: string, saved: unknown) => saved),
}))

import { reloadAgentMcp } from './reload'

const fetchMock = vi.fn()
const SERVERS = [{ id: 'web', name: 'Web', transport: 'streamable_http', url: 'http://mcp.example/mcp' }]
const body = () => JSON.parse(fetchMock.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('reloadAgentMcp', () => {
  test('names the owner of the servers it sends', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ servers: [] }), { status: 200 }))
    await reloadAgentMcp('member-1', SERVERS)
    expect(String(fetchMock.mock.calls[0][0])).toContain('/mcp/reload')
    expect(body()).toEqual({ ownerId: 'member-1', userMcpServers: SERVERS })
  })

  test('a reload the agent applied: no warning', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ servers: [] }), { status: 200 }))
    expect(await reloadAgentMcp('member-1', SERVERS)).toEqual([])
  })

  test("a reload deferred while another owner's run is live: saved, with the mcp_toolset_busy warning", async () => {
    fetchMock.mockResolvedValue(new Response(
      JSON.stringify({ deferred: true, code: 'mcp_toolset_busy', message: 'agent text' }), { status: 202 }))
    const warnings = await reloadAgentMcp('member-1', SERVERS)
    expect(warnings).toEqual([{
      service: 'agent',
      message: 'Your MCP Tool Plugins load at your next agent run: another user\'s run is using the agent now',
      code: 'mcp_toolset_busy',
    }])
    expect(JSON.stringify(warnings)).not.toContain('agent text')
  })

  test('a 202 that is not a deferral is not reported as one', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ servers: [] }), { status: 202 }))
    expect(await reloadAgentMcp('member-1', SERVERS)).toEqual([])
  })

  test('a refused reload keeps its warning', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'boom' }), { status: 500 }))
    const [warning] = await reloadAgentMcp('member-1', SERVERS)
    expect(warning).toMatchObject({ service: 'agent', code: 'agent_error', upstreamStatus: 500 })
  })
})

/**
 * Saved graph views.
 *
 * Three things must hold, and each was a real trap:
 *
 *  - the stored Cypher NEVER leaves the process. Handing raw Cypher to an
 *    external model leaks the graph schema and gives the caller an injection
 *    carrier, and the browser route does return it because it has no `select`.
 *  - running one needs `graph:cypher`. `recon:read` is the DEFAULT scope on
 *    every minted token, so declaring this tool `recon:read` would hand
 *    arbitrary stored-Cypher execution to the default credential - the exact
 *    capability `graph:cypher` is sold as withholding.
 *  - a refusal must say it is the VIEW that cannot be proven safe here, not
 *    imply the tool is broken. The two paths guard the same stored string by
 *    different rules, so a view that works daily in the UI can be refused.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  findManyViews: vi.fn(),
  findView: vi.fn(),
  execCypher: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    graphView: {
      findMany: (...a: unknown[]) => h.findManyViews(...a),
      findUnique: (...a: unknown[]) => h.findView(...a),
    },
  },
}))
vi.mock('@/lib/mcp/graphClient', () => ({
  execCypher: (...a: unknown[]) => h.execCypher(...a),
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { listGraphViews, runGraphView } from './viewTools'
import type { McpContext } from './tools'

const ctx = (scopes: string[] = ['recon:read', 'graph:cypher']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const SECRET_QUERY = 'MATCH (s:Subdomain) WHERE s.name CONTAINS "admin" RETURN s.name'

const ownNode = () => ({
  _kind: 'node', labels: ['Subdomain'], properties: { user_id: 'owner', project_id: 'p1' },
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.findManyViews.mockResolvedValue([
    { id: 'g1', name: 'Exposed admin panels', description: 'The daily one', createdAt: new Date() },
  ])
  h.findView.mockResolvedValue({
    id: 'g1', projectId: 'p1', name: 'Exposed admin panels',
    description: 'The daily one', cypherQuery: SECRET_QUERY,
  })
  h.execCypher.mockResolvedValue({ records: [{ n: ownNode() }] })
})

describe('list_graph_views', () => {
  test('needs recon:read and ownership', async () => {
    await expect(listGraphViews(ctx([]), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(listGraphViews(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
  })

  test('the stored Cypher is NEVER returned', async () => {
    const r = await listGraphViews(ctx(), 'p1')
    expect(JSON.stringify(r)).not.toContain('MATCH')
    expect(JSON.stringify(r)).not.toContain('Subdomain')
  })

  test('it is not even SELECTED, so it cannot leak through a later refactor', async () => {
    await listGraphViews(ctx(), 'p1')
    expect(h.findManyViews.mock.calls[0][0].select.cypherQuery).toBeUndefined()
  })

  test('a view naming a Domain the graph no longer has is flagged, the query still unseen', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: 'api.nwlab.test', subdomainList: [] })
    h.findManyViews.mockImplementation(async (args: { select: Record<string, boolean> }) => (
      args.select.cypherQuery
        ? [{ id: 'g1', cypherQuery: "MATCH (d:Domain {name:'api.nwlab.test'})-[:HAS_SUBDOMAIN]->(s) RETURN s" }]
        : [{ id: 'g1', name: 'Legacy domain view', description: null, createdAt: new Date() }]
    ))
    const r = await listGraphViews(ctx(), 'p1')
    expect(r.views[0].mayNeedUpdate).toBe(true)
    expect(JSON.stringify(r)).not.toContain('MATCH')
    expect(JSON.stringify(r)).not.toContain('api.nwlab.test')
    // The listed rows themselves never carried the query.
    const listCall = h.findManyViews.mock.calls.find(([a]) => a.select.name)!
    expect(listCall[0].select.cypherQuery).toBeUndefined()
  })

  test('the query is scoped to the project', async () => {
    await listGraphViews(ctx(), 'p1')
    expect(h.findManyViews.mock.calls[0][0].where).toEqual({ projectId: 'p1' })
  })

  test('it warns that a view working in the UI may still be refused here', async () => {
    const notes = (await listGraphViews(ctx(), 'p1')).notes.join(' ')
    expect(notes).toMatch(/stricter rules than the app applies/)
  })

  test('the scope select carries the hostname policy columns', async () => {
    await listGraphViews(ctx(), 'p1')
    const scopeCall = h.findProject.mock.calls.find(([a]) => a?.select?.ipMode)!
    for (const key of ['ipHostnameMode', 'ipHostnameInclude', 'ipHostnameExclude', 'ipHostnamePassiveExpand',
      'ipHostnameScanAllConfirmed', 'ipHostnameMaxScanned', 'ipHostnamePassiveMaxNames']) {
      expect(scopeCall[0].select[key], key).toBe(true)
    }
  })

  test('an IP project shows its hostname policy; a domain project shows none', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', ipMode: true, ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*.example.com'], ipHostnameExclude: [], ipHostnamePassiveExpand: true,
      ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
    })
    const r = await listGraphViews(ctx(), 'p1') as Record<string, unknown>
    expect(r.hostnamePolicy).toEqual({
      ipHostnameMode: 'record_filter', include: ['*.example.com'], exclude: [], passiveExpand: true,
      scanAllConfirmed: false, maxScanned: 100, passiveMaxNames: 500,
    })
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: 'example.com', subdomainList: [] })
    expect(await listGraphViews(ctx(), 'p1')).not.toHaveProperty('hostnamePolicy')
  })
})

describe('run_graph_view permissions', () => {
  test('it needs graph:cypher, not merely recon:read', async () => {
    // DEFAULT_MCP_SCOPES has no graph:cypher, so without this the default token
    // could execute arbitrary stored Cypher.
    await expect(runGraphView(ctx(['recon:read']), 'p1', 'g1'))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('it still needs recon:read', async () => {
    await expect(runGraphView(ctx(['graph:cypher']), 'p1', 'g1'))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test("another project's view is refused without running its query", async () => {
    h.findView.mockResolvedValue({ id: 'g1', projectId: 'other', cypherQuery: SECRET_QUERY })
    await expect(runGraphView(ctx(), 'p1', 'g1'))
      .rejects.toMatchObject({ code: 'not_found' })
    expect(h.execCypher).not.toHaveBeenCalled()
  })

  test('a missing view is the SAME answer, so ids cannot be enumerated', async () => {
    h.findView.mockResolvedValue({ id: 'g1', projectId: 'other', cypherQuery: SECRET_QUERY })
    const foreign = await runGraphView(ctx(), 'p1', 'g1').catch(e => e)
    h.findView.mockResolvedValue(null)
    const missing = await runGraphView(ctx(), 'p1', 'nope').catch(e => e)

    expect(missing.message).toBe(foreign.message)
    // It names the VIEW, not the project: the caller has already proved it owns
    // the project, so "Project not found" sent it retrying the wrong argument.
    expect(missing.message).toMatch(/saved view/)
    expect(missing.message).not.toBe('Project not found')
  })
})

describe('run_graph_view execution', () => {
  test('the stored query goes through execCypher, never straight to the database', async () => {
    // It is the only thing standing between a stored string and Neo4j: the
    // creating route persists cypherQuery with no write-keyword check, no
    // length bound and no scoping proof, because every guard lives on the
    // reader.
    await runGraphView(ctx(), 'p1', 'g1')
    expect(h.execCypher).toHaveBeenCalledWith('owner', 'p1', SECRET_QUERY)
  })

  test('the answer names the view but never echoes its query', async () => {
    const r = await runGraphView(ctx(), 'p1', 'g1')
    expect(r.view).toEqual({ viewId: 'g1', name: 'Exposed admin panels' })
    expect(JSON.stringify(r)).not.toContain('CONTAINS')
  })

  test('truncation is reported', async () => {
    h.execCypher.mockResolvedValue({ records: [], truncated: true })
    expect((await runGraphView(ctx(), 'p1', 'g1')).truncated).toBe(true)
  })

  test('a cross-tenant row in the result drops the WHOLE response', async () => {
    h.execCypher.mockResolvedValue({
      records: [
        { n: ownNode() },
        { n: { _kind: 'node', labels: ['Subdomain'], properties: { user_id: 'mallory', project_id: 'pX' } } },
      ],
    })
    await expect(runGraphView(ctx(), 'p1', 'g1')).rejects.toThrow(/safety check/i)
  })

  test('an empty stored query is refused clearly', async () => {
    h.findView.mockResolvedValue({ id: 'g1', projectId: 'p1', name: 'Empty', cypherQuery: '   ' })
    await expect(runGraphView(ctx(), 'p1', 'g1')).rejects.toThrow(/no query stored/i)
  })
})

describe('a refused view says it is the VIEW, not the tool', () => {
  test('a guard refusal names the view and explains the asymmetry', async () => {
    // The two paths do not apply the same guards to the same stored string, so
    // a view the operator uses daily can fail here. Without this the operator
    // concludes MCP is broken rather than that this query cannot be proven safe.
    h.execCypher.mockRejectedValue(
      new McpToolError('Query rejected: write operation rejected (set); read-only', 'execute_failed')
    )
    const err = await runGraphView(ctx(), 'p1', 'g1').catch((e: McpToolError) => e)
    expect(err).toMatchObject({ code: 'view_not_runnable' })
    expect((err as McpToolError).message).toMatch(/"Exposed admin panels" cannot be run over MCP/)
  })

  test('it says the view itself is unchanged', async () => {
    h.execCypher.mockRejectedValue(new McpToolError('Query rejected: no labelled node pattern', 'execute_failed'))
    await expect(runGraphView(ctx(), 'p1', 'g1')).rejects.toThrow(/view itself\s+is unchanged/)
  })

  test('an unreachable graph stays a dependency failure, not a "bad view"', async () => {
    // Telling the operator their view is unrunnable when the service is simply
    // down would send them rewriting a query that is fine.
    h.execCypher.mockRejectedValue(
      new McpToolError('The graph service is unavailable.', 'agent_unreachable')
    )
    await expect(runGraphView(ctx(), 'p1', 'g1')).rejects.toMatchObject({ code: 'agent_unreachable' })
  })
})

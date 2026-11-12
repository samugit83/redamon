/**
 * Route handler tests for the AI Surface + AI Risk red-zone endpoints.
 *
 * Both routes fire MULTIPLE session.run() calls (one per sub-sheet), so the
 * mock returns a QUEUE of record-sets — one shift per run() call, in route order.
 *
 * Run: npx vitest run src/app/api/analytics/redzone/aiTablesRoutes.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: vi.fn().mockResolvedValue(null) }))

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runQueue: Array<Array<Record<string, unknown>>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      const rows = runQueue.shift() ?? []
      return { records: rows.map(row => ({ get: (key: string) => row[key] })) }
    },
    close: async () => { /* no-op */ },
  }),
}))

const aiSurface = await import('./aiSurface/route')
const aiRisk = await import('./aiRisk/route')

function req(projectId: string | null): any {
  const url = projectId
    ? `http://localhost:3000/api/analytics/redzone/test?projectId=${projectId}`
    : 'http://localhost:3000/api/analytics/redzone/test'
  return { nextUrl: new URL(url) }
}

beforeEach(() => {
  runCalls.length = 0
  runQueue = []
  shouldThrow = null
})

// --------------------------------------------------------------------------- //
describe('AI red-zone routes — guards', () => {
  test.each([
    ['aiSurface', aiSurface.GET],
    ['aiRisk', aiRisk.GET],
  ])('%s returns 400 when projectId missing', async (_name, handler) => {
    const res = await handler(req(null))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/projectId/i)
  })

  test.each([
    ['aiSurface', aiSurface.GET],
    ['aiRisk', aiRisk.GET],
  ])('%s returns 500 on query error with a fixed message and the Neo4j code', async (_name, handler) => {
    // The raw Neo4j message can quote the Cypher and its target values; only
    // the code reaches the browser.
    shouldThrow = Object.assign(new Error('boom: MATCH (h {name:"target.example"})'), {
      code: 'Neo.TransientError.General.DatabaseUnavailable',
    })
    const res = await handler(req('p1'))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Query failed', code: 'Neo.TransientError.General.DatabaseUnavailable' })
    expect(JSON.stringify(body)).not.toContain('target.example')
  })

  test.each([
    ['aiSurface', aiSurface.GET, ['llmEndpoints', 'mcpServers', 'technologies', 'vectorDbs', 'models']],
    ['aiRisk', aiRisk.GET, ['testedVulns', 'findings', 'injectableParams', 'ragPoints', 'exposedRuntimes', 'unauthenticatedMcp']],
  ])('%s smoke: empty graph -> 200 with all sheet keys as []', async (_name, handler, keys) => {
    const res = await handler(req('p1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    for (const k of keys as string[]) {
      expect(body.sheets[k]).toEqual([])
      expect(body.meta[k]).toBe(0)
    }
    expect(runCalls).toHaveLength((keys as string[]).length) // one query per sheet
    expect(runCalls.every(c => c.params.pid === 'p1')).toBe(true)
  })
})

// --------------------------------------------------------------------------- //
describe('aiSurface route — field mapping', () => {
  test('maps every sub-sheet and converts neo4j ints', async () => {
    runQueue = [
      // llmEndpoints
      [{ baseUrl: 'http://h:9106', path: '/v1/chat/completions', method: 'GET',
         interfaceType: 'llm-chat', streaming: true, tools: true, vision: true,
         modelFamily: 'llama', latencyMs: 11.2, ragIngest: null, framework: null,
         frontend: null, schemaRef: '/tmp/x.json', source: 'ai_surface_recon' }],
      // mcpServers (toolCount as neo4j int {low})
      [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'demo', serverVersion: '1.0',
         protocolVersion: '2025-06-18', toolCount: { low: 4, high: 0 }, resourceCount: { low: 1, high: 0 },
         promptCount: { low: 1, high: 0 }, capabilities: ['tools', 'prompts'],
         authRequired: false, toolsHash: 'abc' }],
      // technologies
      [{ name: 'qdrant', category: 'ai-vector-db', version: '', detectedBy: ['naabu-ai-port'], attachedTo: { low: 2, high: 0 } }],
      // vectorDbs
      [{ name: 'qdrant', host: '1.2.3.4', port: { low: 6333, high: 0 }, detectedBy: 'ai-surface-recon-probe' }],
      // models
      [{ modelId: 'gpt-4o', family: 'gpt', baseUrl: 'http://h:9106', sourceEndpoint: '/v1/models' }],
    ]
    const res = await aiSurface.GET(req('p1'))
    const { sheets, meta } = await res.json()

    expect(sheets.llmEndpoints[0]).toMatchObject({ interfaceType: 'llm-chat', streaming: true, latencyMs: 11.2 })
    expect(sheets.mcpServers[0].toolCount).toBe(4)        // {low:4} -> 4
    expect(sheets.mcpServers[0].resourceCount).toBe(1)
    expect(sheets.mcpServers[0].capabilities).toEqual(['tools', 'prompts'])
    expect(sheets.mcpServers[0].authRequired).toBe(false)
    expect(sheets.technologies[0].attachedTo).toBe(2)
    expect(sheets.vectorDbs[0].port).toBe(6333)
    expect(sheets.models[0]).toMatchObject({ modelId: 'gpt-4o', family: 'gpt' })
    expect(meta).toMatchObject({ llmEndpoints: 1, mcpServers: 1, technologies: 1, vectorDbs: 1, models: 1 })
  })

  test('null array fields default to []', async () => {
    runQueue = [
      [], // llm
      [{ baseUrl: 'http://h', path: '/mcp', serverName: 'd', serverVersion: null,
         protocolVersion: null, toolCount: null, resourceCount: null, promptCount: null,
         capabilities: null, authRequired: null, toolsHash: null }],
      [{ name: 't', category: 'ai-runtime', version: null, detectedBy: null, attachedTo: null }],
      [], [],
    ]
    const res = await aiSurface.GET(req('p1'))
    const { sheets } = await res.json()
    expect(sheets.mcpServers[0].capabilities).toEqual([])
    expect(sheets.mcpServers[0].toolCount).toBeNull()
    expect(sheets.technologies[0].detectedBy).toEqual([])
  })
})

// --------------------------------------------------------------------------- //
describe('aiRisk route — field mapping', () => {
  test('maps findings + risk sheets with OWASP/ATLAS + exposedOn array', async () => {
    runQueue = [
      // findings
      [{ severity: 'high', type: 'mcp_tool_poisoning', name: 'poison', owasp: 'LLM01',
         atlas: 'AML.T0051', payloadClass: 'mcp_static', evidence: '{}', findingId: 'aisr_1',
         baseUrl: 'http://h:9107', endpointPath: '/mcp' }],
      // injectableParams
      [{ name: 'query', endpointPath: '/mcp', baseUrl: 'http://h:9107',
         toolArgPath: '/inputSchema/properties/query', position: 'body' }],
      // ragPoints
      [],
      // exposedRuntimes
      [{ name: 'ollama', category: 'ai-runtime', version: null, exposedOn: ['1.2.3.4:11434'] }],
      // unauthenticatedMcp
      [{ baseUrl: 'http://h:9107', path: '/mcp', serverName: 'demo', toolCount: { low: 4, high: 0 } }],
    ]
    const res = await aiRisk.GET(req('p1'))
    const { sheets, meta } = await res.json()

    expect(sheets.findings[0]).toMatchObject({ type: 'mcp_tool_poisoning', owasp: 'LLM01', atlas: 'AML.T0051' })
    expect(sheets.injectableParams[0].toolArgPath).toBe('/inputSchema/properties/query')
    expect(sheets.exposedRuntimes[0].exposedOn).toEqual(['1.2.3.4:11434'])
    expect(sheets.unauthenticatedMcp[0].toolCount).toBe(4)
    expect(meta).toMatchObject({ findings: 1, injectableParams: 1, ragPoints: 0, exposedRuntimes: 1, unauthenticatedMcp: 1 })
  })

  test('exposedOn defaults to [] when null', async () => {
    runQueue = [[], [], [], [{ name: 'x', category: 'ai-proxy', version: null, exposedOn: null }], []]
    const res = await aiRisk.GET(req('p1'))
    const { sheets } = await res.json()
    expect(sheets.exposedRuntimes[0].exposedOn).toEqual([])
  })

  test('testedVulns corroborates the attack tools by (OWASP, target)', async () => {
    // 6th query = tested vulns. Two tools on the SAME OWASP+target -> one row.
    runQueue = [[], [], [], [], [], [
      { source: 'garak', severity: 'medium', type: 'ai_attack_jailbreak', owaspLlmId: 'LLM01',
        asr: 0.4, trials: { low: 5, high: 0 }, payloadClass: 'garak-dan', transcriptRef: '/o/g.jsonl',
        evidence: 'dan', probePackVersion: 'garak/0.15.1', target: 'http://h/v1', endpointPath: '/v1' },
      { source: 'promptfoo', severity: 'high', type: 'ai_attack_jailbreak', owaspLlmId: 'LLM01',
        asr: 0.7, trials: { low: 3, high: 0 }, payloadClass: 'promptfoo-pliny', transcriptRef: '/o/p.json',
        evidence: 'pliny', probePackVersion: 'promptfoo/0.121.17', target: 'http://h/v1', endpointPath: '/v1' },
    ]]
    const res = await aiRisk.GET(req('p1'))
    const { sheets, meta } = await res.json()
    expect(meta.testedVulns).toBe(1)                       // corroborated into one row
    expect(sheets.testedVulns[0]).toMatchObject({
      owasp: 'LLM01', attack: 'jailbreak', target: 'http://h/v1/v1',
      foundBy: ['garak', 'promptfoo'], asr: '70%', trials: 8, severity: 'high',
    })
  })
})

// --------------------------------------------------------------------------- //
describe('aiRisk route — Cypher shape', () => {
  test('queries are project-scoped and target the right nodes', async () => {
    await aiRisk.GET(req('proj-x'))
    expect(runCalls).toHaveLength(6)
    expect(runCalls[0].cypher).toMatch(/Vulnerability.*source: 'ai_surface_recon'/s)
    expect(runCalls[1].cypher).toMatch(/is_ai_prompt_injectable = true/)
    expect(runCalls[2].cypher).toMatch(/is_ai_rag_ingest = true/)
    expect(runCalls[3].cypher).toMatch(/\['ai-runtime','ai-proxy'\]/)
    expect(runCalls[4].cypher).toMatch(/ai_mcp_auth_required/)
    // tested vulns queried last: the four attack-tool sources
    expect(runCalls[5].cypher).toMatch(/source IN \['garak', 'pyrit', 'giskard', 'promptfoo'\]/)
    expect(runCalls.every(c => c.params.pid === 'proj-x')).toBe(true)
  })
})

// --------------------------------------------------------------------------- //
describe('AI red-zone routes — Node ID', () => {
  // The node each sheet's row is about, in route query order.
  test.each([
    ['aiSurface', aiSurface.GET, ['ep', 'ep', 't', 't', 'min(ep)']],
    ['aiRisk', aiRisk.GET, ['v', 'p', 'ep', 't', 'ep', 'v']],
  ])('%s projects the row node id in every sheet query', async (_name, handler, vars) => {
    await handler(req('p1'))
    ;(vars as string[]).forEach((v, i) => {
      const expr = v === 'min(ep)' ? 'toString(min(id(ep)))' : `toString(id(${v}))`
      expect(runCalls[i].cypher).toContain(expr)
      expect(runCalls[i].cypher).toMatch(/\bnodeId\b/)
    })
  })

  test('aiSurface maps nodeId on every sheet, null when absent', async () => {
    runQueue = [
      [{ nodeId: '1' }], [{ nodeId: '2' }], [{ nodeId: '3' }], [{ nodeId: '4' }], [{}],
    ]
    const { sheets } = await (await aiSurface.GET(req('p1'))).json()
    expect(sheets.llmEndpoints[0].nodeId).toBe('1')
    expect(sheets.mcpServers[0].nodeId).toBe('2')
    expect(sheets.technologies[0].nodeId).toBe('3')
    expect(sheets.vectorDbs[0].nodeId).toBe('4')
    expect(sheets.models[0].nodeId).toBeNull()
  })

  test('aiRisk maps nodeId on every sheet; testedVulns keeps the representative row', async () => {
    runQueue = [
      [{ nodeId: '10' }], [{ nodeId: '11' }], [{ nodeId: '12' }], [{ nodeId: '13', exposedOn: [] }],
      [{ nodeId: '14' }],
      [
        { nodeId: '20', source: 'garak', severity: 'medium', owaspLlmId: 'LLM01', asr: 0.4,
          target: 'http://h/v1', evidence: 'weak' },
        { nodeId: '21', source: 'promptfoo', severity: 'high', owaspLlmId: 'LLM01', asr: 0.7,
          target: 'http://h/v1', evidence: 'strong' },
      ],
    ]
    const { sheets } = await (await aiRisk.GET(req('p1'))).json()
    expect(sheets.findings[0].nodeId).toBe('10')
    expect(sheets.injectableParams[0].nodeId).toBe('11')
    expect(sheets.ragPoints[0].nodeId).toBe('12')
    expect(sheets.exposedRuntimes[0].nodeId).toBe('13')
    expect(sheets.unauthenticatedMcp[0].nodeId).toBe('14')
    // Two tools fold into one row; its id is the worst-ASR row whose evidence it shows.
    expect(sheets.testedVulns).toHaveLength(1)
    expect(sheets.testedVulns[0]).toMatchObject({ nodeId: '21', evidence: 'strong' })
  })
})

describe('AI red-zone routes — endpoints known only from an API specification', () => {
  const PREDICATE = 'coalesce(ep.openapi_declared_only, ep.openapi_declared, false) AS declaredOnly'

  test('aiSurface flags declared-only LLM endpoints instead of hiding them', async () => {
    runQueue = [[{ baseUrl: 'https://a', path: '/v1/chat', method: 'POST', declaredOnly: true }]]
    const body = await (await aiSurface.GET(req('p1'))).json()
    expect(runCalls[0].cypher).toContain(PREDICATE)
    expect(body.sheets.llmEndpoints[0].declaredOnly).toBe(true)
  })

  test('aiRisk reads the flag from the parent Endpoint for parameters, and on RAG points', async () => {
    await aiRisk.GET(req('p1'))
    const params = runCalls.find(c => c.cypher.includes('is_ai_prompt_injectable'))!.cypher
    expect(params).toContain('coalesce(e.openapi_declared_only, e.openapi_declared, false) AS declaredOnly')
    const rag = runCalls.find(c => c.cypher.includes('is_ai_rag_ingest = true'))!.cypher
    expect(rag).toContain(PREDICATE)
  })

  test('a row without the flag reads as observed', async () => {
    runQueue = [[{ baseUrl: 'https://a', path: '/v1/chat', declaredOnly: null }]]
    const body = await (await aiSurface.GET(req('p1'))).json()
    expect(body.sheets.llmEndpoints[0].declaredOnly).toBe(false)
  })
})

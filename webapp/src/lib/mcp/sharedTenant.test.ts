/**
 * The tenant of every MCP read on a shared project is the project's OWNER (step 4.10; SH-35, T9):
 * the graph, finding, mute and triage reads pass the owner's id to the agent, so an opted-in
 * collaborator's token gets the owner's rows, and the result check holds the rows to the owner, not
 * to the token's user (which would discard every shared row as a tenant violation). Also: the
 * natural-language query is refused on a shared project, raw Cypher and saved views need Raw data &
 * files there (no rule over an arbitrary answer tells step content apart, so nothing is "stripped"
 * on MCP), list_projects lists owned ∪ opted-in shares with each row's `myAccess`, and a reader's
 * project reads drop the `share: secret` columns.
 *
 * Real access check over the sharedProjectDb double; the graph client, the triage reads and the
 * agent are doubles that record the tenant they were handed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  tenants: [] as Array<{ via: string; userId: unknown }>,
  agentCalls: 0,
  /** Who the next graph answer's rows are stamped with: the tenant asked (default) or someone else. */
  stampAs: null as string | null,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined }))
vi.mock('@/lib/mcp/graphClient', async (orig) => {
  const record = (via: string, userId: string, projectId: string) => {
    h.tenants.push({ via, userId })
    h.agentCalls += 1
    const stamp = h.stampAs ?? userId
    return { records: [{ n: { _kind: 'node', labels: ['Domain'], properties: { name: 'example.test', user_id: stamp, project_id: projectId } } }] }
  }
  return {
    ...(await orig<typeof import('@/lib/mcp/graphClient')>()),
    execCypher: async (userId: string, projectId: string) => record('execCypher', userId, projectId),
    nlQuery: async (userId: string, projectId: string) => record('nlQuery', userId, projectId),
  }
})
vi.mock('@/lib/mcp/triageGraph', async (orig) => {
  const seen = (via: string) => (userId: string) => { h.tenants.push({ via, userId }); h.agentCalls += 1 }
  return {
    ...(await orig<typeof import('@/lib/mcp/triageGraph')>()),
    listTriageFindings: async (userId: string) => { seen('listTriageFindings')(userId); return { findings: [], total: 0 } },
    listMutedFindings: async (userId: string) => { seen('listMutedFindings')(userId); return { findings: [], total: 0 } },
    listMutedPage: async (userId: string) => { seen('listMutedPage')(userId); return { findings: [], total: 0 } },
    mutedFacets: async (userId: string) => { seen('mutedFacets')(userId); return { total: 0, by_person: [], by_mcp: 0, labels: [], rules: [], tokens: [] } },
  }
})
vi.mock('@/lib/triage/actions', async (orig) => {
  const seen = (via: string, tenant: { userId: string }) => { h.tenants.push({ via, userId: tenant.userId }); h.agentCalls += 1 }
  return {
    ...(await orig<typeof import('@/lib/triage/actions')>()),
    readFinding: async (tenant: { userId: string }) => { seen('readFinding', tenant); return { row: {} } },
    readEvidence: async (tenant: { userId: string }) => { seen('readEvidence', tenant); return {} },
    triageFacets: async (tenant: { userId: string }) => { seen('triageFacets', tenant); return {} },
  }
})
vi.mock('@/lib/triage/preflight', async (orig) => ({
  ...(await orig<typeof import('@/lib/triage/preflight')>()),
  computePreflight: async (tenant: { userId: string }) => { h.tenants.push({ via: 'computePreflight', userId: tenant.userId }); return null },
}))
vi.mock('@/lib/mcp/activity', async (orig) => ({
  ...(await orig<typeof import('@/lib/mcp/activity')>()),
  readProjectActivity: async () => ({ scans: [], agentSession: false, triageRun: false, muteRulesApply: false, activating: false, unknown: false }),
}))

import { McpAccessDenied, McpLevelDenied, __resetRateLimiter, type ResolvedMcpToken } from '@/lib/mcpAuth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { SHARE_SECRET_FIELDS } from '@/lib/authz/projectReadView'
import {
  COLLABORATOR, OWNER, SHARED_PROJECT, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'
import { getReconSettings, graphSummary, listProjects, queryGraph, type McpContext } from './tools'
import { runGraphView } from './viewTools'
import { getAttackSurfaceOverview, getBlastRadius, listExploitPaths } from './analyticsTools'
import { listFindings, listMuted } from './findingTools'
import { searchMutedFindings } from './muteTools'
import { getFindingEvidence, getFindingTriage, getTriageStatus } from './triageTools'
import { preflightScopeCheck } from './engagementTools'
import { McpToolError } from './errors'

const SCOPES = ['recon:read', 'graph:cypher', 'triage:read'] as never
const tokenOf = (userId: string, sharedProjects: ResolvedMcpToken['sharedProjects'] = { allowlist: [] }): ResolvedMcpToken =>
  ({ tokenId: `tok-${userId}`, userId, tokenPrefix: 'rdmn_mcp_0a1b2c3d', name: 'agent', scopes: SCOPES, sharedProjects })
const ctxOf = (userId: string, sharedProjects?: ResolvedMcpToken['sharedProjects']): McpContext => ({ token: tokenOf(userId, sharedProjects) })

const VIEW = { id: 'view-1', projectId: SHARED_PROJECT, name: 'Domains', description: '', cypherQuery: 'MATCH (d:Domain) RETURN d' }

/** Every read tool that hands a tenant to the graph or the triage reads. */
const READS: Array<{ tool: string; call: (ctx: McpContext) => Promise<unknown> }> = [
  { tool: 'graph_summary', call: ctx => graphSummary(ctx, SHARED_PROJECT) },
  { tool: 'query_graph (cypher)', call: ctx => queryGraph(ctx, SHARED_PROJECT, { cypher: 'MATCH (d:Domain) RETURN d' }) },
  { tool: 'run_graph_view', call: ctx => runGraphView(ctx, SHARED_PROJECT, VIEW.id) },
  { tool: 'get_attack_surface_overview', call: ctx => getAttackSurfaceOverview(ctx, SHARED_PROJECT) },
  { tool: 'list_exploit_paths', call: ctx => listExploitPaths(ctx, SHARED_PROJECT) },
  { tool: 'get_blast_radius', call: ctx => getBlastRadius(ctx, SHARED_PROJECT) },
  { tool: 'list_findings', call: ctx => listFindings(ctx, SHARED_PROJECT) },
  { tool: 'list_muted_findings', call: ctx => listMuted(ctx, SHARED_PROJECT) },
  { tool: 'search_muted_findings', call: ctx => searchMutedFindings(ctx, SHARED_PROJECT, { facets: true }) },
  { tool: 'get_finding_triage', call: ctx => getFindingTriage(ctx, SHARED_PROJECT, 'f-1') },
  { tool: 'get_finding_evidence', call: ctx => getFindingEvidence(ctx, SHARED_PROJECT, 'f-1') },
  { tool: 'get_triage_status', call: ctx => getTriageStatus(ctx, SHARED_PROJECT) },
]

let agentBodies: Array<Record<string, unknown>> = []

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.tenants.length = 0
  h.agentCalls = 0
  h.stampAs = null
  agentBodies = []
  h.db.models.graphView = { findUnique: () => ({ ...VIEW }) }
  __resetRateLimiter()
  // graph_summary's census goes to the agent directly.
  vi.stubGlobal('fetch', async (_url: string, init?: { body?: string }) => {
    const body = JSON.parse(init?.body ?? '{}') as Record<string, unknown>
    agentBodies.push(body)
    if (typeof body.user_id === 'string') h.tenants.push({ via: 'fetch', userId: body.user_id })
    return new Response(JSON.stringify({ nodes: [], relationships: [] }), { status: 200 })
  })
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("each graph, finding, mute and triage tool returns the owner's rows to an opted-in collaborator's token", () => {
  test.each(READS)('$tool: the tenant handed on is the owner', async ({ call }) => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    await call(ctxOf(COLLABORATOR)).catch((err: unknown) => {
      // The access check and the result check must pass; what a double answers past them is not under test.
      expect(err).not.toBeInstanceOf(McpAccessDenied)
      expect((err as McpToolError).code).not.toBe('tenant_violation')
    })
    expect(h.tenants.length).toBeGreaterThan(0)
    expect(h.tenants.filter(t => t.userId !== OWNER)).toEqual([])
  })

  test.each(READS)("$tool: the owner's own token hands on the same tenant, as before", async ({ call }) => {
    await call(ctxOf(OWNER, null)).catch(() => undefined)
    expect(h.tenants.length).toBeGreaterThan(0)
    expect(h.tenants.every(t => t.userId === OWNER)).toBe(true)
  })

  test.each(READS)('$tool: a token that did not opt in is refused before any read', async ({ call }) => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    await expect(call(ctxOf(COLLABORATOR, null))).rejects.toThrow(new McpAccessDenied())
    expect(h.tenants).toEqual([])
    expect(agentBodies).toEqual([])
  })

  test("the result check holds the rows to the owner: a row stamped with the token's user is a violation", async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    h.stampAs = COLLABORATOR
    const err = await queryGraph(ctxOf(COLLABORATOR), SHARED_PROJECT, { cypher: 'MATCH (d:Domain) RETURN d' }).catch(e => e)
    expect(err).toBeInstanceOf(McpToolError)
    expect((err as McpToolError).code).toBe('tenant_violation')
  })

  test("the owner's rows reach the collaborator whole", async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    const out = await queryGraph(ctxOf(COLLABORATOR), SHARED_PROJECT, { cypher: 'MATCH (d:Domain) RETURN d' })
    expect(out.records).toEqual([{ n: { _kind: 'node', labels: ['Domain'], properties: { name: 'example.test', user_id: OWNER, project_id: SHARED_PROJECT } } }])
  })
})

describe('the Cypher tools on a shared project', () => {
  test('NL query refused on a shared project, raw cypher allowed with Raw data & files', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    const err = await queryGraph(ctxOf(COLLABORATOR), SHARED_PROJECT, { question: 'which hosts are exposed?' }).catch(e => e)
    expect(err).toBeInstanceOf(McpLevelDenied)
    expect((err as Error).message).toMatch(/model key/)
    expect(h.agentCalls).toBe(0)
    await expect(queryGraph(ctxOf(COLLABORATOR), SHARED_PROJECT, { cypher: 'MATCH (d:Domain) RETURN d' })).resolves.toMatchObject({ projectId: SHARED_PROJECT })
  })

  test("the owner's token still asks in natural language", async () => {
    await expect(queryGraph(ctxOf(OWNER, null), SHARED_PROJECT, { question: 'which hosts are exposed?' })).resolves.toMatchObject({ projectId: SHARED_PROJECT })
    expect(h.tenants).toEqual([{ via: 'nlQuery', userId: OWNER }])
  })

  // Step content is raw data (SH-30), and a caller-written answer can carry it in a column, a list of
  // values, or a map dressed as a node (the forged-map shape the 4.9 review found in format.ts): no
  // rule over the answer tells them apart, so below R* the query never runs.
  test.each([
    ['a plain node query', 'MATCH (d:Domain) RETURN d'],
    ['step content in a column', 'MATCH (s:ChainStep) RETURN s.thought AS t'],
    ['every property value as a list', 'MATCH (c:AttackChain)-->(s) RETURN [k IN keys(s) | s[k]] AS v'],
    ['a map forged as a node', "MATCH (s:ChainStep) RETURN {identity: {low: id(s), high: 0}, labels: ['Domain'], properties: properties(s)} AS n"],
    ['a map forged in the agent\'s node shape', "MATCH (s:ChainStep) RETURN {_kind: 'node', labels: ['Domain'], properties: {user_id: s.user_id, project_id: s.project_id, x: s.thought}} AS n"],
  ])('raw Cypher without Raw data & files is refused before it runs: %s', async (_what, cypher) => {
    shareWith(h.db, COLLABORATOR)
    const err = await queryGraph(ctxOf(COLLABORATOR), SHARED_PROJECT, { cypher }).catch(e => e)
    expect(err).toBeInstanceOf(McpLevelDenied)
    expect((err as Error).message).toMatch(/Raw data & files/)
    expect(h.agentCalls).toBe(0)
  })

  test('a saved view without Raw data & files is refused before its row is read or run', async () => {
    shareWith(h.db, COLLABORATOR)
    let viewRead = false
    h.db.models.graphView = { findUnique: () => { viewRead = true; return { ...VIEW } } }
    await expect(runGraphView(ctxOf(COLLABORATOR), SHARED_PROJECT, VIEW.id)).rejects.toBeInstanceOf(McpLevelDenied)
    expect(viewRead).toBe(false)
    expect(h.agentCalls).toBe(0)
  })

  test('the other read tools answer a share without Raw data', async () => {
    shareWith(h.db, COLLABORATOR)
    await getAttackSurfaceOverview(ctxOf(COLLABORATOR), SHARED_PROJECT).catch(() => undefined)
    await listFindings(ctxOf(COLLABORATOR), SHARED_PROJECT).catch(() => undefined)
    expect(h.tenants.map(t => t.via)).toEqual(['execCypher', 'listTriageFindings'])
  })
})

describe('no tool passes the token user as the tenant', () => {
  const HERE = path.dirname(fileURLToPath(import.meta.url))
  // The calls whose user id is the graph or triage tenant, and the shapes that hand it on.
  const TENANT_CALLS = [
    'execCypher', 'nlQuery', 'callTriage', 'listTriageFindings', 'listMutedFindings', 'listMutedPage', 'mutedFacets',
    'muteMany', 'unmuteMany', 'resolveMuted', 'releaseBroughtBack', 'legacyGraphDomains', 'seedProjectDomains',
    'markOutOfPolicy', 'assertTenantScoped', 'resolveAiHooks',
  ]
  const SHAPES: RegExp[] = [
    new RegExp(`\\b(${TENANT_CALLS.join('|')})\\(\\s*ctx\\.token\\.userId\\b`),
    new RegExp(`\\b(${TENANT_CALLS.join('|')})\\([^)]*,\\s*ctx\\.token\\.userId\\s*[,)]`),
    // readFinding, readEvidence, computePreflight, submitReview, recordVerdict... take a tenant object.
    /TriageTenant\s*=\s*\{\s*userId:\s*ctx\.token\.userId/,
    /(\(|^)\s*\{\s*userId:\s*ctx\.token\.userId\s*,\s*projectId\s*\}/,
    /\buser_id:\s*ctx\.token\.userId/,
    /\blastRunCounts\([^)]*userId:\s*ctx\.token\.userId/,
    /\bconst\s+(userId|tenant|owner)\s*=\s*ctx\.token\.userId\b/,
  ]

  function problems(source: string, file: string): string[] {
    const out: string[] = []
    for (const [i, line] of source.split('\n').entries()) {
      if (SHAPES.some(re => re.test(line))) out.push(`${file}:${i + 1}: ${line.trim()}`)
    }
    return out
  }

  test('every MCP tool file hands the access check\'s owner on, never the token\'s user', () => {
    const files = readdirSync(HERE).filter(f => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    expect(files).toContain('tools.ts')
    const found = files.flatMap(f => problems(readFileSync(path.join(HERE, f), 'utf8'), f))
    expect(found).toEqual([])
  })

  test('the scan catches the shapes it names', () => {
    expect(problems('    result = await execCypher(ctx.token.userId, projectId, cypher)', 'x.ts')).toHaveLength(1)
    expect(problems('  const tenant: TriageTenant = { userId: ctx.token.userId, projectId }', 'x.ts')).toHaveLength(1)
    expect(problems('      { userId: ctx.token.userId, projectId },', 'x.ts')).toHaveLength(1)
    expect(problems('        user_id: ctx.token.userId,', 'x.ts')).toHaveLength(1)
    expect(problems('  && await seedProjectDomains(addedOrgs, ctx.token.userId, args.projectId)', 'x.ts')).toHaveLength(1)
    expect(problems('  const userId = ctx.token.userId', 'x.ts')).toHaveLength(1)
    // The actor of a write is the token's user, and stays so.
    expect(problems('    actorId: ctx.token.userId,', 'x.ts')).toEqual([])
    expect(problems('        verdictBy: ctx.token.userId,', 'x.ts')).toEqual([])
  })
})

describe("a reader's project reads", () => {
  /** The project row as Prisma would answer the select it was given, the owner's secrets in it. */
  function projectRows(selects: Array<Record<string, unknown>>) {
    const stored: Record<string, unknown> = {
      id: SHARED_PROJECT, userId: OWNER, name: 'rbac-shared', updatedAt: new Date('2026-11-01T00:00:00Z'),
      httpxCustomHeaders: ['X-Api-Key: s3cr3t-owner-key'], katanaCustomHeaders: ['Cookie: session=owner'],
      naabuEnabled: true, scanModules: ['domain_discovery'], ipMode: false,
    }
    h.db.models.project = {
      findUnique: (args: unknown) => {
        const { where, select } = args as { where: { id: string }; select?: Record<string, unknown> }
        if (where.id !== SHARED_PROJECT) return null
        if (select) selects.push(select)
        return select ? Object.fromEntries(Object.keys(select).filter(k => k in stored).map(k => [k, stored[k]])) : { ...stored }
      },
    }
  }

  test('get_recon_settings: a collaborator neither loads nor gets the share: secret columns; the owner does', async () => {
    shareWith(h.db, COLLABORATOR)
    const selects: Array<Record<string, unknown>> = []
    projectRows(selects)
    const shared = await getReconSettings(ctxOf(COLLABORATOR), SHARED_PROJECT)
    const settingsSelect = selects.find(s => 'naabuEnabled' in s)!
    expect(SHARE_SECRET_FIELDS.filter(k => k in settingsSelect)).toEqual([])
    expect(JSON.stringify(shared)).not.toMatch(/s3cr3t-owner-key|session=owner/)
    expect(shared.settings).toHaveProperty('naabuEnabled', true)

    const own = await getReconSettings(ctxOf(OWNER, null), SHARED_PROJECT)
    expect(JSON.stringify(own)).toMatch(/s3cr3t-owner-key/)
  })

  test("preflight_scope_check: a collaborator gets no header list and no authorization record, only that one exists", async () => {
    shareWith(h.db, COLLABORATOR)
    projectRows([])
    h.db.models.engagementAuthorization = {
      findFirst: () => ({ id: 'auth-1', documentSha256: 'a'.repeat(64), documentKind: 'roe_document', sourceUrl: 'https://example.test/private-programme', programHandle: 'h', issuedAt: null, recordedAt: new Date(), recordedVia: 'mcp', recordedByTokenId: 't', summary: 'scope letter' }),
      count: () => 1,
    }
    const shared = await preflightScopeCheck(ctxOf(COLLABORATOR), SHARED_PROJECT)
    expect(shared.authorization).toBeNull()
    expect(shared).toHaveProperty('authorizationWithheld', true)
    expect(JSON.stringify(shared)).not.toMatch(/s3cr3t-owner-key|session=owner|private-programme/)

    const own = await preflightScopeCheck(ctxOf(OWNER, null), SHARED_PROJECT)
    expect(own.authorization).toMatchObject({ id: 'auth-1' })
    expect(own).not.toHaveProperty('authorizationWithheld')
  })
})

describe('list_projects', () => {
  const OWN_ROW = { id: 'P-bob', name: 'mine', userId: COLLABORATOR, user: { name: 'Bob', email: 'bob@example.test' } }
  const SHARED_ROW = {
    id: SHARED_PROJECT, name: 'rbac-shared', userId: OWNER, user: { name: 'Alice', email: 'alice@example.test' }, collaborators: [{ rawData: true }],
  }
  const common = { targetDomain: 'example.test', targetIps: [], ipMode: false, domainBatchMode: false, updatedAt: new Date(), domainBatchHosts: [], subdomainList: [] }

  function rowsAnswer(rows: Array<Record<string, unknown>>, seen: Array<Record<string, unknown>>) {
    h.db.models.project = { findMany: (args: unknown) => { seen.push(args as Record<string, unknown>); return rows.map(r => ({ ...common, ...r })) } }
  }

  test('a token that did not opt in lists its own projects only', async () => {
    const seen: Array<Record<string, unknown>> = []
    rowsAnswer([OWN_ROW], seen)
    const out = await listProjects(ctxOf(COLLABORATOR, null))
    expect(seen[0].where).toEqual({ userId: COLLABORATOR })
    expect(out.projects.map(p => p.id)).toEqual(['P-bob'])
    expect(out.projects[0]).toMatchObject({ myAccess: { level: 'owner', via: 'owner' } })
  })

  test('an opted-in token lists owned ∪ shared, each with its myAccess, and no owner id', async () => {
    const seen: Array<Record<string, unknown>> = []
    rowsAnswer([OWN_ROW, SHARED_ROW], seen)
    const out = await listProjects(ctxOf(COLLABORATOR))
    expect(JSON.stringify(seen[0].where)).toContain('collaborators')
    expect(out.projects.map(p => p.id)).toEqual(['P-bob', SHARED_PROJECT])
    const shared = out.projects[1] as Record<string, unknown>
    expect(shared.myAccess).toEqual({ level: 'read', toggles: { rawData: true }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' } })
    for (const p of out.projects as Array<Record<string, unknown>>) {
      expect(p).not.toHaveProperty('userId')
      expect(p).not.toHaveProperty('user')
      expect(p).not.toHaveProperty('collaborators')
    }
  })

  test('the allowlist narrows the shared projects, never the owned ones', async () => {
    const seen: Array<Record<string, unknown>> = []
    rowsAnswer([OWN_ROW], seen)
    await listProjects(ctxOf(COLLABORATOR, { allowlist: ['P-x'] }))
    const where = seen[0].where as { OR: Array<Record<string, unknown>> }
    expect(where.OR[0]).toEqual({ userId: COLLABORATOR })
    expect(JSON.stringify(where.OR[1])).toContain('"in":["P-x"]')
    expect(JSON.stringify(where.OR[1])).toContain('collaborators')
  })

  test('with the sharing switch off the rows come back as before: own projects, no myAccess (DV-30)', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    const seen: Array<Record<string, unknown>> = []
    rowsAnswer([OWN_ROW], seen)
    const out = await listProjects(ctxOf(COLLABORATOR))
    expect(seen[0].where).toEqual({ userId: COLLABORATOR })
    expect(out.projects[0]).not.toHaveProperty('myAccess')
    expect(out.projects[0]).not.toHaveProperty('userId')
  })
})

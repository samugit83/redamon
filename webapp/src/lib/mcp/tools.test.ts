/**
 * The MCP read tools.
 *
 * Two rules dominate these tests, because breaking either produces a FALSE
 * NEGATIVE in a security tool rather than a visible error:
 *
 *  - a dependency failure is never an empty result. "Nothing found" and
 *    "could not ask" must not look the same to an agent writing a report.
 *  - ownership is checked before anything else, and a foreign project is
 *    indistinguishable from a missing one.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

import { isReadableProjectField } from '@/lib/mcpReadableFields'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  findManyProjects: vi.fn(),
  findVersion: vi.fn(),
  agentState: vi.fn(),
  liveTriageRun: vi.fn(),
  liveNodeFilterRun: vi.fn(),
  liveGraphWriters: vi.fn(),
  findRemediations: vi.fn(),
  countRemediations: vi.fn(),
  orchestratorFetch: vi.fn(),
  findScanJob: vi.fn(),
  isActivating: vi.fn(),
  /** The raw `/system/active-scans` body, cross-project exactly as it ships. */
  activeScans: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      findMany: (...a: unknown[]) => h.findManyProjects(...a),
    },
    scanVersion: { findFirst: (...a: unknown[]) => h.findVersion(...a) },
    scanJob: { findFirst: (...a: unknown[]) => h.findScanJob(...a) },
    remediation: {
      findMany: (...a: unknown[]) => h.findRemediations(...a),
      count: (...a: unknown[]) => h.countRemediations(...a),
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.isActivating(...a) }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => h.liveTriageRun(...a) }))
vi.mock('@/lib/nodeFilterRun', () => ({ findLiveNodeFilterRun: (...a: unknown[]) => h.liveNodeFilterRun(...a) }))
vi.mock('@/lib/agentSessions', () => ({ checkAgentSessions: (...a: unknown[]) => h.agentState(...a) }))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: (...a: unknown[]) => h.liveGraphWriters(...a),
}))

import { McpScopeError, McpAccessDenied, __resetRateLimiter, __resetLlmBudget } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { __resetSchemaCache } from './graphClient'
import { __resetToolboxCache } from './kaliClient'
import { readProjectActivity } from './activity'
import {
  getProjectActivity,
  getReconSettings,
  getReconStatus,
  listRemediations,
  graphSchema,
  graphSummary,
  kaliToolbox,
  listProjects,
  queryGraph,
  resolveLiveGraphState,
  type McpContext,
} from './tools'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const ownNode = (label: string) => ({
  _kind: 'node', labels: [label], properties: { user_id: 'owner', project_id: 'p1' },
})

/** One `/system/active-scans` row, in the orchestrator's own snake_case shape. */
const scanRow = (over: Record<string, unknown> = {}) => ({
  kind: 'full_recon', project_id: 'p1', run_id: '', tool_id: '', status: 'running',
  current_phase: 'port_scan', current_group: null, group_number: null,
  total_groups: null, started_at: '2026-09-14T10:00:00Z',
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  __resetRateLimiter()
  __resetLlmBudget()
  __resetSchemaCache()
  __resetToolboxCache()
  vi.stubGlobal('fetch', h.fetch)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.findManyProjects.mockResolvedValue([{ id: 'p1', name: 'Target', targetDomain: 'x.tld' }])
  h.findVersion.mockResolvedValue({ id: 'v3', seq: 3, label: 'Scan 3', createdAt: new Date() })
  h.isActivating.mockResolvedValue(false)
  h.liveNodeFilterRun.mockResolvedValue(null)
  h.agentState.mockResolvedValue('idle')
  h.liveTriageRun.mockResolvedValue(null)
  h.liveGraphWriters.mockResolvedValue(null)
  h.findRemediations.mockResolvedValue([])
  h.countRemediations.mockResolvedValue(0)
  h.activeScans.mockReturnValue([])
  // Dispatch on the path: get_recon_status and the activity helper both go
  // through orchestratorFetch, and they are different endpoints.
  h.orchestratorFetch.mockImplementation(async (url: unknown) => {
    if (String(url).includes('/system/active-scans')) {
      return { ok: true, json: async () => ({ scans: h.activeScans() }) }
    }
    return { ok: true, json: async () => ({ status: 'idle' }) }
  })
})

// --- list_projects -------------------------------------------------------------

describe('list_projects', () => {
  test('is scoped to the token owner, so other ids cannot be enumerated', async () => {
    await listProjects(ctx())
    expect(h.findManyProjects).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'owner' } })
    )
  })

  test('needs recon:read', async () => {
    await expect(listProjects(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('never selects a credential-bearing column', async () => {
    await listProjects(ctx())
    const select = h.findManyProjects.mock.calls[0][0].select
    for (const key of Object.keys(select)) {
      expect(key).not.toMatch(/Token|ApiKey|Secret|Password|authProfile/)
    }
  })

  test('does not fan out to the orchestrator', async () => {
    // That is what get_recon_status is for; a list must stay cheap.
    await listProjects(ctx())
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('reports the derived enumeration counts and a one-line scope, never the raw lists', async () => {
    h.findManyProjects.mockResolvedValue([
      { id: 'b', name: 'batch', targetDomain: '', targetIps: [], ipMode: false, domainBatchMode: true,
        updatedAt: new Date(), subdomainList: [],
        domainBatchHosts: ['*.example.com', 'www.acme.co.uk', '*.example.org'] },
      { id: 's', name: 'single', targetDomain: 'example.net', targetIps: [], ipMode: false, domainBatchMode: false,
        updatedAt: new Date(), subdomainList: ['.'], domainBatchHosts: [] },
    ])
    const { projects } = await listProjects(ctx())
    expect(projects.map(p => [p.wildcardDomainCount, p.enumerateGroupCount, p.scopeSummary])).toEqual([
      [2, 2, '3 scope groups across 3 domains (2 enumerated)'],
      [0, 1, '*.example.net (enumerated, +root)'],
    ])
    expect(projects[0]).not.toHaveProperty('domainBatchHosts')
    expect(projects[0]).not.toHaveProperty('subdomainList')
  })
})

// --- get_recon_status ----------------------------------------------------------

describe('get_recon_status', () => {
  test('returns the orchestrator status', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'running', current_phase: 'port_scan' }),
    })
    const r = await getReconStatus(ctx(), 'p1')
    expect(r).toMatchObject({ status: 'running', currentPhase: 'port_scan', failed: false })
  })

  // REGRESSION (e2e finding: a canceled scan was indistinguishable from no scan).
  // The orchestrator only knows the RUNNING container. Once it exits, its status
  // is a flat `idle` with null timestamps whether the scan completed, failed,
  // was canceled at 10%, or never ran at all. Every scenario that reasons about
  // a PAST scan - nightly monitoring diffing last night's run, CI gating on a
  // fresh scan, an auditor asking for proof of coverage - was reading that
  // `idle` as success. The durable answer is in ScanJob, and this surface was
  // the only one not consulting it.
  describe('REGRESSION: the last run is reported, not just the live one', () => {
    test('a canceled run is named as canceled, with its timestamps', async () => {
      h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
      h.findScanJob.mockResolvedValue({
        status: 'canceled',
        startedAt: new Date('2026-09-14T13:52:26.441Z'),
        finishedAt: new Date('2026-09-14T13:54:09.296Z'),
        trigger: 'manual',
        mode: 'new',
        nodeCount: 9,
      })
      const r = await getReconStatus(ctx(), 'p1') as Record<string, never>

      expect(r.status).toBe('idle')
      expect(r.lastRun).toMatchObject({
        status: 'canceled',
        completed: false,
        trigger: 'manual',
        mode: 'new',
        nodeCount: 9,
        startedAt: '2026-09-14T13:52:26.441Z',
        finishedAt: '2026-09-14T13:54:09.296Z',
      })
    })

    test('a completed run is distinguishable from a canceled one', async () => {
      h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
      h.findScanJob.mockResolvedValue({
        status: 'completed',
        startedAt: new Date('2026-09-14T10:00:00.000Z'),
        finishedAt: new Date('2026-09-14T10:40:00.000Z'),
        trigger: 'scheduled',
        mode: 'new',
        nodeCount: 812,
      })
      const r = await getReconStatus(ctx(), 'p1') as Record<string, never>
      expect(r.lastRun).toMatchObject({ status: 'completed', completed: true })
    })

    test('a project that has never been scanned says so, rather than idling', async () => {
      h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
      h.findScanJob.mockResolvedValue(null)
      const r = await getReconStatus(ctx(), 'p1') as Record<string, never>
      expect(r.lastRun).toBeNull()
    })

    test('only this project\'s FULL recon runs are consulted', async () => {
      h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'idle' }) })
      h.findScanJob.mockResolvedValue(null)
      await getReconStatus(ctx(), 'p1')
      expect(h.findScanJob).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { projectId: 'p1', kind: 'full_recon' },
          orderBy: { createdAt: 'desc' },
        })
      )
    })

    // A history read must never be the reason a status call fails: the live
    // status is the part the caller asked for.
    test('a history read that throws does not take the live status down with it',
      async () => {
        h.orchestratorFetch.mockResolvedValue({
          ok: true, json: async () => ({ status: 'running', current_phase: 'vuln_scan' }),
        })
        h.findScanJob.mockRejectedValue(new Error('postgres is down'))
        const r = await getReconStatus(ctx(), 'p1') as Record<string, never>
        expect(r.status).toBe('running')
        expect(r.lastRun).toBeUndefined()
      })
  })

  // REGRESSION (audit finding F5): the raw ReconState carries `container_id`
  // and an `error` populated with raw exception text. A Docker SDK failure
  // embeds the deployment's absolute HOST PATHS and image names, and returning
  // it verbatim handed an untrusted agent reconnaissance about the host, then
  // put it in a model's context. errors.ts forbids exactly that everywhere else.
  test('REGRESSION: the raw orchestrator body is NOT passed through', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'error',
        container_id: 'a1b2c3d4e5f6',
        error: 'invalid mount config for type "bind": bind source path does not '
             + 'exist: /home/operator/deploy/redamon/recon',
      }),
    })
    const r = await getReconStatus(ctx(), 'p1')
    const serialised = JSON.stringify(r)

    expect(serialised).not.toContain('/home/operator')
    expect(serialised).not.toContain('a1b2c3d4e5f6')
    expect(serialised).not.toMatch(/bind source path/)
    // The FACT of failure still reaches the caller; only the detail does not.
    expect(r.failed).toBe(true)
    expect(r.status).toBe('error')
  })

  test('an unreachable orchestrator is "unknown", NEVER "not running"', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(getReconStatus(ctx(), 'p1')).rejects.toThrow(/unknown/i)
  })

  test('a non-200 is "unknown" too', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 502, json: async () => ({}) })
    await expect(getReconStatus(ctx(), 'p1')).rejects.toThrow(/unknown/i)
  })

  test("another user's project is refused before the orchestrator is called", async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(getReconStatus(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

// --- get_recon_settings ---------------------------------------------------------

describe('get_recon_settings', () => {
  test('returns only the allowlisted subset', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, nucleiEnabled: true })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.settings).toEqual({ naabuThreads: 25, nucleiEnabled: true })
  })

  test('the prisma select is built FROM the registry, so no secret is loaded', async () => {
    // The shape of this check changed with the recon settings registry, and the
    // change is deliberate. A `*DockerImage` column IS selected now, because it
    // is open and the runtime pins a non-allowlisted value at scan start; the
    // scope and the Rules of Engagement ARE selected, because an agent that
    // cannot see its own ceiling cannot verify it is inside it.
    //
    // What must never be selected is what is withheld from every read on this
    // surface, and that is a registry query rather than a pattern.
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({})
    await getReconSettings(ctx(), 'p1')

    const select = h.findProject.mock.calls[1][0].select
    const withheld = Object.keys(select).filter(k => !isReadableProjectField(k))
    expect(withheld, 'get_recon_settings selects a column withheld from every read').toEqual([])

    // The named credentials and personal data, by name.
    for (const secret of [
      'cypherfixGithubToken', 'graphqlAuthValue', 'ownershipToken',
      'roeClientContactEmail', 'roeEmergencyContact', 'roeDocumentData', 'roeRawText',
    ]) {
      expect(select, `${secret} must not be selected`).not.toHaveProperty(secret)
    }
  })

  test('an IP project lists the toggles its hostname mode forces as effective_overrides (D-20)', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ ipMode: true, ipHostnameMode: 'ip_only', shodanReverseDns: true })
    const r = await getReconSettings(ctx(), 'p1') as Record<string, unknown>
    expect(r.effective_overrides).toEqual([
      { key: 'tlsxRevPtrSni', value: false, reason: 'forced by Hostnames on target IPs: ip_only' },
      { key: 'shodanReverseDns', value: false, reason: 'forced by Hostnames on target IPs: ip_only' },
      { key: 'vhostSniUseGraphCandidates', value: false, reason: 'forced by Hostnames on target IPs: ip_only' },
    ])
    // The stored value is still echoed: settings report what was written.
    expect((r.settings as Record<string, unknown>).shodanReverseDns).toBe(true)
    const select = h.findProject.mock.calls[1][0].select
    expect(select.ipMode && select.ipHostnameMode).toBe(true)
  })

  test('a recording mode forces only the reverse-PTR SNI; a domain project nothing', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ ipMode: true, ipHostnameMode: 'record_filter' })
    const r = await getReconSettings(ctx(), 'p1') as Record<string, unknown>
    expect(r.effective_overrides).toEqual([
      { key: 'tlsxRevPtrSni', value: false, reason: 'forced by Hostnames on target IPs: record_filter' },
    ])
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ ipMode: false, ipHostnameMode: 'ip_only' })
    expect(await getReconSettings(ctx(), 'p1')).not.toHaveProperty('effective_overrides')
  })
})

// --- graph_summary ----------------------------------------------------------------

describe('graph_summary', () => {
  /**
   * graph_summary makes TWO agent calls: the fixed `summary` op for the counts,
   * and one counted Cypher for the stale total. They are told apart by op, so a
   * test can fail one without failing the other.
   */
  const okSummary = (stale?: number | 'fail') =>
    h.fetch.mockImplementation(async (_url: unknown, init: { body: string }) => {
      const body = JSON.parse(init.body) as { op?: string }
      if (body.op === 'summary') {
        return {
          ok: true,
          json: async () => ({
            nodes: [{ label: 'IP', count: 12 }],
            relationships: [{ type: 'RESOLVES_TO', count: 8 }],
          }),
        }
      }
      if (stale === 'fail') throw new Error('ECONNREFUSED')
      return { ok: true, json: async () => ({ records: stale === undefined ? [] : [{ stale }] }) }
    })

  test('returns counts per label and the current version', async () => {
    okSummary()
    const r = await graphSummary(ctx(), 'p1')
    expect(r.nodes).toEqual([{ label: 'IP', count: 12 }])
    expect(r.scanVersion).toMatchObject({ seq: 3 })
  })

  test('it uses the FIXED summary op, not caller-supplied Cypher', async () => {
    okSummary()
    await graphSummary(ctx(), 'p1')
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.op).toBe('summary')
    expect(body.cypher).toBeUndefined()
  })

  test('it carries the FULL tenant key, not project_id alone', async () => {
    okSummary()
    await graphSummary(ctx(), 'p1')
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.user_id).toBe('owner')
    expect(body.project_id).toBe('p1')
  })

  test('a graph failure is a plain failure, NEVER an empty summary', async () => {
    // An empty summary reads as "nothing has ever been scanned", which is the
    // false negative graph_summary exists to prevent.
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(graphSummary(ctx(), 'p1')).rejects.toThrow(/unavailable/i)
  })

  test('a non-200 from the agent also fails rather than returning zeros', async () => {
    h.fetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) })
    await expect(graphSummary(ctx(), 'p1')).rejects.toBeInstanceOf(McpToolError)
  })

  test('a scan in flight is reported, with a warning', async () => {
    okSummary()
    h.activeScans.mockReturnValue([scanRow()])
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('scan_running')
    expect(r.warning).toMatch(/not settled/i)
  })

  test('an activation in flight is reported, with a warning', async () => {
    okSummary()
    h.isActivating.mockResolvedValue(true)
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('activating')
    expect(r.warning).toBeTruthy()
  })

  test('REGRESSION: a Mute Rules apply is not "stable": the counts exclude what it is muting', async () => {
    okSummary()
    h.liveNodeFilterRun.mockResolvedValue({ id: 'nf1', revision: 3 })
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('agent_writing')
    expect(r.warning).toMatch(/Mute Rules apply/)
  })

  test('a settled graph carries no warning', async () => {
    okSummary()
    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('stable')
    expect(r.warning).toBeUndefined()
  })

  test('the stale total is reported when it can be read', async () => {
    okSummary(7)
    expect((await graphSummary(ctx(), 'p1')).hiddenFromCounts).toEqual({ stale: 7 })
  })

  test('a readable stale total of zero is still reported', async () => {
    // Zero is a real answer here and means "nothing is hidden"; it is only a
    // lie when it stands in for "could not read".
    okSummary(0)
    expect((await graphSummary(ctx(), 'p1')).hiddenFromCounts).toEqual({ stale: 0 })
  })

  test('an unreadable stale total OMITS the key rather than reporting 0', async () => {
    okSummary('fail')
    const r = await graphSummary(ctx(), 'p1')
    expect(r).not.toHaveProperty('hiddenFromCounts')
    // The counts themselves are still true, so the tool degrades by dropping an
    // explanatory field rather than by refusing to answer.
    expect(r.nodes).toEqual([{ label: 'IP', count: 12 }])
  })

  test('no muted count is ever emitted', async () => {
    // Deferred deliberately: the only implementation available today would make
    // this tool fetch every muted finding on every call.
    okSummary(3)
    expect(JSON.stringify(await graphSummary(ctx(), 'p1'))).not.toMatch(/muted/i)
  })

  describe('a lost graph reads as lost, not as never scanned (plan 09.4)', () => {
    beforeEach(() => h.findScanJob.mockResolvedValue(null))
    const census = (nodes: { label: string; count: number }[]) =>
      h.fetch.mockImplementation(async (_url: unknown, init: { body: string }) => {
        const body = JSON.parse(init.body) as { op?: string }
        if (body.op === 'summary') return { ok: true, json: async () => ({ nodes, relationships: [] }) }
        return { ok: true, json: async () => ({ records: [{ stale: 0 }] }) }
      })
    const versions = (current: number | null, latestSaved: { seq: number; nodeCount: number } | null) =>
      h.findVersion.mockImplementation(async (args: { where: Record<string, unknown> }) =>
        args.where.isCurrent
          ? { id: 'v4', seq: 4, label: 'Scan 4', createdAt: new Date(), nodeCount: current }
          : latestSaved)

    test('a saved version held nodes and the live census is empty: graph_data_missing', async () => {
      census([])
      versions(null, { seq: 3, nodeCount: 5000 })
      const r = await graphSummary(ctx(), 'p1')
      expect(r.liveGraphState).toBe('stable')
      expect(r.warning).toBe('graph_data_missing')
      expect(r.graphDataMissing).toMatchObject({ liveNodes: 0, expectedNodes: 5000, basis: 'scan_version', versionSeq: 3 })
      expect(r.graphDataMissing?.detail).toMatch(/UNKNOWN/)
    })

    test('a census below a tenth of the version it should hold also warns', async () => {
      census([{ label: 'Domain', count: 1 }, { label: 'IP', count: 300 }])
      versions(5000, null)
      const r = await graphSummary(ctx(), 'p1')
      expect(r.warning).toBe('graph_data_missing')
      expect(r.graphDataMissing).toMatchObject({ liveNodes: 301, expectedNodes: 5000, versionSeq: 4 })
    })

    test('a census at or above a tenth does not', async () => {
      census([{ label: 'IP', count: 600 }])
      versions(5000, null)
      const r = await graphSummary(ctx(), 'p1')
      expect(r.warning).toBeUndefined()
      expect(r).not.toHaveProperty('graphDataMissing')
    })

    test('no node count anywhere and no completed scan: an empty graph is just empty', async () => {
      census([])
      versions(null, null)
      const r = await graphSummary(ctx(), 'p1')
      expect(r.warning).toBeUndefined()
    })

    test('an empty graph after a completed full scan warns even with no saved version', async () => {
      census([])
      versions(null, null)
      h.findScanJob.mockResolvedValue({ finishedAt: new Date('2026-10-24T10:00:00Z') })
      const r = await graphSummary(ctx(), 'p1')
      expect(r.warning).toBe('graph_data_missing')
      expect(r.graphDataMissing).toMatchObject({ liveNodes: 0, expectedNodes: null, basis: 'completed_scan' })
      const where = h.findScanJob.mock.calls[0][0].where
      expect(where).toMatchObject({ projectId: 'p1', kind: 'full_recon', status: 'completed' })
    })

    test('while something rewrites the graph, the state warning stands and nothing is called lost', async () => {
      census([])
      versions(null, { seq: 3, nodeCount: 5000 })
      h.activeScans.mockReturnValue([scanRow()])
      const r = await graphSummary(ctx(), 'p1')
      expect(r.liveGraphState).toBe('scan_running')
      expect(r.warning).toMatch(/not settled/i)
      expect(r).not.toHaveProperty('graphDataMissing')
    })

    test('a history that cannot be read never fails the tool and never invents a warning', async () => {
      census([])
      h.findVersion.mockImplementation(async (args: { where: Record<string, unknown> }) => {
        if (args.where.isCurrent) return { id: 'v4', seq: 4, label: 'Scan 4', createdAt: new Date(), nodeCount: null }
        throw new Error('db down')
      })
      const r = await graphSummary(ctx(), 'p1')
      expect(r.nodes).toEqual([])
      expect(r.warning).toBeUndefined()
    })

    test('the version node count is used, not returned', async () => {
      census([{ label: 'IP', count: 12 }])
      versions(20, null)
      expect((await graphSummary(ctx(), 'p1')).scanVersion).not.toHaveProperty('nodeCount')
    })
  })

  describe('the coverage block (plan 09.2)', () => {
    const withCoverage = (coverage: unknown) =>
      h.fetch.mockImplementation(async (_url: unknown, init: { body: string }) => {
        const body = JSON.parse(init.body) as { op?: string }
        if (body.op === 'summary') {
          return {
            ok: true,
            json: async () => ({ nodes: [{ label: 'BaseURL', count: 6 }], relationships: [], coverage }),
          }
        }
        return { ok: true, json: async () => ({ records: [{ stale: 0 }] }) }
      })

    test('per module, the hosts in each state and the live ones never looked at', async () => {
      withCoverage({
        js_recon: { recorded: true, complete: 3, partial: 1, no_input: 1, failed: 0, not_scanned: 1 },
        nuclei: { recorded: false },
      })
      const r = await graphSummary(ctx(), 'p1')
      expect(r.coverage).toEqual({
        js_recon: { recorded: true, complete: 3, partial: 1, no_input: 1, failed: 0, not_scanned: 1 },
        nuclei: { recorded: false },
      })
    })

    test('it costs no round trip of its own: it rides the summary op', async () => {
      withCoverage({ js_recon: { recorded: false }, nuclei: { recorded: false } })
      await graphSummary(ctx(), 'p1')
      const ops = h.fetch.mock.calls.map(c => JSON.parse(c[1].body).op)
      expect(ops).toEqual(['summary', 'cypher'])
    })

    test('an agent that sent no block (older image, or the count failed) omits the key, never zeros', async () => {
      okSummary(0)
      expect(await graphSummary(ctx(), 'p1')).not.toHaveProperty('coverage')
    })

    test('only the known modules and counts pass through', async () => {
      withCoverage({
        js_recon: { recorded: true, complete: '2', partial: 0, no_input: 0, failed: 0, not_scanned: 0, url: 'x' },
        nuclei: { recorded: false },
        evil: { recorded: true, complete: 1 },
      })
      const r = await graphSummary(ctx(), 'p1')
      expect(r.coverage).toEqual({
        js_recon: { recorded: true, complete: 2, partial: 0, no_input: 0, failed: 0, not_scanned: 0 },
        nuclei: { recorded: false },
      })
    })
  })
})

// =============================================================================
// REGRESSION: graph_summary reported `stable` during five of the seven scan
// kinds. describeScanWriters covers full and partial recon only; the GVM,
// GitHub Secret Hunt, TruffleHog, supply-chain and AI attack-surface scans all
// write finding nodes into the live graph and were invisible here. The wiki
// documents `stable` as "the counts are trustworthy", so an agent asking for a
// malicious-package count DURING the supply-chain scan that produces those
// nodes got a partial count stamped trustworthy.
// =============================================================================

describe('REGRESSION: every scan kind moves the live-graph state', () => {
  for (const kind of [
    'full_recon', 'gvm', 'github_hunt', 'supply_chain',
    'trufflehog', 'partial_recon', 'ai_attack',
  ]) {
    test(`${kind} reports scan_running, never stable`, async () => {
      h.activeScans.mockReturnValue([scanRow({ kind })])
      expect(await resolveLiveGraphState('p1')).toBe('scan_running')
    })
  }
})

describe('resolveLiveGraphState', () => {
  test('activation outranks a running scan', async () => {
    h.isActivating.mockResolvedValue(true)
    h.activeScans.mockReturnValue([scanRow()])
    expect(await resolveLiveGraphState('p1')).toBe('activating')
  })

  test('an unreachable orchestrator is "unknown", NEVER stable', async () => {
    // The rule the whole surface exists to protect: a dependency failure is not
    // an empty result. The webapp's own Activity view answers [] here, which is
    // right for a UI with database fallbacks and a false negative on this one.
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  // REGRESSION: a 200 carrying valid JSON whose `scans` key is missing or
  // renamed was substituted with [] and NOT flagged unknown, so graph_summary
  // reported `stable` - "the counts are trustworthy" - during a live scan.
  // That is the exact false negative FIX-0 closed, re-entered through schema
  // drift instead of through a missing scan kind.
  test('REGRESSION: a 200 with no scans key is "unknown", not "nothing running"', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({}) })
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  test('REGRESSION: a 200 whose scans key is not an array is "unknown"', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ scans: 'none' }) })
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  test('a non-200 from active-scans is "unknown" too', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) })
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  test('unknown outranks a running scan, because it must never read as stable', async () => {
    h.activeScans.mockReturnValue([scanRow()])
    h.liveTriageRun.mockRejectedValue(new Error('db down'))
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  test('a live agent session is agent_writing', async () => {
    h.agentState.mockResolvedValue('running')
    expect(await resolveLiveGraphState('p1')).toBe('agent_writing')
  })

  test('a session flag the agent could not confirm is agent_writing, never stable (C-8)', async () => {
    h.agentState.mockResolvedValue('unverified')
    expect(await resolveLiveGraphState('p1')).toBe('agent_writing')
  })

  test('a live triage run is agent_writing', async () => {
    h.liveTriageRun.mockResolvedValue({ id: 'r1', status: 'running' })
    expect(await resolveLiveGraphState('p1')).toBe('agent_writing')
  })

  test('a Mute Rules apply is agent_writing: counts move while it mutes page by page', async () => {
    h.liveNodeFilterRun.mockResolvedValue({ id: 'nf1', revision: 3 })
    expect(await resolveLiveGraphState('p1')).toBe('agent_writing')
  })

  test('an unreadable Mute Rules apply state is unknown, never stable', async () => {
    h.liveNodeFilterRun.mockRejectedValue(new Error('db down'))
    expect(await resolveLiveGraphState('p1')).toBe('unknown')
  })

  test('a running scan outranks an agent session', async () => {
    h.activeScans.mockReturnValue([scanRow()])
    h.agentState.mockResolvedValue('running')
    expect(await resolveLiveGraphState('p1')).toBe('scan_running')
  })

  test('nothing running is stable', async () => {
    expect(await resolveLiveGraphState('p1')).toBe('stable')
  })
})

describe('another project\'s activity never leaks', () => {
  test('a foreign active scan does not set the state', async () => {
    // /system/active-scans is cross-project by design: it returns every user's
    // running scans. The operator's Activity view deliberately shows a count of
    // other people's work; on a token surface that is cross-tenant metadata.
    h.activeScans.mockReturnValue([scanRow({ project_id: 'someone-elses-project' })])
    expect(await resolveLiveGraphState('p1')).toBe('stable')
  })

  test("a foreign project's id is never returned", async () => {
    h.activeScans.mockReturnValue([
      scanRow({ project_id: 'someone-elses-project', kind: 'gvm' }),
      scanRow({ project_id: 'p1' }),
    ])
    const activity = await readProjectActivity('p1')
    expect(activity.scans).toHaveLength(1)
    expect(JSON.stringify(activity)).not.toContain('someone-elses-project')
  })

  test('and is not reported as a count either', async () => {
    h.activeScans.mockReturnValue([
      scanRow({ project_id: 'a' }), scanRow({ project_id: 'b' }),
    ])
    const activity = await readProjectActivity('p1')
    expect(activity.scans).toEqual([])
    expect(activity.unknown).toBe(false)
  })
})

// --- graph_schema -------------------------------------------------------------------

describe('graph_schema', () => {
  test('returns the schema document', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'NODE TYPES ...' }) })
    expect(await graphSchema(ctx())).toEqual({ schema: 'NODE TYPES ...' })
  })

  test('it is cached, so it cannot fail on a dependency after the first read', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'NODE TYPES ...' }) })
    await graphSchema(ctx())
    h.fetch.mockRejectedValue(new Error('agent down'))
    expect(await graphSchema(ctx())).toEqual({ schema: 'NODE TYPES ...' })
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  test('it takes no projectId, so it exposes no tenant data', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ schema: 'x' }) })
    await graphSchema(ctx())
    expect(h.findProject).not.toHaveBeenCalled()
  })
})

// --- kali_toolbox -------------------------------------------------------------------

describe('kali_toolbox', () => {
  const catalogue = '**Exploitation:** msfvenom, sqlmap ...'

  test('returns the catalogue', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ toolbox: catalogue }) })
    expect(await kaliToolbox(ctx())).toEqual({ toolbox: catalogue })
  })

  test('needs recon:read', async () => {
    await expect(kaliToolbox(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('it is cached, so it cannot fail on a dependency after the first read', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ toolbox: catalogue }) })
    await kaliToolbox(ctx())
    h.fetch.mockRejectedValue(new Error('agent down'))
    expect(await kaliToolbox(ctx())).toEqual({ toolbox: catalogue })
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  test('it takes no projectId, so it exposes no tenant data', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ toolbox: catalogue }) })
    await kaliToolbox(ctx())
    expect(h.findProject).not.toHaveBeenCalled()
  })

  test('it reads the catalogue, never the kali-sandbox', async () => {
    // The webapp holds no MCP_AUTH_TOKEN and must not learn to reach the
    // target-facing tier: the only call this makes is to the agent.
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ toolbox: catalogue }) })
    await kaliToolbox(ctx())
    const url = String(h.fetch.mock.calls[0][0])
    expect(url).toContain('/kali/toolbox')
    expect(url).not.toContain('kali-sandbox')
  })

  test('an unreachable agent is an error, never an empty catalogue', async () => {
    // An empty list reads as "this image ships no tools", which would have an
    // agent report a capability gap that does not exist.
    h.fetch.mockRejectedValue(new Error('agent down'))
    await expect(kaliToolbox(ctx())).rejects.toBeInstanceOf(McpToolError)
  })

  test('an empty catalogue from the agent is an error too', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ toolbox: '' }) })
    await expect(kaliToolbox(ctx())).rejects.toBeInstanceOf(McpToolError)
  })
})

// --- query_graph ---------------------------------------------------------------------

describe('query_graph argument handling', () => {
  test('exactly one of question or cypher is required', async () => {
    await expect(queryGraph(ctx(), 'p1', {})).rejects.toThrow(/exactly one/i)
    await expect(queryGraph(ctx(), 'p1', { question: 'q', cypher: 'MATCH (n:IP) RETURN n' }))
      .rejects.toThrow(/exactly one/i)
  })

  test('raw cypher needs the graph:cypher scope', async () => {
    await expect(queryGraph(ctx(['recon:read']), 'p1', { cypher: 'MATCH (n:IP) RETURN n' }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('a natural-language question needs only recon:read', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await expect(queryGraph(ctx(['recon:read']), 'p1', { question: 'list ips' })).resolves.toBeTruthy()
  })
})

describe('query_graph', () => {
  test('returns records and the generated cypher', async () => {
    h.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ records: [{ n: ownNode('IP') }], cypher: 'MATCH (i:IP) RETURN i' }),
    })
    const r = await queryGraph(ctx(), 'p1', { question: 'list ips' })
    expect(r.records).toHaveLength(1)
    expect(r.cypher).toBe('MATCH (i:IP) RETURN i')
  })

  test('it reports truncation rather than silently shortening', async () => {
    h.fetch.mockResolvedValue({
      ok: true, json: async () => ({ records: [], truncated: true }),
    })
    expect((await queryGraph(ctx(), 'p1', { question: 'everything' })).truncated).toBe(true)
  })

  test('the resolved identity is sent, never one from the arguments', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'list ips' })
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.user_id).toBe('owner')
    expect(body.project_id).toBe('p1')
  })

  test('it never goes through the webapp text-to-cypher proxy', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'list ips' })
    expect(h.fetch.mock.calls[0][0]).not.toContain('/api/agent/text-to-cypher')
    expect(h.fetch.mock.calls[0][0]).toContain('/graph/nl-query')
  })

  test('raw cypher goes to graph/exec marked as MCP-originated', async () => {
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(['recon:read', 'graph:cypher']), 'p1', { cypher: 'MATCH (n:IP) RETURN n' })
    const body = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(body.op).toBe('cypher')
    expect(body.source).toBe('mcp')
  })

  test("a cross-tenant row in the RESULT drops the whole response", async () => {
    // Defence in depth: even if the server-side filter regressed.
    h.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        records: [
          { n: ownNode('IP') },
          { n: { _kind: 'node', labels: ['IP'], properties: { user_id: 'mallory', project_id: 'pX' } } },
        ],
      }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'list ips' })).rejects.toThrow(/safety check/i)
  })

  test('a generation failure is distinguishable from an execution failure', async () => {
    h.fetch.mockResolvedValue({
      ok: false, status: 422,
      json: async () => ({ error: 'Could not generate a valid query.', stage: 'generate' }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'nonsense' }))
      .rejects.toMatchObject({ code: 'generate_failed' })

    h.fetch.mockResolvedValue({
      ok: false, status: 413,
      json: async () => ({ error: 'result too large, narrow your query', stage: 'execute' }),
    })
    await expect(queryGraph(ctx(), 'p1', { question: 'everything' }))
      .rejects.toMatchObject({ code: 'execute_failed' })
  })

  test('an unreachable agent is an error, never an empty record set', async () => {
    h.fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(queryGraph(ctx(), 'p1', { question: 'list ips' }))
      .rejects.toMatchObject({ code: 'agent_unreachable' })
  })

  test('the per-token LLM budget is enforced on the question path', async () => {
    vi.stubEnv('MCP_LLM_DAILY_BUDGET', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'q1' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q2' })).rejects.toThrow(/budget/i)
  })

  test('the raw-cypher path does not consume the LLM budget', async () => {
    vi.stubEnv('MCP_LLM_DAILY_BUDGET', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    const c = ctx(['recon:read', 'graph:cypher'])
    await queryGraph(c, 'p1', { cypher: 'MATCH (n:IP) RETURN n' })
    await expect(queryGraph(c, 'p1', { cypher: 'MATCH (n:Host) RETURN n' })).resolves.toBeTruthy()
  })

  test('ownership is checked before any agent call', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q' })).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('rate limiting applies per tool class', () => {
  test('the query bucket refuses once exhausted', async () => {
    vi.stubEnv('MCP_RATE_QUERY_PER_MIN', '1')
    h.fetch.mockResolvedValue({ ok: true, json: async () => ({ records: [] }) })
    await queryGraph(ctx(), 'p1', { question: 'q1' })
    await expect(queryGraph(ctx(), 'p1', { question: 'q2' })).rejects.toThrow(/rate limit/i)
  })

  test('the refusal says when to retry', async () => {
    vi.stubEnv('MCP_RATE_READ_PER_MIN', '1')
    await listProjects(ctx())
    await expect(listProjects(ctx())).rejects.toThrow(/try again in \d+s/i)
  })
})

// =============================================================================
// REGRESSION: expectedUpdatedAt was unobtainable (audit finding F7)
// =============================================================================

describe('REGRESSION: get_recon_settings returns the concurrency token', () => {
  test('updatedAt is returned so expectedUpdatedAt can be passed back', async () => {
    // update_recon_settings' own description says "Read get_recon_settings
    // first ... pass expectedUpdatedAt from a prior read". updatedAt is
    // classified 'identity' in the allowlist, so it was excluded from the
    // select and the anti-clobber control was dead in its documented flow.
    const when = new Date('2026-09-13T10:00:00.000Z')
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, updatedAt: when })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.updatedAt).toBe('2026-09-13T10:00:00.000Z')
  })

  test('updatedAt is METADATA, not smuggled into the settings object', async () => {
    // It must not look settable: it is not in the allowlist and a write to it
    // would be refused.
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 25, updatedAt: new Date() })

    const r = await getReconSettings(ctx(), 'p1')
    expect(r.settings).not.toHaveProperty('updatedAt')
  })
})

// =============================================================================
// REGRESSION: graph_summary sampled liveGraphState BEFORE the counts (F8)
// =============================================================================

describe('REGRESSION: the live-graph state is sampled AFTER the counts', () => {
  test('a scan starting mid-call reports scan_running, not stable', async () => {
    // Sampling first meant a scan that began between the state read and the
    // count read was reported `stable` alongside mid-wipe near-zero counts -
    // the exact false negative the field exists to prevent. Reading it after
    // makes the same race over-warn instead.
    h.activeScans.mockReturnValue([])
    h.fetch.mockImplementation(async () => {
      // The scan starts while the counts are being read.
      h.activeScans.mockReturnValue([scanRow()])
      return { ok: true, json: async () => ({ nodes: [], relationships: [], records: [] }) }
    })

    const r = await graphSummary(ctx(), 'p1')
    expect(r.liveGraphState).toBe('scan_running')
    expect(r.warning).toBeTruthy()
  })
})


// =============================================================================
// get_recon_status: the progress fields a poller needs (plan 5.7)
// =============================================================================

describe('get_recon_status reports progress a poller can use', () => {
  test('the phase number comes with its denominator', async () => {
    // Without totalPhases a poller has a numerator and no way to turn it into
    // progress.
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'running', phase_number: 3, total_phases: 9 }),
    })
    expect(await getReconStatus(ctx(), 'p1')).toMatchObject({ phaseNumber: 3, totalPhases: 9 })
  })

  test('domain-batch group progress is reported', async () => {
    // Phases RESTART per group, so on a multi-domain scan the phase number
    // barely moves for an hour and the group is the only thing that advances.
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'running', current_group: 'batch-2', group_number: 2, total_groups: 6,
      }),
    })
    expect(await getReconStatus(ctx(), 'p1')).toMatchObject({
      currentGroup: 'batch-2', groupNumber: 2, totalGroups: 6,
    })
  })

  test('the new fields did not reopen the host-detail leak', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'error', total_phases: 9, container_id: 'a1b2c3d4e5f6',
        error: 'bind source path does not exist: /home/operator/deploy',
      }),
    })
    const s = JSON.stringify(await getReconStatus(ctx(), 'p1'))
    expect(s).not.toContain('/home/operator')
    expect(s).not.toContain('a1b2c3d4e5f6')
  })
})

// =============================================================================
// get_project_activity
// =============================================================================

describe('get_project_activity', () => {
  test('needs recon:read and ownership', async () => {
    await expect(getProjectActivity(ctx([]), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(getProjectActivity(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
  })

  test('it reports this project\'s scans with their progress', async () => {
    h.activeScans.mockReturnValue([scanRow({ kind: 'gvm', status: 'running' })])
    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.scans).toHaveLength(1)
    expect(r.scans[0]).toMatchObject({ kind: 'gvm', status: 'running', currentPhase: 'port_scan' })
  })

  test("another project's scan is neither listed nor counted", async () => {
    h.activeScans.mockReturnValue([scanRow({ project_id: 'other', kind: 'gvm' })])
    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.scans).toEqual([])
    expect(JSON.stringify(r)).not.toContain('other')
  })

  // A.27: deriving this from the cheap /system/active-scans read would
  // sometimes answer "yes, you can start" and then have start_recon refuse,
  // because start_recon ALSO gates on a live triage run and an agent session,
  // neither of which appears in the orchestrator's scan list. For an unattended
  // agent that is a retry loop - worse than not offering the field.
  test('canStartFullScan comes from the same check start_recon makes', async () => {
    h.activeScans.mockReturnValue([])          // the cheap read says "idle"
    h.liveGraphWriters.mockResolvedValue('a triage run is in progress')

    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.scans).toEqual([])
    expect(r.canStartFullScan).toBe(false)
    expect(r.startBlockedBecause).toMatch(/triage run/)
  })

  test('a Mute Rules apply is reported by name', async () => {
    h.liveNodeFilterRun.mockResolvedValue({ id: 'nf1', revision: 3 })
    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.muteRulesApply).toBe(true)
    expect(r.liveGraphState).toBe('agent_writing')
  })

  test('a free project can start, and says nothing is blocking', async () => {
    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.canStartFullScan).toBe(true)
    expect(r).not.toHaveProperty('startBlockedBecause')
  })

  // One call fans out to as many as eight upstream requests, so it cannot sit
  // in the bucket sized for a single cheap read.
  test('it is metered as a query, not as a cheap read', async () => {
    vi.stubEnv('MCP_RATE_QUERY_PER_MIN', '1')
    await getProjectActivity(ctx(), 'p1')
    await expect(getProjectActivity(ctx(), 'p1')).rejects.toThrow(/rate limit/i)
  })

  test('an unreadable source is reported, never as "nothing running"', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    const r = await getProjectActivity(ctx(), 'p1')
    expect(r.unknown).toBe(true)
    expect(r.liveGraphState).toBe('unknown')
  })
})

// =============================================================================
// list_remediations
// =============================================================================

const remediation = (over: Record<string, unknown> = {}) => ({
  id: 'r1', title: 'Patch nginx', severity: 'high', priority: 8, priorityScore: 91.2,
  category: 'vulnerability', status: 'pending', cvssScore: 9.1, cveIds: ['CVE-2026-1'],
  cweIds: [], capecIds: [], exploitAvailable: true, cisaKev: true,
  fixComplexity: 'low', estimatedFiles: 2, groupKey: 'g1', findingIds: ['v1'],
  stillDetected: true, prStatus: 'none',
  createdAt: new Date(), updatedAt: new Date(),
  ...over,
})

describe('list_remediations', () => {
  test('needs triage:read, not recon:read', async () => {
    await expect(listRemediations(ctx(['recon:read']), 'p1')).rejects.toBeInstanceOf(McpScopeError)
  })

  test('ownership is checked before the query', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(listRemediations(ctx(['triage:read']), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.findRemediations).not.toHaveBeenCalled()
  })

  test('it queries Prisma directly, never its own internal-key HTTP route', async () => {
    // GET /api/remediations skips ALL ownership checks for an internal-key
    // caller, and internalKeyHeaders is this codebase's own server-to-server
    // idiom. Composing those two would leave assertMcpProjectAccess as the only
    // thing between a caller and every tenant's remediations.
    h.findRemediations.mockResolvedValue([remediation()])
    await listRemediations(ctx(['triage:read']), 'p1')
    expect(h.fetch).not.toHaveBeenCalled()
    expect(h.findRemediations).toHaveBeenCalledOnce()
  })

  test('the query is scoped to the project in the WHERE clause', async () => {
    await listRemediations(ctx(['triage:read']), 'p1')
    expect(h.findRemediations.mock.calls[0][0].where).toMatchObject({ projectId: 'p1' })
  })

  test('the large, internal and credential-bearing columns are never selected', async () => {
    await listRemediations(ctx(['triage:read']), 'p1')
    const select = h.findRemediations.mock.calls[0][0].select
    // prUrl can be https://x-access-token:ghs_...@github.com/... - a credential.
    for (const forbidden of ['agentNotes', 'fileChanges', 'evidence', 'attackChainPath', 'prUrl']) {
      expect(select[forbidden], forbidden).toBeUndefined()
    }
  })

  test('the @db.Text columns come only on request', async () => {
    await listRemediations(ctx(['triage:read']), 'p1')
    expect(h.findRemediations.mock.calls[0][0].select.solution).toBeUndefined()

    __resetRateLimiter()
    await listRemediations(ctx(['triage:read']), 'p1', { detail: true })
    expect(h.findRemediations.mock.calls[1][0].select.solution).toBe(true)
  })

  test('an unknown sort is refused by name rather than silently ignored', async () => {
    await expect(listRemediations(ctx(['triage:read']), 'p1', { sort: 'whatever' }))
      .rejects.toThrow(/one of/i)
  })

  test('truncation is visible', async () => {
    h.findRemediations.mockResolvedValue([remediation()])
    h.countRemediations.mockResolvedValue(87)
    const r = await listRemediations(ctx(['triage:read']), 'p1', { limit: 1 })
    expect(r.total).toBe(87)
    expect(r.returned).toBe(1)
    expect(r.truncated).toBe(true)
  })

  test('the limit is clamped', async () => {
    await listRemediations(ctx(['triage:read']), 'p1', { limit: 99_999 })
    expect(h.findRemediations.mock.calls[0][0].take).toBe(100)
  })
})

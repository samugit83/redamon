/**
 * Reports and fireteam step content (4.9 review): a report is generated once (`reports:generate`,
 * W, which always reaches R*) and opened by every `reports:read` holder (R). Its fireteam section
 * carries the agent's own reasoning and output (plan rationale, member task, completion reason,
 * error), so:
 *   - POST records in the report's metrics whether it holds any (`stepContent`);
 *   - GET of one report answers a reader below R* (a Read share without Raw data, an overseer) 403
 *     naming reports:read and R* when it holds some or predates the record, before the file is
 *     read; a report that recorded none opens at R. The owner and a share with Raw data & files
 *     open every report, unchanged.
 *
 * The guard answers a context with the access under test; Prisma, fs, the data and the agent are
 * doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  access: null as unknown, report: null as unknown, create: vi.fn(), readFile: vi.fn(), gather: vi.fn(), fireteams: undefined as unknown,
}))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string) => ({ permission, effective: { userId: 'alice' }, access: h.access }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findUnique: async () => ({ featureModels: { report_narratives: 'gpt-5' } }) },
    report: { create: (...a: unknown[]) => h.create(...a), findFirst: async () => h.report },
  },
}))
vi.mock('@/lib/featureAgentCall', () => ({
  callFeatureAgent: async () => ({ ok: true, body: { executiveSummary: 'ok', model_used: 'gpt-5' } }),
}))
vi.mock('@/lib/report/reportData', () => ({ gatherReportData: (...a: unknown[]) => h.gather(...a) }))
vi.mock('@/lib/report/reportTemplate', () => ({ generateReportHtml: () => '<html></html>' }))
vi.mock('fs', () => ({
  writeFileSync: vi.fn(), mkdirSync: vi.fn(), existsSync: () => true, unlinkSync: vi.fn(),
  readFileSync: (...a: unknown[]) => h.readFile(...a),
}))

import { POST } from './route'
import { GET as reportGET } from './[reportId]/route'

const access = (level: string, rawData: boolean, via: string) => ({ project: { id: 'p1', userId: 'alice' }, level, toggles: { rawData }, via })
const BELOW_RAW: Array<[string, unknown]> = [['a read share without Raw data', access('read', false, 'share')], ['an overseer', access('read', false, 'oversight')]]
const WHOLE: Array<[string, unknown]> = [['the owner', access('owner', true, 'owner')], ['a share with Raw data & files', access('read', true, 'share')]]

const member = (over: Record<string, unknown>) => ({
  memberIdKey: 'm-1', name: 'recon', task: '', skills: [], status: 'failed', completionReason: null,
  iterationsUsed: 1, tokensUsed: 1, findingsCount: 0, wallClockSeconds: null, errorMessage: null, ...over,
})
function reportData() {
  const empty = new Proxy({}, { get: () => [] })
  return {
    project: { name: 'Proj', targetDomain: 'rbac.test' },
    metrics: { riskScore: 1, riskLabel: 'Low' },
    graphOverview: empty, attackSurface: empty,
    vulnerabilities: { findings: [] }, cveIntelligence: { cveChains: [], exploits: [], githubSecrets: [] },
    attackChains: { chains: [], exploitSuccesses: [] }, remediations: [],
    trufflehog: { findings: [] }, secrets: {}, jsRecon: { findings: [] },
    supplyChain: { findings: [] }, graphqlScan: { findings: [] }, vhostSni: { findings: [] },
    tlsx: { findings: [], topIssuers: [] }, webCachePoison: { findings: [] },
    aiSurface: { findings: [], attackFindings: [] }, otx: { pulses: [] },
    fireteams: h.fireteams,
  }
}
const stored = (metrics: unknown) => ({ id: 'r1', projectId: 'p1', filePath: '/data/reports/r.html', filename: 'r.html', metrics })
const openReport = () => reportGET(new NextRequest('http://localhost:3000/api/projects/p1/reports/r1'), { params: Promise.resolve({ id: 'p1', reportId: 'r1' }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.fireteams = undefined
  h.gather.mockImplementation(async () => reportData())
  h.create.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'r1', ...data }))
  h.readFile.mockReturnValue(Buffer.from('<html>report</html>'))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('POST records whether the report holds fireteam step content', () => {
  test('a fireteam member\'s error: stepContent true', async () => {
    h.access = access('owner', true, 'owner')
    h.fireteams = { totalFireteams: 1, totalMembers: 1, totalFindings: 0, deployments: [{ fireteamIdKey: 'ft', iteration: 1, planRationale: '', startedAt: 'x', completedAt: null, wallClockSeconds: null, statusCounts: null, status: 'done', members: [member({ errorMessage: 'stderr: denied' })] }] }
    const res = await POST(new NextRequest('http://localhost:3000/api/projects/p1/reports', { method: 'POST' }), { params: Promise.resolve({ id: 'p1' }) })
    expect(res.status).toBe(201)
    expect(h.create.mock.calls[0][0].data.metrics).toMatchObject({ stepContent: true, riskScore: 1 })
  })

  test('no fireteam: stepContent false', async () => {
    h.access = access('write', true, 'share')
    const res = await POST(new NextRequest('http://localhost:3000/api/projects/p1/reports', { method: 'POST' }), { params: Promise.resolve({ id: 'p1' }) })
    expect(res.status).toBe(201)
    expect(h.create.mock.calls[0][0].data.metrics).toMatchObject({ stepContent: false })
  })
})

describe('GET one report', () => {
  test.each(BELOW_RAW)('%s: a report that holds step content answers 403 naming reports:read and R*, before the file is read', async (_who, a) => {
    h.access = a
    h.report = stored({ riskScore: 1, stepContent: true })
    const res = await openReport()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'reports:read', level: 'R*' })
    expect(h.readFile).not.toHaveBeenCalled()
  })

  test.each(BELOW_RAW)('%s: a report generated before the record existed answers 403 too (fails closed)', async (_who, a) => {
    h.access = a
    h.report = stored({ riskScore: 1 })
    expect((await openReport()).status).toBe(403)
    expect(h.readFile).not.toHaveBeenCalled()
  })

  test.each(BELOW_RAW)('%s: a report that recorded none opens', async (_who, a) => {
    h.access = a
    h.report = stored({ riskScore: 1, stepContent: false })
    const res = await openReport()
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('<html>report</html>')
  })

  test.each(WHOLE)('%s: every report opens, whatever it recorded', async (_who, a) => {
    h.access = a
    for (const metrics of [{ stepContent: true }, { riskScore: 1 }, null]) {
      h.report = stored(metrics)
      expect((await openReport()).status).toBe(200)
    }
  })

  test.each(BELOW_RAW)('%s: a report of another project is 404 before any level check', async (_who, a) => {
    h.access = a
    h.report = null
    expect((await openReport()).status).toBe(404)
  })
})

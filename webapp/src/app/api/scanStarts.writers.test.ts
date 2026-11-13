/**
 * Every manual scan start asks who else is writing the project (step 5.11, SH-40): the six start
 * routes hand startUnderGraphLock the effective user and the owner their guard read, and a second
 * writer's 409 `project_writer_busy` comes back before anything reaches the orchestrator; the full
 * scan route forwards startFullScan's refusal with its code and the holder. The writer check
 * itself is a double here (its rules are projectWriters.test.ts and startScan.writers.test.ts).
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const OWNER = 'owner-1'
const BUSY = 'Olivia Owner (olivia@example.test) is running an agent session'

const h = vi.hoisted(() => ({
  actor: 'collab-1',
  orchestratorFetch: vi.fn(),
  checks: [] as Array<Record<string, unknown>>,
  holder: null as string | null,
}))

const PROJECT = {
  id: 'p1', userId: 'owner-1', name: 'P', targetDomain: 'example.com', subdomainList: [], ipMode: false,
  targetIps: [], domainBatchMode: false, domainBatchHosts: [], roeExcludedHosts: [], engagementKind: 'internal',
  supplyChainInputMode: 'github', supplyChainRepoUrl: 'https://github.com/acme/app', supplyChainSbomFile: null,
  ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: false,
  ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 50, ipHostnamePassiveMaxNames: 50,
}

vi.mock('@/lib/authz/projectWriters', () => {
  const refusal = (input: Record<string, unknown>) => {
    h.checks.push(input)
    if (!h.holder || input.personId === h.holder) return null
    return { status: 409, code: 'project_writer_busy', busy: BUSY, error: `${BUSY} on this project.` }
  }
  return {
    secondWriterRefusal: async (input: Record<string, unknown>) => refusal(input),
    secondWriterResponse: async (input: Record<string, unknown>) => {
      const r = refusal(input)
      return r ? NextResponse.json({ error: r.error, code: r.code, busy: r.busy }, { status: 409 }) : null
    },
  }
})
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return {
    ...real,
    requirePermission: async (_request: Request, permission: string, opts: { projectId?: string } = {}) => ({
      session: { userId: h.actor, role: 'standard' },
      principal: { id: h.actor, role: 'standard' },
      actingAs: null,
      effective: { userId: h.actor },
      permission,
      access: { project: { id: opts.projectId, userId: OWNER }, level: 'write', toggles: { rawData: true }, via: 'share' },
    }),
    requireAlso: () => null,
  }
})
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: async () => ({ ...PROJECT }) } } }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', async (orig) => ({
  ...(await orig<typeof import('@/lib/activationLock')>()),
  assertGraphNotActivating: async () => null,
  isActivationInProgress: async () => false,
}))
vi.mock('@/lib/engagementGate', () => ({ assertEngagementStartable: async () => null }))
vi.mock('@/lib/engagement', async (orig) => ({
  ...(await orig<typeof import('@/lib/engagement')>()),
  currentRoeTextSha256: async () => null,
}))
vi.mock('@/lib/legacyGraph', async (orig) => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))
vi.mock('@/lib/nodeFilterRun', async (orig) => ({
  ...(await orig<typeof import('@/lib/nodeFilterRun')>()),
  describeNodeFilterWriter: async () => null,
}))
vi.mock('@/lib/scanTimeline', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  recordScanStart: async () => null,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getEffectiveUser: async () => ({ userId: h.actor }),
}))
vi.mock('@/lib/scanJobCredential', () => ({ scanStartFields: async () => ({}) }))
vi.mock('@/lib/trufflehogStart', async (orig) => ({
  ...(await orig<typeof import('@/lib/trufflehogStart')>()),
  resolveTrufflehogStart: async (projectId: string) => ({
    ok: true,
    source: 'docker',
    body: { project_id: projectId, user_id: OWNER, webapp_api_url: 'http://localhost:3000', source: 'docker', config: { images: ['nginx:1.25'] }, common: {}, secrets: {} },
  }),
}))
vi.mock('fs', async (orig) => ({ ...(await orig<typeof import('fs')>()), existsSync: () => true }))

type Handler = (request: NextRequest, context: { params: Promise<{ projectId: string }> }) => Promise<Response>

const ROUTES: Array<[string, () => Promise<Handler>, Record<string, unknown>]> = [
  ['gvm', async () => (await import('./gvm/[projectId]/start/route')).POST, {}],
  ['github-hunt', async () => (await import('./github-hunt/[projectId]/start/route')).POST, {}],
  ['supply-chain', async () => (await import('./supply-chain/[projectId]/start/route')).POST, {}],
  ['trufflehog', async () => (await import('./trufflehog/[projectId]/start/route')).POST, { source: 'docker' }],
  ['ai-attack-surface', async () => (await import('./ai-attack-surface/[projectId]/start/route')).POST,
    { tool: 'garak', targets: [], roe_confirmed: true }],
  ['recon partial', async () => (await import('./recon/[projectId]/partial/route')).POST,
    { tool_id: 'Naabu', graph_inputs: { domains: ['example.com'] } }],
]

async function start(load: () => Promise<Handler>, body: Record<string, unknown>) {
  const handler = await load()
  return handler(
    new NextRequest('http://localhost:3000/api/x/p1/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
}

beforeEach(() => {
  h.checks = []
  h.holder = null
  h.orchestratorFetch.mockReset()
  h.orchestratorFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ status: 'starting', run_id: 'r1' }) })
})
afterEach(() => { h.actor = 'collab-1' })

describe('the six start routes', () => {
  test.each(ROUTES)('%s: second writer refused, naming who holds the project; nothing reaches the orchestrator', async (_name, load, body) => {
    h.holder = OWNER
    const res = await start(load, body)
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: `${BUSY} on this project.`, code: 'project_writer_busy', busy: BUSY })
    expect(h.checks).toEqual([{ projectId: 'p1', personId: 'collab-1', ownerId: OWNER }])
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('%s: the same person can run two things as today', async (_name, load, body) => {
    h.holder = 'collab-1'
    const res = await start(load, body)
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
  })
})

describe('the full scan route', () => {
  test('forwards the refusal with its code and the holder', async () => {
    h.holder = OWNER
    const { POST } = await import('./recon/[projectId]/start/route')
    const res = await POST(
      new NextRequest('http://localhost:3000/api/recon/p1/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }),
      { params: Promise.resolve({ projectId: 'p1' }) },
    )
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'project_writer_busy', busy: BUSY, error: `${BUSY} on this project.` })
    expect(h.checks).toEqual([{ projectId: 'p1', personId: 'collab-1' }])
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

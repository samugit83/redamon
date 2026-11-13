/**
 * Every manual scan start names its actor (step 5.5, SH-37, D-14): the six start routes send the
 * orchestrator the owner as `user_id` (the job credential's tenant, whose graph and keys the scan
 * uses) and the person whose permission check let the start through as `actor_user_id`, which the
 * orchestrator's per-user admission ceiling counts. For the owner the two are the same person.
 *
 * The guard is doubled with a context naming the effective user; everything past it runs as the
 * route does, over a project row that passes each route's own checks.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { verifyJobCredential } from '@/lib/authz/machineCredential'

const OWNER = 'owner-1'

const h = vi.hoisted(() => ({
  actor: 'collab-1',
  orchestratorFetch: vi.fn(),
}))

const PROJECT = {
  id: 'p1', userId: 'owner-1', name: 'P', targetDomain: 'example.com', subdomainList: [], ipMode: false,
  targetIps: [], domainBatchMode: false, domainBatchHosts: [], roeExcludedHosts: [],
  supplyChainInputMode: 'github', supplyChainRepoUrl: 'https://github.com/acme/app', supplyChainSbomFile: null,
  ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: false,
  ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 50, ipHostnamePassiveMaxNames: 50,
}

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
      access: { project: { id: opts.projectId, userId: 'owner-1' }, level: 'read', toggles: { rawData: false }, via: 'share' },
    }),
  }
})
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: async () => ({ ...PROJECT }) } } }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', async (orig) => ({
  ...(await orig<typeof import('@/lib/activationLock')>()),
  assertGraphNotActivating: async () => null,
}))
vi.mock('@/lib/projectGraphLock', async (orig) => ({
  ...(await orig<typeof import('@/lib/projectGraphLock')>()),
  withGraphStartLock: async (_projectId: string, start: () => Promise<unknown>) => ({ acquired: true, value: await start() }),
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
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/scanTimeline', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  recordScanStart: async () => null,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getEffectiveUser: async () => ({ userId: h.actor }),
}))
vi.mock('@/lib/trufflehogStart', async (orig) => ({
  ...(await orig<typeof import('@/lib/trufflehogStart')>()),
  resolveTrufflehogStart: async (projectId: string) => ({
    ok: true,
    source: 'docker',
    body: {
      project_id: projectId, user_id: 'owner-1', webapp_api_url: 'http://localhost:3000', source: 'docker',
      config: { images: ['nginx:1.25'] }, common: {}, secrets: {},
    },
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
  const res = await handler(
    new NextRequest('http://localhost:3000/api/x/p1/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ projectId: 'p1' }) },
  )
  expect(res).not.toBeInstanceOf(Error)
  return res
}

const sentBody = () => JSON.parse(h.orchestratorFetch.mock.calls[0][1].body) as Record<string, unknown>

const savedKey = process.env.INTERNAL_API_KEY

beforeEach(() => {
  h.orchestratorFetch.mockReset()
  h.orchestratorFetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ status: 'starting', run_id: 'r1' }) })
  process.env.INTERNAL_API_KEY = 'scan-start-actor-test-master'
})
afterEach(() => {
  h.actor = 'collab-1'
  if (savedKey === undefined) delete process.env.INTERNAL_API_KEY
  else process.env.INTERNAL_API_KEY = savedKey
})

describe('each manual start names its actor beside the owner', () => {
  test.each(ROUTES)('%s: a collaborator is the actor, the owner the tenant', async (_name, load, body) => {
    h.actor = 'collab-1'
    const res = await start(load, body)
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalledTimes(1)
    const sent = sentBody()
    expect(sent.actor_user_id).toBe('collab-1')
    expect(sent.user_id).toBe(OWNER)
    expect(verifyJobCredential(sent.job_credential as string)).toMatchObject({ ten: OWNER, pid: 'p1' })
  })

  test.each(ROUTES)("%s: the owner's own start is the owner's (unchanged)", async (_name, load, body) => {
    h.actor = OWNER
    const res = await start(load, body)
    expect(res.status).toBe(200)
    const sent = sentBody()
    expect(sent.actor_user_id).toBe(OWNER)
    expect(sent.user_id).toBe(OWNER)
  })
})

test('the guard double answers a context, never a response', async () => {
  const { requirePermission } = await import('@/lib/authz/guards')
  const ctx = await requirePermission(new Request('http://x'), 'scan:gvm', { projectId: 'p1' })
  expect(ctx).not.toBeInstanceOf(NextResponse)
})

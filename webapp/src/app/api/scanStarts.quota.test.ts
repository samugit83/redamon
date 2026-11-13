/**
 * The actor's scan quota (step 6.8, GV-10): beside step 5.5's `actor_user_id`, each manual start sends
 * the orchestrator `actor_max_concurrent`, the maxConcurrentScans quota of that same actor (never the
 * owner's), which admission applies as the smaller of it and RECON_MAX_CONCURRENT_PER_USER. Unlimited,
 * or with RBAC_GOVERNANCE_ENABLED off (nothing read), the field is absent and the body is 5.5's. A
 * failed quota read starts nothing (the orchestrator is never called). The resolution is the real
 * lib/authz/quotas.ts over a doubled instance row, account and capability resolution.
 *
 * Same harness as scanStarts.actor.test.ts.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { setFlagsForTests } from '@/lib/authz/flags'

const OWNER = 'owner-1'

const h = vi.hoisted(() => ({
  actor: 'collab-1',
  orchestratorFetch: vi.fn(),
  quotas: {} as unknown,
  instanceRead: vi.fn(),
  failRead: false,
}))

vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => {
    h.instanceRead()
    if (h.failRead) throw new Error('database unavailable')
    return { quotas: h.quotas }
  },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: [], permissionOverrides: [] }),
}))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({ accountType: 'member', sets: [{ id: 'builtin:default-member', name: 'Default member', kind: 'member', via: 'default' }] }),
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
beforeEach(() => {
  h.quotas = { defaults: { maxConcurrentScans: 5 }, perUser: { 'collab-1': { maxConcurrentScans: 2 }, 'owner-1': { maxConcurrentScans: 9 } } }
  h.failRead = false
  h.instanceRead.mockClear()
  setFlagsForTests({ identity: true, permissions: true, governance: true })
})
afterEach(() => {
  setFlagsForTests(null)
  h.actor = 'collab-1'
  if (savedKey === undefined) delete process.env.INTERNAL_API_KEY
  else process.env.INTERNAL_API_KEY = savedKey
})

describe("each manual start sends its actor's scan quota", () => {
  test.each(ROUTES)("%s: the collaborator's quota, not the owner's", async (_name, load, body) => {
    const res = await start(load, body)
    expect(res.status).toBe(200)
    const sent = sentBody()
    expect(sent.actor_user_id).toBe('collab-1')
    expect(sent.user_id).toBe(OWNER)
    expect(sent.actor_max_concurrent).toBe(2)
  })

  test.each(ROUTES)("%s: the owner's own start carries the owner's quota", async (_name, load, body) => {
    h.actor = OWNER
    await start(load, body)
    expect(sentBody().actor_max_concurrent).toBe(9)
  })

  test.each(ROUTES)('%s: an unlimited actor sends no quota', async (_name, load, body) => {
    h.quotas = { perUser: { 'collab-1': { maxConcurrentScans: null } } }
    await start(load, body)
    expect(sentBody()).not.toHaveProperty('actor_max_concurrent')
  })

  test.each(ROUTES)('%s: switch off, no quota sent and nothing read', async (_name, load, body) => {
    setFlagsForTests({ identity: true, permissions: true })
    await start(load, body)
    expect(sentBody()).not.toHaveProperty('actor_max_concurrent')
    expect(sentBody().actor_user_id).toBe('collab-1')
    expect(h.instanceRead).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('%s: a failed quota read starts nothing', async (_name, load, body) => {
    h.failRead = true
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const handler = await load()
    const outcome = await handler(
      new NextRequest('http://localhost:3000/api/x/p1/start', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      }),
      { params: Promise.resolve({ projectId: 'p1' }) },
    ).then((r) => r.status, () => 'thrown')
    expect(outcome === 'thrown' || outcome === 500).toBe(true)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

test('the guard double answers a context, never a response', async () => {
  const { requirePermission } = await import('@/lib/authz/guards')
  const ctx = await requirePermission(new Request('http://x'), 'scan:gvm', { projectId: 'p1' })
  expect(ctx).not.toBeInstanceOf(NextResponse)
})

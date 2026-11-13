/**
 * The start paths refuse a second writer (step 5.11, SH-40): the six start buttons
 * (startUnderGraphLock), the queue and scheduler (dispatchStart) and the full scan (startFullScan)
 * ask who else is writing the project INSIDE the project's graph lock, so two people starting at
 * once meet each other: the second start runs after the first one's orchestrator answer and sees
 * its scan. The same person runs several things at once, as before.
 *
 * Real: projectWriters, projectGraphLock, startScan, startFullScan. Doubles: the orchestrator (an
 * in-memory list of active scans its start calls fill), the agent's live-session authors, Prisma,
 * the sharing policy, and the start paths' other checks (activation, engagement, versions).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const OWNER = 'owner-1'
const BOB = 'bob-1'

const h = vi.hoisted(() => ({
  sharing: true,
  active: [] as Array<Record<string, unknown>>,
  starts: [] as Array<{ path: string; actor: unknown }>,
  authors: [] as string[],
  prepare: vi.fn(),
}))

const PROJECT = {
  id: 'p1', userId: 'owner-1', name: 'P', targetDomain: 'example.com', subdomainList: [], ipMode: false,
  targetIps: [], domainBatchMode: false, domainBatchHosts: [], engagementKind: 'internal', supplyChainInputMode: 'github',
  ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: false,
  ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 50, ipHostnamePassiveMaxNames: 50,
}
const PEOPLE: Record<string, { id: string; name: string; email: string; role: string }> = {
  'owner-1': { id: 'owner-1', name: 'Olivia Owner', email: 'olivia@example.test', role: 'standard' },
  'bob-1': { id: 'bob-1', name: 'Bob Builder', email: 'bob@example.test', role: 'standard' },
}

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ ...PROJECT }) },
    triageRun: { findMany: async () => [], updateMany: async () => ({ count: 0 }) },
    nodeFilterRun: { findMany: async () => [], updateMany: async () => ({ count: 0 }) },
    engagementAuthorization: { count: async () => 0, findFirst: async () => null },
    user: { findMany: async ({ where }: { where: { id: { in: string[] } } }) => where.id.in.map(id => PEOPLE[id]).filter(Boolean) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async (url: string, init: { method?: string; body?: string } = {}) => {
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    if (path === '/system/active-scans') return { ok: true, status: 200, json: async () => ({ scans: [...h.active] }) }
    const body = init.body ? JSON.parse(init.body) : {}
    // A real start takes a moment; the lock is what keeps the next check behind it.
    await new Promise(resolve => setTimeout(resolve, 5))
    h.starts.push({ path, actor: body.actor_user_id })
    const kind = path.endsWith('/partial') ? 'partial_recon' : path.endsWith('/recon/p1/start') ? 'full_recon' : 'gvm'
    h.active.push({ kind, project_id: 'p1', run_id: `r${h.starts.length}`, status: 'starting', actor_user_id: body.actor_user_id ?? null })
    return { ok: true, status: 200, json: async () => ({ project_id: 'p1', status: 'starting', run_id: `r${h.starts.length}` }) }
  },
}))
vi.mock('@/lib/agentSessions', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentSessions')>()),
  runningSessionAuthors: async () => ({ userIds: [...h.authors] }),
}))
vi.mock('@/lib/authz/sharingPolicy', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/sharingPolicy')>()),
  sharingInForce: async () => ({ enabled: h.sharing, maxLevel: 'write' }),
}))
vi.mock('@/lib/authz/root', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/root')>()),
  loadInstanceRoot: async () => null,
}))
vi.mock('@/lib/activationLock', async (orig) => ({
  ...(await orig<typeof import('@/lib/activationLock')>()),
  assertGraphNotActivating: async () => null,
  isActivationInProgress: async () => false,
}))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/engagementGate', () => ({ assertEngagementStartable: async () => null }))
vi.mock('@/lib/engagement', async (orig) => ({
  ...(await orig<typeof import('@/lib/engagement')>()),
  currentRoeTextSha256: async () => null,
  loadEngagement: async () => ({ blockers: [], documentTextSha256: null }),
  currentAuthorization: async () => null,
}))
vi.mock('@/lib/legacyGraph', async (orig) => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))
vi.mock('@/lib/scanJobCredential', () => ({ scanStartFields: async () => ({}) }))
vi.mock('@/lib/scanRetention', () => ({ applyRetentionSafe: async () => null }))
vi.mock('@/lib/scanTimeline', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  prepareVersionsForFullScan: (...a: unknown[]) => h.prepare(...a),
  rollbackPreparedVersions: async () => true,
  createScanJob: async () => ({ id: 'job1' }),
  recordScanStart: async () => null,
}))

import { dispatchStart, startUnderGraphLock } from './startScan'
import { startFullScan } from './startFullScan'
import { orchestratorFetch } from './orchestrator'

/** A start button's route: the orchestrator call, run under the lock with its starter. */
function pressStart(person: string): Promise<NextResponse> {
  return startUnderGraphLock('p1', async () => {
    const res = await orchestratorFetch('http://orch/recon/p1/partial', { method: 'POST', body: JSON.stringify({ actor_user_id: person }) })
    return NextResponse.json(await res.json(), { status: res.status })
  }, { personId: person, ownerId: OWNER })
}

beforeEach(() => {
  h.sharing = true
  h.active = []
  h.starts = []
  h.authors = []
  h.prepare.mockReset()
  h.prepare.mockResolvedValue({ currentVersion: { id: 'v2', seq: 2, label: 'Scan 2' }, frozenVersionId: 'v1', frozenNodeCount: 3 })
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('the start buttons (startUnderGraphLock)', () => {
  test('two people at once: the first starts, the second meets it and is refused naming them', async () => {
    const [first, second] = await Promise.all([pressStart(BOB), pressStart(OWNER)])
    expect(first.status).toBe(200)
    expect(second.status).toBe(409)
    expect(await second.json()).toEqual({
      code: 'project_writer_busy',
      busy: 'Bob Builder (bob@example.test) is running a partial recon',
      error: expect.stringContaining('Bob Builder (bob@example.test) is running a partial recon on this project.'),
    })
    expect(h.starts).toEqual([{ path: '/recon/p1/partial', actor: BOB }])
  })

  test('the same start twice by the same person: both reach the orchestrator, as today', async () => {
    const [first, second] = await Promise.all([pressStart(BOB), pressStart(BOB)])
    expect([first.status, second.status]).toEqual([200, 200])
    expect(h.starts.map(s => s.actor)).toEqual([BOB, BOB])
  })

  test("another person's agent session refuses the start before the route's own checks run", async () => {
    h.authors = [BOB]
    const res = await pressStart(OWNER)
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe('Bob Builder (bob@example.test) is running an agent session')
    expect(h.starts).toEqual([])
  })

  test("the person's own agent session: the start goes ahead (an agent run beside a scan, as today)", async () => {
    h.authors = [OWNER]
    expect((await pressStart(OWNER)).status).toBe(200)
  })

  test('sharing not in force: two people never meet here (DV-30)', async () => {
    h.sharing = false
    h.active = [{ kind: 'gvm', project_id: 'p1', status: 'running', actor_user_id: BOB }]
    expect((await pressStart(OWNER)).status).toBe(200)
  })
})

describe('the queue and the scheduler (dispatchStart)', () => {
  test("a collaborator's queued partial recon gets the 409 the queue requeues while the owner's agent runs", async () => {
    h.authors = [OWNER]
    const res = await dispatchStart('partial_recon', 'p1', { actorUserId: BOB, payload: { tool_id: 'Naabu', graph_inputs: {} } })
    expect(res).toMatchObject({
      ok: false, status: 409, code: 'project_writer_busy',
      busy: 'Olivia Owner (olivia@example.test) is running an agent session',
    })
    expect(h.starts).toEqual([])
  })

  test("the owner's own queued GVM scan dispatches beside the owner's agent run", async () => {
    h.authors = [OWNER]
    const res = await dispatchStart('gvm', 'p1', { actorUserId: OWNER })
    expect(res.ok).toBe(true)
    expect(h.starts).toEqual([{ path: '/gvm/p1/start', actor: undefined }])
  })

  test('a job with no recorded actor is the owner\'s', async () => {
    h.active = [{ kind: 'gvm', project_id: 'p1', status: 'running', actor_user_id: OWNER }]
    expect((await dispatchStart('github_hunt', 'p1', { actorUserId: null })).ok).toBe(true)
  })
})

describe('the full scan (startFullScan)', () => {
  test("another person's partial recon refuses the full scan before any version is frozen", async () => {
    h.active = [{ kind: 'partial_recon', project_id: 'p1', status: 'running', actor_user_id: BOB }]
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: OWNER })
    expect(res).toMatchObject({ ok: false, status: 409, code: 'project_writer_busy', busy: 'Bob Builder (bob@example.test) is running a partial recon' })
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.starts).toEqual([])
  })

  test("a scheduled full scan acting for a collaborator waits while the owner's agent runs", async () => {
    h.authors = [OWNER]
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', actorUserId: BOB, scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 409, code: 'project_writer_busy' })
  })

  test("the person's own agent run: the full scan starts as today", async () => {
    h.authors = [BOB]
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: BOB })
    expect(res.ok).toBe(true)
    expect(h.prepare).toHaveBeenCalledTimes(1)
    expect(h.starts.map(s => s.path)).toEqual(['/recon/p1/start'])
  })
})

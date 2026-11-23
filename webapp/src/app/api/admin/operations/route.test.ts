/**
 * GET /api/admin/operations and POST /api/admin/operations/agent-runs/stop (step 6.5; GV-06, GV-18):
 * the admin console's operations view and its per-run stop. With RBAC_GOVERNANCE_ENABLED off both are
 * 404 having read nothing; platform:operations opens the view (a 403 naming it otherwise, so a User
 * manager is refused and a Platform operator let in) and listing writes no audit row; scans carry
 * their project's owner and the actor step 5.5 records, from the queue, the ScanJobs and the
 * orchestrator, each scan once; agent runs come from the agent's /agent-sessions/all with the admin
 * behind an act-as run; triage runs with a stale heartbeat are left out without a write; shell
 * sessions name their project's owner and never their target. A source that does not answer is named
 * by its code and the rest still render. The stop needs platform:emergency_stop as well, is
 * same-origin JSON, calls the agent's /agent-session/stop for exactly that run and is audited
 * `agent.run_stop` only when a run stopped.
 *
 * Group 1 (WI-S16-6): the running Kali sandboxes come from the orchestrator through the gateway
 * (`listSandboxes`), with their person, view, state and times and never a token, a host or a project
 * list; shells keep their sandbox instance, so two sessions numbered alike in two sandboxes stay two
 * rows, and the view says how many sandboxes did not answer. POST .../sandboxes/stop stops one
 * person's sandboxes under platform:emergency_stop, audited `sandbox.stopped` by the gateway. A
 * per-user shell counts for its chat's project only when the agent's tags name the person who wrote
 * the chat and whose sandbox mounts the project (review F1); a row whose id is not the session
 * manager's shape is dropped (review F2).
 *
 * The routes and lib/authz/adminOperations.ts are real; the session, the permission answers, the
 * principal, the shared-tool decision, the act-as reader, the agent, the orchestrator, the clock and
 * Prisma are doubles (Prisma inline: the queries and the audit rows are asserted).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/operations/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  session: { userId: 'ops-1', role: 'admin' } as { userId: string; role: string } | null,
  held: new Set<string>(),
  stopVia: 'admin' as 'admin' | 'compat' | null,
  actingAs: null as string | null,
  touched: [] as string[],
  agent: vi.fn(),
  orchestrator: vi.fn(),
  db: {
    queueFindMany: vi.fn(),
    queueCount: vi.fn(),
    scanJobFindMany: vi.fn(),
    triageFindMany: vi.fn(),
    triageUpdateMany: vi.fn(),
    conversationFindMany: vi.fn(),
    projectFindMany: vi.fn(),
    userFindMany: vi.fn(),
    auditCreate: vi.fn(),
  },
  shared: vi.fn(),
  mounts: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    jobQueue: { findMany: h.db.queueFindMany, count: h.db.queueCount },
    scanJob: { findMany: h.db.scanJobFindMany },
    triageRun: { findMany: h.db.triageFindMany, updateMany: h.db.triageUpdateMany },
    conversation: { findMany: h.db.conversationFindMany },
    project: { findMany: h.db.projectFindMany },
    user: { findMany: h.db.userFindMany },
    auditLog: { create: h.db.auditCreate },
  }
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => { h.touched.push('session'); return h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }),
}))
vi.mock('@/lib/authz/adminPermission', async () => {
  const { forbiddenResponse } = await import('@/lib/authz/guards')
  return {
    sessionHolds: vi.fn(async (_s: unknown, p: string) => h.held.has(p)),
    requireSessionPermission: vi.fn(async (_s: unknown, p: Parameters<typeof forbiddenResponse>[0]) => (h.held.has(p) ? null : forbiddenResponse(p))),
  }
})
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: vi.fn(async (id: string, opts?: { fresh?: boolean }) => { h.touched.push(`principal:${id}:${opts?.fresh ? 'fresh' : 'cached'}`); return { id, role: 'admin', legacyGrants: [], createdAt: new Date(0) } }),
}))
vi.mock('@/lib/authz/sharedTools', () => ({ sharedToolAccess: h.shared }))
vi.mock('@/lib/userAudit', () => ({ actingAsUserId: vi.fn(async () => h.actingAs) }))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: h.agent,
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: h.orchestrator }))
vi.mock('@/lib/sandbox/gateway', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/gateway')>()),
  sandboxProjectsFor: (...a: unknown[]) => h.mounts(...a),
}))

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { AgentUnreachableError } from '@/lib/agentFetch'
import { GET as readView } from './route'
import { POST as stopRun } from './agent-runs/stop/route'
import { POST as stopSandboxRoute } from './sandboxes/stop/route'
import { resetSandboxGatewayForTests } from '@/lib/sandbox/gateway'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const ago = (ms: number) => new Date(NOW.getTime() - ms)
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

let agentSessions: () => Response | Promise<Response>
let agentShells: () => Response | Promise<Response>
let agentStop: (body: Record<string, unknown>) => Response | Promise<Response>
let liveAnswer: () => Response | Promise<Response>
let sandboxList: () => Response | Promise<Response>
let sandboxStatus: (userId: string) => Response | Promise<Response>
let sandboxStop: (userId: string, body: Record<string, unknown>) => Response | Promise<Response>

function queueRow(id: string, over: Record<string, unknown> = {}) {
  return {
    id, projectId: 'p-1', userId: 'mem-a', kind: 'full_recon', status: 'queued', runId: '', scanJobId: null,
    blockedCode: '', blockedReason: '', enqueuedAt: ago(60_000), startedAt: null, ...over,
  }
}
function scanJob(id: string, over: Record<string, unknown> = {}) {
  return { id, projectId: 'p-1', kind: 'full_recon', runId: '', initiatedByUserId: 'mem-a', startedAt: ago(10 * 60_000), createdAt: ago(10 * 60_000), ...over }
}
function live(over: Record<string, unknown> = {}) {
  return { kind: 'gvm', project_id: 'p-2', run_id: '', tool_id: '', status: 'running', started_at: ago(5 * 60_000).toISOString(), actor_user_id: 'mem-b', ...over }
}
function triage(id: string, over: Record<string, unknown> = {}) {
  return {
    id, projectId: 'p-1', actorUserId: 'mem-a', realActorUserId: null, status: 'running', trigger: 'app', phase: 'review',
    progress: 40, startedAt: ago(120_000), heartbeatAt: ago(20_000), ...over,
  }
}

const view = () => readView(new NextRequest('http://redamon.test/api/admin/operations'))
function stop(body: unknown = { userId: 'mem-a', projectId: 'p-1', sessionId: 's-1' }, headers: Record<string, string> = {}) {
  return stopRun(new NextRequest('http://redamon.test/api/admin/operations/agent-runs/stop', {
    method: 'POST',
    headers: { 'content-type': 'application/json', host: 'redamon.test', origin: 'http://redamon.test', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }))
}
function stopSandbox(body: unknown = { userId: 'mem-a' }, headers: Record<string, string> = {}) {
  return stopSandboxRoute(new NextRequest('http://redamon.test/api/admin/operations/sandboxes/stop', {
    method: 'POST',
    headers: { 'content-type': 'application/json', host: 'redamon.test', origin: 'http://redamon.test', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }))
}
const body = async (res: Response) => res.json() as Promise<Record<string, any>>
const orchestratorCalls = () => h.orchestrator.mock.calls.map((c) => `${(c[1] as RequestInit | undefined)?.method ?? 'GET'} ${new URL(String(c[0])).pathname}`)
const auditRows = () => h.db.auditCreate.mock.calls.map((c) => c[0].data)
const agentPaths = () => h.agent.mock.calls.map((c) => c[0])

beforeEach(() => {
  setFlagsForTests(GOV)
  setNowForTests(() => NOW)
  h.session = { userId: 'ops-1', role: 'admin' }
  h.held = new Set(['platform:operations'])
  h.stopVia = 'admin'
  h.actingAs = null
  h.touched = []
  for (const fn of Object.values(h.db)) fn.mockReset()
  h.db.queueFindMany.mockResolvedValue([])
  h.db.queueCount.mockResolvedValue(0)
  h.db.scanJobFindMany.mockResolvedValue([])
  h.db.triageFindMany.mockResolvedValue([])
  h.db.conversationFindMany.mockResolvedValue([])
  h.db.projectFindMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
    where.id.in.filter((id) => id !== 'p-gone').map((id) => ({ id, name: `${id} name`, userId: id === 'p-2' ? 'own-b' : 'own-a' })))
  h.db.userFindMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
    where.id.in.filter((id) => id !== 'gone-user').map((id) => ({ id, name: `Name ${id}` })))
  h.db.auditCreate.mockImplementation(async ({ data }: { data: object }) => ({ id: 'al-1', createdAt: NOW, ...data }))
  h.shared.mockReset()
  h.shared.mockImplementation(async (_p: unknown, tool: string) => (tool === 'emergency_stop_all' && h.stopVia ? { allowed: true, via: h.stopVia } : { allowed: false, via: null }))
  agentSessions = () => json({ sessions: [] })
  agentShells = () => json({ sessions: [], jobs: [], non_msf_sessions: [] })
  agentStop = () => json({ stopped: true })
  liveAnswer = () => json({ scans: [] })
  sandboxList = () => json({ sandboxes: [] })
  sandboxStatus = () => json({ instances: [] })
  sandboxStop = () => json({ stopped: 1 })
  resetSandboxGatewayForTests()
  h.mounts.mockReset().mockImplementation(async (userId: string) => ({ 'mem-a': ['p-1'], 'mem-b': ['p-2'] } as Record<string, string[]>)[userId] ?? [])
  h.agent.mockReset()
  h.agent.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path === '/agent-sessions/all') return agentSessions()
    if (path === '/sessions') return agentShells()
    if (path === '/agent-session/stop') return agentStop(JSON.parse(String(init?.body)))
    if (/^\/sandboxes\/[^/]+\/drop$/.test(path)) return json({ dropped: true })
    return json({}, 404)
  })
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname
    if (path === '/system/active-scans') return liveAnswer()
    if (path === '/sandboxes') return sandboxList()
    const stop = path.match(/^\/sandboxes\/([^/]+)\/stop$/)
    if (stop && init?.method === 'POST') return sandboxStop(decodeURIComponent(stop[1]), JSON.parse(String(init.body)))
    const status = path.match(/^\/sandboxes\/([^/]+)$/)
    if (status) return sandboxStatus(decodeURIComponent(status[1]))
    return json({ detail: 'Not Found' }, 404)
  })
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('with RBAC_GOVERNANCE_ENABLED off', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('%s: the view and the stop are 404 and read nothing', async (_what, flags) => {
    setFlagsForTests(flags)
    expect((await view()).status).toBe(404)
    expect((await stop()).status).toBe(404)
    expect(h.touched).toEqual([])
    expect(h.db.queueFindMany).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })
})

describe('GET /api/admin/operations: who may read it', () => {
  test('signed out: 401, nothing read', async () => {
    h.session = null
    expect((await view()).status).toBe(401)
    expect(h.db.queueFindMany).not.toHaveBeenCalled()
  })

  test('without platform:operations (a User manager): 403 naming it, no source read', async () => {
    h.held = new Set(['users:read', 'users:edit'])
    const res = await view()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'platform:operations' })
    expect(h.db.queueFindMany).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('a Platform operator reads it; listing writes no audit row and asks the stop without counting a use', async () => {
    const res = await view()
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const out = await body(res)
    expect(out.generatedAt).toBe(NOW.toISOString())
    expect(out.actions).toEqual({ stopRuns: true })
    expect(h.shared).toHaveBeenCalledWith(expect.objectContaining({ id: 'ops-1' }), 'emergency_stop_all', { record: false })
    expect(h.db.auditCreate).not.toHaveBeenCalled()
    expect(h.db.triageUpdateMany).not.toHaveBeenCalled()
  })

  test('without platform:emergency_stop the view offers no stop', async () => {
    h.stopVia = null
    expect((await body(await view())).actions).toEqual({ stopRuns: false })
  })
})

describe('lists runs with owners and actors', () => {
  test('scans from the three sources, each once, with the owner and the actor of step 5.5', async () => {
    h.db.queueFindMany.mockImplementation(async ({ where }: { where: { status: { in: string[] } } }) =>
      (where.status.in.includes('running')
        ? [queueRow('q-run', { status: 'running', runId: 'r-1', kind: 'partial_recon', scanJobId: 'sj-q', userId: 'mem-c', startedAt: ago(30_000) })]
        : [queueRow('q-wait', { blockedCode: 'ram', blockedReason: 'waiting for memory' }), queueRow('q-rev', { status: 'needs_review', projectId: 'p-2' })]))
    h.db.queueCount.mockResolvedValue(2)
    h.db.scanJobFindMany.mockResolvedValue([
      scanJob('sj-q', { kind: 'partial_recon', runId: 'r-1' }),
      scanJob('sj-free', { kind: 'trufflehog', runId: 'src-a', initiatedByUserId: 'mem-d' }),
    ])
    liveAnswer = () => json({
      scans: [
        live({ kind: 'partial_recon', project_id: 'p-1', run_id: 'r-1', tool_id: 'naabu', actor_user_id: 'mem-c' }),
        live({ kind: 'trufflehog', project_id: 'p-1', run_id: 'src-a', tool_id: 'src-a', actor_user_id: 'mem-d' }),
        live({ kind: 'gvm', project_id: 'p-2', actor_user_id: 'mem-b' }),
      ],
    })
    const out = await body(await view())
    expect(out.scans.orchestrator).toEqual({ ok: true })
    expect(out.scans.running.map((s: any) => [s.key, s.source, s.kind, s.project.id, s.project.owner?.id, s.actor?.id])).toEqual([
      ['queue:q-run', 'queue', 'partial_recon', 'p-1', 'own-a', 'mem-c'],
      ['scan:sj-free', 'scan', 'trufflehog', 'p-1', 'own-a', 'mem-d'],
      ['live:gvm:p-2:', 'live', 'gvm', 'p-2', 'own-b', 'mem-b'],
    ])
    expect(out.scans.running[0].project).toEqual({ id: 'p-1', name: 'p-1 name', owner: { id: 'own-a', name: 'Name own-a' } })
    expect(out.scans.running[0].actor).toEqual({ id: 'mem-c', name: 'Name mem-c' })
    expect(out.scans.queued.map((s: any) => [s.key, s.status, s.blockedCode, s.project.owner.id, s.actor.id])).toEqual([
      ['queue:q-wait', 'queued', 'ram', 'own-a', 'mem-a'],
      ['queue:q-rev', 'needs_review', '', 'own-b', 'mem-a'],
    ])
    expect(out.scans.queuedTotal).toBe(2)
    // Every scan of the instance, not the caller's: no project or user filter on the reads.
    for (const call of h.db.queueFindMany.mock.calls) expect(Object.keys(call[0].where)).toEqual(['status'])
    expect(h.db.scanJobFindMany.mock.calls[0][0].where).toEqual({ status: 'running' })
  })

  test("a ScanJob left 'running' by a scan that ended is dropped once the orchestrator's set is known; kept while it is not", async () => {
    h.db.scanJobFindMany.mockResolvedValue([
      scanJob('sj-phantom', { projectId: 'p-1', startedAt: ago(30 * 60_000) }),
      scanJob('sj-new', { projectId: 'p-2', kind: 'gvm', startedAt: ago(10_000) }),
    ])
    liveAnswer = () => json({ scans: [live({ kind: 'github_hunt', project_id: 'p-3' })] })
    let out = await body(await view())
    expect(out.scans.running.map((s: any) => s.key)).toEqual(['scan:sj-new', 'live:github_hunt:p-3:'])

    liveAnswer = () => json({ scans: [] })
    out = await body(await view())
    expect(out.scans.running.map((s: any) => s.key)).toEqual(['scan:sj-phantom', 'scan:sj-new'])
  })

  test('agent runs: the person, the admin behind an act-as run, the owner, running first', async () => {
    agentSessions = () => json({
      sessions: [
        { user_id: 'mem-a', project_id: 'p-2', session_id: 's-idle', running: false, connected: true, actor_id: null },
        { user_id: 'mem-b', project_id: 'p-1', session_id: 's-run', running: true, connected: false, actor_id: 'adm-x' },
        { user_id: '', project_id: 'p-1', session_id: 'bad' },
      ],
    })
    const out = await body(await view())
    expect(out.agentRuns.state).toEqual({ ok: true })
    expect(out.agentRuns.runs).toEqual([
      {
        key: 'mem-b:p-1:s-run', sessionId: 's-run', running: true, connected: false,
        project: { id: 'p-1', name: 'p-1 name', owner: { id: 'own-a', name: 'Name own-a' } },
        actor: { id: 'mem-b', name: 'Name mem-b' }, realActor: { id: 'adm-x', name: 'Name adm-x' },
      },
      {
        key: 'mem-a:p-2:s-idle', sessionId: 's-idle', running: false, connected: true,
        project: { id: 'p-2', name: 'p-2 name', owner: { id: 'own-b', name: 'Name own-b' } },
        actor: { id: 'mem-a', name: 'Name mem-a' }, realActor: null,
      },
    ])
    expect(agentPaths()).toContain('/agent-sessions/all')
  })

  test('a run on a project deleted since, or of an account deleted since, is still listed', async () => {
    agentSessions = () => json({ sessions: [{ user_id: 'gone-user', project_id: 'p-gone', session_id: 's-1', running: true, connected: false, actor_id: null }] })
    const [run] = (await body(await view())).agentRuns.runs
    expect(run.project).toEqual({ id: 'p-gone', name: null, owner: null })
    expect(run.actor).toEqual({ id: 'gone-user', name: null })
  })

  test('triage runs with a fresh heartbeat, with the actor and the admin behind it; a stale one left out without a write', async () => {
    h.db.triageFindMany.mockResolvedValue([
      triage('t-live', { realActorUserId: 'adm-x', trigger: 'mcp' }),
      triage('t-dead', { heartbeatAt: ago(60 * 60_000) }),
    ])
    const out = await body(await view())
    expect(out.triageRuns).toEqual([{
      id: 't-live', status: 'running', trigger: 'mcp', phase: 'review', progress: 40,
      startedAt: ago(120_000).toISOString(), heartbeatAt: ago(20_000).toISOString(),
      project: { id: 'p-1', name: 'p-1 name', owner: { id: 'own-a', name: 'Name own-a' } },
      actor: { id: 'mem-a', name: 'Name mem-a' }, realActor: { id: 'adm-x', name: 'Name adm-x' },
    }])
    expect(h.db.triageFindMany.mock.calls[0][0].where).toEqual({ status: { in: ['running', 'publishing'] } })
    expect(h.db.triageUpdateMany).not.toHaveBeenCalled()
  })

  test('shell sessions name their project owner and their sandbox\'s person, never the target; jobs are a count', async () => {
    const own = (sandbox: string, person: string) => ({ sandbox, sandbox_user: person, sandbox_view: 'own' })
    agentShells = () => json({
      sessions: [
        { id: 3, type: 'meterpreter', info: 'root @ host', connection: '198.51.100.1:4444 -> 203.0.113.9:5555', target_ip: '203.0.113.9', chat_session_id: 'chat-1', ...own('aaaaa1', 'own-a') },
        { id: 4, type: 'shell', target_ip: '203.0.113.10', chat_session_id: null, ...own('aaaaa1', 'own-a') },
        // A row the agent did not tag with its sandbox stands for no project and no person.
        { id: 5, type: 'shell', chat_session_id: 'chat-1' },
      ],
      non_msf_sessions: [{ id: 'raw-1', type: 'netcat', chat_session_id: 'chat-2', ...own('bbbbb1', 'own-b') }],
      jobs: [{ id: 0, sandbox: 'aaaaa1' }, { id: 1, sandbox: 'bbbbb1' }],
    })
    h.db.conversationFindMany.mockResolvedValue([
      { sessionId: 'chat-1', projectId: 'p-1', userId: 'own-a' },
      { sessionId: 'chat-2', projectId: 'p-2', userId: 'own-b' },
    ])
    const res = await view()
    const raw = await res.clone().text()
    const out = await body(res)
    expect(out.shells.state).toEqual({ ok: true })
    expect(out.shells.jobs).toBe(2)
    expect(out.shells.unavailable).toBe(0)
    expect(out.shells.sessions).toEqual([
      { key: 'session:aaaaa1:3', id: '3', kind: 'session', type: 'meterpreter', sandbox: 'aaaaa1', project: { id: 'p-1', name: 'p-1 name', owner: { id: 'own-a', name: 'Name own-a' } }, person: { id: 'own-a', name: 'Name own-a' } },
      { key: 'session:aaaaa1:4', id: '4', kind: 'session', type: 'shell', sandbox: 'aaaaa1', project: null, person: { id: 'own-a', name: 'Name own-a' } },
      { key: 'session:5', id: '5', kind: 'session', type: 'shell', sandbox: null, project: null, person: null },
      { key: 'listener:bbbbb1:raw-1', id: 'raw-1', kind: 'listener', type: 'netcat', sandbox: 'bbbbb1', project: { id: 'p-2', name: 'p-2 name', owner: { id: 'own-b', name: 'Name own-b' } }, person: { id: 'own-b', name: 'Name own-b' } },
    ])
    expect(raw).not.toContain('203.0.113')
    expect(raw).not.toContain('root @ host')
    expect(h.db.conversationFindMany.mock.calls[0][0].where).toEqual({ sessionId: { in: ['chat-1', 'chat-2'] } })
  })

  test('nothing running: empty lists, no project or account read', async () => {
    const out = await body(await view())
    expect(out.agentRuns.runs).toEqual([])
    expect(out.scans).toEqual({ orchestrator: { ok: true }, running: [], queued: [], queuedTotal: 0 })
    expect(out.triageRuns).toEqual([])
    expect(out.shells).toEqual({ state: { ok: true }, sessions: [], jobs: 0, unavailable: 0 })
    expect(out.sandboxes).toEqual({ state: { ok: true }, list: [] })
    expect(h.db.projectFindMany).not.toHaveBeenCalled()
    expect(h.db.userFindMany).not.toHaveBeenCalled()
    expect(h.db.conversationFindMany).not.toHaveBeenCalled()
  })
})

describe('a source that does not answer', () => {
  test('the agent down: agent runs and shells say agent_unreachable, scans and triage still render', async () => {
    h.agent.mockImplementation(async () => { throw new AgentUnreachableError(Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } })) })
    h.db.triageFindMany.mockResolvedValue([triage('t-1')])
    const res = await view()
    expect(res.status).toBe(200)
    const out = await body(res)
    expect(out.agentRuns).toEqual({ state: { ok: false, code: 'agent_unreachable' }, runs: [] })
    expect(out.shells).toEqual({ state: { ok: false, code: 'agent_unreachable' }, sessions: [], jobs: 0, unavailable: 0 })
    expect(out.triageRuns).toHaveLength(1)
  })

  test('an agent older than this view (404 on /agent-sessions/all): agent_route_missing; a timeout, an error, no key, a refused key: each its code', async () => {
    agentSessions = () => json({ detail: 'Not Found' }, 404)
    expect((await body(await view())).agentRuns.state).toEqual({ ok: false, code: 'agent_route_missing' })
    agentSessions = () => { throw new AgentUnreachableError(Object.assign(new Error('timeout'), { name: 'TimeoutError' })) }
    expect((await body(await view())).agentRuns.state).toEqual({ ok: false, code: 'agent_timeout' })
    agentShells = () => json({ error: 'Session manager timeout' }, 504)
    expect((await body(await view())).shells.state).toEqual({ ok: false, code: 'agent_error' })
    agentSessions = () => json({ detail: 'INTERNAL_API_KEY is not configured; this endpoint is disabled.' }, 503)
    expect((await body(await view())).agentRuns.state).toEqual({ ok: false, code: 'agent_not_ready' })
    agentSessions = () => json({ detail: 'Unauthorized' }, 401)
    expect((await body(await view())).agentRuns.state).toEqual({ ok: false, code: 'agent_refused' })
  })

  test('the orchestrator down: its code, the database scans still listed and none dropped as a phantom', async () => {
    h.orchestrator.mockImplementation(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }) })
    h.db.scanJobFindMany.mockResolvedValue([scanJob('sj-1', { startedAt: ago(60 * 60_000) })])
    const out = await body(await view())
    expect(out.scans.orchestrator).toEqual({ ok: false, code: 'orchestrator_unreachable' })
    expect(out.scans.running.map((s: any) => s.key)).toEqual(['scan:sj-1'])
    expect(out.sandboxes).toEqual({ state: { ok: false, code: 'orchestrator_unreachable' }, list: [] })
  })

  test('a failed database read is a coded 500 without the error text', async () => {
    h.db.queueFindMany.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:5432 secret'), { code: 'P1001' }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await view()
    expect(res.status).toBe(500)
    const out = await body(res)
    expect(out).toEqual({ error: 'Could not load the operations view', code: 'P1001' })
  })
})

describe('POST /api/admin/operations/agent-runs/stop', () => {
  beforeEach(() => { h.held = new Set(['platform:operations']) })

  test('stop one run: the agent stops exactly that run, read fresh, audited agent.run_stop with the project', async () => {
    let sent: Record<string, unknown> | null = null
    agentStop = (b) => { sent = b; return json({ stopped: true }) }
    const res = await stop()
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ stopped: true })
    expect(sent).toEqual({ user_id: 'mem-a', project_id: 'p-1', session_id: 's-1' })
    expect(h.touched).toContain('principal:ops-1:fresh')
    expect(h.shared).toHaveBeenCalledWith(expect.objectContaining({ id: 'ops-1' }), 'emergency_stop_all')
    expect(auditRows()).toEqual([expect.objectContaining({
      action: 'agent.run_stop', actorId: 'ops-1', targetType: 'agent_session', targetId: 's-1', projectId: 'p-1',
      permission: 'platform:emergency_stop', after: { userId: 'mem-a', via: 'admin' }, source: 'api',
    })])
  })

  test('global stop needs the permission: platform:operations alone is refused 403 platform:emergency_stop, the agent not called', async () => {
    h.stopVia = null
    const res = await stop()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'platform:emergency_stop' })
    expect(agentPaths()).toEqual([])
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('without platform:operations: 403 naming it before the stop permission or the agent', async () => {
    h.held = new Set()
    const res = await stop()
    expect(res.status).toBe(403)
    expect((await body(res)).permission).toBe('platform:operations')
    expect(h.shared).not.toHaveBeenCalled()
    expect(h.agent).not.toHaveBeenCalled()
  })

  test('held through the escape hatch: the stop counts as a use and the row says so', async () => {
    h.stopVia = 'compat'
    expect((await stop()).status).toBe(200)
    expect(auditRows()[0].after).toEqual({ userId: 'mem-a', via: 'compat' })
  })

  test('under act-as the row names the real person and the account acted as', async () => {
    h.actingAs = 'mem-z'
    await stop()
    expect(auditRows()[0]).toMatchObject({ actorId: 'ops-1', onBehalfOfUserId: 'mem-z' })
  })

  test('the same event twice: the second finds the run over, answers stopped false and writes no row', async () => {
    const answers = [true, false]
    agentStop = () => json({ stopped: answers.shift() })
    expect(await body(await stop())).toEqual({ stopped: true })
    expect(await body(await stop())).toEqual({ stopped: false })
    expect(auditRows()).toHaveLength(1)
  })

  test('cross-origin 403 and a non-JSON body 415, nothing stopped', async () => {
    expect((await stop(undefined, { origin: 'http://evil.test' })).status).toBe(403)
    expect((await stop('userId=mem-a', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect(h.agent).not.toHaveBeenCalled()
  })

  test.each([
    [{ projectId: 'p-1', sessionId: 's-1' }, 'userId'],
    [{ userId: 'mem-a:p-9', projectId: 'p-1', sessionId: 's-1' }, 'userId'],
    [{ userId: 'mem-a', projectId: 'p 1', sessionId: 's-1' }, 'projectId'],
    [{ userId: 'mem-a', projectId: 'p-1', sessionId: '' }, 'sessionId'],
    [{ userId: 'mem-a', projectId: 'p-1', sessionId: 'x'.repeat(201) }, 'sessionId'],
  ])('a bad target answers 400 naming the field: %j', async (target, field) => {
    const res = await stop(target)
    expect(res.status).toBe(400)
    expect(await body(res)).toMatchObject({ code: 'invalid_target', field })
    expect(h.agent).not.toHaveBeenCalled()
  })

  test('the agent unreachable: 503 agent_unreachable, an [rbac] line, no row', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agent.mockImplementation(async () => { throw new AgentUnreachableError(Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } })) })
    const res = await stop()
    expect(res.status).toBe(503)
    expect((await body(res)).code).toBe('agent_unreachable')
    expect(errors.mock.calls.some((c) => String(c[0]).startsWith('[rbac] operations run stop failed'))).toBe(true)
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('the agent answering an error: 502 with its status, never its text, no row', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    agentStop = () => json({ detail: 'Traceback: key=abc' }, 500)
    const res = await stop()
    expect(res.status).toBe(502)
    const out = await body(res)
    expect(out).toMatchObject({ error: 'Could not stop the agent run', upstreamStatus: 500 })
    expect(JSON.stringify(out)).not.toContain('Traceback')
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('signed out: 401', async () => {
    h.session = null
    expect((await stop()).status).toBe(401)
    expect(h.agent).not.toHaveBeenCalled()
  })
})

describe('Kali sandboxes and shells across sandboxes (group 1, WI-S16-6)', () => {
  const T0 = Date.UTC(2026, 10, 13, 9, 0, 0) / 1000
  const iso = (epoch: number) => new Date(epoch * 1000).toISOString()

  beforeEach(() => {
    sandboxList = () => json({
      sandboxes: [
        { user_id: 'mem-a', view: 'own', instance: 'aaaaa1', host: 'redamon-kali-0123456789abcdef-aaaaa1', token: 'tok-SECRET-a', state: 'running' },
        { user_id: 'mem-b', view: 'act_as', instance: 'bbbbb1', host: 'redamon-kali-fedcba9876543210-bbbbb1', token: 'tok-SECRET-b', state: 'draining' },
      ],
    })
    sandboxStatus = (userId) => json({
      instances: userId === 'mem-a'
        ? [{ instance: 'aaaaa1', view: 'own', state: 'running', projects_hash: 'feedfacecafebeef', created_at: T0, last_used: T0 + 600, lease_kinds: ['run'], stop_at: T0 + 1800, stop_reason: null, warn: false, reverse_port: 4444 }]
        : [],
    })
  })

  test('each running sandbox with its person, view, state and times; never a token, a host or a project list', async () => {
    const res = await view()
    const raw = await res.clone().text()
    const out = await body(res)
    expect(out.sandboxes.state).toEqual({ ok: true })
    expect('mode' in out.sandboxes).toBe(false)
    expect(out.sandboxes.list).toEqual([
      {
        key: 'mem-a:aaaaa1', instance: 'aaaaa1', person: { id: 'mem-a', name: 'Name mem-a' }, view: 'own', state: 'running',
        createdAt: iso(T0), lastUsed: iso(T0 + 600), stopAt: iso(T0 + 1800),
        // 4444 from an orchestrator that sends no state: no port, reason not reported (FU-24).
        reversePort: { port: null, state: null },
      },
      {
        key: 'mem-b:bbbbb1', instance: 'bbbbb1', person: { id: 'mem-b', name: 'Name mem-b' }, view: 'act_as', state: 'draining',
        createdAt: null, lastUsed: null, stopAt: null, reversePort: null,
      },
    ])
    for (const leak of ['tok-SECRET', 'redamon-kali-', 'feedfacecafebeef', 'projects', 'lease_kinds', 'reverse_port']) {
      expect(raw).not.toContain(leak)
    }
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test("each sandbox's reverse port (FU-24): from the list entry, else the person's status; the reason when there is none", async () => {
    sandboxList = () => json({
      sandboxes: [
        { user_id: 'mem-a', view: 'own', instance: 'aaaaa1', host: 'h-a', token: 'tok-SECRET-a', state: 'running', reverse_port: 31001, reverse_port_state: 'assigned' },
        { user_id: 'mem-b', view: 'own', instance: 'bbbbb1', host: 'h-b', token: 'tok-SECRET-b', state: 'running' },
        { user_id: 'mem-c', view: 'own', instance: 'ccccc1', host: 'h-c', token: 'tok-SECRET-c', state: 'running', reverse_port: 4444, reverse_port_state: 'pool_full' },
      ],
    })
    sandboxStatus = (userId) => json({
      instances: userId === 'mem-b'
        ? [{ instance: 'bbbbb1', view: 'own', state: 'running', projects_hash: 'feedfacecafebeef', created_at: T0, last_used: T0, lease_kinds: [], stop_at: null, stop_reason: null, warn: false, reverse_port: 4444, reverse_port_state: 'no_pool' }]
        : [],
    })
    const out = await body(await view())
    expect(out.sandboxes.list.map((s: { key: string; reversePort: unknown }) => [s.key, s.reversePort])).toEqual([
      ['mem-a:aaaaa1', { port: 31001, state: 'assigned' }],
      ['mem-b:bbbbb1', { port: null, state: 'no_pool' }],
      ['mem-c:ccccc1', { port: null, state: 'pool_full' }],
    ])
  })

  test('two shells numbered alike in two sandboxes stay two rows, each naming its instance; the unavailable count is carried', async () => {
    agentShells = () => json({
      sessions: [
        { id: 1, type: 'shell', chat_session_id: 'chat-1', sandbox: 'aaaaa1', sandbox_user: 'mem-a', sandbox_view: 'own' },
        { id: 1, type: 'meterpreter', chat_session_id: 'chat-2', sandbox: 'bbbbb1', sandbox_user: 'mem-b', sandbox_view: 'own' },
      ],
      non_msf_sessions: [{ id: 'raw-1', type: 'netcat', chat_session_id: null, sandbox: 'bbbbb1', sandbox_user: 'mem-b', sandbox_view: 'own' }],
      jobs: [{ id: 0, sandbox: 'aaaaa1' }, { id: 0, sandbox: 'bbbbb1' }],
      unavailable: ['ccccc1', 'ddddd1'],
    })
    h.db.conversationFindMany.mockResolvedValue([
      { sessionId: 'chat-1', projectId: 'p-1', userId: 'mem-a' },
      { sessionId: 'chat-2', projectId: 'p-2', userId: 'mem-b' },
    ])
    const shells = (await body(await view())).shells
    expect(shells.sessions.map((s: any) => [s.key, s.id, s.sandbox, s.project?.id])).toEqual([
      ['session:aaaaa1:1', '1', 'aaaaa1', 'p-1'],
      ['session:bbbbb1:1', '1', 'bbbbb1', 'p-2'],
      ['listener:bbbbb1:raw-1', 'raw-1', 'bbbbb1', undefined],
    ])
    expect(new Set(shells.sessions.map((s: any) => s.key)).size).toBe(3)
    expect(shells.jobs).toBe(2)
    expect(shells.unavailable).toBe(2)
  })

  test('the sandbox source does not answer, or answers outside the contract: its code, the rest still render', async () => {
    sandboxList = () => json({ detail: 'Internal Server Error' }, 500)
    let out = await body(await view())
    expect(out.sandboxes).toEqual({ state: { ok: false, code: 'orchestrator_error' }, list: [] })
    expect(out.scans.orchestrator).toEqual({ ok: true })
    sandboxList = () => new Promise<Response>(() => {})
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const pending = view()
      await vi.advanceTimersByTimeAsync(8_500)
      out = await body(await pending)
    } finally {
      vi.useRealTimers()
    }
    expect(out.sandboxes).toEqual({ state: { ok: false, code: 'orchestrator_timeout' }, list: [] })
  })

  test('an orchestrator without the sandbox routes is a source that does not answer, never "no sandbox"', async () => {
    sandboxList = () => json({ detail: 'Not Found' }, 404)
    expect((await body(await view())).sandboxes).toEqual({ state: { ok: false, code: 'sandbox_routes_missing' }, list: [] })
  })
})

describe('POST /api/admin/operations/sandboxes/stop', () => {
  beforeEach(() => { h.held = new Set(['platform:operations']) })
  const stops = () => orchestratorCalls().filter((c) => c.startsWith('POST /sandboxes/'))

  test("stops one person's sandboxes as an operator stop, audited sandbox.stopped with the admin as actor", async () => {
    let sent: Record<string, unknown> | null = null
    sandboxStop = (userId, b) => { sent = { userId, ...b }; return json({ stopped: 2 }) }
    const res = await stopSandbox()
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ stopped: 2 })
    expect(sent).toEqual({ userId: 'mem-a', reason: 'operator' })
    expect(h.touched).toContain('principal:ops-1:fresh')
    expect(h.shared).toHaveBeenCalledWith(expect.objectContaining({ id: 'ops-1' }), 'emergency_stop_all')
    expect(agentPaths()).toContain('/sandboxes/mem-a/drop')
    expect(auditRows()).toEqual([expect.objectContaining({
      action: 'sandbox.stopped', actorId: 'ops-1', targetType: 'user', targetId: 'mem-a',
      after: { reason: 'operator', stopped: 2 },
    })])
    expect(auditRows()[0].onBehalfOfUserId ?? null).toBeNull()
    expect(JSON.stringify(auditRows())).not.toMatch(/tok-|token/)
  })

  test('without platform:emergency_stop: 403 naming it, nothing stopped, no row', async () => {
    h.stopVia = null
    const res = await stopSandbox()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'platform:emergency_stop' })
    expect(stops()).toEqual([])
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('without platform:operations: 403 naming it before the stop permission or the orchestrator', async () => {
    h.held = new Set()
    const res = await stopSandbox()
    expect(res.status).toBe(403)
    expect((await body(res)).permission).toBe('platform:operations')
    expect(h.shared).not.toHaveBeenCalled()
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('held through the escape hatch: allowed, the decision counted as a use', async () => {
    h.stopVia = 'compat'
    expect((await stopSandbox()).status).toBe(200)
    expect(h.shared).toHaveBeenCalledWith(expect.anything(), 'emergency_stop_all')
    expect(h.shared.mock.calls.find((c) => c[1] === 'emergency_stop_all')?.[2]).toBeUndefined()
  })

  test('under act-as the row names the real person and the account acted as', async () => {
    h.actingAs = 'mem-z'
    await stopSandbox()
    expect(auditRows()[0]).toMatchObject({ action: 'sandbox.stopped', actorId: 'ops-1', onBehalfOfUserId: 'mem-z' })
  })

  test('nothing running: stopped 0 and no row', async () => {
    sandboxStop = () => json({ stopped: 0 })
    expect(await body(await stopSandbox())).toEqual({ stopped: 0 })
    expect(h.db.auditCreate).not.toHaveBeenCalled()
    expect(agentPaths()).not.toContain('/sandboxes/mem-a/drop')
  })

  test('cross-origin 403 and a non-JSON body 415, nothing stopped', async () => {
    expect((await stopSandbox(undefined, { origin: 'http://evil.test' })).status).toBe(403)
    expect((await stopSandbox('userId=mem-a', { 'content-type': 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test.each([
    [{}],
    [{ userId: '' }],
    [{ userId: 'mem-a/../x' }],
    [{ userId: 'ensure' }],
    [{ userId: 'stop-all' }],
    [{ userId: 'x'.repeat(65) }],
    [{ userId: 7 }],
  ])('a bad person answers 400 invalid_target naming userId: %j', async (target) => {
    const res = await stopSandbox(target)
    expect(res.status).toBe(400)
    expect(await body(res)).toMatchObject({ code: 'invalid_target', field: 'userId' })
    expect(stops()).toEqual([])
  })

  test('the orchestrator unreachable: 503 with its code and an [rbac] line, no row', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.orchestrator.mockImplementation(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }) })
    const res = await stopSandbox()
    expect(res.status).toBe(503)
    expect((await body(res)).code).toBe('orchestrator_unreachable')
    expect(errors.mock.calls.some((c) => String(c[0]).startsWith('[rbac] operations sandbox stop failed'))).toBe(true)
    expect(h.db.auditCreate).not.toHaveBeenCalled()
  })

  test('with RBAC_GOVERNANCE_ENABLED off: 404, nothing read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    expect((await stopSandbox()).status).toBe(404)
    expect(h.touched).toEqual([])
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('signed out: 401', async () => {
    h.session = null
    expect((await stopSandbox()).status).toBe(401)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })
})

describe('shells of per-user sandboxes: attribution and id shape (review F1, F2)', () => {
  beforeEach(() => {
    h.db.conversationFindMany.mockResolvedValue([
      { sessionId: 'chat-1', projectId: 'p-1', userId: 'mem-a' },
      { sessionId: 'chat-2', projectId: 'p-2', userId: 'mem-b' },
    ])
  })

  test("a sandbox naming another person's chat, or a project its person's sandbox does not mount, is shown unattributed, under its own person", async () => {
    agentShells = () => json({
      sessions: [
        { id: 7, type: 'meterpreter', chat_session_id: 'chat-2', sandbox: 'aaaaa1', sandbox_user: 'mem-a', sandbox_view: 'own' },
        { id: 8, type: 'shell', chat_session_id: 'chat-1', sandbox: 'aaaaa1', sandbox_user: 'mem-a', sandbox_view: 'act_as' },
        { id: 9, type: 'shell', chat_session_id: 'chat-1', sandbox: 'aaaaa1' },
        { id: 10, type: 'shell', chat_session_id: 'chat-1', sandbox: 'aaaaa1', sandbox_user: 'mem-a', sandbox_view: 'own' },
      ],
      non_msf_sessions: [], jobs: [],
    })
    h.mounts.mockImplementation(async (userId: string, opts: { actingAs?: boolean } = {}) => (userId === 'mem-a' && !opts.actingAs ? ['p-1'] : []))
    const rows = (await body(await view())).shells.sessions
    expect(rows.map((s: any) => [s.id, s.project?.id ?? null, s.person?.id ?? null])).toEqual([
      ['7', null, 'mem-a'],
      ['8', null, 'mem-a'],
      ['9', null, null],
      ['10', 'p-1', 'mem-a'],
    ])
    expect(h.mounts).toHaveBeenCalledWith('mem-a', { actingAs: true })
  })

  test('rows whose id is not the session manager\'s shape are dropped, and not counted as jobs', async () => {
    agentShells = () => json({
      sessions: [{ id: '../emergency-stop-all?', type: 'shell', chat_session_id: 'chat-1' }, { id: 3, type: 'shell', chat_session_id: 'chat-1' }],
      non_msf_sessions: [{ id: 'nc-1', type: 'netcat' }, { id: 'raw-12', type: 'netcat' }],
      jobs: [{ id: '../x' }, { id: 0 }],
    })
    const shells = (await body(await view())).shells
    expect(shells.sessions.map((s: any) => s.key)).toEqual(['session:3', 'listener:raw-12'])
    expect(shells.jobs).toBe(1)
  })
})

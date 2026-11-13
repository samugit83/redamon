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

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { AgentUnreachableError } from '@/lib/agentFetch'
import { GET as readView } from './route'
import { POST as stopRun } from './agent-runs/stop/route'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const ago = (ms: number) => new Date(NOW.getTime() - ms)
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

let agentSessions: () => Response | Promise<Response>
let agentShells: () => Response | Promise<Response>
let agentStop: (body: Record<string, unknown>) => Response | Promise<Response>
let liveAnswer: () => Response | Promise<Response>

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
const body = async (res: Response) => res.json() as Promise<Record<string, any>>
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
  h.agent.mockReset()
  h.agent.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path === '/agent-sessions/all') return agentSessions()
    if (path === '/sessions') return agentShells()
    if (path === '/agent-session/stop') return agentStop(JSON.parse(String(init?.body)))
    return json({}, 404)
  })
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async () => liveAnswer())
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

  test('shell sessions name their project owner and the chat person, never the target; jobs are a count', async () => {
    agentShells = () => json({
      sessions: [
        { id: 3, type: 'meterpreter', info: 'root @ host', connection: '198.51.100.1:4444 -> 203.0.113.9:5555', target_ip: '203.0.113.9', chat_session_id: 'chat-1' },
        { id: 4, type: 'shell', target_ip: '203.0.113.10', chat_session_id: null },
      ],
      non_msf_sessions: [{ id: 'nc-1', type: 'netcat', chat_session_id: 'chat-2' }],
      jobs: [{ id: 0 }, { id: 1 }],
    })
    h.db.conversationFindMany.mockResolvedValue([
      { sessionId: 'chat-1', projectId: 'p-1', userId: 'mem-a' },
      { sessionId: 'chat-2', projectId: 'p-2', userId: 'mem-b' },
    ])
    const res = await view()
    const raw = await res.clone().text()
    const out = await body(res)
    expect(out.shells.state).toEqual({ ok: true })
    expect(out.shells.jobs).toBe(2)
    expect(out.shells.sessions).toEqual([
      { key: 'session:3', id: '3', kind: 'session', type: 'meterpreter', project: { id: 'p-1', name: 'p-1 name', owner: { id: 'own-a', name: 'Name own-a' } }, person: { id: 'mem-a', name: 'Name mem-a' } },
      { key: 'session:4', id: '4', kind: 'session', type: 'shell', project: null, person: null },
      { key: 'listener:nc-1', id: 'nc-1', kind: 'listener', type: 'netcat', project: { id: 'p-2', name: 'p-2 name', owner: { id: 'own-b', name: 'Name own-b' } }, person: { id: 'mem-b', name: 'Name mem-b' } },
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
    expect(out.shells).toEqual({ state: { ok: true }, sessions: [], jobs: 0 })
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
    expect(out.shells).toEqual({ state: { ok: false, code: 'agent_unreachable' }, sessions: [], jobs: 0 })
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

/**
 * Shell sessions across per-user Kali sandboxes (group 1: E3; TD-11, B.12, WI-S16-1, WI-S16-2).
 *
 * Each sandbox runs its own msfconsole, which numbers its sessions from 1, so a session is the pair
 * (sandbox instance, number): the agent's list tags every session, job and listener with its
 * `sandbox`, and the drive routes take `?sandbox=<instance>`. The webapp looks the PAIR up in the
 * agent's list and authorizes that entry's project exactly as before; a number authorized in one
 * sandbox never reaches the same number in another. In per-user mode the parameter is required
 * (400 without it); an instance that is not in the caller's view is the same 404 as any other.
 *
 * Alice owns p-alice; Bob owns p-bob and p-shared, which he shares with Alice at Read + Write with
 * Exploitation & shells (W+X, the level agent:sessions needs on a share). Bob's sandbox bbbbb1 holds
 * session 1 on p-shared and session 2 on p-bob; his draining instance bbbbb2 holds a session 1 on
 * p-bob; Alice's own sandbox aaaaa1 holds her session 1; the shared container (`shared`, still
 * running during the transition) holds a session 3 of Alice's.
 *
 * A sandbox's root controls what its session manager reports, the chat ids included, so a per-user row
 * counts for its chat's project only when the agent's own tags (`sandbox_user`, `sandbox_view`, added
 * from the sandbox handle after the row) name the person who wrote that chat AND the project is one
 * that person's sandbox mounts for that view; otherwise the row is unattributed, as an untagged one.
 * Those tags never reach the browser. Rows whose id is not the session manager's shape are dropped.
 * The instances that did not answer are a count for everyone; their ids go to holders of every
 * session, and to anyone else only for the silent instances that could hold that viewer's rows (S16b).
 *
 * The session, the account read, Prisma, the agent, the sandbox mode and the mount lists are doubles;
 * the access rule, sharedToolAccess and the routes are real; projectAccess() answers Alice's share.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireSession = vi.fn()
const mockEffectiveUser = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockConversations = vi.fn()
const mockWriteAudit = vi.fn()
// The drive's `attempted` row (written before forwarding, in auditedTransaction); mockWriteAudit gets the outcome row.
const mockWriteAuditTx = vi.fn()
const mockAgentFetch = vi.fn()
const mockMode = vi.fn()
const mockMounts = vi.fn()
const mockRunning = vi.fn()
const mockProjects = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => mockRequireSession(...a),
  getEffectiveUser: (...a: unknown[]) => mockEffectiveUser(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
  writeAuditTx: (...a: unknown[]) => mockWriteAuditTx(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: (...a: unknown[]) => mockConversations(...a) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({}),
    project: { findMany: (...a: unknown[]) => mockProjects(...a) },
    auditLog: { findFirst: vi.fn(async () => null) },
  },
}))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
}))
vi.mock('@/lib/sandbox/gateway', () => ({
  sandboxMode: (...a: unknown[]) => mockMode(...a),
  sandboxProjectsFor: (...a: unknown[]) => mockMounts(...a),
}))
vi.mock('@/lib/sandbox/orchestratorClient', async (orig) => ({
  ...(await orig<typeof import('@/lib/sandbox/orchestratorClient')>()),
  orchestratorList: (...a: unknown[]) => mockRunning(...a),
  orchestratorStatus: vi.fn(async () => { throw new Error('the naming must not read a status') }),
}))
vi.mock('./projectAccess', async (orig) => {
  const actual = await orig<typeof import('./projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})
vi.mock('./visibleProjects', async (orig) => {
  const actual = await orig<typeof import('./visibleProjects')>()
  return { ...actual, visibleProjects: vi.fn(actual.visibleProjects) }
})

import {
  authorizeSessionTarget, resolveSessionsViewer, visibleSessions, resetUnavailableNamingForTests,
  NAMING_RUNNING_TTL_MS, NAMING_VERDICT_TTL_MS, type SessionsViewer,
} from './agentSessionsAccess'
import { setFlagsForTests } from './flags'
import { resetSharedToolsForTests } from './sharedTools'
import { projectAccess, type ProjectAccess } from './projectAccess'
import { visibleProjects } from './visibleProjects'
import { POST as interact } from '@/app/api/agent/sessions/[id]/interact/route'
import { POST as killSession } from '@/app/api/agent/sessions/[id]/kill/route'
import { POST as killJob } from '@/app/api/agent/jobs/[id]/kill/route'

const NOW = new Date('2026-09-01T00:00:00Z')

function principal(id: string, role = 'standard') {
  return { id, email: `${id}@x`, role, hasPassword: true, createdAt: NOW, legacyGrants: [] as string[] }
}

function signedIn(real: ReturnType<typeof principal>, actingAs?: string) {
  mockRequireSession.mockResolvedValue({ userId: real.id, role: real.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === real.id ? real : null))
  mockEffectiveUser.mockResolvedValue({ userId: actingAs ?? real.id })
}

async function viewerFor(real: ReturnType<typeof principal>): Promise<SessionsViewer> {
  signedIn(real)
  const v = await resolveSessionsViewer()
  if (v instanceof NextResponse) throw new Error(`no viewer: ${v.status}`)
  return v
}

// `userId` is the conversation's author; `project.userId` the project's owner.
const CONVERSATIONS = [
  { sessionId: 'chat-alice', projectId: 'p-alice', userId: 'alice', project: { userId: 'alice' } },
  { sessionId: 'chat-shared', projectId: 'p-shared', userId: 'bob', project: { userId: 'bob' } },
  { sessionId: 'chat-bob', projectId: 'p-bob', userId: 'bob', project: { userId: 'bob' } },
  // Alice's own conversation on Bob's p-shared, from while it was shared with her.
  { sessionId: 'chat-alice-on-shared', projectId: 'p-shared', userId: 'alice', project: { userId: 'bob' } },
]

/** The tags the agent adds from the sandbox handle, after the sandbox's own row. */
const ALICE = { sandbox_user: 'alice', sandbox_view: 'own' }
const BOB = { sandbox_user: 'bob', sandbox_view: 'own' }

/** The agent's per-user answer: every row names its sandbox instance and that sandbox's person. */
function perUserList(): Record<string, unknown> {
  return {
    sessions: [
      { id: 1, type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: 1, type: 'meterpreter', chat_session_id: 'chat-shared', sandbox: 'bbbbb1', ...BOB },
      { id: 2, type: 'shell', chat_session_id: 'chat-bob', sandbox: 'bbbbb1', ...BOB },
      { id: 1, type: 'shell', chat_session_id: 'chat-bob', sandbox: 'bbbbb2', ...BOB },
      { id: 3, type: 'shell', chat_session_id: 'chat-alice', sandbox: 'shared' },
    ],
    jobs: [
      { id: 0, name: 'Exploit: multi/handler', payload: 'p', port: 4444, sandbox: 'aaaaa1', ...ALICE },
      { id: 0, name: 'Exploit: multi/handler', payload: 'p', port: 4444, sandbox: 'bbbbb1', ...BOB },
    ],
    non_msf_sessions: [
      { id: 'raw-1', type: 'listener', tool: 'netcat', chat_session_id: 'chat-shared', sandbox: 'bbbbb1', ...BOB },
      { id: 'raw-2', type: 'listener', tool: 'netcat', chat_session_id: 'chat-bob', sandbox: 'bbbbb1', ...BOB },
    ],
    unavailable: ['ccccc1'],
    cache_age_seconds: 0.5,
    agent_busy: false,
  }
}

/** What each person's sandbox mounts (sandboxProjectsFor), per view; Alice's share of p-shared is in force. */
let mounts: Record<string, string[]>

/** The running sandboxes (the gateway's listSandboxes: person, view, instance; never a token or host). */
const RUNNING = [
  { user_id: 'alice', view: 'own', instance: 'aaaaa1', state: 'running' },
  { user_id: 'alice', view: 'act_as', instance: 'eeeee1', state: 'running' },
  { user_id: 'bob', view: 'own', instance: 'bbbbb1', state: 'running' },
  { user_id: 'bob', view: 'own', instance: 'bbbbb2', state: 'draining' },
  { user_id: 'carol', view: 'own', instance: 'ccccc1', state: 'running' },
]
const PROJECTS = [
  { id: 'p-alice', userId: 'alice' }, { id: 'p-bob', userId: 'bob' },
  { id: 'p-shared', userId: 'bob' }, { id: 'p-carol', userId: 'carol' },
]


/** The agent's shared-mode answer (one console, untagged rows), as before group 1. */
function sharedList(): Record<string, unknown> {
  return {
    sessions: [
      { id: 1, type: 'shell', chat_session_id: 'chat-alice' },
      { id: 2, type: 'shell', chat_session_id: 'chat-bob' },
    ],
    jobs: [],
    non_msf_sessions: [],
  }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

let list: () => Record<string, unknown>
function agent(driveBody: unknown = { busy: false, output: 'ok' }) {
  mockAgentFetch.mockImplementation(async (path: string) => (path === '/sessions' ? json(list()) : json(driveBody)))
}

const params = (id: string) => ({ params: Promise.resolve({ id }) })
const post = (query = '', body?: unknown) => new NextRequest(`http://x/api${query}`, {
  method: 'POST',
  ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
})
const drives = () => mockAgentFetch.mock.calls.map(c => c[0] as string).filter(p => p !== '/sessions')
const auditRows = () => mockWriteAudit.mock.calls.map(c => c[0])
const pairs = (rows: Array<{ id?: unknown; sandbox?: unknown }>) => rows.map(r => `${String(r.sandbox)}:${String(r.id)}`)

const policy = vi.mocked(projectAccess)
const lists = vi.mocked(visibleProjects)
const shareToAlice = Object.freeze({
  project: { id: 'p-shared', userId: 'bob' }, level: 'write', toggles: { rawData: true, exploit: true }, via: 'share',
}) as unknown as ProjectAccess

let warn: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  mockRequireSession.mockReset()
  mockEffectiveUser.mockReset()
  mockLoadPrincipal.mockReset()
  mockConversations.mockReset().mockImplementation(async (args: { where: { sessionId: { in: string[] } } }) =>
    CONVERSATIONS.filter(c => args.where.sessionId.in.includes(c.sessionId)))
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockWriteAuditTx.mockReset().mockResolvedValue(undefined)
  mockAgentFetch.mockReset()
  mockMode.mockReset().mockResolvedValue('per_user')
  mounts = { 'alice:own': ['p-alice', 'p-shared'], 'alice:act_as': ['p-alice'], 'bob:own': ['p-bob', 'p-shared'], 'bob:act_as': ['p-bob', 'p-shared'] }
  mockMounts.mockReset().mockImplementation(async (userId: string, opts: { actingAs?: boolean } = {}) =>
    mounts[`${userId}:${opts.actingAs ? 'act_as' : 'own'}`] ?? [])
  mockRunning.mockReset().mockResolvedValue({ mode: 'per_user', sandboxes: RUNNING })
  resetUnavailableNamingForTests()
  mockProjects.mockReset().mockImplementation(async (args: { where: { id: { in: string[] } } }) =>
    PROJECTS.filter(p => args.where.id.in.includes(p.id)))
  list = perUserList
  resetSharedToolsForTests()
  setFlagsForTests({})
  // Sharing in force: p-shared reaches Alice at W+X; nothing else of Bob's reaches her.
  lists.mockResolvedValue({ where: {}, withShares: true })
  policy.mockImplementation(async (subject: { userId: string }, projectId: string) =>
    (subject.userId === 'alice' && projectId === 'p-shared' ? shareToAlice : null))
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(async () => {
  warn.mockRestore()
  const actual = await vi.importActual<typeof import('./projectAccess')>('./projectAccess')
  policy.mockImplementation(actual.projectAccess)
  const actualLists = await vi.importActual<typeof import('./visibleProjects')>('./visibleProjects')
  lists.mockImplementation(actualLists.visibleProjects)
})

describe('the list across sandboxes (WI-S16-1)', () => {
  test('each row keeps its sandbox; the visibility rule is unchanged; the unavailable sandboxes are a count', async () => {
    const out = await visibleSessions(perUserList(), await viewerFor(principal('alice')))
    expect(pairs(out.sessions)).toEqual(['aaaaa1:1', 'bbbbb1:1', 'shared:3'])
    expect(out.sessions.find(s => s.sandbox === 'bbbbb1')).toMatchObject({ id: 1, project_id: 'p-shared' })
    expect(pairs(out.non_msf_sessions)).toEqual(['bbbbb1:raw-1'])
    expect(out.jobs).toEqual([])
    expect(out.unavailable_count).toBe(1)
  })

  test('Bob sees both of his instances, each session under its own instance', async () => {
    const out = await visibleSessions(perUserList(), await viewerFor(principal('bob')))
    expect(pairs(out.sessions)).toEqual(['bbbbb1:1', 'bbbbb1:2', 'bbbbb2:1'])
  })

  test('the unavailable instances: a count for everyone, every id only for holders of every session; once each', async () => {
    // Changed by design (S16b review 3a): a member is now named the silent instances that could hold
    // her rows; Carol's ccccc1 and an instance no sandbox runs are not among them.
    const odd = { ...perUserList(), unavailable: ['ccccc1', 'ccccc1', 'shared', '../etc', 'CCCCC1', 7, null, 'ddddd1'] }
    const member = await visibleSessions(odd, await viewerFor(principal('alice')))
    expect(member.unavailable_count).toBe(3)
    expect(member.unavailable).toEqual(['shared'])
    const admin = await visibleSessions(odd, await viewerFor(principal('admin-a', 'admin')))
    expect(admin.unavailable_count).toBe(3)
    expect(admin.unavailable).toEqual(['ccccc1', 'shared', 'ddddd1'])
    const none = await visibleSessions(sharedList(), await viewerFor(principal('alice')))
    expect(none).not.toHaveProperty('unavailable')
    expect(none).not.toHaveProperty('unavailable_count')
  })
})

describe('the silent instances named to a viewer (S16b review 3a)', () => {
  // The browser keeps a busy sandbox's last rows only for the instances named to it, so each viewer is
  // named the silent instances that could hold a row she may see: her own sandboxes, and those whose
  // person's mount list (for that view) holds a project whose sessions she may see. Never another id.
  const silent = (...ids: string[]) => ({ ...perUserList(), unavailable: ids })
  const ALL = ['aaaaa1', 'eeeee1', 'bbbbb1', 'bbbbb2', 'ccccc1', 'shared']

  test("Alice: her own instances, Bob's (they mount p-shared, which he shares with her at W+X), never Carol's", async () => {
    const out = await visibleSessions(silent(...ALL), await viewerFor(principal('alice')))
    expect(out.unavailable).toEqual(['aaaaa1', 'eeeee1', 'bbbbb1', 'bbbbb2', 'shared'])
    expect(out.unavailable_count).toBe(6)
  })

  test("M-b test 4: Alice drives Bob's session on p-shared and Bob's sandbox is the busy one: it is named to her", async () => {
    const out = await visibleSessions(silent('bbbbb1'), await viewerFor(principal('alice')))
    expect(out.unavailable).toEqual(['bbbbb1'])
  })

  test("Bob: his own, and Alice's own sandbox (it mounts his p-shared), not her act_as one (p-alice only)", async () => {
    const out = await visibleSessions(silent(...ALL), await viewerFor(principal('bob')))
    expect(out.unavailable).toEqual(['aaaaa1', 'bbbbb1', 'bbbbb2', 'shared'])
    expect(mockMounts).toHaveBeenCalledWith('alice', { actingAs: true })
  })

  test('Carol: only her own', async () => {
    const out = await visibleSessions(silent(...ALL), await viewerFor(principal('carol')))
    expect(out.unavailable).toEqual(['ccccc1', 'shared'])
  })

  test("a share Bob withdrew: his instances are no longer named to Alice", async () => {
    policy.mockImplementation(async () => null)
    const out = await visibleSessions(silent('bbbbb1', 'aaaaa1'), await viewerFor(principal('alice')))
    expect(out.unavailable).toEqual(['aaaaa1'])
  })

  test('the running sandboxes cannot be read: only `shared` is named (the browser then keeps nothing)', async () => {
    mockRunning.mockRejectedValue(new Error('orchestrator down'))
    const out = await visibleSessions(silent('aaaaa1', 'shared'), await viewerFor(principal('alice')))
    expect(out.unavailable).toEqual(['shared'])
    expect(out.unavailable_count).toBe(2)
  })

  test('a malformed row of the running list counts for nobody; a failed mount read names nothing', async () => {
    mockRunning.mockResolvedValue({ mode: 'per_user', sandboxes: [
      { user_id: '../alice', view: 'own', instance: 'fffff1' }, { user_id: 'bob', view: 'root', instance: 'fffff2' },
      { user_id: 'bob', view: 'own', instance: 'fffff3' },
    ] })
    mockMounts.mockRejectedValue(new Error('db down'))
    const out = await visibleSessions(silent('fffff1', 'fffff2', 'fffff3'), await viewerFor(principal('alice')))
    expect(out.unavailable).toEqual([])
  })

  test('holders of every session still get every id, and nothing is read for them', async () => {
    const out = await visibleSessions(silent(...ALL), await viewerFor(principal('admin-a', 'admin')))
    expect(out.unavailable).toEqual(ALL)
    expect(mockRunning).not.toHaveBeenCalled()
  })

  test('nothing silent: nothing is read', async () => {
    await visibleSessions(silent(), await viewerFor(principal('alice')))
    expect(mockRunning).not.toHaveBeenCalled()
  })
})

describe('the naming is cheap while a sandbox stays silent (S16b review round 3)', () => {
  // A hung or deliberately silent sandbox must not turn every viewer's poll into orchestrator and
  // database reads: the running list is read alone (no status reads) and kept process-wide for
  // NAMING_RUNNING_TTL_MS; each verdict (viewer, person, view) for NAMING_VERDICT_TTL_MS.
  const silent = (...ids: string[]) => ({ ...perUserList(), unavailable: ids })
  let now: number
  let clock: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    now = 5_000_000
    clock = vi.spyOn(Date, 'now').mockImplementation(() => now)
  })
  afterEach(() => { clock.mockRestore() })

  test('polls within the TTL read the running list once, with no status read, for every viewer', async () => {
    const alice = await viewerFor(principal('alice'))
    const bob = await viewerFor(principal('bob'))
    for (let i = 0; i < 3; i++) {
      await visibleSessions(silent('bbbbb1'), alice)
      await visibleSessions(silent('aaaaa1'), bob)
      now += 1_000
    }
    expect(mockRunning).toHaveBeenCalledTimes(1)
    now += NAMING_RUNNING_TTL_MS
    await visibleSessions(silent('bbbbb1'), alice)
    expect(mockRunning).toHaveBeenCalledTimes(2)
  })

  test("a verdict is reused for at most NAMING_VERDICT_TTL_MS: a share withdrawn stops naming Bob's instance by then", async () => {
    const alice = await viewerFor(principal('alice'))
    expect((await visibleSessions(silent('bbbbb1'), alice)).unavailable).toEqual(['bbbbb1'])
    policy.mockImplementation(async () => null)
    now += NAMING_VERDICT_TTL_MS - 1
    // Still named: the cost of the memo, bounded; naming only keeps rows already sent, every drive is re-authorized.
    expect((await visibleSessions(silent('bbbbb1'), alice)).unavailable).toEqual(['bbbbb1'])
    expect(mockMounts).toHaveBeenCalledTimes(1)
    now += 2
    expect((await visibleSessions(silent('bbbbb1'), alice)).unavailable).toEqual([])
    expect(NAMING_VERDICT_TTL_MS).toBeLessThanOrEqual(10_000)
  })

  test("a verdict is the viewer's own: Alice's does not name Bob's instance to Carol", async () => {
    expect((await visibleSessions(silent('bbbbb1'), await viewerFor(principal('alice')))).unavailable).toEqual(['bbbbb1'])
    expect((await visibleSessions(silent('bbbbb1'), await viewerFor(principal('carol')))).unavailable).toEqual([])
  })

  test('a failed running-list read is not kept: the next poll reads again', async () => {
    mockRunning.mockRejectedValueOnce(new Error('orchestrator down'))
    const alice = await viewerFor(principal('alice'))
    expect((await visibleSessions(silent('aaaaa1'), alice)).unavailable).toEqual([])
    expect((await visibleSessions(silent('aaaaa1'), alice)).unavailable).toEqual(['aaaaa1'])
    expect(mockRunning).toHaveBeenCalledTimes(2)
  })
})

describe('a target is the pair (instance, number) (WI-S16-2)', () => {
  test("Alice drives Bob's session on the project he shares with her", async () => {
    const v = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '1', 'bbbbb1')).toEqual({ projectId: 'p-shared', via: 'share', sandboxUser: 'bob' })
  })

  test("Alice cannot drive Bob's session on his own project", async () => {
    const v = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '2', 'bbbbb1')).toBeNull()
  })

  test("the shared project's session number paired with Bob's other instance is refused", async () => {
    const v = await viewerFor(principal('alice'))
    // Number 1 is Alice's to drive in bbbbb1 (p-shared); in bbbbb2 the same number is Bob's own project.
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '1', 'bbbbb2')).toBeNull()
    // Nor does her own number travel: aaaaa1 holds no session 2, bbbbb1's 2 is Bob's.
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '2', 'aaaaa1')).toBeNull()
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '1', 'ccccc1')).toBeNull()
  })

  test('without an instance, a per-user list has no target at all', async () => {
    const v = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '1')).toBeNull()
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '1', null)).toBeNull()
  })

  test("the shared container's sessions are addressed as `shared`", async () => {
    const v = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '3', 'shared')).toEqual({ projectId: 'p-alice', via: 'owner' })
    expect(await authorizeSessionTarget(perUserList(), v, 'session', '3', 'aaaaa1')).toBeNull()
  })

  test('a job is a pair too: an admin kills exactly the job of the instance named', async () => {
    const admin = await viewerFor(principal('admin-a', 'admin'))
    expect(await authorizeSessionTarget(perUserList(), admin, 'job', '0', 'bbbbb1')).toEqual({ projectId: null, via: 'admin', sandboxUser: 'bob' })
    expect(await authorizeSessionTarget(perUserList(), admin, 'job', '0', 'ddddd1')).toBeNull()
    const alice = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(perUserList(), alice, 'job', '0', 'aaaaa1')).toBeNull()
  })

  test('the shared-mode list keeps answering as before when no instance is named', async () => {
    const v = await viewerFor(principal('alice'))
    expect(await authorizeSessionTarget(sharedList(), v, 'session', '1')).toEqual({ projectId: 'p-alice', via: 'owner' })
    expect(await authorizeSessionTarget(sharedList(), v, 'session', '1', 'shared')).toBeNull()
  })
})

describe('the drive routes take ?sandbox=', () => {
  test('per-user mode without the parameter: 400 sandbox_required, nothing typed, no audit row', async () => {
    signedIn(principal('alice'))
    agent()
    for (const call of [
      () => interact(post('', { command: 'id' }), params('1')),
      () => killSession(post(), params('1')),
      () => killJob(post(), params('0')),
    ]) {
      const res = await call()
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ code: 'sandbox_required' })
    }
    expect(drives()).toEqual([])
    expect(auditRows()).toEqual([])
  })

  test("Alice drives Bob's shared-project session: the same instance is forwarded and audited as <instance>:<number>", async () => {
    signedIn(principal('alice'))
    agent()
    const res = await interact(post('?sandbox=bbbbb1', { command: 'whoami' }), params('1'))
    expect(res.status).toBe(200)
    expect(drives()).toEqual(['/sessions/1/interact?sandbox=bbbbb1'])
    expect(auditRows()).toHaveLength(1)
    expect(auditRows()[0]).toMatchObject({
      actorId: 'alice', action: 'agent.session_interact', targetType: 'msf_session', targetId: 'bbbbb1:1',
      after: { projectId: 'p-shared', via: 'share', sandbox: 'bbbbb1', sandboxUser: 'bob' },
    })
    expect(JSON.stringify(auditRows())).not.toContain('whoami')
  })

  test("an authorized number paired with another instance is 404 and reaches no console", async () => {
    signedIn(principal('alice'))
    agent()
    expect((await interact(post('?sandbox=bbbbb2', { command: 'id' }), params('1'))).status).toBe(404)
    expect((await killSession(post('?sandbox=bbbbb2'), params('1'))).status).toBe(404)
    expect((await killSession(post('?sandbox=bbbbb1'), params('2'))).status).toBe(404)
    expect(drives()).toEqual([])
    expect(auditRows()).toEqual([])
  })

  test("two sessions with the same number in two sandboxes leave two audit trails apart", async () => {
    signedIn(principal('bob'))
    agent({ busy: false, output: 'Killed' })
    expect((await killSession(post('?sandbox=bbbbb1'), params('1'))).status).toBe(200)
    expect((await killSession(post('?sandbox=bbbbb2'), params('1'))).status).toBe(200)
    expect(drives()).toEqual(['/sessions/1/kill?sandbox=bbbbb1', '/sessions/1/kill?sandbox=bbbbb2'])
    expect(auditRows().map(r => [r.targetId, r.after.sandbox, r.after.projectId])).toEqual([
      ['bbbbb1:1', 'bbbbb1', 'p-shared'],
      ['bbbbb2:1', 'bbbbb2', 'p-bob'],
    ])
  })

  test("the shared container: `shared` is forwarded and audited as shared:<number>", async () => {
    signedIn(principal('alice'))
    agent({ busy: false, output: 'Killed' })
    expect((await killSession(post('?sandbox=shared'), params('3'))).status).toBe(200)
    expect(drives()).toEqual(['/sessions/3/kill?sandbox=shared'])
    expect(auditRows()[0]).toMatchObject({ targetId: 'shared:3', after: { projectId: 'p-alice', via: 'owner', sandbox: 'shared' } })
  })

  test('an admin kills one job of one instance', async () => {
    signedIn(principal('admin-a', 'admin'))
    agent({ busy: false, output: 'Stopping job 0' })
    expect((await killJob(post('?sandbox=bbbbb1'), params('0'))).status).toBe(200)
    expect(drives()).toEqual(['/jobs/0/kill?sandbox=bbbbb1'])
    expect(auditRows()[0]).toMatchObject({ action: 'agent.job_kill', targetType: 'msf_job', targetId: 'bbbbb1:0', after: { via: 'admin', sandbox: 'bbbbb1' } })
  })

  test.each(['', 'BBBBB1', 'bbbbb', 'bbbbb12', '../etc', 'bbbbb1/../x', 'shared2', 'bbbbb1 '])(
    'a value that is no instance (%j): 400 invalid_sandbox before the agent is asked', async (value) => {
      signedIn(principal('alice'))
      agent()
      const res = await killSession(post(`?sandbox=${encodeURIComponent(value)}`), params('1'))
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({ code: 'invalid_sandbox' })
      expect(mockAgentFetch).not.toHaveBeenCalled()
    })

  test('a hidden session named with ?sandbox=000000 is 404 in both modes (the live matrix rows)', async () => {
    signedIn(principal('member-c'))
    agent()
    for (const mode of ['per_user', 'shared']) {
      mockMode.mockResolvedValue(mode)
      list = mode === 'per_user' ? perUserList : sharedList
      expect((await interact(post('?sandbox=000000', { command: 'id' }), params('rbac-not-a-session'))).status).toBe(404)
      expect((await interact(post('?sandbox=000000', { command: 'id' }), params('999999'))).status).toBe(404)
      expect((await killSession(post('?sandbox=000000'), params('rbac-not-a-session'))).status).toBe(404)
      expect((await killJob(post('?sandbox=000000'), params('rbac-not-a-job'))).status).toBe(404)
    }
    expect(drives()).toEqual([])
  })

  test('shared mode: no parameter drives the one console as before, audited as shared:<number>; a miss stays 404', async () => {
    mockMode.mockResolvedValue('shared')
    list = sharedList
    signedIn(principal('alice'))
    agent()
    expect((await interact(post('', { command: 'id' }), params('1'))).status).toBe(200)
    expect(drives()).toEqual(['/sessions/1/interact'])
    expect(auditRows()[0]).toMatchObject({ targetId: 'shared:1', after: { projectId: 'p-alice', via: 'owner', sandbox: 'shared' } })
    expect((await interact(post('', { command: 'id' }), params('2'))).status).toBe(404)
    expect((await interact(post('', { command: 'id' }), params('99'))).status).toBe(404)
  })

  test('the mode cannot be read: a miss without the parameter is 404, never a guess of per-user', async () => {
    mockMode.mockRejectedValue(new Error('orchestrator unreachable'))
    signedIn(principal('alice'))
    agent()
    expect((await killSession(post(), params('1'))).status).toBe(404)
    expect(drives()).toEqual([])
  })
})

// Review F1: Alice is root in her own sandbox aaaaa1, so she answers its session manager herself and
// can name any chat id she knows. Her row counts for that chat's project only when she wrote the chat
// and her sandbox mounts the project for its view; otherwise it is unattributed: listed only to
// holders of every session, drivable only by them, audited with no project.
describe("a sandbox's row counts for its chat's project only when the project is that person's (review F1)", () => {
  const forged = (row: Record<string, unknown>) => () => ({ sessions: [{ id: 7, type: 'meterpreter', sandbox: 'aaaaa1', ...row }], jobs: [], non_msf_sessions: [] })

  test("after Bob revokes the share, Alice's old chat on p-shared no longer makes her row Bob's", async () => {
    mounts['alice:own'] = ['p-alice']
    list = forged({ chat_session_id: 'chat-alice-on-shared', ...ALICE })
    const bobView = await visibleSessions(list(), await viewerFor(principal('bob')))
    expect(bobView.sessions).toEqual([])
    signedIn(principal('bob'))
    agent()
    expect((await interact(post('?sandbox=aaaaa1', { command: 'net user administrator S3cret! /domain' }), params('7'))).status).toBe(404)
    expect(drives()).toEqual([])
    expect(auditRows()).toEqual([])
  })

  test("a chat Alice did not write never attributes her row, even to a project her sandbox mounts", async () => {
    list = forged({ chat_session_id: 'chat-shared', ...ALICE })
    expect((await visibleSessions(list(), await viewerFor(principal('bob')))).sessions).toEqual([])
    expect((await visibleSessions(list(), await viewerFor(principal('alice')))).sessions).toEqual([])
    list = forged({ chat_session_id: 'chat-bob', ...ALICE })
    expect((await visibleSessions(list(), await viewerFor(principal('bob')))).sessions).toEqual([])
  })

  test('her own chat on a project her sandbox mounts counts: the shared project, as for any collaborator', async () => {
    list = forged({ chat_session_id: 'chat-alice-on-shared', ...ALICE })
    const bobView = await visibleSessions(list(), await viewerFor(principal('bob')))
    expect(bobView.sessions).toEqual([expect.objectContaining({ id: 7, sandbox: 'aaaaa1', project_id: 'p-shared' })])
    expect(mockMounts).toHaveBeenCalledWith('alice', { actingAs: false })
  })

  test('the act_as view is judged on the act_as mount list', async () => {
    list = forged({ chat_session_id: 'chat-alice-on-shared', sandbox_user: 'alice', sandbox_view: 'act_as' })
    expect((await visibleSessions(list(), await viewerFor(principal('bob')))).sessions).toEqual([])
    expect(mockMounts).toHaveBeenCalledWith('alice', { actingAs: true })
  })

  test("a per-user row without the agent's person, or with a malformed one, is unattributed", async () => {
    for (const row of [
      { chat_session_id: 'chat-bob' },
      { chat_session_id: 'chat-bob', sandbox_user: 'bob' },
      { chat_session_id: 'chat-bob', sandbox_user: 'bob', sandbox_view: 'root' },
      { chat_session_id: 'chat-bob', sandbox_user: 'bob/../x', sandbox_view: 'own' },
      { chat_session_id: 'chat-bob', sandbox_user: 7, sandbox_view: 'own' },
    ]) {
      list = forged(row)
      expect((await visibleSessions(list(), await viewerFor(principal('bob')))).sessions, JSON.stringify(row)).toEqual([])
    }
  })

  test('an unattributed row is listed to holders of every session with no project, and their drive is audited with the sandbox person', async () => {
    mounts['alice:own'] = ['p-alice']
    list = forged({ chat_session_id: 'chat-alice-on-shared', ...ALICE })
    const admin = await visibleSessions(list(), await viewerFor(principal('admin-a', 'admin')))
    expect(admin.sessions).toEqual([expect.objectContaining({ id: 7, sandbox: 'aaaaa1', project_id: null })])
    signedIn(principal('admin-a', 'admin'))
    agent()
    expect((await killSession(post('?sandbox=aaaaa1'), params('7'))).status).toBe(200)
    expect(auditRows()[0]).toMatchObject({ targetId: 'aaaaa1:7', after: { projectId: null, via: 'admin', sandbox: 'aaaaa1', sandboxUser: 'alice' } })
  })

  test('a failed read of the mount list attributes nothing', async () => {
    mockMounts.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    list = forged({ chat_session_id: 'chat-alice-on-shared', ...ALICE })
    expect((await visibleSessions(list(), await viewerFor(principal('bob')))).sessions).toEqual([])
  })

  test("the agent's person and view tags never reach the browser, on any row and for any viewer", async () => {
    for (const who of [principal('alice'), principal('bob'), principal('admin-a', 'admin')]) {
      const text = JSON.stringify(await visibleSessions(perUserList(), await viewerFor(who)))
      expect(text).not.toContain('sandbox_user')
      expect(text).not.toContain('sandbox_view')
    }
  })

  test('the shared container keeps the chat rule it had: no person tag is needed there', async () => {
    const out = await visibleSessions(perUserList(), await viewerFor(principal('alice')))
    expect(out.sessions.find(s => s.sandbox === 'shared')).toMatchObject({ id: 3, project_id: 'p-alice' })
  })
})

// Review F2: a row's id goes into a browser URL, so a row whose id is not the session manager's shape
// (sessions and jobs: a non-negative integer; listeners: raw-<digits>) is dropped and never a target.
describe("rows whose id is not the session manager's shape are dropped (review F2)", () => {
  const planted = () => ({
    sessions: [
      { id: '../emergency-stop-all?', type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: -1, type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: 1.5, type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: '4', type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: 5, type: 'shell', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
    ],
    jobs: [
      { id: '../emergency-stop-all?', name: 'x', sandbox: 'aaaaa1', ...ALICE },
      { id: 0, name: 'handler', sandbox: 'aaaaa1', ...ALICE },
    ],
    non_msf_sessions: [
      { id: 'raw-1/../../x', type: 'listener', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: 'nc-1', type: 'listener', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
      { id: 'raw-1795290000000', type: 'listener', chat_session_id: 'chat-alice', sandbox: 'aaaaa1', ...ALICE },
    ],
  })

  test('the list keeps only well-shaped ids, for an owner and for a holder of every session', async () => {
    const own = await visibleSessions(planted(), await viewerFor(principal('alice')))
    expect(own.sessions.map(s => s.id)).toEqual(['4', 5])
    expect(own.non_msf_sessions.map(s => s.id)).toEqual(['raw-1795290000000'])
    const admin = await visibleSessions(planted(), await viewerFor(principal('admin-a', 'admin')))
    expect(admin.jobs.map(j => j.id)).toEqual([0])
  })

  test('a malformed row is never a target', async () => {
    const admin = await viewerFor(principal('admin-a', 'admin'))
    expect(await authorizeSessionTarget(planted(), admin, 'job', '../emergency-stop-all?', 'aaaaa1')).toBeNull()
    expect(await authorizeSessionTarget(planted(), admin, 'session', '-1', 'aaaaa1')).toBeNull()
    expect(await authorizeSessionTarget(planted(), admin, 'session', '5', 'aaaaa1')).toEqual({ projectId: 'p-alice', via: 'admin', sandboxUser: 'alice' })
  })
})

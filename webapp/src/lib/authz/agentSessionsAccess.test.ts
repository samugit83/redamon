/**
 * Which shell sessions a person sees and drives (HD-01, HD-02, SH-49 map).
 *
 * The agent's session list gathers every person's Kali sandbox, each row tagged with its sandbox
 * instance and that sandbox's person (group 1). A session belongs to the chat whose run opened it
 * (the manager's session-to-chat map), the chat to its conversation (`Conversation.sessionId`,
 * unique) and the conversation to its project. A member sees the sessions of the projects the
 * effective user owns; unattributed sessions, other projects' sessions and the background jobs
 * only with `shell_sessions_all` (admins, the legacy grant, the escape hatch for pre-upgrade
 * accounts), judged on the signed-in account. The per-sandbox attribution rules are
 * agentSessionsAccess.sandbox.test.ts.
 *
 * The session, the account read, Prisma and the sandbox mount lists are mocked; sharedToolAccess,
 * visibleProjects and projectAccess() are the real ones (sharing off) unless a step 5.10 test
 * answers for the policy.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const mockRequireSession = vi.fn()
const mockEffectiveUser = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockConversations = vi.fn()
const mockCutoff = vi.fn()
const mockWriteAudit = vi.fn()
const mockUsers = vi.fn()
const mockProjects = vi.fn()

vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => mockRequireSession(...a),
  getEffectiveUser: (...a: unknown[]) => mockEffectiveUser(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
  writeAuditTx: (_tx: unknown, entry: unknown) => mockWriteAudit(entry),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: (...a: unknown[]) => mockConversations(...a) },
    user: { findMany: (...a: unknown[]) => mockUsers(...a) },
    project: { findMany: (...a: unknown[]) => mockProjects(...a) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({}),
    auditLog: { findFirst: (...a: unknown[]) => mockCutoff(...a) },
  },
}))
/** What each person's own sandbox mounts (the gateway's sandboxProjectsFor). */
let mounts: Record<string, string[]> = {}
vi.mock('@/lib/sandbox/gateway', () => ({
  sandboxProjectsFor: async (userId: string) => mounts[userId] ?? [],
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
  authorizeSessionTarget,
  resolveSessionsViewer,
  visibleSessions,
  type SessionsViewer,
} from './agentSessionsAccess'
import { setFlagsForTests } from './flags'
import { resetSharedToolsForTests } from './sharedTools'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from './projectAccess'
import { visibleProjects } from './visibleProjects'

const CUTOFF = new Date('2026-06-01T00:00:00Z')
const BEFORE_CUTOFF = new Date('2026-01-01T00:00:00Z')
const AFTER_CUTOFF = new Date('2026-09-01T00:00:00Z')

function principal(id: string, role = 'standard', legacyGrants: string[] = [], createdAt = AFTER_CUTOFF) {
  return { id, email: `${id}@x`, role, hasPassword: true, createdAt, legacyGrants }
}

/** Signs `real` in; `actingAs` is the effective user when an admin acts as someone. */
function signedIn(real: ReturnType<typeof principal>, actingAs?: string) {
  mockRequireSession.mockResolvedValue({ userId: real.id, role: real.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === real.id ? real : null))
  mockEffectiveUser.mockResolvedValue({ userId: actingAs ?? real.id })
}

// chat-a in project-a (member-a's, written by member-a), chat-b in project-b (member-b's, by
// member-b); chat-gone has no conversation.
const CONVERSATIONS = [
  { sessionId: 'chat-a', projectId: 'project-a', userId: 'member-a', project: { userId: 'member-a' } },
  { sessionId: 'chat-b', projectId: 'project-b', userId: 'member-b', project: { userId: 'member-b' } },
]

/** member-a's own sandbox is `aaaaa1`, member-b's `bbbbb1`; the agent adds the person tags. */
const IN_A = { sandbox: 'aaaaa1', sandbox_user: 'member-a', sandbox_view: 'own' }
const IN_B = { sandbox: 'bbbbb1', sandbox_user: 'member-b', sandbox_view: 'own' }
const SANDBOX_OF: Record<string, string> = { '2': 'bbbbb1' }
/** The instance a drive of this number names (the row's own). */
const sandboxOf = (id: string) => SANDBOX_OF[id] ?? 'aaaaa1'

function agentList() {
  return {
    sessions: [
      { id: 1, type: 'meterpreter', info: 'uid=0', connection: 'c1', target_ip: '10.0.0.1', chat_session_id: 'chat-a', ...IN_A },
      { id: 2, type: 'shell', info: '', connection: 'c2', target_ip: '10.0.0.2', chat_session_id: 'chat-b', ...IN_B },
      { id: 3, type: 'shell', info: '', connection: 'c3', target_ip: '10.0.0.3', chat_session_id: null, ...IN_A },
      { id: 4, type: 'shell', info: '', connection: 'c4', target_ip: '10.0.0.4', chat_session_id: 'chat-gone', ...IN_A },
    ],
    jobs: [
      { id: 0, name: 'Exploit: multi/handler', payload: 'linux/x64/meterpreter/reverse_tcp', port: 4444, ...IN_A },
      { id: 1, name: 'Exploit: multi/handler', payload: 'linux/x64/meterpreter/reverse_tcp', port: 4444, ...IN_B },
    ],
    non_msf_sessions: [
      { id: 'raw-1', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4445', chat_session_id: 'chat-a', ...IN_A },
      { id: 'raw-2', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4446', chat_session_id: 'chat-b', ...IN_B },
      { id: 'raw-3', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4447', ...IN_A },
    ],
    cache_age_seconds: 1.5,
    busy: ['aaaaa1', 'bbbbb1'],
  }
}

async function viewerFor(real: ReturnType<typeof principal>, actingAs?: string): Promise<SessionsViewer> {
  signedIn(real, actingAs)
  const v = await resolveSessionsViewer()
  if (v instanceof NextResponse) throw new Error(`no viewer: ${v.status}`)
  return v
}

const ids = (rows: { id?: unknown }[]) => rows.map(r => r.id)
const compatRows = () => mockWriteAudit.mock.calls.map(c => c[0]).filter(e => e.action === 'rbac.compat_used')

let warn: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  mockRequireSession.mockReset()
  mockEffectiveUser.mockReset()
  mockLoadPrincipal.mockReset()
  mockConversations.mockReset().mockImplementation(async (args: { where: { sessionId: { in: string[] } } }) =>
    CONVERSATIONS.filter(c => args.where.sessionId.in.includes(c.sessionId)))
  mockCutoff.mockReset().mockResolvedValue({ createdAt: CUTOFF })
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockUsers.mockReset().mockResolvedValue([])
  mockProjects.mockReset().mockResolvedValue([])
  mounts = { 'member-a': ['project-a'], 'member-b': ['project-b'] }
  resetSharedToolsForTests()
  setFlagsForTests({})
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  warn.mockRestore()
  setFlagsForTests({})
})

describe('the sessions list', () => {
  test("own project's session visible", async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toContain(1)
    expect(out.sessions.find(s => s.id === 1)).toMatchObject({ chat_session_id: 'chat-a', project_id: 'project-a' })
    expect(ids(out.non_msf_sessions)).toEqual(['raw-1'])
  })

  test("another project's hidden", async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).not.toContain(2)
    expect(ids(out.non_msf_sessions)).not.toContain('raw-2')
    const b = await visibleSessions(agentList(), await viewerFor(principal('member-b')))
    expect(ids(b.sessions)).toEqual([2])
    expect(ids(b.non_msf_sessions)).toEqual(['raw-2'])
  })

  test('unattributed hidden for a member', async () => {
    // No chat, or a chat with no conversation (deleted, or another instance's).
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toEqual([1])
    expect(ids(out.non_msf_sessions)).toEqual(['raw-1'])
  })

  // Changed by decision D-D: a job belongs to the sandbox it runs in, so a member sees their own.
  test("a member sees the jobs of their own sandbox, never another person's (D-D)", async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(out.jobs).toEqual([{ id: 0, name: 'Exploit: multi/handler', payload: 'linux/x64/meterpreter/reverse_tcp', port: 4444, sandbox: 'aaaaa1' }])
    const b = await visibleSessions(agentList(), await viewerFor(principal('member-b')))
    expect(ids(b.jobs)).toEqual([1])
  })

  test('every row visible to a legacy holder and an admin', async () => {
    for (const who of [principal('holder', 'standard', ['shell_sessions']), principal('admin-a', 'admin')]) {
      const out = await visibleSessions(agentList(), await viewerFor(who))
      expect(ids(out.sessions)).toEqual([1, 2, 3, 4])
      expect(ids(out.jobs)).toEqual([0, 1])
      expect(ids(out.non_msf_sessions)).toEqual(['raw-1', 'raw-2', 'raw-3'])
      // The map: each session names its project, or none.
      expect(out.sessions.map(s => s.project_id)).toEqual(['project-a', 'project-b', null, null])
    }
  })

  test('another grant does not open every session', async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('m', 'standard', ['kali_terminal', 'tunnels'])))
    expect(out.sessions).toEqual([])
    expect(out.jobs).toEqual([])
  })

  test("an admin acting as a member still holds the admin's view; the member's projects are the effective user's", async () => {
    const v = await viewerFor(principal('admin-a', 'admin'), 'member-a')
    expect(v.effectiveUserId).toBe('member-a')
    expect(ids((await visibleSessions(agentList(), v)).sessions)).toEqual([1, 2, 3, 4])
  })

  test('the project is the one the effective user owns, not the conversation author', async () => {
    // A conversation in member-a's project is member-a's, whoever wrote in it: here member-b, whose
    // sandbox mounts project-a (shared with him).
    mounts['member-b'] = ['project-a', 'project-b']
    mockConversations.mockResolvedValue([{ sessionId: 'chat-b', projectId: 'project-a', userId: 'member-b', project: { userId: 'member-a' } }])
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toEqual([2])
  })

  test('no count of hidden sessions: the answer carries only the agent fields', async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(Object.keys(out).sort()).toEqual(['busy', 'cache_age_seconds', 'jobs', 'non_msf_sessions', 'sessions'])
    expect(out.cache_age_seconds).toBe(1.5)
    // Each sandbox has its own console: member-a is told only about the sandbox her rows come from.
    expect(out.busy).toEqual(['aaaaa1'])
  })

  test('the old single busy flag is not passed on (one console per sandbox)', async () => {
    const out = await visibleSessions({ ...agentList(), busy: undefined, agent_busy: true }, await viewerFor(principal('member-a')))
    expect(out).not.toHaveProperty('agent_busy')
    expect(out).not.toHaveProperty('busy')
  })

  test('one conversation read, for the distinct chat ids only; none when nothing is tagged', async () => {
    await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(mockConversations).toHaveBeenCalledTimes(1)
    const where = mockConversations.mock.calls[0][0].where
    expect([...where.sessionId.in].sort()).toEqual(['chat-a', 'chat-b', 'chat-gone'])
    mockConversations.mockClear()
    const out = await visibleSessions({ sessions: [{ id: 9, chat_session_id: null }], jobs: [] }, await viewerFor(principal('member-a')))
    expect(mockConversations).not.toHaveBeenCalled()
    expect(out).toMatchObject({ sessions: [], jobs: [], non_msf_sessions: [] })
  })

  test('a malformed agent answer reads as no sessions', async () => {
    const v = await viewerFor(principal('admin-a', 'admin'))
    for (const bad of [null, 'x', 42, { sessions: 'nope', jobs: {}, non_msf_sessions: null }]) {
      expect(await visibleSessions(bad, v)).toMatchObject({ sessions: [], jobs: [], non_msf_sessions: [] })
    }
  })

  test('listing under the escape hatch shows everything but is not counted as a use', async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    const out = await visibleSessions(agentList(), await viewerFor(principal('old', 'standard', [], BEFORE_CUTOFF)))
    expect(ids(out.sessions)).toEqual([1, 2, 3, 4])
    expect(compatRows()).toEqual([])
    const late = await visibleSessions(agentList(), await viewerFor(principal('new', 'standard', [], AFTER_CUTOFF)))
    expect(late.sessions).toEqual([])
  })
})

describe('the viewer', () => {
  test('no session is a 401', async () => {
    mockRequireSession.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const v = await resolveSessionsViewer()
    expect(v).toBeInstanceOf(NextResponse)
    expect((v as NextResponse).status).toBe(401)
  })

  test('an account gone since sign-in is a 401', async () => {
    mockRequireSession.mockResolvedValue({ userId: 'gone', role: 'admin' })
    mockLoadPrincipal.mockResolvedValue(null)
    mockEffectiveUser.mockResolvedValue({ userId: 'gone' })
    const v = await resolveSessionsViewer()
    expect((v as NextResponse).status).toBe(401)
  })

  test('the database role is judged, not the token', async () => {
    mockRequireSession.mockResolvedValue({ userId: 'm', role: 'admin' })
    mockLoadPrincipal.mockResolvedValue(principal('m', 'standard'))
    mockEffectiveUser.mockResolvedValue({ userId: 'm' })
    const v = await resolveSessionsViewer()
    expect((v as SessionsViewer).all.allowed).toBe(false)
  })
})

describe('a target to drive', () => {
  test("a member drives their own project's session", async () => {
    const t = await authorizeSessionTarget(agentList(), await viewerFor(principal('member-a')), 'session', '1', sandboxOf('1'))
    expect(t).toEqual({ projectId: 'project-a', via: 'owner', sandboxUser: 'member-a', sandboxView: 'own' })
  })

  test("kill of a hidden session 404: no target for another project, an unattributed session, another person's job or a missing id", async () => {
    const v = await viewerFor(principal('member-a'))
    for (const [kind, id] of [['session', '2'], ['session', '3'], ['session', '4'], ['session', '99'], ['session', 'x']] as const) {
      expect(await authorizeSessionTarget(agentList(), v, kind, id, sandboxOf(id))).toBeNull()
    }
    // member-b's job in member-b's sandbox, and the same number paired with member-a's own instance.
    expect(await authorizeSessionTarget(agentList(), v, 'job', '1', 'bbbbb1')).toBeNull()
    expect(await authorizeSessionTarget(agentList(), v, 'job', '1', 'aaaaa1')).toBeNull()
  })

  test('a member stops the job of their own sandbox (D-D)', async () => {
    const v = await viewerFor(principal('member-a'))
    expect(await authorizeSessionTarget(agentList(), v, 'job', '0', 'aaaaa1')).toEqual({ projectId: null, via: 'own_sandbox', sandboxUser: 'member-a', sandboxView: 'own' })
  })

  test('a holder or an admin drives any session and job', async () => {
    const holder = await viewerFor(principal('holder', 'standard', ['shell_sessions']))
    expect(await authorizeSessionTarget(agentList(), holder, 'session', '2', sandboxOf('2'))).toEqual({ projectId: 'project-b', via: 'legacy', sandboxUser: 'member-b', sandboxView: 'own' })
    expect(await authorizeSessionTarget(agentList(), holder, 'session', '3', sandboxOf('3'))).toEqual({ projectId: null, via: 'legacy', sandboxUser: 'member-a', sandboxView: 'own' })
    expect(await authorizeSessionTarget(agentList(), holder, 'job', '0', sandboxOf('0'))).toEqual({ projectId: null, via: 'legacy', sandboxUser: 'member-a', sandboxView: 'own' })
    const admin = await viewerFor(principal('admin-a', 'admin'))
    expect(await authorizeSessionTarget(agentList(), admin, 'session', '4', sandboxOf('4'))).toEqual({ projectId: null, via: 'admin', sandboxUser: 'member-a', sandboxView: 'own' })
    expect(await authorizeSessionTarget(agentList(), admin, 'job', '7', sandboxOf('7'))).toBeNull()
  })

  test("driving another's session under the escape hatch is a recorded use; one's own is not", async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    const v = await viewerFor(principal('member-a', 'standard', [], BEFORE_CUTOFF))
    expect(await authorizeSessionTarget(agentList(), v, 'session', '1', sandboxOf('1'))).toEqual({ projectId: 'project-a', via: 'owner', sandboxUser: 'member-a', sandboxView: 'own' })
    expect(compatRows()).toEqual([])
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2', sandboxOf('2'))).toEqual({ projectId: 'project-b', via: 'compat', sandboxUser: 'member-b', sandboxView: 'own' })
    expect(compatRows()).toHaveLength(1)
    expect(compatRows()[0]).toMatchObject({ actorId: 'member-a', targetId: 'shell_sessions_all' })
  })
})

// Step 5.10 (SH-48): agent:sessions on a shared project needs W+X. member-a's project-b access is the
// policy's answer (doubled here): a Read + Write share with Exploitation & shells shows project-b's
// sessions and listeners and lets them be driven (`via: 'share'`, audited as such); without the toggle,
// with a read share or under oversight nothing of project-b shows. Jobs and untagged sessions stay
// the escape hatch's.
describe('a project shared with the viewer (step 5.10)', () => {
  const policy = vi.mocked(projectAccess)
  const toProjectB = (level: 'read' | 'write', toggles: Partial<ProjectAccessToggles> = {}, via: ProjectAccess['via'] = 'share') =>
    Object.freeze({ project: { id: 'project-b', userId: 'member-b' }, level, toggles: { rawData: level === 'write', ...toggles }, via }) as ProjectAccess
  const answering = (access: ProjectAccess | null) =>
    policy.mockImplementation(async (_s, projectId: string) => (projectId === 'project-b' ? access : null))
  const lists = vi.mocked(visibleProjects)

  // Sharing in force: the list admits shares (each project is then judged by projectAccess()).
  beforeEach(() => {
    policy.mockClear()
    lists.mockResolvedValue({ where: {}, withShares: true })
  })
  afterEach(async () => {
    const actual = await vi.importActual<typeof import('./projectAccess')>('./projectAccess')
    policy.mockImplementation(actual.projectAccess)
    const actualLists = await vi.importActual<typeof import('./visibleProjects')>('./visibleProjects')
    lists.mockImplementation(actualLists.visibleProjects)
  })

  test('sharing not in force: no project of anyone else is asked of the policy', async () => {
    const actualLists = await vi.importActual<typeof import('./visibleProjects')>('./visibleProjects')
    lists.mockImplementation(actualLists.visibleProjects)
    answering(toProjectB('write', { exploit: true }))
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toEqual([1])
    expect(policy).not.toHaveBeenCalled()
  })

  test('collaborator with exploit: sees the shared project\'s sessions and listeners and drives them as a share', async () => {
    answering(toProjectB('write', { exploit: true }))
    const v = await viewerFor(principal('member-a'))
    const out = await visibleSessions(agentList(), v)
    expect(ids(out.sessions)).toEqual([1, 2])
    expect(out.sessions.find(s => s.id === 2)).toMatchObject({ project_id: 'project-b' })
    expect(ids(out.non_msf_sessions)).toEqual(['raw-1', 'raw-2'])
    // A share reaches the project's sessions, never the sharer's sandbox: member-b's job stays hidden (D-D).
    expect(ids(out.jobs)).toEqual([0])
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2', sandboxOf('2'))).toEqual({ projectId: 'project-b', via: 'share', sandboxUser: 'member-b', sandboxView: 'own' })
    expect(await authorizeSessionTarget(agentList(), v, 'job', '1', 'bbbbb1')).toBeNull()
    expect(await authorizeSessionTarget(agentList(), v, 'session', '3', sandboxOf('3'))).toBeNull()
    expect(policy).toHaveBeenCalledWith({ userId: 'member-a' }, 'project-b')
  })

  test('collaborator with exploit: the own project is never asked of the policy', async () => {
    answering(toProjectB('write', { exploit: true }))
    await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(policy.mock.calls.map(c => c[1])).toEqual(['project-b'])
  })

  test.each([
    ['Read + Write without Exploitation & shells', toProjectB('write', { useAgent: true, runScans: true, manage: true })],
    ['a read share with Raw data & files', toProjectB('read', { rawData: true })],
    ['oversight', toProjectB('read', {}, 'oversight')],
    ['break-glass', toProjectB('read', { rawData: true }, 'break_glass')],
    ['no access', null],
  ])('without exploit refused: %s shows none of the project\'s sessions and drives none', async (_what, access) => {
    answering(access)
    const v = await viewerFor(principal('member-a'))
    const out = await visibleSessions(agentList(), v)
    expect(ids(out.sessions)).toEqual([1])
    expect(ids(out.non_msf_sessions)).toEqual(['raw-1'])
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2', sandboxOf('2'))).toBeNull()
  })

  test('an admin acting as the collaborator: the share is asked as acted (read at most), and the admin\'s own view stays', async () => {
    answering(toProjectB('read'))
    const v = await viewerFor(principal('admin-a', 'admin'), 'member-a')
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2', sandboxOf('2'))).toEqual({ projectId: 'project-b', via: 'admin', sandboxUser: 'member-b', sandboxView: 'own' })
    expect(policy).toHaveBeenCalledWith({ userId: 'member-a' }, 'project-b', { actingAs: true })
  })

  test('a shared session driven is audited with via share', async () => {
    answering(toProjectB('write', { exploit: true }))
    const v = await viewerFor(principal('member-a'))
    const target = await authorizeSessionTarget(agentList(), v, 'session', '2', sandboxOf('2'))
    const { beginDriveAudit } = await import('@/app/api/agent/sessions/sessionDrive')
    // Group 1 (TD-11): a drive is named `<instance>:<number>`. The row is written before the drive
    // is forwarded (S16b), so it carries `outcome: 'attempted'`.
    await beginDriveAudit('agent.session_kill', 'session', '2', 'bbbbb1', v, target!)
    expect(mockWriteAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'agent.session_kill', actorId: 'member-a', targetId: 'bbbbb1:2',
      after: expect.objectContaining({ projectId: 'project-b', via: 'share', sandbox: 'bbbbb1', sandboxUser: 'member-b', outcome: 'attempted' }),
    }))
  })
})

describe('every-session holders: busy consoles and whose row it is (gaps G-15, G-33)', () => {
  test('the busy instances: all of them for a holder of every session, malformed ids dropped', async () => {
    const out = await visibleSessions({ ...agentList(), busy: ['aaaaa1', 'bbbbb1', '../x', 7] }, await viewerFor(principal('admin-a', 'admin')))
    expect(out.busy).toEqual(['aaaaa1', 'bbbbb1'])
  })

  test('another person\'s busy sandbox is never named to someone without a row from it', async () => {
    const out = await visibleSessions({ ...agentList(), busy: ['bbbbb1'] }, await viewerFor(principal('member-a')))
    expect(out.busy).toEqual([])
  })

  test('each row says whose sandbox and which project, from the agent\'s tags and one read of each table', async () => {
    mockUsers.mockResolvedValue([{ id: 'member-a', name: 'Alice', email: 'a@x' }, { id: 'member-b', name: null, email: 'b@x' }])
    mockProjects.mockResolvedValue([{ id: 'project-a', name: 'Project A' }, { id: 'project-b', name: 'Project B' }])
    const out = await visibleSessions(agentList(), await viewerFor(principal('admin-a', 'admin')))
    const one = out.sessions.find(r => r.id === 1)!
    expect(one).toMatchObject({ person_label: 'Alice', project_label: 'Project A', project_id: 'project-a' })
    expect(out.sessions.find(r => r.id === 2)).toMatchObject({ person_label: 'b@x', project_label: 'Project B' })
    // An unattributed session names its sandbox's person but no project.
    expect(out.sessions.find(r => r.id === 3)).toMatchObject({ person_label: 'Alice' })
    expect(out.sessions.find(r => r.id === 3)).not.toHaveProperty('project_label')
    expect(out.jobs.map(j => j.person_label)).toEqual(['Alice', 'b@x'])
    // The agent's own person tags still never reach the browser.
    expect(JSON.stringify(out)).not.toContain('sandbox_user')
    expect(mockUsers).toHaveBeenCalledTimes(1)
    expect(mockProjects).toHaveBeenCalledTimes(1)
  })

  test('an act-as sandbox says so', async () => {
    mockUsers.mockResolvedValue([{ id: 'member-a', name: 'Alice', email: 'a@x' }])
    const list = { ...agentList(), sessions: [], non_msf_sessions: [], jobs: [{ id: 5, name: 'h', payload: '', port: 0, sandbox: 'ccccc1', sandbox_user: 'member-a', sandbox_view: 'act_as' }] }
    const out = await visibleSessions(list, await viewerFor(principal('admin-a', 'admin')))
    expect(out.jobs[0].person_label).toBe('Alice (act-as)')
  })

  test('an owner\'s own rows carry no labels, and nothing is read for them', async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    for (const row of [...out.sessions, ...out.jobs, ...out.non_msf_sessions]) {
      expect(row).not.toHaveProperty('person_label')
      expect(row).not.toHaveProperty('project_label')
    }
    expect(mockUsers).not.toHaveBeenCalled()
  })

  test('a failed read labels nothing and the list still answers', async () => {
    mockUsers.mockRejectedValue(new Error('db down'))
    const out = await visibleSessions(agentList(), await viewerFor(principal('admin-a', 'admin')))
    expect(ids(out.sessions)).toEqual([1, 2, 3, 4])
    expect(out.sessions[0]).not.toHaveProperty('person_label')
  })
})

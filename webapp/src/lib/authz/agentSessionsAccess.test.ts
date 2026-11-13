/**
 * Which shell sessions a person sees and drives (HD-01, HD-02, SH-49 map).
 *
 * The Kali sandbox has one msfconsole for the whole instance, so its session list holds
 * every user's sessions. A session belongs to the chat whose run opened it (the
 * manager's session-to-chat map), the chat to its conversation (`Conversation.sessionId`,
 * unique) and the conversation to its project. A member sees the sessions of the
 * projects the effective user owns; untagged sessions, other projects' sessions and the
 * background jobs only with `shell_sessions_all` (admins, the legacy grant, the escape
 * hatch for pre-upgrade accounts), judged on the signed-in account.
 *
 * The session, the account read and Prisma are mocked; sharedToolAccess, visibleProjects and
 * projectAccess() are the real ones (sharing off) unless a step 5.10 test answers for the policy.
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

vi.mock('@/lib/session', () => ({
  requireSession: (...a: unknown[]) => mockRequireSession(...a),
  getEffectiveUser: (...a: unknown[]) => mockEffectiveUser(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    conversation: { findMany: (...a: unknown[]) => mockConversations(...a) },
    auditLog: { findFirst: (...a: unknown[]) => mockCutoff(...a) },
  },
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

// chat-a in project-a (member-a's), chat-b in project-b (member-b's); chat-gone has no conversation.
const CONVERSATIONS = [
  { sessionId: 'chat-a', projectId: 'project-a', project: { userId: 'member-a' } },
  { sessionId: 'chat-b', projectId: 'project-b', project: { userId: 'member-b' } },
]

function agentList() {
  return {
    sessions: [
      { id: 1, type: 'meterpreter', info: 'uid=0', connection: 'c1', target_ip: '10.0.0.1', chat_session_id: 'chat-a' },
      { id: 2, type: 'shell', info: '', connection: 'c2', target_ip: '10.0.0.2', chat_session_id: 'chat-b' },
      { id: 3, type: 'shell', info: '', connection: 'c3', target_ip: '10.0.0.3', chat_session_id: null },
      { id: 4, type: 'shell', info: '', connection: 'c4', target_ip: '10.0.0.4', chat_session_id: 'chat-gone' },
    ],
    jobs: [{ id: 0, name: 'Exploit: multi/handler', payload: 'linux/x64/meterpreter/reverse_tcp', port: 4444 }],
    non_msf_sessions: [
      { id: 'raw-1', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4445', chat_session_id: 'chat-a' },
      { id: 'raw-2', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4446', chat_session_id: 'chat-b' },
      { id: 'raw-3', type: 'listener', tool: 'netcat', command: 'nc -lvnp 4447' },
    ],
    cache_age_seconds: 1.5,
    agent_busy: false,
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

  test('untagged hidden for a member', async () => {
    // No chat, or a chat with no conversation (deleted, or another instance's).
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toEqual([1])
    expect(ids(out.non_msf_sessions)).toEqual(['raw-1'])
  })

  test('jobs hidden for a member', async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(out.jobs).toEqual([])
  })

  test('untagged visible to a legacy holder and an admin', async () => {
    for (const who of [principal('holder', 'standard', ['shell_sessions']), principal('admin-a', 'admin')]) {
      const out = await visibleSessions(agentList(), await viewerFor(who))
      expect(ids(out.sessions)).toEqual([1, 2, 3, 4])
      expect(ids(out.jobs)).toEqual([0])
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
    // A conversation in member-a's project is member-a's, whoever wrote in it.
    mockConversations.mockResolvedValue([{ sessionId: 'chat-b', projectId: 'project-a', project: { userId: 'member-a' } }])
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(ids(out.sessions)).toEqual([2])
  })

  test('no count of hidden sessions: the answer carries only the agent fields', async () => {
    const out = await visibleSessions(agentList(), await viewerFor(principal('member-a')))
    expect(Object.keys(out).sort()).toEqual(['agent_busy', 'cache_age_seconds', 'jobs', 'non_msf_sessions', 'sessions'])
    expect(out.cache_age_seconds).toBe(1.5)
    expect(out.agent_busy).toBe(false)
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
    const t = await authorizeSessionTarget(agentList(), await viewerFor(principal('member-a')), 'session', '1')
    expect(t).toEqual({ projectId: 'project-a', via: 'owner' })
  })

  test('kill of a hidden session 404: no target for another project, an untagged session, a job or a missing id', async () => {
    const v = await viewerFor(principal('member-a'))
    for (const [kind, id] of [['session', '2'], ['session', '3'], ['session', '4'], ['job', '0'], ['session', '99'], ['session', 'x']] as const) {
      expect(await authorizeSessionTarget(agentList(), v, kind, id)).toBeNull()
    }
  })

  test('a holder or an admin drives any session and job', async () => {
    const holder = await viewerFor(principal('holder', 'standard', ['shell_sessions']))
    expect(await authorizeSessionTarget(agentList(), holder, 'session', '2')).toEqual({ projectId: 'project-b', via: 'legacy' })
    expect(await authorizeSessionTarget(agentList(), holder, 'session', '3')).toEqual({ projectId: null, via: 'legacy' })
    expect(await authorizeSessionTarget(agentList(), holder, 'job', '0')).toEqual({ projectId: null, via: 'legacy' })
    const admin = await viewerFor(principal('admin-a', 'admin'))
    expect(await authorizeSessionTarget(agentList(), admin, 'session', '4')).toEqual({ projectId: null, via: 'admin' })
    expect(await authorizeSessionTarget(agentList(), admin, 'job', '7')).toBeNull()
  })

  test("driving another's session under the escape hatch is a recorded use; one's own is not", async () => {
    setFlagsForTests({ sharedToolsCompat: true })
    const v = await viewerFor(principal('member-a', 'standard', [], BEFORE_CUTOFF))
    expect(await authorizeSessionTarget(agentList(), v, 'session', '1')).toEqual({ projectId: 'project-a', via: 'owner' })
    expect(compatRows()).toEqual([])
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2')).toEqual({ projectId: 'project-b', via: 'compat' })
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
    expect(out.jobs).toEqual([])
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2')).toEqual({ projectId: 'project-b', via: 'share' })
    expect(await authorizeSessionTarget(agentList(), v, 'job', '0')).toBeNull()
    expect(await authorizeSessionTarget(agentList(), v, 'session', '3')).toBeNull()
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
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2')).toBeNull()
  })

  test('an admin acting as the collaborator: the share is asked as acted (read at most), and the admin\'s own view stays', async () => {
    answering(toProjectB('read'))
    const v = await viewerFor(principal('admin-a', 'admin'), 'member-a')
    expect(await authorizeSessionTarget(agentList(), v, 'session', '2')).toEqual({ projectId: 'project-b', via: 'admin' })
    expect(policy).toHaveBeenCalledWith({ userId: 'member-a' }, 'project-b', { actingAs: true })
  })

  test('a shared session driven is audited with via share', async () => {
    answering(toProjectB('write', { exploit: true }))
    const v = await viewerFor(principal('member-a'))
    const target = await authorizeSessionTarget(agentList(), v, 'session', '2')
    const { auditDrive } = await import('@/app/api/agent/sessions/sessionDrive')
    await auditDrive('agent.session_kill', 'session', '2', v, target!)
    expect(mockWriteAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'agent.session_kill', actorId: 'member-a', after: { projectId: 'project-b', via: 'share' },
    }))
  })
})

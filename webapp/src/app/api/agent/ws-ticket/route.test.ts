/**
 * Unit tests for POST /api/agent/ws-ticket — STRIDE S6, HD-04, HD-25.
 *
 * The ticket identity MUST come from the verified session cookie, never the
 * request body, so a caller cannot mint a ticket for another user. The ticket
 * names the socket it opens (`aud`), and a Kali terminal ticket is minted only for
 * a REAL signed-in user who holds the terminal (admin, legacy grant, or the
 * escape hatch): an admin acting as a member never borrows the member's grant.
 * An `agent` ticket carries `cap` (step 3.9b, SH-34): the agent permissions agentTicketCap
 * (authz/agentCap.ts, tested there) gives the identity on the ticket's project. Every ticket
 * names the project's owner, from the project check, as its tenant (`ten`, step 5.3, SH-33);
 * the doubles' project belongs to `real-user` unless a case says otherwise.
 * session, auth and agentCap are mocked; sharedToolAccess is the real one.
 *
 * Run: npx vitest run "src/app/api/agent/ws-ticket/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGetAuthzIdentity = vi.fn()
const mockGetSession = vi.fn()
const mockLoadPrincipal = vi.fn()
const mockRequireProjectAccess = vi.fn()
const mockCreateWsTicket = vi.fn()
const mockWriteAudit = vi.fn()
const mockCutoff = vi.fn()
const mockAgentCap = vi.fn()
// The conversation a ticket's session id already names (5.3 review: sessionTicketRefusal); none by default.
const mockConversation = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overAuthzIdentity()))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => mockGetAuthzIdentity(...a),
  getSession: (...a: unknown[]) => mockGetSession(...a),
}))
vi.mock('@/lib/authz/agentCap', () => ({
  agentTicketCap: (...a: unknown[]) => mockAgentCap(...a),
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: (...a: unknown[]) => mockLoadPrincipal(...a),
}))
vi.mock('@/lib/access', () => ({
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))
// The terminal branch asks projectAccess() itself (step 4.3: the owner level). By default it
// answers what the access double above answers, so every case keeps one project double: a refusal
// is null, an allowed project the owner's access. A case sets `mockProjectAccess` for another answer.
const mockProjectAccess = vi.fn()
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: (...a: unknown[]) => mockProjectAccess(...a),
}))
vi.mock('@/lib/auth', () => ({
  createWsTicket: (...a: unknown[]) => mockCreateWsTicket(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
  // A socket whose effective user is not the owner writes its credits.used row first (step 5.6).
  writeAuditTx: async () => undefined,
}))
vi.mock('@/lib/activationLock', () => ({
  assertGraphNotActivating: async () => null,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    auditLog: { findFirst: (...a: unknown[]) => mockCutoff(...a) },
    conversation: { findUnique: (...a: unknown[]) => mockConversation(...a) },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'
import { WS_SESSION_ID_MAX } from '@/lib/wsTicket'

function req(body: unknown): NextRequest {
  return new NextRequest('http://x/api/agent/ws-ticket', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const BEFORE_CUTOFF = new Date('2026-01-01T00:00:00Z')
const CUTOFF = new Date('2026-06-01T00:00:00Z')

function principal(id: string, role: string, legacyGrants: string[] = [], createdAt = new Date('2026-09-01T00:00:00Z')) {
  return { id, email: `${id}@x`, role, hasPassword: true, createdAt, legacyGrants }
}

/** The real signed-in user is `real`; the effective user is `effective` (an admin acting as them). */
function signedIn(real: ReturnType<typeof principal>, effective = real.id) {
  mockGetAuthzIdentity.mockResolvedValue({
    session: { userId: real.id, role: real.role },
    principal: real,
    actingAs: effective === real.id ? null : principal(effective, 'standard'),
  })
  mockGetSession.mockResolvedValue({ userId: real.id, role: real.role })
  mockLoadPrincipal.mockImplementation(async (id: string) => (id === real.id ? real : principal(id, 'standard', ['kali_terminal'])))
}

/** A member signed in as themselves. */
const signedInAs = (userId: string) => signedIn(principal(userId, 'standard'))

const ALL_CAP = ['agent:approve_phase', 'agent:approve_dangerous', 'agent:fireteam', 'agent:kali_exec']

const terminal = (over: Record<string, unknown> = {}) => req({ projectId: 'p', sessionId: 's', socket: 'kali-terminal', ...over })

beforeEach(() => {
  mockGetAuthzIdentity.mockReset()
  mockGetSession.mockReset().mockResolvedValue(null)
  mockAgentCap.mockReset().mockResolvedValue(ALL_CAP)
  mockLoadPrincipal.mockReset()
  mockRequireProjectAccess.mockReset().mockResolvedValue({ project: { id: 'p', userId: 'real-user' } })
  mockProjectAccess.mockReset().mockImplementation(async (subject: unknown, projectId: unknown) => {
    const allowed = await mockRequireProjectAccess(subject, projectId)
    if (allowed instanceof Response) return null
    return { project: allowed.project, level: 'owner', toggles: { rawData: true }, via: 'owner' }
  })
  mockCreateWsTicket.mockReset().mockResolvedValue('signed.ticket.value')
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockCutoff.mockReset().mockResolvedValue({ createdAt: CUTOFF })
  mockConversation.mockReset().mockResolvedValue(null)
  resetSharedToolsForTests()
  setFlagsForTests({})
})
afterEach(() => setFlagsForTests(null))

describe('POST /api/agent/ws-ticket — S6 + impersonation', () => {
  test('no session → 401, no ticket minted', async () => {
    mockGetAuthzIdentity.mockResolvedValue(null)
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(401)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('missing projectId/sessionId → 400', async () => {
    signedInAs('u1')
    expect((await POST(req({ projectId: 'p' }))).status).toBe(400)
    expect((await POST(req({ sessionId: 's' }))).status).toBe(400)
  })

  test("a session id the agent's writer check would refuse is never signed: 400 invalid_session_id, nothing read", async () => {
    // Over the bound, the writer check's 400 refuses every run on the socket; a CR/LF would forge log lines.
    signedInAs('real-user')
    for (const socket of ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']) {
      for (const sessionId of ['s'.repeat(WS_SESSION_ID_MAX + 1), 's\n[rbac] forged', 's\r', 'nul\u0000']) {
        const res = await POST(req({ projectId: 'p', sessionId, socket }))
        expect([socket, res.status, (await res.json()).code]).toEqual([socket, 400, 'invalid_session_id'])
      }
    }
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
    expect(mockRequireProjectAccess).not.toHaveBeenCalled()
    expect(mockConversation).not.toHaveBeenCalled()
  })

  test('a session id at the bound is signed as given', async () => {
    signedInAs('real-user')
    const sessionId = 's'.repeat(WS_SESSION_ID_MAX)
    expect((await POST(req({ projectId: 'p', sessionId }))).status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('real-user', 'p', sessionId, 'agent', undefined, ALL_CAP, 'real-user')
  })

  test('identity is bound to the EFFECTIVE user, never the body', async () => {
    signedInAs('real-user')
    // Attacker tries to smuggle a different userId in the body.
    const res = await POST(req({ userId: 'victim', projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ticket: 'signed.ticket.value' })
    expect(mockCreateWsTicket).toHaveBeenCalledWith('real-user', 'p', 's', 'agent', undefined, ALL_CAP, 'real-user')
  })

  test('admin simulating X → ticket minted for X (impersonation-consistent)', async () => {
    signedIn(principal('admin-1', 'admin'), 'user-X')
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p', userId: 'user-X' } })
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(mockRequireProjectAccess).toHaveBeenCalledWith({ userId: 'user-X' }, 'p')
    expect(mockCreateWsTicket).toHaveBeenCalledWith('user-X', 'p', 's', 'agent', 'admin-1', ALL_CAP, 'user-X')
  })

  test('the real admin behind an act-as is carried as the actor', async () => {
    signedIn(principal('admin-1', 'admin'), 'user-X')
    const res = await POST(req({ projectId: 'p', sessionId: 's', socket: 'cypherfix-triage' }))
    expect(res.status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('user-X', 'p', 's', 'cypherfix-triage', 'admin-1', undefined, 'real-user')
  })

  test('EXPLOIT: minting a ticket for a project the effective user does not own → blocked, no ticket', async () => {
    signedInAs('attacker')
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(req({ projectId: 'victimProj', sessionId: 's' }))
    expect(res.status).toBe(404)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('null ticket (secret unset) is passed through for agent fail-open', async () => {
    signedInAs('u1')
    mockCreateWsTicket.mockResolvedValue(null)
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ticket: null })
  })

  test('a mint that throws answers a readable body with its code, not an empty 500', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signedInAs('u1')
    mockCreateWsTicket.mockRejectedValue(Object.assign(new Error('secret material: abc'), { name: 'TypeError' }))
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not issue a ticket for the agent connection', code: 'TypeError' })
  })
})

describe('the ticket names its socket (HD-25)', () => {
  test('aud set from socket, for each of the four', async () => {
    signedIn(principal('admin-1', 'admin'))
    for (const socket of ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']) {
      mockCreateWsTicket.mockClear()
      const res = await POST(req({ projectId: 'p', sessionId: 's', socket }))
      expect(res.status, socket).toBe(200)
      if (socket === 'agent') expect(mockCreateWsTicket).toHaveBeenCalledWith('admin-1', 'p', 's', socket, undefined, ALL_CAP, 'real-user')
      else expect(mockCreateWsTicket).toHaveBeenCalledWith('admin-1', 'p', 's', socket, undefined, undefined, 'real-user')
    }
  })

  test('no socket in the body is the chat socket (a browser bundle from before the update)', async () => {
    signedInAs('u1')
    expect((await POST(req({ projectId: 'p', sessionId: 's' }))).status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('u1', 'p', 's', 'agent', undefined, ALL_CAP, 'real-user')
  })

  test('unknown socket 400', async () => {
    signedInAs('u1')
    for (const socket of ['shell', '', 'KALI-TERMINAL', null, 7, ['agent'], { aud: 'agent' }]) {
      const res = await POST(req({ projectId: 'p', sessionId: 's', socket }))
      expect(res.status, JSON.stringify(socket)).toBe(400)
      expect((await res.json()).code).toBe('unknown_socket')
    }
    expect(mockRequireProjectAccess).not.toHaveBeenCalled()
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })
})

describe('the Kali terminal needs the terminal grant (HD-04)', () => {
  test('terminal refused for a new member', async () => {
    signedIn(principal('member-new', 'standard'))
    const res = await POST(terminal())
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: 'The Kali terminal is open to whoever holds platform:kali_terminal, and to accounts that kept it at the upgrade.',
      code: 'forbidden',
      permission: 'platform:kali_terminal',
    })
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('the new member still gets every other socket', async () => {
    signedIn(principal('member-new', 'standard'))
    for (const socket of ['agent', 'cypherfix-triage', 'cypherfix-codefix']) {
      expect((await POST(req({ projectId: 'p', sessionId: 's', socket }))).status, socket).toBe(200)
    }
  })

  test('terminal allowed for a legacy holder and an admin', async () => {
    for (const [who, via] of [[principal('member-old', 'standard', ['kali_terminal']), 'legacy'], [principal('admin-1', 'admin'), 'admin']] as const) {
      mockCreateWsTicket.mockClear()
      mockWriteAudit.mockClear()
      signedIn(who)
      const res = await POST(terminal())
      expect(res.status, who.id).toBe(200)
      expect(mockCreateWsTicket).toHaveBeenCalledWith(who.id, 'p', 's', 'kali-terminal', undefined, undefined, 'real-user')
      expect(mockWriteAudit).toHaveBeenCalledWith({
        actorId: who.id, action: 'agent.terminal_opened', targetType: 'project', targetId: 'p',
        after: { via }, source: 'ui',
      })
    }
  })

  test('the grant is judged on a fresh read of the signed-in account (step 2.2)', async () => {
    signedIn(principal('admin-1', 'admin'))
    expect((await POST(terminal())).status).toBe(200)
    expect(mockGetAuthzIdentity).toHaveBeenCalledWith({ fresh: true })
    expect(mockLoadPrincipal).toHaveBeenCalledWith('admin-1', { fresh: true })
  })

  test('a grant for another shared tool does not open the terminal', async () => {
    signedIn(principal('member-tunnels', 'standard', ['tunnels', 'shell_sessions']))
    expect((await POST(terminal())).status).toBe(403)
  })

  test('act-as cannot borrow the target\'s terminal grant', async () => {
    // The effective user holds the grant; the real signed-in account does not. Only an
    // admin can act as someone today, so the real account is a demoted one here.
    signedIn(principal('former-admin', 'standard'), 'member-old')
    const res = await POST(terminal())
    expect(res.status).toBe(403)
    // Read fresh (step 2.2), and only the real account is ever read.
    expect(mockLoadPrincipal).toHaveBeenCalledWith('former-admin', { fresh: true })
    expect(mockLoadPrincipal.mock.calls.map(c => c[0])).toEqual(['former-admin'])
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('an admin acting as a member opens it through the admin, and the row names both', async () => {
    signedIn(principal('admin-1', 'admin'), 'member-new')
    const res = await POST(terminal())
    expect(res.status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-new', 'p', 's', 'kali-terminal', 'admin-1', undefined, 'real-user')
    expect(mockWriteAudit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: 'admin-1', action: 'agent.terminal_opened', targetId: 'p',
      after: { via: 'admin', actingAsUserId: 'member-new' },
    }))
  })

  test('the escape hatch opens it for an account older than the upgrade only', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    setFlagsForTests({ sharedToolsCompat: true })
    signedIn(principal('member-pre', 'standard', [], BEFORE_CUTOFF))
    expect((await POST(terminal())).status).toBe(200)
    signedIn(principal('member-post', 'standard'))
    expect((await POST(terminal())).status).toBe(403)
  })

  test('a project the caller cannot see answers 404 before the grant is read', async () => {
    signedIn(principal('member-new', 'standard'))
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await POST(terminal())).status).toBe(404)
    expect(mockLoadPrincipal).not.toHaveBeenCalled()
  })

  test('the project is asked of the effective user, read fresh, as the account acted as (step 4.3; D-22 since step 5.2)', async () => {
    signedIn(principal('admin-1', 'admin'), 'member-new')
    expect((await POST(terminal())).status).toBe(200)
    // Under act-as the account's share reaches read only (step 5.2 lifted the terminal to W+X).
    expect(mockProjectAccess).toHaveBeenCalledWith({ userId: 'member-new' }, 'p', { fresh: true, actingAs: true })
  })

  test.each([
    ['a read share', 'share', false],
    ['a read share with Raw data', 'share', true],
    ['oversight', 'oversight', false],
    ['break-glass', 'break_glass', true],
  ])('a read collaborator gets no terminal ticket on the shared project: %s is 403 below W+X, before the grant is read', async (_what, via, rawData) => {
    // An admin holds the terminal: the refusal is the access level's, not the platform tool's.
    signedIn(principal('admin-1', 'admin'))
    mockProjectAccess.mockResolvedValue({ project: { id: 'p', userId: 'someone-else' }, level: 'read', toggles: { rawData }, via })
    const res = await POST(terminal())
    expect(res.status).toBe(403)
    // Step 5.2: the hold is Exploitation & shells (W+X), not the owner level; the refusal names it.
    expect(await res.json()).toEqual({
      error: "Opening the Kali terminal on this project needs Exploitation & shells on it: the project's owner, or a collaborator whose share includes it.",
      code: 'forbidden', permission: 'platform:kali_terminal', level: 'W+X',
    })
    expect(mockLoadPrincipal).not.toHaveBeenCalled()
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('a real account that is gone answers 401', async () => {
    signedInAs('u1')
    mockGetSession.mockResolvedValue(null)
    expect((await POST(terminal())).status).toBe(401)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('no ticket minted (secret unset) writes no audit row', async () => {
    signedIn(principal('admin-1', 'admin'))
    mockCreateWsTicket.mockResolvedValue(null)
    expect(await (await POST(terminal())).json()).toEqual({ ticket: null })
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })
})

describe('the agent ticket carries the approval permissions (step 3.9b, SH-34)', () => {
  test('cap is what agentTicketCap gives the identity on the ticket\'s project', async () => {
    signedIn(principal('member-b', 'standard'))
    mockAgentCap.mockResolvedValue(['agent:fireteam'])
    expect((await POST(req({ projectId: 'p', sessionId: 's', socket: 'agent' }))).status).toBe(200)
    expect(mockAgentCap).toHaveBeenCalledTimes(1)
    const [identity, projectId] = mockAgentCap.mock.calls[0]
    expect(projectId).toBe('p')
    expect(identity).toMatchObject({ principal: { id: 'member-b' }, actingAs: null })
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-b', 'p', 's', 'agent', undefined, ['agent:fireteam'], 'real-user')
  })

  test('holding none is written as an empty cap, never left out (no claim = everything)', async () => {
    signedInAs('u1')
    mockAgentCap.mockResolvedValue([])
    await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(mockCreateWsTicket).toHaveBeenCalledWith('u1', 'p', 's', 'agent', undefined, [], 'real-user')
  })

  test('under act-as the cap is asked of both people: the admin and the account acted as', async () => {
    signedIn(principal('admin-1', 'admin'), 'member-a')
    await POST(req({ projectId: 'p', sessionId: 's' }))
    const [identity] = mockAgentCap.mock.calls[0]
    expect(identity).toMatchObject({ principal: { id: 'admin-1' }, actingAs: { id: 'member-a' } })
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-a', 'p', 's', 'agent', 'admin-1', ALL_CAP, 'real-user')
  })

  test('the other sockets carry no cap and ask for none', async () => {
    signedIn(principal('admin-1', 'admin'))
    for (const socket of ['kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']) {
      await POST(req({ projectId: 'p', sessionId: 's', socket }))
    }
    expect(mockAgentCap).not.toHaveBeenCalled()
  })

  test('a project the caller cannot see answers 404 before the cap is read', async () => {
    signedInAs('u1')
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await POST(req({ projectId: 'p', sessionId: 's' }))).status).toBe(404)
    expect(mockAgentCap).not.toHaveBeenCalled()
  })

  test('a failed cap read is a coded 500 and mints nothing', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signedInAs('u1')
    mockAgentCap.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not issue a ticket for the agent connection', code: 'P1001' })
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })
})

describe('every ticket names the project\'s owner as its tenant (step 5.3, SH-33)', () => {
  test.each(['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'])(
    '%s: the tenant is the owner the project check read, never the effective user or the body', async (socket) => {
      // An admin holds the terminal; the effective user differs from the owner the check answers.
      signedIn(principal('admin-1', 'admin'))
      mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p', userId: 'owner-1' } })
      const res = await POST(req({ projectId: 'p', sessionId: 's', socket, ten: 'victim', tenantUserId: 'victim', userId: 'victim' }))
      expect(res.status).toBe(200)
      const args = mockCreateWsTicket.mock.calls[0]
      expect(args[0]).toBe('admin-1')
      expect(args[6]).toBe('owner-1')
    })

  test('a project check that names no owner mints nothing: a coded 500, never a ticket for sub alone', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signedIn(principal('admin-1', 'admin'))
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p', userId: '' } })
    for (const socket of ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']) {
      const res = await POST(req({ projectId: 'p', sessionId: 's', socket }))
      expect(res.status, socket).toBe(500)
      expect((await res.json()).error).toBe('Could not issue a ticket for the agent connection')
    }
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })
})

// 5.3 review (HIGH, last piece): the session id comes from the body, and a reader of a shared project sees
// its attack-chain ids, so a ticket for a session must be refused unless the session is new or a
// conversation of the ticket's person on the ticket's project (lib/authz/conversationRun.ts).
describe('the session a ticket names is new or the person\'s own on this project (5.3 review)', () => {
  test("another person's session -> 403 session_not_yours, nothing minted, for every socket", async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signedIn(principal('admin-1', 'admin'))
    mockConversation.mockResolvedValue({ userId: 'someone-else', projectId: 'p' })
    for (const socket of ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']) {
      const res = await POST(req({ projectId: 'p', sessionId: 'their-session', socket }))
      expect(res.status, socket).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'session_not_yours' })
    }
    expect(mockConversation).toHaveBeenCalledWith({ where: { sessionId: 'their-session' }, select: { userId: true, projectId: true } })
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test("the person's own session on another project -> 403, nothing minted", async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    signedInAs('real-user')
    mockConversation.mockResolvedValue({ userId: 'real-user', projectId: 'another-project' })
    const res = await POST(req({ projectId: 'p', sessionId: 'mine-elsewhere' }))
    expect(res.status).toBe(403)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('own session and a new one -> minted', async () => {
    signedInAs('real-user')
    mockConversation.mockResolvedValueOnce({ userId: 'real-user', projectId: 'p' })
    expect((await POST(req({ projectId: 'p', sessionId: 'mine' }))).status).toBe(200)
    mockConversation.mockResolvedValueOnce(null)
    expect((await POST(req({ projectId: 'p', sessionId: 'brand-new' }))).status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledTimes(2)
  })

  test('under act-as the session is judged for the account acted as', async () => {
    signedIn(principal('admin-1', 'admin'), 'member-x')
    mockConversation.mockResolvedValue({ userId: 'member-x', projectId: 'p' })
    expect((await POST(req({ projectId: 'p', sessionId: 'members-session' }))).status).toBe(200)
  })

  test('a failed read is a coded 500 and mints nothing', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signedInAs('real-user')
    mockConversation.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(500)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('a project the caller cannot see answers 404 before the session is read', async () => {
    signedInAs('intruder')
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    expect((await POST(req({ projectId: 'p', sessionId: 's' }))).status).toBe(404)
    expect(mockConversation).not.toHaveBeenCalled()
  })
})

/**
 * Unit tests for POST /api/agent/ws-ticket — STRIDE S6, HD-04, HD-25.
 *
 * The ticket identity MUST come from the verified session cookie, never the
 * request body, so a caller cannot mint a ticket for another user. The ticket
 * names the socket it opens (`aud`), and a Kali terminal ticket is minted only for
 * a REAL signed-in user who holds the terminal (admin, legacy grant, or the
 * escape hatch): an admin acting as a member never borrows the member's grant.
 * An `agent` ticket carries `cap` (step 3.9b, SH-34): the agent permissions agentTicketCap
 * (authz/agentCap.ts, tested there) gives the identity on the ticket's project.
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
vi.mock('@/lib/auth', () => ({
  createWsTicket: (...a: unknown[]) => mockCreateWsTicket(...a),
}))
vi.mock('@/lib/audit', () => ({
  writeAudit: (...a: unknown[]) => mockWriteAudit(...a),
}))
vi.mock('@/lib/activationLock', () => ({
  assertGraphNotActivating: async () => null,
}))
vi.mock('@/lib/prisma', () => ({
  default: { auditLog: { findFirst: (...a: unknown[]) => mockCutoff(...a) } },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

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
  mockCreateWsTicket.mockReset().mockResolvedValue('signed.ticket.value')
  mockWriteAudit.mockReset().mockResolvedValue(undefined)
  mockCutoff.mockReset().mockResolvedValue({ createdAt: CUTOFF })
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

  test('identity is bound to the EFFECTIVE user, never the body', async () => {
    signedInAs('real-user')
    // Attacker tries to smuggle a different userId in the body.
    const res = await POST(req({ userId: 'victim', projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ticket: 'signed.ticket.value' })
    expect(mockCreateWsTicket).toHaveBeenCalledWith('real-user', 'p', 's', 'agent', undefined, ALL_CAP)
  })

  test('admin simulating X → ticket minted for X (impersonation-consistent)', async () => {
    signedIn(principal('admin-1', 'admin'), 'user-X')
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'p', userId: 'user-X' } })
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(mockRequireProjectAccess).toHaveBeenCalledWith({ userId: 'user-X' }, 'p')
    expect(mockCreateWsTicket).toHaveBeenCalledWith('user-X', 'p', 's', 'agent', 'admin-1', ALL_CAP)
  })

  test('the real admin behind an act-as is carried as the actor', async () => {
    signedIn(principal('admin-1', 'admin'), 'user-X')
    const res = await POST(req({ projectId: 'p', sessionId: 's', socket: 'cypherfix-triage' }))
    expect(res.status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('user-X', 'p', 's', 'cypherfix-triage', 'admin-1')
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
      if (socket === 'agent') expect(mockCreateWsTicket).toHaveBeenCalledWith('admin-1', 'p', 's', socket, undefined, ALL_CAP)
      else expect(mockCreateWsTicket).toHaveBeenCalledWith('admin-1', 'p', 's', socket)
    }
  })

  test('no socket in the body is the chat socket (a browser bundle from before the update)', async () => {
    signedInAs('u1')
    expect((await POST(req({ projectId: 'p', sessionId: 's' }))).status).toBe(200)
    expect(mockCreateWsTicket).toHaveBeenCalledWith('u1', 'p', 's', 'agent', undefined, ALL_CAP)
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
      error: 'The Kali terminal is open to administrators and to accounts that kept it at the upgrade.',
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
      expect(mockCreateWsTicket).toHaveBeenCalledWith(who.id, 'p', 's', 'kali-terminal')
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
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-new', 'p', 's', 'kali-terminal', 'admin-1')
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
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-b', 'p', 's', 'agent', undefined, ['agent:fireteam'])
  })

  test('holding none is written as an empty cap, never left out (no claim = everything)', async () => {
    signedInAs('u1')
    mockAgentCap.mockResolvedValue([])
    await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(mockCreateWsTicket).toHaveBeenCalledWith('u1', 'p', 's', 'agent', undefined, [])
  })

  test('under act-as the cap is asked of both people: the admin and the account acted as', async () => {
    signedIn(principal('admin-1', 'admin'), 'member-a')
    await POST(req({ projectId: 'p', sessionId: 's' }))
    const [identity] = mockAgentCap.mock.calls[0]
    expect(identity).toMatchObject({ principal: { id: 'admin-1' }, actingAs: { id: 'member-a' } })
    expect(mockCreateWsTicket).toHaveBeenCalledWith('member-a', 'p', 's', 'agent', 'admin-1', ALL_CAP)
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

/**
 * The chat socket's ticket refuses a second writer (step 5.11, SH-40): the ticket is where agent
 * runs start, so while another person writes the project (a scan, an agent session, a triage run,
 * a mute-rule apply) the agent ticket answers 409 `project_writer_busy` naming them, and none is
 * minted. The same person reconnects as before; the triage and CodeFix sockets keep their own
 * checks; with sharing off nothing is asked (DV-30).
 *
 * Real guard, can(), projectAccess(), sharing policy reader and projectWriters; the session, Prisma,
 * the ticket signer, the activation lock, the orchestrator's active-scan list and the agent's
 * live-session authors are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  createWsTicket: vi.fn(async () => 'signed.ticket.value'),
  scans: [] as Array<Record<string, unknown>>,
  authors: [] as string[],
  orchestrator: vi.fn(),
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  mayActAs: async () => false,
}))
vi.mock('@/lib/auditActor', () => ({
  signedInActor: async () => null,
  auditActorOf: (actor: { id: string }) => actor,
  actorFields: (actor: { id: string }) => ({ actorId: actor.id }),
}))
vi.mock('@/lib/auth', () => ({ createWsTicket: h.createWsTicket }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestrator(...a) }))
vi.mock('@/lib/agentSessions', () => ({ runningSessionAuthors: async () => ({ userIds: [...h.authors] }) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === 'P-alice' ? { id: 'P-alice', userId: 'alice' } : null) },
    projectCollaborator: { findUnique: async () => null },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: { findUnique: async () => ({ sharingPolicy: { enabled: true }, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }) },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    triageRun: { findMany: async () => [], updateMany: async () => ({ count: 0 }) },
    nodeFilterRun: { findMany: async () => [] },
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => account(where.id),
      findMany: async ({ where }: { where: { id: { in: string[] } } }) => where.id.in.map(id => account(id)),
    },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'

function account(id: string) {
  return {
    id, email: `${id}@example.test`, name: id[0].toUpperCase() + id.slice(1), role: 'standard', password: 'hash',
    createdAt: new Date('2026-09-01T00:00:00Z'), legacyGrants: [] as string[], status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, lastLoginAt: null, hasPassword: true,
    permissionSets: [] as string[], permissionOverrides: [],
  }
}

const post = (socket?: string) => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId: 'P-alice', sessionId: 's', ...(socket ? { socket } : {}) }),
}))

beforeEach(() => {
  h.createWsTicket.mockClear()
  h.scans = []
  h.authors = []
  h.orchestrator.mockReset()
  h.orchestrator.mockImplementation(async () => ({ ok: true, status: 200, json: async () => ({ scans: h.scans }) }))
  h.identity = { session: { userId: 'alice', role: 'standard' }, principal: account('alice'), actingAs: null }
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the agent ticket and a second writer (step 5.11)', () => {
  test("another person's scan refuses the owner's agent ticket, naming them; nothing is minted", async () => {
    h.scans = [{ kind: 'partial_recon', project_id: 'P-alice', status: 'running', actor_user_id: 'bob' }]
    const res = await post()
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({
      code: 'project_writer_busy',
      busy: 'Bob (bob@example.test) is running a partial recon',
      error: 'Bob (bob@example.test) is running a partial recon on this project. One person writes a project at a time: wait for it to finish, or ask them to stop it.',
    })
    expect(h.createWsTicket).not.toHaveBeenCalled()
  })

  test("another person's agent session refuses it too (two agent runs)", async () => {
    h.authors = ['bob']
    const res = await post('agent')
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe('Bob (bob@example.test) is running an agent session')
  })

  test('the same person reconnects beside their own scan and session, as today', async () => {
    h.scans = [{ kind: 'full_recon', project_id: 'P-alice', status: 'running', actor_user_id: 'alice' }]
    h.authors = ['alice']
    expect((await post('agent')).status).toBe(200)
    expect(h.createWsTicket).toHaveBeenCalledTimes(1)
  })

  test("a writer whose access ended mid-run still holds the project until it stops", async () => {
    // bob has no share row (none exists in this double): his scan is still live in the orchestrator.
    h.scans = [{ kind: 'gvm', project_id: 'P-alice', status: 'running', actor_user_id: 'bob' }]
    expect((await post('agent')).status).toBe(409)
    h.scans = []
    expect((await post('agent')).status).toBe(200)
  })

  test("the triage and CodeFix sockets keep their own checks: no writer read", async () => {
    h.scans = [{ kind: 'partial_recon', project_id: 'P-alice', status: 'running', actor_user_id: 'bob' }]
    expect((await post('cypherfix-triage')).status).toBe(200)
    expect((await post('cypherfix-codefix')).status).toBe(200)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })

  test('the orchestrator unreachable: the owner still gets a ticket (DV-30), with a log line', async () => {
    h.orchestrator.mockRejectedValue(new Error('ECONNREFUSED'))
    expect((await post('agent')).status).toBe(200)
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] project_writer_unverified project=P-alice person=alice/))
  })

  test('sharing off: the ticket is minted as before and nobody is asked', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    h.scans = [{ kind: 'partial_recon', project_id: 'P-alice', status: 'running', actor_user_id: 'bob' }]
    expect((await post('agent')).status).toBe(200)
    expect(h.orchestrator).not.toHaveBeenCalled()
  })
})

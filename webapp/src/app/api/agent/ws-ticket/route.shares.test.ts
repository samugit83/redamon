/**
 * The WebSocket ticket on a shared project (step 4.3): a read collaborator, with or without Raw data
 * & files, mints no ticket. The chat socket needs `agent:chat` (W+A), CypherFix triage `triage:run`
 * and CodeFix `codefix:run` (write levels too), which a share at read never reaches; the Kali
 * terminal needs the owner level (its run credential takes the ticket's `sub` as the graph tenant,
 * T15). The owner keeps every ticket, the agent's with its `cap`.
 *
 * Real guard, can(), projectAccess(), sharing policy reader, capabilities and agentTicketCap; the
 * session (getAuthzIdentity), Prisma, the ticket signer and the activation lock are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  shares: new Map<string, { access: string; rawData: boolean; expiresAt: Date | null; user: { status: string } }>(),
  createWsTicket: vi.fn(async () => 'signed.ticket.value'),
  writeAudit: vi.fn(async () => undefined),
}))
// Whole-module doubles: no case acts as anyone, and none reaches the terminal's audit row.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  mayActAs: async () => false,
}))
vi.mock('@/lib/auditActor', () => ({
  signedInActor: async () => {
    const identity = h.identity as { principal: { id: string; email: string } } | null
    return identity ? { id: identity.principal.id, email: identity.principal.email } : null
  },
  auditActorOf: (actor: { id: string }) => actor,
  actorFields: (actor: { id: string }) => ({ actorId: actor.id }),
}))
vi.mock('@/lib/auth', () => ({ createWsTicket: h.createWsTicket }))
vi.mock('@/lib/audit', () => ({ writeAudit: h.writeAudit }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === 'P-alice' ? { id: 'P-alice', userId: 'alice' } : null) },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) =>
        h.shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`) ?? null,
    },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: { findUnique: async () => ({ sharingPolicy: { enabled: true }, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }) },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => ({ ...account(where.id), role: where.id.startsWith('admin') ? 'admin' : 'standard' }),
    },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetSharedToolsForTests } from '@/lib/authz/sharedTools'

function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, email: `${id}@example.test`, name: id, role: 'standard', password: 'hash', createdAt: new Date('2026-09-01T00:00:00Z'),
    legacyGrants: [] as string[], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, hasPassword: true, permissionSets: [] as string[], permissionOverrides: [], ...over,
  }
}

function signedInAs(principal: ReturnType<typeof account>) {
  h.identity = { session: { userId: principal.id, role: principal.role }, principal, actingAs: null }
}

const post = (socket: string) => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId: 'P-alice', sessionId: 's', socket }),
}))

beforeEach(() => {
  h.shares.clear()
  h.createWsTicket.mockClear()
  h.writeAudit.mockClear()
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  resetSharedToolsForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('a read collaborator mints no ticket on the shared project (step 4.3)', () => {
  test.each([[false], [true]])('raw data %s: the chat, triage and CodeFix sockets answer 403 naming their permission', async (rawData) => {
    h.shares.set('P-alice|bob', { access: 'write', rawData, expiresAt: null, user: { status: 'active' } })
    signedInAs(account('bob'))
    for (const [socket, permission] of [['agent', 'agent:chat'], ['cypherfix-triage', 'triage:run'], ['cypherfix-codefix', 'codefix:run']]) {
      const res = await post(socket)
      expect([socket, res.status]).toEqual([socket, 403])
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission })
    }
    expect(h.createWsTicket).not.toHaveBeenCalled()
  })

  test('a read collaborator gets no terminal ticket on the shared project, even holding the terminal (a legacy grant)', async () => {
    h.shares.set('P-alice|bob', { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    signedInAs(account('bob', { legacyGrants: ['kali_terminal'] }))
    const res = await post('kali-terminal')
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: "Only the project's owner can open the Kali terminal on it.", code: 'owner_only', permission: 'platform:kali_terminal' })
    expect(h.createWsTicket).not.toHaveBeenCalled()
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('an admin reaching the project by oversight mints no ticket either', async () => {
    signedInAs(account('admin-1', { role: 'admin' }))
    expect((await post('agent')).status).toBe(403)
    expect((await post('kali-terminal')).status).toBe(403)
    expect(h.createWsTicket).not.toHaveBeenCalled()
  })

  test('someone the project is not shared with: 404, as before', async () => {
    signedInAs(account('carol'))
    expect((await post('agent')).status).toBe(404)
    expect((await post('kali-terminal')).status).toBe(404)
  })

  test('the owner keeps every ticket; the agent ticket carries the four approval permissions', async () => {
    signedInAs(account('alice'))
    expect((await post('agent')).status).toBe(200)
    expect(h.createWsTicket).toHaveBeenLastCalledWith('alice', 'P-alice', 's', 'agent', undefined,
      ['agent:approve_phase', 'agent:approve_dangerous', 'agent:fireteam', 'agent:kali_exec'], 'alice')
    expect((await post('cypherfix-triage')).status).toBe(200)
  })
})

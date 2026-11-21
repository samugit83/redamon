/**
 * The sandbox warm-up on the ticket mint (group 1, B.10, S13): once a ticket for the chat (`agent`)
 * or the Kali terminal (`kali-terminal`) socket is minted, the route starts the ticket person's
 * sandbox in the background (`touchSandbox(sub, {actingAs})`), so the first Kali tool does not wait
 * for a cold start. It is never awaited and never changes the answer: the ticket, its status and its
 * decisions are exactly what they were. Mints in a burst warm each person and view up once (S14: the
 * mint has no rate limit; lib/sandbox/lifecycle.ts holds the cool-down). Under act-as the ticket's person is the account acted as and
 * the view `act_as`; the start's audit row names the admin. Triage and CodeFix sockets, a refused
 * mint and a ticket that could not be signed warm nothing up.
 *
 * Real guard, can(), projectAccess() and sharing policy; the session, Prisma, the ticket signer, the
 * second-writer, quota and spend checks and the gateway are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  createWsTicket: vi.fn(async (): Promise<string | null> => 'signed.ticket.value'),
  touchSandbox: vi.fn(async (_userId: string, _opts: unknown) => undefined),
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  mayActAs: async () => true,
}))
vi.mock('@/lib/auditActor', async (orig) => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  signedInActor: async () => {
    const identity = h.identity as { principal: { id: string; email: string } } | null
    return identity ? { id: identity.principal.id, email: identity.principal.email } : null
  },
}))
vi.mock('@/lib/auth', () => ({ createWsTicket: h.createWsTicket }))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined, writeAuditTx: async () => undefined }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/authz/projectWriters', () => ({ secondWriterResponse: async () => null }))
vi.mock('@/lib/authz/quotas', () => ({ agentRunQuotaRefusal: async () => null }))
vi.mock('@/lib/authz/agentCap', () => ({ agentTicketCap: async () => [] }))
vi.mock('@/lib/authz/conversationRun', () => ({ sessionTicketRefusal: async () => null }))
vi.mock('@/lib/authz/ownerSpend', () => ({ recordOwnerCredentialSpend: async () => undefined }))
vi.mock('@/lib/authz/sharedTools', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/sharedTools')>()),
  sharedToolAccess: async () => ({ allowed: true, via: 'admin' }),
}))
vi.mock('@/lib/sandbox/gateway', () => ({ touchSandbox: (userId: string, opts: unknown) => h.touchSandbox(userId, opts) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async ({ where }: { where: { id: string } }) =>
        ({ 'P-alice': { id: 'P-alice', userId: 'alice' }, 'P-bob': { id: 'P-bob', userId: 'bob' } } as Record<string, unknown>)[where.id] ?? null,
    },
    projectCollaborator: { findUnique: async () => null },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: {
      findUnique: async () => ({ sharingPolicy: { enabled: true }, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }),
    },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    user: { findUnique: async ({ where }: { where: { id: string } }) => account(where.id) },
  },
}))

import { POST } from './route'
import { resetSandboxLifecycleForTests } from '@/lib/sandbox/lifecycle'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'

function account(id: string) {
  return {
    id, email: `${id}@example.test`, name: id, role: id.startsWith('admin') ? 'admin' : 'standard', password: 'hash',
    createdAt: new Date('2026-09-01T00:00:00Z'), legacyGrants: [] as string[], status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, lastLoginAt: null, hasPassword: true, permissionSets: [] as string[],
    permissionOverrides: [],
  }
}
function signedInAs(id: string, actingAs: string | null = null) {
  h.identity = { session: { userId: id, role: account(id).role }, principal: account(id), actingAs: actingAs ? account(actingAs) : null }
}
const post = (socket: string, projectId = 'P-alice') => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId, sessionId: 's', socket }),
}))

beforeEach(() => {
  h.createWsTicket.mockReset()
  h.createWsTicket.mockResolvedValue('signed.ticket.value')
  h.touchSandbox.mockReset()
  h.touchSandbox.mockResolvedValue(undefined)
  resetSandboxLifecycleForTests()
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the warm-up after a ticket for a socket that reaches the Kali tools', () => {
  test('the chat socket: the ticket person\'s own view is warmed up, the answer is the ticket', async () => {
    signedInAs('alice')
    const res = await post('agent')
    expect([res.status, await res.json()]).toEqual([200, { ticket: 'signed.ticket.value' }])
    expect(h.touchSandbox).toHaveBeenCalledTimes(1)
    expect(h.touchSandbox).toHaveBeenCalledWith('alice', { actingAs: false, actor: { actorId: 'alice', onBehalfOfUserId: null, actorEmail: null } })
  })

  test('the Kali terminal socket too', async () => {
    signedInAs('alice')
    expect((await post('kali-terminal')).status).toBe(200)
    expect(h.touchSandbox).toHaveBeenCalledWith('alice', { actingAs: false, actor: { actorId: 'alice', onBehalfOfUserId: null, actorEmail: 'alice@example.test' } })
  })

  test('under act-as: the account acted as, its act_as view, the admin named as the actor', async () => {
    signedInAs('admin-1', 'bob')
    expect((await post('agent', 'P-bob')).status).toBe(200)
    expect(h.touchSandbox).toHaveBeenLastCalledWith('bob', { actingAs: true, actor: { actorId: 'admin-1', onBehalfOfUserId: 'bob', actorEmail: null } })
    resetSandboxLifecycleForTests()
    expect((await post('kali-terminal', 'P-bob')).status).toBe(200)
    expect(h.touchSandbox).toHaveBeenLastCalledWith('bob', { actingAs: true, actor: { actorId: 'admin-1', onBehalfOfUserId: 'bob', actorEmail: 'admin-1@example.test' } })
  })

  test('triage and CodeFix sockets warm nothing up', async () => {
    signedInAs('alice')
    expect((await post('cypherfix-triage')).status).toBe(200)
    expect((await post('cypherfix-codefix')).status).toBe(200)
    expect(h.touchSandbox).not.toHaveBeenCalled()
  })

  test('a refused mint and a ticket that could not be signed warm nothing up', async () => {
    signedInAs('carol')
    expect((await post('agent')).status).toBe(404)
    signedInAs('alice')
    h.createWsTicket.mockResolvedValue(null)
    const res = await post('agent')
    expect([res.status, await res.json()]).toEqual([200, { ticket: null }])
    expect(h.touchSandbox).not.toHaveBeenCalled()
  })

  test('a burst of mints warms the person and view up once; the other view is its own', async () => {
    signedInAs('alice')
    for (let i = 0; i < 4; i++) expect((await post(i % 2 ? 'agent' : 'kali-terminal')).status).toBe(200)
    expect(h.touchSandbox).toHaveBeenCalledTimes(1)
    signedInAs('admin-1', 'bob')
    expect((await post('agent', 'P-bob')).status).toBe(200)
    signedInAs('bob')
    expect((await post('agent', 'P-bob')).status).toBe(200)
    expect(h.touchSandbox.mock.calls.map(([who, opts]) => [who, (opts as { actingAs: boolean }).actingAs]))
      .toEqual([['alice', false], ['bob', true], ['bob', false]])
  })

  test('never awaited: a warm-up that has not finished does not hold the answer back', async () => {
    h.touchSandbox.mockImplementation(() => new Promise<undefined>(() => {}))
    signedInAs('alice')
    const res = await post('agent')
    expect([res.status, await res.json()]).toEqual([200, { ticket: 'signed.ticket.value' }])
    expect(h.touchSandbox).toHaveBeenCalledTimes(1)
  })
})

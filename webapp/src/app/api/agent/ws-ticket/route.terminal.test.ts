/**
 * The Kali terminal ticket on a shared project at Read + Write (step 5.2; SH-35 terminal part, the 5.3
 * assumption "the terminal on a shared project opens at W+X"): the kali-terminal branch asks
 * Exploitation & shells (`W+X`) of the effective user's access instead of the owner level step 4.3 held
 * it at. A write share without that toggle (an editor, a co-owner) is refused 403 naming the level; a
 * share with it (as step 5.6 will open it) gets a ticket whose tenant is the owner and whose person is
 * the collaborator; under act-as the account's share reaches read only (D-22), so an acting admin never
 * borrows it. The platform tool (platform:kali_terminal) is still required on top (route.test.ts).
 *
 * Real guard, can(), projectAccess() (observed, and once answered as 5.6's toggle would) and sharing
 * policy; the session, Prisma, the ticket signer, the platform-tool check and the audit are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  shares: new Map<string, Record<string, unknown>>(),
  createWsTicket: vi.fn(async () => 'signed.ticket.value'),
  writeAudit: vi.fn(async () => undefined),
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  mayActAs: async () => true,
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
vi.mock('@/lib/authz/projectWriters', () => ({ secondWriterResponse: async () => null }))
vi.mock('@/lib/authz/sharedTools', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/sharedTools')>()),
  sharedToolAccess: async () => ({ allowed: true, via: 'permission' }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...real, projectAccess: vi.fn(real.projectAccess) }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === 'P-alice' ? { id: 'P-alice', userId: 'alice' } : null) },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
        const row = h.shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`)
        return row ? { ...row, user: { status: 'active' } } : null
      },
    },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: {
      findUnique: async () => ({
        sharingPolicy: { enabled: true, maxLevel: 'write' }, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
      }),
    },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    user: { findUnique: async ({ where }: { where: { id: string } }) => account(where.id) },
  },
}))

import { POST } from './route'
import { projectAccess, type ProjectAccess } from '@/lib/authz/projectAccess'
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
const terminal = () => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId: 'P-alice', sessionId: 's', socket: 'kali-terminal' }),
}))
const WRITE = { access: 'write', rawData: false, expiresAt: null, runScans: true, useAgent: true, exploit: true, manage: true }
const LEVEL_REFUSAL = {
  error: "Opening the Kali terminal on this project needs Exploitation & shells on it: the project's owner, or a collaborator whose share includes it.",
  code: 'forbidden', permission: 'platform:kali_terminal', level: 'W+X',
}

beforeEach(() => {
  h.shares.clear()
  h.createWsTicket.mockClear()
  h.writeAudit.mockClear()
  vi.mocked(projectAccess).mockClear()
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the Kali terminal ticket asks Exploitation & shells (W+X) on a shared project (step 5.2)', () => {
  test('a write share without Exploitation (Manage included) is refused naming the level; nothing minted', async () => {
    // Every toggle stored on: the run toggles read off until step 5.6 (effectiveToggles), Manage is not W+X.
    h.shares.set('P-alice|bob', WRITE)
    signedInAs('bob')
    const res = await terminal()
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual(LEVEL_REFUSAL)
    expect(h.createWsTicket).not.toHaveBeenCalled()
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('a share reaching W+X (as step 5.6 opens Exploitation) gets a ticket: the person is the collaborator, the tenant the owner', async () => {
    h.shares.set('P-alice|bob', WRITE)
    signedInAs('bob')
    const exploit: ProjectAccess = {
      project: { id: 'P-alice', userId: 'alice' }, level: 'write', via: 'share',
      toggles: { rawData: true, runScans: false, useAgent: false, exploit: true, manage: false },
    }
    vi.mocked(projectAccess).mockResolvedValueOnce(exploit)
    const res = await terminal()
    expect(res.status).toBe(200)
    expect(h.createWsTicket).toHaveBeenCalledWith('bob', 'P-alice', 's', 'kali-terminal', undefined, undefined, 'alice')
    expect(h.writeAudit).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.terminal_opened', targetId: 'P-alice' }))
  })

  test("under act-as the account's write share is asked at read (D-22): refused", async () => {
    h.shares.set('P-alice|bob', WRITE)
    signedInAs('admin-1', 'bob')
    const res = await terminal()
    expect(res.status).toBe(403)
    expect(vi.mocked(projectAccess)).toHaveBeenCalledWith({ userId: 'bob' }, 'P-alice', { fresh: true, actingAs: true })
    expect(h.createWsTicket).not.toHaveBeenCalled()
  })

  test('the owner opens it as before, asked without act-as', async () => {
    signedInAs('alice')
    expect((await terminal()).status).toBe(200)
    expect(vi.mocked(projectAccess)).toHaveBeenCalledWith({ userId: 'alice' }, 'P-alice', { fresh: true })
    expect(h.createWsTicket).toHaveBeenCalledWith('alice', 'P-alice', 's', 'kali-terminal', undefined, undefined, 'alice')
  })

  test('write sharing not in force: the same share reads as read, refused by level, as in Phase 4', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    h.shares.set('P-alice|bob', WRITE)
    signedInAs('bob')
    const res = await terminal()
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual(LEVEL_REFUSAL)
  })
})

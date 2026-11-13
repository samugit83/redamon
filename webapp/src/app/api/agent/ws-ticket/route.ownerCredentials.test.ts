/**
 * The agent sockets whose work spends the project owner's model and keys (step 5.6, C1; GV-12): a
 * collaborator's chat, CodeFix or Kali terminal ticket is minted only after a `credits.used` row
 * names them (no row, no ticket); the owner's own sockets write none, and the triage socket leaves
 * its record to the run's start. The permission or level each socket asks reaches a collaborator
 * only with the owner's consent (projectAccess, ownerCredentials.test.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  person: 'collab-1',
  audit: [] as Array<Record<string, unknown>>,
  auditFails: false,
  createWsTicket: vi.fn(),
}))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string, opts: { projectId?: string }) => ({
    session: { userId: h.person, role: 'standard' }, principal: { id: h.person, role: 'standard' }, actingAs: null,
    effective: { userId: h.person }, permission, capabilities: {},
    access: { project: { id: opts.projectId, userId: 'owner-1' }, level: h.person === 'owner-1' ? 'owner' : 'write', toggles: { rawData: true }, via: 'share' },
  }),
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: async () => ({ session: { userId: h.person, role: 'standard' }, principal: { id: h.person, role: 'standard' }, actingAs: null }),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_s: unknown, projectId: string) => ({
    project: { id: projectId, userId: 'owner-1' }, level: h.person === 'owner-1' ? 'owner' : 'write',
    toggles: { rawData: true, runScans: true, useAgent: true, exploit: true, manage: false }, via: 'share',
  }),
}))
vi.mock('@/lib/auditActor', async (orig) => ({
  ...(await orig<typeof import('@/lib/auditActor')>()),
  signedInActor: async () => ({ id: h.person, email: `${h.person}@example.test` }),
}))
vi.mock('@/lib/authz/principal', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/principal')>()),
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active' }),
}))
vi.mock('@/lib/authz/sharedTools', () => ({ sharedToolAccess: async () => ({ allowed: true, via: 'permission' }) }))
vi.mock('@/lib/authz/agentCap', () => ({ agentTicketCap: async () => [] }))
vi.mock('@/lib/authz/projectWriters', () => ({ secondWriterResponse: async () => null }))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: async () => null }))
vi.mock('@/lib/auth', () => ({ createWsTicket: (...a: unknown[]) => h.createWsTicket(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    // A ticket's session that no conversation holds yet (5.3 review: sessionTicketRefusal).
    conversation: { findUnique: async () => null },
    auditLog: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        if (h.auditFails && data.action === 'credits.used') throw new Error('audit table down')
        h.audit.push(data)
        return data
      },
    },
  },
}))

import { POST } from './route'

const post = (socket: string) => POST(new NextRequest('http://x/api/agent/ws-ticket', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ projectId: 'P1', sessionId: 's1', socket }),
}))
const spends = () => h.audit.filter((r) => r.action === 'credits.used')

beforeEach(() => {
  h.person = 'collab-1'
  h.audit = []
  h.auditFails = false
  h.createWsTicket.mockReset().mockImplementation(async () => {
    expect(spends().length).toBeLessThanOrEqual(1)
    return 'signed.ticket'
  })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})

describe("a collaborator's socket spends the owner's credentials", () => {
  test.each([
    ['agent', 'agent_session', 'agent:chat'],
    ['cypherfix-codefix', 'codefix_session', 'codefix:run'],
    ['kali-terminal', 'shell_session', 'platform:kali_terminal'],
  ])('spend attributed to the actor: %s writes credits.used (%s) before the ticket', async (socket, feature, permission) => {
    let rowsAtMint = -1
    h.createWsTicket.mockImplementationOnce(async () => {
      rowsAtMint = spends().length
      return 'signed.ticket'
    })
    const res = await post(socket)
    expect(res.status).toBe(200)
    expect(rowsAtMint).toBe(1)
    expect(spends()).toEqual([expect.objectContaining({
      actorId: 'collab-1', projectId: 'P1', permission, after: { feature, actor: 'collab-1' },
    })])
    expect(h.createWsTicket.mock.calls[0][6]).toBe('owner-1')
  })

  test('the triage socket writes nothing here (the run records its own spend when it starts)', async () => {
    expect((await post('cypherfix-triage')).status).toBe(200)
    expect(spends()).toEqual([])
  })

  test.each(['agent', 'cypherfix-codefix', 'kali-terminal', 'cypherfix-triage'])("the owner's own %s socket writes no credits.used row", async (socket) => {
    h.person = 'owner-1'
    expect((await post(socket)).status).toBe(200)
    expect(spends()).toEqual([])
  })

  test.each(['agent', 'cypherfix-codefix', 'kali-terminal'])('no credits.used row, no ticket: %s answers 503 spend_not_recorded', async (socket) => {
    h.auditFails = true
    const res = await post(socket)
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('spend_not_recorded')
    expect(h.createWsTicket).not.toHaveBeenCalled()
  })
})

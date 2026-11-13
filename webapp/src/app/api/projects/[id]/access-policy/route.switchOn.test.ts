/**
 * The whole consent path with the switches on (step 5.6, C1; SH-32, OQ-06): the real route, guard,
 * can(), projectAccess(), consent store and share list over one in-memory database. A write share
 * whose row holds Run scans and Use AI agent reaches neither until the owner consents; the owner's
 * consent opens both at the next check; a co-owner and the collaborator cannot consent; the owner's
 * withdrawal closes them again at once and asks the agent to end the collaborators' work there.
 *
 * Prisma is the share routes' in-memory store (shareDb.ts) plus the policy table, the job queue and
 * the triage runs; the session, the step-up check and the agent are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

type PolicyRow = { projectId: string; ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null }

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
  agentFetch: vi.fn(),
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
// Whole-module double: importing the real session module first would bind the guards to it.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: (h.identity.principal as { id: string }).id } : null),
  mayActAs: async () => true,
  actAsInForce: async () => null,
}))
vi.mock('@/lib/authz/stepUp', () => ({
  requireStepUp: async (_r: unknown, password: unknown) =>
    (password === 'owner-password' ? null : NextResponse.json({ code: 'step_up_required' }, { status: 403 })),
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { agentFetch: (...a: unknown[]) => h.agentFetch(...a), AgentUnreachableError }
})

import { GET, POST } from './route'
import { can } from '@/lib/authz/can'
import { projectAccess } from '@/lib/authz/projectAccess'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import type { PermissionId } from '@/lib/authz/permissions'

const T0 = new Date('2026-11-13T12:00:00Z')
let db: ShareDb
let policies: Map<string, PolicyRow>
let jobUpdates: unknown[]
const accounts: Record<string, ShareAccount> = {}

function signIn(id: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: null }
}

const params = { params: Promise.resolve({ id: 'P1' }) }
const get = () => GET(new NextRequest('http://localhost/api/projects/P1/access-policy'), params)
const post = (body: Record<string, unknown>) => POST(new NextRequest('http://localhost/api/projects/P1/access-policy', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}), params)
const SPENDING: PermissionId[] = ['agent:chat', 'recon:scan', 'agent:assistants', 'triage:run']
const reaches = async (id: string) => {
  const out: string[] = []
  for (const p of SPENDING) if ((await can(accounts[id] as never, p, { projectId: 'P1' })).allowed) out.push(p)
  return out
}

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  policies = new Map()
  jobUpdates = []
  const policyTable = {
    findUnique: async ({ where }: { where: { projectId: string } }) => {
      const row = policies.get(where.projectId)
      return row ? { ownerCredentialConsentAt: row.ownerCredentialConsentAt, ownerCredentialConsentById: row.ownerCredentialConsentById } : null
    },
    upsert: async ({ where, update }: { where: { projectId: string }; update: Omit<PolicyRow, 'projectId'> }) => {
      policies.set(where.projectId, { projectId: where.projectId, ...update })
      return update
    },
  }
  const client: Record<string | symbol, unknown> = {
    ...db.client,
    projectAccessPolicy: policyTable,
    jobQueue: { updateMany: async (args: unknown) => { jobUpdates.push(args); return { count: 1 } } },
    triageRun: { findMany: async () => [] },
  }
  // One transaction over both stores: the share store's (which undoes its audit rows) and the policy table.
  client.$transaction = (fn: (tx: unknown) => Promise<unknown>) => (db.client.$transaction as (f: () => Promise<unknown>) => Promise<unknown>)(async () => {
    const saved = new Map(policies)
    try {
      return await fn(client)
    } catch (err) {
      policies = saved
      throw err
    }
  })
  h.client = client
  for (const k of Object.keys(accounts)) delete accounts[k]
  for (const a of [shareAccount('alice'), shareAccount('bob'), shareAccount('carol')]) {
    accounts[a.id] = a
    db.addUser(a)
  }
  db.addProject('P1', 'alice')
  db.addShare({ projectId: 'P1', userId: 'bob', access: 'write', runScans: true, useAgent: true })
  db.addShare({ projectId: 'P1', userId: 'carol', access: 'write', manage: true })
  db.setPolicy({ enabled: true, maxLevel: 'write' })
  h.agentFetch.mockReset().mockImplementation(async (path: string) =>
    new Response(JSON.stringify(path === '/ws/close' ? { closed: 1, stopped_runs: 0 } : { stopped: 1 }), { status: 200 }))
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the consent path with the switches on (step 5.6)', () => {
  test('consent opens the run toggles; withdrawal closes them and ends the collaborators\' work', async () => {
    // Before: the row holds Run scans and Use AI agent, and neither counts.
    expect(await projectAccess({ userId: 'bob' }, 'P1')).toMatchObject({ level: 'write', toggles: { runScans: false, useAgent: false } })
    expect(await reaches('bob')).toEqual([])

    // Neither the collaborator nor the co-owner can consent.
    signIn('bob')
    expect((await post({ ownerCredentialConsent: true, stepUpPassword: 'owner-password' })).status).toBe(403)
    signIn('carol')
    expect(await (await get()).json()).toEqual({ ownerCredentialConsent: false, consentAt: null })
    const coOwner = await post({ ownerCredentialConsent: true, stepUpPassword: 'owner-password' })
    expect(coOwner.status).toBe(403)
    expect(await coOwner.json()).toMatchObject({ code: 'forbidden', permission: 'project:share', level: 'O' })
    expect(policies.size).toBe(0)

    // The owner consents (with the password): the next check opens both toggles.
    signIn('alice')
    const granted = await post({ ownerCredentialConsent: true, stepUpPassword: 'owner-password' })
    expect(granted.status).toBe(200)
    expect(await granted.json()).toEqual({ ownerCredentialConsent: true, consentAt: T0.toISOString(), changed: true })
    expect(policies.get('P1')).toEqual({ projectId: 'P1', ownerCredentialConsentAt: T0, ownerCredentialConsentById: 'alice' })
    expect(db.audit().filter(r => r.action === 'project.owner_consent.grant')).toEqual([
      expect.objectContaining({ actorId: 'alice', projectId: 'P1', permission: 'project:share', targetId: 'P1' }),
    ])
    expect(await projectAccess({ userId: 'bob' }, 'P1')).toMatchObject({ toggles: { runScans: true, useAgent: true, exploit: false } })
    expect(await reaches('bob')).toEqual(SPENDING)
    // The co-owner's row holds no run toggle: the consent opens nothing for it.
    expect(await reaches('carol')).toEqual([])

    // The owner withdraws (no password): closed again at once, the agent asked to end both collaborators' work.
    const withdrawn = await post({ ownerCredentialConsent: false })
    expect(withdrawn.status).toBe(200)
    expect(await withdrawn.json()).toMatchObject({ ownerCredentialConsent: false, changed: true, ended: { collaborators: 2, failed: [] } })
    expect(await reaches('bob')).toEqual([])
    const asked = h.agentFetch.mock.calls.map(([path, init]) => [path, JSON.parse((init as RequestInit).body as string).user_id])
    expect(asked).toEqual([['/agent-sessions/stop-for', 'bob'], ['/ws/close', 'bob'], ['/agent-sessions/stop-for', 'carol'], ['/ws/close', 'carol']])
    expect(jobUpdates).toHaveLength(1)
    expect(db.audit().map(r => r.action).filter(a => a.startsWith('project.owner_consent'))).toEqual([
      'project.owner_consent.grant', 'project.owner_consent.withdraw',
    ])
    // The owner never depended on it.
    for (const p of SPENDING) expect((await can(accounts.alice as never, p, { projectId: 'P1' })).allowed).toBe(true)
  })

  test('a failed audit row undoes the consent: nothing opens', async () => {
    signIn('alice')
    db.failAudit('project.owner_consent.grant')
    expect((await post({ ownerCredentialConsent: true, stepUpPassword: 'owner-password' })).status).toBe(500)
    expect(policies.size).toBe(0)
    expect(await reaches('bob')).toEqual([])
  })

  test('the write switch turned off: the route is gone and a kept consent opens nothing', async () => {
    policies.set('P1', { projectId: 'P1', ownerCredentialConsentAt: T0, ownerCredentialConsentById: 'alice' })
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    signIn('alice')
    expect((await get()).status).toBe(404)
    expect((await post({ ownerCredentialConsent: false })).status).toBe(404)
    expect(await projectAccess({ userId: 'bob' }, 'P1')).toMatchObject({ level: 'read' })
    expect(await reaches('bob')).toEqual([])
    expect(policies.get('P1')?.ownerCredentialConsentAt).toEqual(T0)
  })
})

/**
 * GET /api/projects with shares (step 4.5; SH-39, SH-09): the list is the projects the effective
 * user owns and, with sharing in force, those shared with them by a live share, each row with its
 * owner (`user`, as before) and the person's own access (`myAccess`, the project GET's view). A share
 * that expired, of a disabled account, or of someone else lists nothing; with RBAC_SHARING_ENABLED
 * off the answer is the owner-only list without the key (DV-30). Real visibleProjects, flags, clock
 * and policy; the database is an evaluating double (projectListDb.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/route.list.shared.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from '@/lib/authz/__testing__/projectListDb'

const h = vi.hoisted(() => ({ db: null as unknown, eff: { userId: 'bob' } as { userId: string }, actingAs: false }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn(async () => h.eff) }))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: vi.fn(async () => (h.actingAs ? { actingAs: { userId: h.eff.userId } } : { actingAs: null })),
}))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')
const ON = { identity: true, permissions: true, sharing: true }

type Listed = { id: string; userId: string; user: { name: string; email: string }; myAccess?: Record<string, unknown> }

let state: ProjectListState

function project(id: string, userId: string, createdAt: number) {
  return {
    id, userId, name: id, description: null, targetDomain: `${id}.example.test`, subdomainList: [], ipMode: false,
    targetIps: [], domainBatchMode: false, domainBatchHosts: [], captureProxyEnabled: false,
    createdAt: new Date(createdAt), updatedAt: new Date(createdAt), roeDocumentData: 'never listed',
  }
}

async function list(): Promise<Listed[]> {
  const res = await GET()
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  state = emptyProjectListState()
  state.users = [
    { id: 'alice', name: 'Alice', email: 'alice@example.test', status: 'active' },
    { id: 'bob', name: 'Bob', email: 'bob@example.test', status: 'active' },
    { id: 'carol', name: 'Carol', email: 'carol@example.test', status: 'active' },
  ]
  state.projects = [project('p-bob', 'bob', 1), project('p-alice', 'alice', 2), project('p-alice-raw', 'alice', 3), project('p-carol', 'carol', 4)]
  state.shares = [
    { projectId: 'p-alice', userId: 'bob', access: 'read', rawData: false, expiresAt: null },
    { projectId: 'p-alice-raw', userId: 'bob', access: 'read', rawData: true, expiresAt: new Date(NOW.getTime() + 60_000) },
  ]
  h.db = projectListPrisma(state)
  h.eff = { userId: 'bob' }
  h.actingAs = false
  setFlagsForTests(ON)
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('sharing in force', () => {
  test('list includes shared with owner and level', async () => {
    const rows = await list()
    expect(rows.map((r) => r.id)).toEqual(['p-alice-raw', 'p-alice', 'p-bob'])
    const byId = new Map(rows.map((r) => [r.id, r]))
    expect(byId.get('p-bob')?.myAccess).toEqual({
      level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: 'bob@example.test' },
    })
    expect(byId.get('p-alice')?.myAccess).toEqual({
      level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' },
    })
    expect(byId.get('p-alice-raw')?.myAccess).toMatchObject({ level: 'read', toggles: { rawData: true }, via: 'share' })
    // The owner every card already reads, unchanged; the share row itself never leaves the server.
    expect(byId.get('p-alice')?.user).toEqual({ id: 'alice', name: 'Alice', email: 'alice@example.test' })
    for (const r of rows) {
      expect(r).not.toHaveProperty('collaborators')
      expect(r).not.toHaveProperty('roeDocumentData')
    }
  })

  test('expired share disappears (injected clock)', async () => {
    expect((await list()).map((r) => r.id)).toContain('p-alice-raw')
    setNowForTests(() => new Date(NOW.getTime() + 60_000))
    expect((await list()).map((r) => r.id)).toEqual(['p-alice', 'p-bob'])
  })

  test("a disabled collaborator, someone else's share and an unknown share kind list nothing", async () => {
    state.shares.push(
      { projectId: 'p-carol', userId: 'alice', access: 'read', rawData: false, expiresAt: null },
      { projectId: 'p-carol', userId: 'bob', access: 'admin', rawData: true, expiresAt: null },
    )
    expect((await list()).map((r) => r.id)).not.toContain('p-carol')
    state.users[1].status = 'disabled'
    expect((await list()).map((r) => r.id)).toEqual(['p-bob'])
  })

  test('a write share reads as a read share while write sharing is off', async () => {
    state.shares[0].access = 'write'
    const row = (await list()).find((r) => r.id === 'p-alice')
    expect(row?.myAccess).toMatchObject({ level: 'read', via: 'share' })
  })

  test("the owner sees its project once, as the owner, whoever it is shared with", async () => {
    h.eff = { userId: 'alice' }
    const rows = await list()
    expect(rows.map((r) => r.id)).toEqual(['p-alice-raw', 'p-alice'])
    expect(rows.every((r) => r.myAccess?.level === 'owner')).toBe(true)
  })
})

// The S4 finding: the list answered a consented collaborator's Run scans / Use AI agent / Exploitation as off while
// the project GET and /my-access (projectAccess) answered them on, so a project picked from the header showed its
// controls off until the access poll. The list now asks the owner's consent as projectAccess() does, one read per list.
describe('write sharing in force: the run toggles follow the owner consent, as the project GET', () => {
  const OPERATOR = { access: 'write', runScans: true, useAgent: true, exploit: false, manage: false }
  const consent = (projectId: string) => ({ projectId, ownerCredentialConsentAt: new Date(NOW.getTime() - 60_000), ownerCredentialConsentById: 'alice' })

  beforeEach(() => {
    setFlagsForTests({ ...ON, sharingWrite: true })
    state.policy = { enabled: true, maxLevel: 'write' }
    Object.assign(state.shares[0], OPERATOR)
    Object.assign(state.shares[1], { ...OPERATOR, useAgent: false, exploit: true })
  })

  test('with the consent the run toggles are on; without it off; Manage needs none', async () => {
    state.consents = [consent('p-alice')]
    const byId = new Map((await list()).map((r) => [r.id, r]))
    expect(byId.get('p-alice')?.myAccess).toEqual({
      level: 'write', via: 'share', owner: { name: 'Alice', email: 'alice@example.test' },
      toggles: { rawData: true, runScans: true, useAgent: true, exploit: false, manage: false },
    })
    expect(byId.get('p-alice-raw')?.myAccess).toMatchObject({
      level: 'write', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false },
    })
    expect(byId.get('p-bob')?.myAccess).toMatchObject({ level: 'owner' })
  })

  test('a withdrawn consent (the row kept, its date null) reads as none', async () => {
    state.consents = [{ ...consent('p-alice'), ownerCredentialConsentAt: null, ownerCredentialConsentById: null }]
    const row = (await list()).find((r) => r.id === 'p-alice')
    expect(row?.myAccess).toMatchObject({ level: 'write', toggles: { runScans: false, useAgent: false, exploit: false } })
  })

  test('one consent read for every listed write share (never one per row), none when no share holds a run toggle', async () => {
    state.consents = [consent('p-alice'), consent('p-alice-raw')]
    const reads = vi.spyOn((h.db as { projectAccessPolicy: { findMany: () => unknown } }).projectAccessPolicy, 'findMany')
    const byId = new Map((await list()).map((r) => [r.id, r]))
    expect(byId.get('p-alice-raw')?.myAccess).toMatchObject({ toggles: { runScans: true, exploit: true } })
    expect(reads).toHaveBeenCalledTimes(1)
    reads.mockClear()
    for (const share of state.shares) Object.assign(share, { runScans: false, useAgent: false, exploit: false, manage: true })
    expect((await list()).find((r) => r.id === 'p-alice')?.myAccess).toMatchObject({ toggles: { manage: true, runScans: false } })
    expect(reads).not.toHaveBeenCalled()
  })

  test('an admin acting as the collaborator lists the share as read and reads no consent (D-22)', async () => {
    state.consents = [consent('p-alice')]
    h.actingAs = true
    const reads = vi.spyOn((h.db as { projectAccessPolicy: { findMany: () => unknown } }).projectAccessPolicy, 'findMany')
    expect((await list()).find((r) => r.id === 'p-alice')?.myAccess).toMatchObject({ level: 'read', toggles: { rawData: false } })
    expect(reads).not.toHaveBeenCalled()
  })
})

describe('sharing not in force', () => {
  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
  ])('%s: the owned list, without myAccess (DV-30)', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    state.policy = policy
    const rows = await list()
    expect(rows.map((r) => r.id)).toEqual(['p-bob'])
    expect(rows[0]).not.toHaveProperty('myAccess')
    expect(rows[0]).not.toHaveProperty('collaborators')
  })

  test('the switch on, the policy disabled: the owned list, each row as the owner (as the project GET)', async () => {
    state.policy = {}
    const rows = await list()
    expect(rows.map((r) => r.id)).toEqual(['p-bob'])
    expect(rows[0].myAccess).toMatchObject({ level: 'owner', via: 'owner' })
  })
})

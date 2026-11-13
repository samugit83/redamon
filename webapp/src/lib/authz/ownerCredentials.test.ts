/**
 * Owner credentials with consent and attribution (step 5.6, C1; SH-32, GV-12, OQ-06): a collaborator
 * spends the project owner's providers and keys only through Run scans, Use AI agent or Exploitation
 * & shells, which count only while the owner consents; each spend writes `credits.used` naming the
 * collaborator, before the spend and fail closed; a withdrawal ends what collaborators still spend on
 * the project; the owner's usage report lists the spends by collaborator.
 *
 * The real projectAccess(), can() and capability code over a Prisma double (the project, its share,
 * the instance row with write sharing allowed, the accounts, the consent row, the audit table, the
 * job queue); the agent is `agentFetch` doubled, the triage run reader and stopper and the share list
 * are doubled.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/ownerCredentials.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach, type Mock } from 'vitest'

const db = vi.hoisted(() => ({
  policy: { enabled: true, maxLevel: 'write' } as Record<string, unknown>,
  share: { access: 'write', rawData: false, runScans: true, useAgent: true, exploit: true, manage: false } as Record<string, unknown>,
  /** The consent row of P-owner: absent (undefined), withdrawn (null) or a time. */
  consent: undefined as Date | null | undefined,
  withTable: true,
  audit: [] as Record<string, unknown>[],
  auditFails: false,
  auditRows: [] as Array<Record<string, unknown>>,
  projects: [{ id: 'P-owner', name: 'Owned', userId: 'owner' }, { id: 'P-two', name: 'Second', userId: 'owner' }],
  users: [] as Array<{ id: string; name: string | null; email: string | null }>,
  jobUpdates: [] as unknown[],
}))

const table = vi.hoisted(() => ({
  findUnique: null as unknown as Mock<(a: unknown) => Promise<unknown>>,
  upsert: null as unknown as Mock<(a: unknown) => Promise<unknown>>,
}))
function resetTable() {
  table.findUnique = vi.fn(async (a: unknown) => {
    const { where } = a as { where: { projectId: string } }
    return where.projectId === 'P-owner' && db.consent !== undefined
      ? { ownerCredentialConsentAt: db.consent, ownerCredentialConsentById: 'owner' }
      : null
  })
  table.upsert = vi.fn(async (a: unknown) => {
    const { update } = a as { update: { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null } }
    db.consent = update.ownerCredentialConsentAt
    return update
  })
}

vi.mock('@/lib/prisma', () => ({
  default: new Proxy({}, {
    get: (_t, name) => {
      if (name === 'projectAccessPolicy') {
        return db.withTable ? { findUnique: (a: unknown) => table.findUnique(a), upsert: (a: unknown) => table.upsert(a) } : undefined
      }
      const models: Record<string, unknown> = {
        instanceSettings: {
          findUnique: async () => ({
            id: 'instance', sharingPolicy: db.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
          }),
        },
        project: {
          findUnique: async ({ where }: { where: { id: string } }) => db.projects.find((p) => p.id === where.id) ?? null,
          findMany: async ({ where }: { where: { userId?: string } }) => db.projects.filter((p) => p.userId === where.userId),
        },
        projectCollaborator: {
          findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) =>
            (where.projectId_userId.userId === 'collab' && where.projectId_userId.projectId === 'P-owner'
              ? { expiresAt: null, user: { status: 'active' }, ...db.share }
              : null),
        },
        projectBreakGlass: { findFirst: async () => null },
        user: {
          findUnique: async () => null,
          findMany: async ({ where }: { where: { id: { in: string[] } } }) => db.users.filter((u) => where.id.in.includes(u.id)),
        },
        permissionSet: { findMany: async () => [] },
        auditLog: {
          create: async ({ data }: { data: Record<string, unknown> }) => {
            if (db.auditFails) throw Object.assign(new Error('audit table down'), { code: 'P1001' })
            db.audit.push(data)
            return data
          },
          findMany: async (args: { where: Record<string, unknown>; take: number }) => {
            db.audit.push({ read: args })
            return db.auditRows.slice(0, args.take)
          },
        },
        jobQueue: {
          updateMany: async (args: unknown) => {
            db.jobUpdates.push(args)
            return { count: 2 }
          },
        },
      }
      return models[name as string]
    },
  }),
}))

const agentFetch = vi.hoisted(() => vi.fn())
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { agentFetch, AgentUnreachableError }
})
const triage = vi.hoisted(() => ({ live: vi.fn(), stop: vi.fn() }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => triage.live(...a) }))
vi.mock('@/lib/triage/actions', () => ({ stopRun: (...a: unknown[]) => triage.stop(...a) }))
const shares = vi.hoisted(() => ({ list: vi.fn() }))
vi.mock('@/lib/authz/projectShares', () => ({ listShares: (...a: unknown[]) => shares.list(...a) }))

import { setFlagsForTests, type RbacFlags } from './flags'
import { setNowForTests } from './clock'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'
import { clearPrincipalCacheForTests } from './principal'
import { clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { projectAccess, myAccessView, type ProjectAccess } from './projectAccess'
import { can } from './can'
import { agentTicketCap } from './agentCap'
import { ConsentStoreMissing, readOwnerConsent, spendToggleConsentRefusal, writeOwnerConsent } from './ownerConsent'
import { ownerCredentialRefusal, recordFeatureSpend, recordOwnerCredentialSpend } from './ownerSpend'
import { collaboratorSpends, endCollaboratorSpending } from './ownerCredentials'
import { stopAgentRunsOnProjects } from './accountStatus'
import { AgentUnreachableError } from '@/lib/agentFetch'
import type { PermissionContext } from './guards'
import type { PermissionId } from './permissions'
import type { SharingPolicy } from './sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')
const ALL_ON: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true, sharingWrite: true }
const POLICY = { enabled: true, maxLevel: 'write' } as unknown as Readonly<SharingPolicy>
const SPENDING: PermissionId[] = ['recon:scan', 'agent:chat', 'agent:assistants', 'triage:run', 'agent:sessions']

function member(id: string): CapabilityPrincipal {
  return { id, role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [] }
}

const okJson = (body: unknown) => new Response(JSON.stringify(body), { status: 200 })

beforeEach(() => {
  db.policy = { enabled: true, maxLevel: 'write' }
  db.share = { access: 'write', rawData: false, runScans: true, useAgent: true, exploit: true, manage: false }
  db.consent = undefined
  db.withTable = true
  db.audit = []
  db.auditFails = false
  db.auditRows = []
  db.users = []
  db.jobUpdates = []
  resetTable()
  agentFetch.mockReset()
  agentFetch.mockImplementation(async (path: string) => okJson(path === '/ws/close' ? { closed: 2, stopped_runs: 1 } : { stopped: 1 }))
  triage.live.mockReset().mockResolvedValue(null)
  triage.stop.mockReset().mockResolvedValue({ stopped: true })
  shares.list.mockReset().mockResolvedValue([{ user: { id: 'collab' } }, { user: { id: 'coowner' } }])
  setFlagsForTests(ALL_ON)
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the consent decides the run toggles (projectAccess, can, the agent ticket)', () => {
  test('run toggles read true from this step: with the consent a write share reaches W+S, W+A and W+X', async () => {
    db.consent = new Date(NOW.getTime() - 60_000)
    const access = await projectAccess({ userId: 'collab' }, 'P-owner')
    expect(access).toMatchObject({ level: 'write', toggles: { runScans: true, useAgent: true, exploit: true, manage: false } })
    for (const p of SPENDING) {
      expect([p, (await can(member('collab'), p, { projectId: 'P-owner' })).allowed]).toEqual([p, true])
    }
    expect(await agentTicketCap({ principal: member('collab'), actingAs: null }, 'P-owner')).not.toEqual([])
    expect(myAccessView(access!, null).toggles).toMatchObject({ runScans: true, useAgent: true, exploit: true })
  })

  test('without the consent the same row reaches none of them; editing at W still works', async () => {
    expect(await projectAccess({ userId: 'collab' }, 'P-owner')).toMatchObject({
      level: 'write', toggles: { runScans: false, useAgent: false, exploit: false },
    })
    for (const p of SPENDING) {
      expect([p, await can(member('collab'), p, { projectId: 'P-owner' })]).toEqual([p, expect.objectContaining({ allowed: false, status: 403 })])
    }
    expect((await can(member('collab'), 'project:settings', { projectId: 'P-owner' })).allowed).toBe(true)
    expect(await agentTicketCap({ principal: member('collab'), actingAs: null }, 'P-owner')).toEqual([])
  })

  test('a withdrawal counts at the next check (nothing cached), and the owner never depends on it', async () => {
    db.consent = new Date(NOW.getTime() - 60_000)
    expect((await can(member('collab'), 'agent:chat', { projectId: 'P-owner' })).allowed).toBe(true)
    db.consent = null
    expect((await can(member('collab'), 'agent:chat', { projectId: 'P-owner' })).allowed).toBe(false)
    for (const consent of [undefined, null, new Date()]) {
      db.consent = consent
      expect((await can(member('owner'), 'agent:chat', { projectId: 'P-owner' })).allowed).toBe(true)
    }
  })

  test('before the consent table exists no consent can exist: every run toggle stays closed, a write throws', async () => {
    db.withTable = false
    db.consent = new Date(NOW.getTime() - 60_000)
    expect(await readOwnerConsent('P-owner')).toBeNull()
    expect(await projectAccess({ userId: 'collab' }, 'P-owner')).toMatchObject({ toggles: { runScans: false, useAgent: false, exploit: false } })
    await expect(writeOwnerConsent({}, 'P-owner', { at: NOW, byId: 'owner' })).rejects.toBeInstanceOf(ConsentStoreMissing)
  })

  test('the store writes the consent and its withdrawal on the transaction it is given', async () => {
    const tx = { projectAccessPolicy: { findUnique: table.findUnique, upsert: table.upsert } }
    expect(await writeOwnerConsent(tx, 'P-owner', { at: NOW, byId: 'owner' })).toEqual({ at: NOW, byId: 'owner' })
    expect(table.upsert).toHaveBeenCalledWith({
      where: { projectId: 'P-owner' },
      create: { projectId: 'P-owner', ownerCredentialConsentAt: NOW, ownerCredentialConsentById: 'owner' },
      update: { ownerCredentialConsentAt: NOW, ownerCredentialConsentById: 'owner' },
      select: { ownerCredentialConsentAt: true, ownerCredentialConsentById: true },
    })
    expect(await readOwnerConsent('P-owner')).toEqual({ at: NOW, byId: 'owner' })
    expect(await writeOwnerConsent(tx, 'P-owner', null)).toBeNull()
    expect(await readOwnerConsent('P-owner')).toBeNull()
  })
})

describe('the share routes refuse a spend toggle without the consent', () => {
  test('toggle refused without consent: each of the three, 409 owner_consent_required', async () => {
    for (const toggle of ['runScans', 'useAgent', 'exploit']) {
      const res = await spendToggleConsentRefusal('P-owner', POLICY, { access: 'write', [toggle]: true })
      expect(res?.status).toBe(409)
      expect(await res!.json()).toMatchObject({ code: 'owner_consent_required', toggles: [toggle] })
    }
  })

  test('with the consent, a toggle off, or Manage alone: no refusal', async () => {
    expect(await spendToggleConsentRefusal('P-owner', POLICY, { access: 'write', manage: true, runScans: false })).toBeNull()
    expect(await spendToggleConsentRefusal('P-owner', POLICY, { access: 'write', useAgent: 'true' })).toBeNull()
    expect(table.findUnique).not.toHaveBeenCalled()
    db.consent = new Date(NOW.getTime() - 60_000)
    expect(await spendToggleConsentRefusal('P-owner', POLICY, { access: 'write', runScans: true, useAgent: true })).toBeNull()
  })

  test("write sharing not in force: nothing read, the route's own refusal answers as before", async () => {
    expect(await spendToggleConsentRefusal('P-owner', { enabled: true, maxLevel: 'read' } as unknown as SharingPolicy, { useAgent: true })).toBeNull()
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(await spendToggleConsentRefusal('P-owner', POLICY, { useAgent: true })).toBeNull()
    expect(table.findUnique).not.toHaveBeenCalled()
  })
})

function context(access: { level: ProjectAccess['level']; toggles?: Record<string, boolean> }, effective = 'collab'): PermissionContext {
  return {
    session: { userId: effective, role: 'standard' },
    principal: { id: effective, role: 'standard' },
    actingAs: null,
    effective: { userId: effective },
    permission: 'reports:generate',
    access: { project: { id: 'P-owner', userId: 'owner' }, via: 'share', toggles: { rawData: true }, ...access },
  } as unknown as PermissionContext
}

describe('every spend is attributed to the actor', () => {
  test('spend attributed to the actor: a credits.used row names the collaborator, the project and the feature', async () => {
    expect(await recordFeatureSpend(context({ level: 'write', toggles: { rawData: true, useAgent: true } }), 'report_narratives')).toBeNull()
    expect(db.audit).toEqual([{
      actorId: 'collab', projectId: 'P-owner', permission: 'reports:generate',
      action: 'credits.used', targetType: 'project', targetId: 'P-owner',
      after: { feature: 'report_narratives', actor: 'collab' }, source: 'api',
    }])
  })

  test("the owner's own use writes nothing", async () => {
    expect(await recordFeatureSpend(context({ level: 'owner' }, 'owner'), 'roe_parse')).toBeNull()
    expect(await recordOwnerCredentialSpend({ projectId: 'P-owner', ownerId: 'owner', userId: 'owner', feature: 'scan' })).toBe(false)
    expect(db.audit).toEqual([])
  })

  test('no row, no spend: a failed write is a 503 the route returns (and the system writer throws)', async () => {
    db.auditFails = true
    const res = await recordFeatureSpend(context({ level: 'write' }), 'multi_mute')
    expect(res?.status).toBe(503)
    expect(await res!.json()).toMatchObject({ code: 'spend_not_recorded' })
    const lines = vi.mocked(console.error).mock.calls.map((c) => String(c[0]))
    expect(lines.some((l) => l.includes('[rbac] credits.used not recorded project=P-owner user=collab feature=multi_mute'))).toBe(true)
    await expect(recordOwnerCredentialSpend({ projectId: 'P-owner', ownerId: 'owner', userId: 'collab', feature: 'scan' })).rejects.toThrow()
  })

  test('a scan or a run the system starts names the collaborator as actor', async () => {
    await recordOwnerCredentialSpend({ projectId: 'P-owner', ownerId: 'owner', userId: 'collab', feature: 'scan', source: 'system' })
    expect(db.audit[0]).toMatchObject({
      actorId: 'collab', action: 'credits.used', projectId: 'P-owner', after: { feature: 'scan', actor: 'collab' }, source: 'system',
    })
  })

  test('each needs useAgent for a collaborator: the W+A refusal of the features below it', async () => {
    expect(ownerCredentialRefusal(context({ level: 'owner' }, 'owner'))).toBeNull()
    expect(ownerCredentialRefusal(context({ level: 'write', toggles: { rawData: true, useAgent: true } }))).toBeNull()
    const below: Array<{ level: ProjectAccess['level']; toggles: Record<string, boolean> }> = [
      { level: 'write', toggles: { rawData: true, useAgent: false, runScans: true, exploit: true, manage: true } },
      { level: 'read', toggles: { rawData: true } },
    ]
    for (const access of below) {
      const res = ownerCredentialRefusal(context(access))
      expect(res?.status).toBe(403)
      expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: 'reports:generate', level: 'W+A' })
    }
  })
})

describe('withdrawing the consent ends what collaborators spend on the project', () => {
  const KINDS = ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']

  test("withdrawing turns the toggles off, stops the collaborators' runs and closes their sockets", async () => {
    const ended = await endCollaboratorSpending('P-owner', 'owner')
    const calls = agentFetch.mock.calls.map(([path, init]) => [path, JSON.parse((init as RequestInit).body as string)])
    expect(calls).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'collab', project_ids: ['P-owner'] }],
      ['/ws/close', { user_id: 'collab', project_id: 'P-owner', kinds: KINDS, scope: 'access' }],
      ['/agent-sessions/stop-for', { user_id: 'coowner', project_ids: ['P-owner'] }],
      ['/ws/close', { user_id: 'coowner', project_id: 'P-owner', kinds: KINDS, scope: 'access' }],
    ])
    expect(ended).toMatchObject({ collaborators: 2, runsStopped: 2, socketsClosed: 4, scansCancelled: 2, failed: [] })
    expect(db.jobUpdates).toEqual([{
      where: { projectId: 'P-owner', userId: { in: ['collab', 'coowner'] }, status: { in: ['queued', 'needs_review'] } },
      data: expect.objectContaining({ status: 'canceled', blockedCode: 'owner_consent_withdrawn' }),
    }])
  })

  test("a live triage run a collaborator started is stopped; the owner's own run is not", async () => {
    triage.live.mockResolvedValueOnce({ id: 'run-1', actorUserId: 'collab' })
    expect((await endCollaboratorSpending('P-owner', 'owner')).triageStopped).toBe(true)
    expect(triage.stop).toHaveBeenCalledWith({ userId: 'owner', projectId: 'P-owner' }, 'app')
    triage.stop.mockClear()
    triage.live.mockResolvedValueOnce({ id: 'run-2', actorUserId: 'owner' })
    expect((await endCollaboratorSpending('P-owner', 'owner')).triageStopped).toBe(false)
    expect(triage.stop).not.toHaveBeenCalled()
  })

  test('the agent unreachable: every step is tried, each failure logged, nothing thrown', async () => {
    agentFetch.mockRejectedValue(new AgentUnreachableError('down'))
    triage.live.mockRejectedValueOnce(new Error('db'))
    const ended = await endCollaboratorSpending('P-owner', 'owner')
    expect(ended.failed).toEqual(['stop_runs', 'close_sockets', 'stop_triage_run'])
    expect(ended.scansCancelled).toBe(2)
    const lines = vi.mocked(console.error).mock.calls.map((c) => String(c[0]))
    expect(lines.some((l) => l.includes('[rbac] consent-withdrawal step failed step=stop_runs project=P-owner user=collab'))).toBe(true)
    expect(lines.some((l) => l.includes('[rbac] socket-close failed user=collab'))).toBe(true)
  })

  test('no collaborator: nothing asked of the agent or the queue', async () => {
    shares.list.mockResolvedValueOnce([])
    expect(await endCollaboratorSpending('P-owner', 'owner')).toMatchObject({ collaborators: 0, failed: [] })
    expect(agentFetch).not.toHaveBeenCalled()
    expect(db.jobUpdates).toEqual([])
  })

  test('the share list unreadable: logged, nothing else asked, nothing thrown', async () => {
    shares.list.mockRejectedValueOnce(new Error('db'))
    expect((await endCollaboratorSpending('P-owner', 'owner')).failed).toEqual(['list_collaborators'])
    expect(agentFetch).not.toHaveBeenCalled()
  })

  test('the per-project stop sends only that project; no project asks nothing', async () => {
    expect(await stopAgentRunsOnProjects('collab', ['P-owner'])).toEqual({ stopped: 1 })
    expect(JSON.parse((agentFetch.mock.calls[0][1] as RequestInit).body as string)).toEqual({ user_id: 'collab', project_ids: ['P-owner'] })
    agentFetch.mockClear()
    expect(await stopAgentRunsOnProjects('collab', [])).toEqual({ stopped: 0 })
    expect(agentFetch).not.toHaveBeenCalled()
  })
})

describe("the owner's usage report breaks the spends down by collaborator", () => {
  const row = (actor: string, projectId: string, feature: string, at = NOW) =>
    ({ actorId: actor, projectId, after: { feature, actor }, createdAt: at })

  test('usage report breakdown: per collaborator, per feature and per project, names read once', async () => {
    db.users = [{ id: 'collab', name: 'Bob', email: 'bob@example.test' }]
    db.auditRows = [
      row('collab', 'P-owner', 'report_narratives'), row('collab', 'P-two', 'scan'), row('collab', 'P-owner', 'report_narratives'),
      row('coowner', 'P-owner', 'a_feature_of_a_later_release'), row('owner', 'P-owner', 'scan'),
    ]
    expect(await collaboratorSpends('owner')).toEqual({
      sinceDays: 30, truncated: false,
      people: [
        {
          userId: 'collab', name: 'Bob', email: 'bob@example.test', total: 3, byFeature: { report_narratives: 2, scan: 1 },
          projects: [{ id: 'P-owner', name: 'Owned', count: 2 }, { id: 'P-two', name: 'Second', count: 1 }], lastAt: NOW.toISOString(),
        },
        { userId: 'coowner', name: null, email: null, total: 1, byFeature: {}, projects: [{ id: 'P-owner', name: 'Owned', count: 1 }], lastAt: NOW.toISOString() },
      ],
    })
    const read = (db.audit.find((r) => 'read' in r) as { read: { where: Record<string, unknown> } }).read
    expect(read.where).toMatchObject({ action: 'credits.used', projectId: { in: ['P-owner', 'P-two'] } })
  })

  test('write sharing off: no breakdown and nothing read', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(await collaboratorSpends('owner')).toBeNull()
    expect(db.audit).toEqual([])
  })
})

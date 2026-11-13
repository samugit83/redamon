/**
 * Ownership transfer with the recipient's acceptance (step 5.12; SH-15, DV-15, DV-40;
 * lib/authz/ownershipTransfer.ts). The transfer either completes everywhere (the graph, then one
 * Postgres transaction: the project, its shares, its traffic, the old owner's schedules, the consent,
 * the conversations that follow the owner, the settings naming the old owner's own things, the status)
 * or the project stays as it was; the recipient accepts; every step is audited.
 *
 * Over an in-memory database whose transactions roll back on a throw (as Postgres does), a double of
 * the agent (its live-work answer and the graph re-tenant, keeping which project's graph sits under
 * which owner) and of the project lock. The real normalizeUserSkillToggles and Nuclei template judge
 * decide what is cleared.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/ownershipTransfer.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'

type Row = Record<string, unknown>

const h = vi.hoisted(() => {
  const state = {
    tables: {} as Record<string, Row[]>,
    // Each project's graph as nodes (a uniqueness key and the tenant holding it), so a move can stop halfway.
    graph: new Map<string, Array<{ key: string; owner: string }>>(),
    liveWork: { session_ids: [] as string[], codefix_sockets: 0, triage_run: false } as Record<string, unknown> | null,
    // Per re-tenant call, in order: 'ok' (or nothing left) moves every node; 'network' loses the answer before
    // anything moved; 'moved-network' after everything moved; 'partial-network' halfway (the agent restarted
    // mid-move); 'rollback-failed' halfway with the mixin's retenant_rollback_failed; an object answers that code.
    retenantFail: [] as Array<{ status: number; body: Record<string, unknown> } | 'network' | 'moved-network' | 'partial-network' | 'rollback-failed' | 'ok'>,
    retenantCalls: [] as Array<{ project_id: string; from_user_id: string; to_user_id: string; lockHeld: unknown }>,
    // Called inside the Postgres move's transaction, between its read and its update (a concurrent writer).
    beforeProjectUpdate: null as null | (() => void),
    failNextWrite: null as null | string,
    seq: 0,
  }
  return {
    state,
    writers: vi.fn(async (): Promise<string | null> => null),
    closeSockets: vi.fn(async (): Promise<{ ok: true; closed: number; stoppedRuns: number } | { ok: false; reason: string }> =>
      ({ ok: true, closed: 2, stoppedRuns: 0 })),
    stepUp: vi.fn(async (): Promise<Response | null> => null),
    acting: vi.fn(async (): Promise<Response | null> => null),
    notice: vi.fn(async () => undefined),
    invalidate: vi.fn(),
    reduced: vi.fn(async () => ({ sockets: { closed: 0 }, failed: [] })),
  }
})

// ---- the database double ------------------------------------------------------------------------
const db = vi.hoisted(() => {
  function matches(row: Row, where: Row | undefined): boolean {
    if (!where) return true
    return Object.entries(where).every(([key, cond]) => {
      if (key === 'OR') return (cond as Row[]).some((w) => matches(row, w))
      if (key === 'NOT') return !matches(row, cond as Row)
      if (key === 'projectId_userId') return matches(row, cond as Row)
      const value = row[key]
      if (cond !== null && typeof cond === 'object' && !(cond instanceof Date) && !Array.isArray(cond)) {
        const c = cond as Row
        if ('in' in c) return (c.in as unknown[]).includes(value)
        if ('not' in c) return c.not === null ? value !== null && value !== undefined : value !== c.not
        if ('lt' in c) return value instanceof Date && value.getTime() < (c.lt as Date).getTime()
        if ('equals' in c) return JSON.stringify(value) === JSON.stringify(c.equals)
        return false
      }
      if (cond instanceof Date) return value instanceof Date && value.getTime() === cond.getTime()
      return (value ?? null) === (cond ?? null)
    })
  }

  const pick = (row: Row, select?: Row) => (select ? Object.fromEntries(Object.keys(select).map((k) => [k, row[k]])) : { ...row })

  function table(name: string) {
    const rows = () => (h.state.tables[name] ??= [])
    const guard = () => {
      if (h.state.failNextWrite === name) {
        h.state.failNextWrite = null
        throw Object.assign(new Error(`write to ${name} failed`), { code: 'P2034' })
      }
    }
    return {
      findUnique: async ({ where, select }: { where: Row; select?: Row }) => {
        const r = rows().find((x) => matches(x, where))
        return r ? pick(r, select) : null
      },
      findFirst: async ({ where, orderBy }: { where?: Row; orderBy?: Row }) => {
        const found = rows().filter((x) => matches(x, where))
        if (orderBy) found.sort((a, b) => ((b.createdAt as Date)?.getTime() ?? 0) - ((a.createdAt as Date)?.getTime() ?? 0))
        return found[0] ? { ...found[0] } : null
      },
      findMany: async ({ where, select }: { where?: Row; select?: Row } = {}) => rows().filter((x) => matches(x, where)).map((r) => pick(r, select)),
      count: async ({ where }: { where?: Row } = {}) => rows().filter((x) => matches(x, where)).length,
      create: async ({ data }: { data: Row }) => {
        guard()
        const row = { id: `${name}-${++h.state.seq}`, createdAt: new Date(Date.now() + h.state.seq), forced: false, error: null,
          clearedSettings: null, clearedSeenAt: null, decidedAt: null, ...data }
        rows().push(row)
        return { ...row }
      },
      updateMany: async ({ where, data }: { where: Row; data: Row }) => {
        guard()
        if (name === 'project' && h.state.beforeProjectUpdate && 'userId' in data) {
          const hook = h.state.beforeProjectUpdate
          h.state.beforeProjectUpdate = null
          hook()
        }
        let count = 0
        for (const r of rows()) {
          if (!matches(r, where)) continue
          // Prisma moves @updatedAt on every update.
          Object.assign(r, data, name === 'project' ? { updatedAt: new Date(Date.now() + ++h.state.seq) } : {})
          count++
        }
        return { count }
      },
      deleteMany: async ({ where }: { where: Row }) => {
        guard()
        const before = rows().length
        h.state.tables[name] = rows().filter((x) => !matches(x, where))
        return { count: before - h.state.tables[name].length }
      },
    }
  }

  const TABLES = ['projectTransfer', 'project', 'projectCollaborator', 'user', 'capturedHttpTransaction', 'scanSchedule',
    'projectAccessPolicy', 'projectAuthProfile', 'conversation', 'userLlmProvider', 'userAttackSkill', 'nucleiTemplate',
    'jobQueue', 'auditLog'] as const

  const db: Record<string, unknown> = {}
  for (const t of TABLES) db[t] = table(t)
  db.$executeRaw = async () => 1
  db.$transaction = async (fn: (tx: unknown) => Promise<unknown>) => {
    const snapshot = structuredClone(h.state.tables)
    try {
      return await fn(db)
    } catch (err) {
      h.state.tables = snapshot
      throw err
    }
  }
  return db
})
vi.mock('@/lib/prisma', () => ({ default: db }))

// ---- the other boundaries -------------------------------------------------------------------------
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: async (url: string, init: { body?: string } = {}) => {
    if (url.startsWith('/agent-sessions/project-work')) {
      if (h.state.liveWork === null) throw new Error('agent down')
      return new Response(JSON.stringify(h.state.liveWork), { status: 200 })
    }
    if (url === '/graph/retenant') {
      const body = JSON.parse(init.body ?? '{}')
      const project = h.state.tables.project?.find((p) => p.id === body.project_id)
      h.state.retenantCalls.push({ ...body, lockHeld: project?.activationState })
      const nodes = h.state.graph.get(body.project_id) ?? []
      const failure = h.state.retenantFail.shift()
      if (failure === 'network') throw new Error('socket hang up')
      if (failure && typeof failure === 'object') return new Response(JSON.stringify(failure.body), { status: failure.status })
      // The mixin's preflight: a node already under the new owner with a key of one about to move.
      const target = new Set(nodes.filter((n) => n.owner === body.to_user_id).map((n) => n.key))
      const moving = nodes.filter((n) => n.owner === body.from_user_id)
      const twins = moving.filter((n) => target.has(n.key))
      if (twins.length) return new Response(JSON.stringify({ code: 'retenant_conflict', conflicts: { Domain: twins.length } }), { status: 409 })
      const half = failure === 'partial-network' || failure === 'rollback-failed'
      for (const n of half ? moving.slice(0, Math.ceil(moving.length / 2)) : moving) n.owner = body.to_user_id
      if (failure === 'partial-network' || failure === 'moved-network') throw new Error('socket hang up')
      if (failure === 'rollback-failed') return new Response(JSON.stringify({ code: 'retenant_rollback_failed', moved: {} }), { status: 500 })
      return new Response(JSON.stringify({ total_nodes: moving.length, relationships: 0, nodes: {} }), { status: 200 })
    }
    throw new Error(`unexpected agent call ${url}`)
  },
}))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: (...a: unknown[]) => h.closeSockets(...(a as [])) }))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: () => h.writers() }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: (...a: unknown[]) => h.invalidate(...a) }))
vi.mock('@/lib/activationLock', () => {
  const row = (projectId: string) => h.state.tables.project?.find((p) => p.id === projectId)
  const TTL = 15 * 60 * 1000
  const stale = (r: Row) => !(r.activationStartedAt instanceof Date) || Date.now() - r.activationStartedAt.getTime() > TTL
  return {
    acquireTransferLock: async (projectId: string, transferId: string, ownerId: string) => {
      const r = row(projectId)
      if (!r || r.userId !== ownerId) return { acquired: false, split: false }
      const own = `transfer:${transferId}`
      if (r.activationState === 'transfer_split') {
        if (r.activationVersionId !== own || !stale(r)) return { acquired: false, split: false }
        r.activationStartedAt = new Date()
        return { acquired: true, split: true }
      }
      if (r.activationState !== 'idle' && !stale(r)) return { acquired: false, split: false }
      Object.assign(r, { activationState: 'transferring', activationVersionId: own, activationStartedAt: new Date() })
      return { acquired: true, split: false }
    },
    markTransferSplit: async (projectId: string, transferId: string) => {
      const r = row(projectId)
      if (r?.activationState === 'transferring' && r.activationVersionId === `transfer:${transferId}`) r.activationState = 'transfer_split'
    },
    clearTransferSplit: async (projectId: string, transferId: string) => {
      const r = row(projectId)
      if (r?.activationState === 'transfer_split' && r.activationVersionId === `transfer:${transferId}`) {
        Object.assign(r, { activationState: 'idle', activationVersionId: null, activationStartedAt: null })
      }
    },
    parkTransferSplit: async (projectId: string, transferId: string) => {
      const r = row(projectId)
      if (r?.activationState === 'transfer_split' && r.activationVersionId === `transfer:${transferId}`) r.activationStartedAt = null
    },
    refreshTransferLock: async () => undefined,
    releaseTransferLock: async (projectId: string) => {
      const r = row(projectId)
      if (r?.activationState === 'transferring') Object.assign(r, { activationState: 'idle', activationVersionId: null, activationStartedAt: null })
    },
    // As lib/graphHold.ts holdOf reads the row: a split transfer never goes stale.
    graphHold: async (projectId: string) => {
      const r = row(projectId)
      if (!r || !r.activationState || r.activationState === 'idle') return null
      if (r.activationState === 'transfer_split') return 'transferring'
      return stale(r) ? null : r.activationState
    },
  }
})
vi.mock('./stepUp', () => ({ requireStepUp: () => h.stepUp() }))
vi.mock('./revocation', () => ({ onAccessReduced: (...a: unknown[]) => h.reduced(...(a as [])) }))
vi.mock('./actAsRefusals', () => ({ refuseWhileActingAs: () => h.acting() }))
vi.mock('./accountNotices', async (orig) => ({
  ...(await orig<typeof import('./accountNotices')>()),
  appendNotice: (...a: unknown[]) => h.notice(...(a as [])),
}))
vi.mock('./projectAccess', async (orig) => ({
  ...(await orig<typeof import('./projectAccess')>()),
  projectAccess: async ({ userId }: { userId: string }, projectId: string) => {
    const project = h.state.tables.project?.find((p) => p.id === projectId)
    if (!project) return null
    if (project.userId === userId) return { project: { id: projectId, userId }, level: 'owner', toggles: {}, via: 'owner' }
    const share = h.state.tables.projectCollaborator?.find((c) => c.projectId === projectId && c.userId === userId)
    if (!share || (share.expiresAt instanceof Date && share.expiresAt.getTime() <= Date.now())) return null
    return { project: { id: projectId, userId: project.userId }, level: share.access, toggles: { manage: share.manage }, via: 'share' }
  },
}))

import {
  acceptTransfer, cancelTransfer, declineTransfer, offerTransfer, transferBusy, transferStateFor, transfersForAccount,
  acknowledgeCleared, MODEL_COLUMNS, TRANSFER_OFFER_DAYS, readClearedSettings,
} from './ownershipTransfer'
import { PERMISSIONS } from './permissions'
import { meetsLevel } from './projectAccess'
import type { PermissionContext } from './guards'
import type { AuthzIdentity } from '@/lib/session'

const OLD = 'user-old-owner'
const NEW = 'user-new-owner'
const OTHER = 'user-collab-2'
const P = 'proj-1'
const DAY = 86_400_000

function seed() {
  h.state.tables = {
    user: [
      { id: OLD, name: 'Olga Owner', email: 'olga@e2e.local', status: 'active' },
      { id: NEW, name: 'Bob Collab', email: 'bob@e2e.local', status: 'active' },
      { id: OTHER, name: 'Carla', email: 'carla@e2e.local', status: 'active' },
    ],
    project: [
      {
        id: P, userId: OLD, name: 'Client X', jevProviderId: 'prov-jev-old',
        agentOpenaiModel: 'custom/prov-old', aiPipelineModel: 'custom/prov-new', cypherfixLlmModel: 'claude-opus-4-6',
        cypherfixGithubToken: 'ghp_rbacfake0000000000000000000000000000',
        attackSkillConfig: { builtIn: { xss: true }, user: { 'skill-old-a': true, 'skill-old-b': false } },
        nucleiSelectedCustomTemplates: ['old/own.yaml', 'shared/instance.yaml'],
        nucleiTemplates: ['cves/', '/custom-templates/old/own.yaml'], nucleiCustomTemplates: [],
        activationState: 'idle', activationVersionId: null, activationStartedAt: null, updatedAt: new Date('2026-11-13T08:00:00Z'),
      },
      { id: 'proj-2', userId: OLD, name: 'Other project', attackSkillConfig: { builtIn: {}, user: {} } },
    ],
    projectCollaborator: [
      { projectId: P, userId: NEW, access: 'read', rawData: false, runScans: false, useAgent: false, exploit: false, manage: false, expiresAt: null, grantedById: OLD },
      { projectId: P, userId: OTHER, access: 'write', rawData: true, runScans: true, useAgent: false, exploit: false, manage: false, expiresAt: null, grantedById: OLD },
    ],
    capturedHttpTransaction: [
      { id: 'tx-1', projectId: P, userId: OLD }, { id: 'tx-2', projectId: P, userId: OLD }, { id: 'tx-3', projectId: 'proj-2', userId: OLD },
    ],
    scanSchedule: [
      { id: 'sch-old', projectId: P, userId: OLD, enabled: true, pausedReason: null },
      { id: 'sch-other', projectId: P, userId: OTHER, enabled: true, pausedReason: null },
      { id: 'sch-old-2', projectId: 'proj-2', userId: OLD, enabled: true, pausedReason: null },
    ],
    projectAccessPolicy: [{ projectId: P, ownerCredentialConsentAt: new Date('2026-11-01'), ownerCredentialConsentById: OLD, managersSeeAllConversations: false }],
    projectAuthProfile: [{ id: 'ap-1', projectId: P, userId: OLD }],
    conversation: [
      { id: 'c-old', projectId: P, userId: OLD, formerAuthorId: null, formerAuthorLabel: null },
      { id: 'c-inherited', projectId: P, userId: OLD, formerAuthorId: 'gone-user', formerAuthorLabel: 'Gone' },
      { id: 'c-collab', projectId: P, userId: OTHER, formerAuthorId: null, formerAuthorLabel: null },
      { id: 'c-elsewhere', projectId: 'proj-2', userId: OLD, formerAuthorId: null, formerAuthorLabel: null },
    ],
    userLlmProvider: [
      { id: 'prov-old', userId: OLD, name: "Olga's OpenAI-compatible" },
      { id: 'prov-new', userId: NEW, name: "Bob's own" },
      { id: 'prov-jev-old', userId: OLD, name: "Olga's Jev" },
    ],
    userAttackSkill: [
      { id: 'skill-old-a', userId: OLD, name: 'Olga skill A', quarantinedAt: null },
      { id: 'skill-old-b', userId: OLD, name: 'Olga skill B', quarantinedAt: null },
    ],
    nucleiTemplate: [{ path: 'old/own.yaml', ownerUserId: OLD }, { path: 'shared/instance.yaml', ownerUserId: null }],
    jobQueue: [{ id: 'job-done', projectId: P, userId: OLD, status: 'done' }],
    projectTransfer: [],
    auditLog: [],
  }
  h.state.graph = new Map([
    [P, Array.from({ length: 6 }, (_, i) => ({ key: `d${i}.example.test`, owner: OLD }))],
    ['proj-2', [{ key: 'other.example.test', owner: OLD }]],
  ])
  h.state.beforeProjectUpdate = null
  h.state.liveWork = { session_ids: [], codefix_sockets: 0, triage_run: false }
  h.state.retenantFail = []
  h.state.retenantCalls = []
  h.state.failNextWrite = null
}

const session = (userId: string) => ({ userId, role: 'standard' }) as unknown as AuthzIdentity['session']
const identity = (userId: string): AuthzIdentity => ({
  session: session(userId), principal: { id: userId } as AuthzIdentity['principal'], actingAs: null,
})
const ownerAuth = (userId = OLD): PermissionContext => ({
  ...identity(userId), effective: { userId }, permission: 'project:transfer', capabilities: new Set() as never,
  access: { project: { id: P, userId: OLD }, level: 'owner', toggles: { rawData: true }, via: 'owner' } as never,
})
const req = () => new Request('http://x/api/projects/proj-1/transfer', { method: 'POST' })
const rows = (t: string) => h.state.tables[t] ?? []
const project = () => rows('project').find((p) => p.id === P)!
/** The tenants holding the project's graph nodes: one owner when whole, two when split. */
const owners = (projectId = P) => [...new Set((h.state.graph.get(projectId) ?? []).map((n) => n.owner))].sort()
const audits = (action?: string) => rows('auditLog').filter((r) => !action || (r as { action?: string }).action === action)
const transfer = () => rows('projectTransfer').at(-1)!

async function offer(body: Record<string, unknown> = { toUserId: NEW, oldOwnerRole: 'co-owner', stepUpPassword: 'pw' }) {
  return offerTransfer(req(), ownerAuth(), body)
}
const accept = (who = NEW) => acceptTransfer(req(), identity(who), P, 'pw')

beforeEach(() => {
  seed()
  for (const f of [h.writers, h.closeSockets, h.stepUp, h.acting, h.notice, h.invalidate, h.reduced]) f.mockClear()
  h.writers.mockResolvedValue(null)
  h.closeSockets.mockResolvedValue({ ok: true, closed: 2, stoppedRuns: 0 })
  h.stepUp.mockResolvedValue(null)
  h.acting.mockResolvedValue(null)
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('the offer (step 5.12)', () => {
  test('only the owner offers: project:transfer is level O, which no share reaches, Manage included', () => {
    expect(PERMISSIONS['project:transfer'].level).toBe('O')
    const coOwner = { project: { id: P, userId: OLD }, level: 'write', toggles: { rawData: true, runScans: true, useAgent: true, exploit: true, manage: true }, via: 'share' }
    expect(meetsLevel(coOwner as never, 'O')).toBe(false)
  })

  test('the owner offers to an active collaborator, with their password: pending, audited, 7 days', async () => {
    const res = await offer()
    expect(res.status).toBe(201)
    const { offer: view } = await res.json()
    expect(view).toMatchObject({ status: 'pending', oldOwnerRole: 'co-owner', from: { id: OLD, name: 'Olga Owner' }, to: { id: NEW, email: 'bob@e2e.local' }, project: { id: P, name: 'Client X' } })
    expect(Date.parse(view.expiresAt) - Date.parse(view.createdAt)).toBe(TRANSFER_OFFER_DAYS * DAY)
    expect(audits('project.transfer.offer')).toEqual([expect.objectContaining({ actorId: OLD, projectId: P, targetId: NEW, permission: 'project:transfer' })])
    expect(h.stepUp).toHaveBeenCalledTimes(1)
  })

  test('recipient must be a collaborator: a stranger, an expired share, an inactive account, oneself are refused before the password', async () => {
    rows('user').push({ id: 'stranger', status: 'active' })
    expect((await (await offer({ toUserId: 'stranger', oldOwnerRole: 'leave' })).json()).code).toBe('recipient_not_collaborator')
    rows('projectCollaborator')[0].expiresAt = new Date(Date.now() - 1000)
    expect((await (await offer()).json()).code).toBe('recipient_not_collaborator')
    rows('projectCollaborator')[0].expiresAt = null
    rows('user')[1].status = 'disabled'
    expect((await (await offer()).json()).code).toBe('account_not_active')
    expect((await (await offer({ toUserId: OLD, oldOwnerRole: 'leave' })).json()).code).toBe('own_account')
    expect(h.stepUp).not.toHaveBeenCalled()
    expect(rows('projectTransfer')).toEqual([])
  })

  test('the role and the recipient are validated; the password is required; one open offer at a time', async () => {
    expect((await offer({ toUserId: NEW, oldOwnerRole: 'boss' })).status).toBe(400)
    expect((await offer({ oldOwnerRole: 'leave' })).status).toBe(400)
    h.stepUp.mockResolvedValueOnce(Response.json({ code: 'step_up_required' }, { status: 403 }))
    expect((await offer()).status).toBe(403)
    expect(rows('projectTransfer')).toEqual([])
    expect((await offer()).status).toBe(201)
    const second = await offer({ toUserId: OTHER, oldOwnerRole: 'leave', stepUpPassword: 'pw' })
    expect(second.status).toBe(409)
    expect((await second.json()).code).toBe('transfer_already_offered')
  })

  test('refused while an admin acts as the owner', async () => {
    h.acting.mockResolvedValueOnce(Response.json({ code: 'not_while_acting_as' }, { status: 403 }))
    expect((await offer()).status).toBe(403)
    expect(rows('projectTransfer')).toEqual([])
  })
})

describe('accept moves Postgres and graph', () => {
  test('the graph first, then the project, its shares, traffic, schedules, consent and conversations in one transaction', async () => {
    await offer()
    const res = await accept()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.transferred).toEqual({ projectId: P, from: OLD, to: NEW, oldOwnerRole: 'co-owner' })
    // The graph moved, while the project lock was held.
    expect(owners()).toEqual([NEW])
    expect(owners('proj-2')).toEqual([OLD])
    expect(h.state.retenantCalls).toEqual([{ project_id: P, from_user_id: OLD, to_user_id: NEW, lockHeld: 'transfer_split' }])
    expect(project().activationState).toBe('idle')
    // Every socket of the project closed before the move: each ticket names the old owner as tenant.
    expect(h.closeSockets).toHaveBeenCalledWith({ projectId: P, kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'] })
    // Postgres.
    expect(project().userId).toBe(NEW)
    const shares = rows('projectCollaborator').filter((c) => c.projectId === P)
    expect(shares.find((c) => c.userId === NEW)).toBeUndefined()
    expect(shares.find((c) => c.userId === OLD)).toMatchObject({ access: 'write', rawData: true, runScans: true, useAgent: true, exploit: true, manage: true, grantedById: NEW })
    expect(shares.find((c) => c.userId === OLD)?.expiresAt ?? null).toBeNull()
    expect(shares.find((c) => c.userId === OTHER)).toMatchObject({ access: 'write', grantedById: OLD })
    expect(rows('capturedHttpTransaction').map((t) => [t.id, t.userId])).toEqual([['tx-1', NEW], ['tx-2', NEW], ['tx-3', OLD]])
    expect(rows('projectAccessPolicy')[0]).toMatchObject({ ownerCredentialConsentAt: null, ownerCredentialConsentById: null })
    expect(rows('projectAuthProfile')[0].userId).toBe(NEW)
    expect(transfer()).toMatchObject({ status: 'completed', error: null, decidedAt: expect.any(Date) })
    expect(audits('project.transfer.accept')).toHaveLength(1)
    expect(audits('project.transfer.completed')).toEqual([expect.objectContaining({
      actorId: NEW, projectId: P, before: { ownerId: OLD },
      after: expect.objectContaining({ ownerId: NEW, oldOwnerRole: 'co-owner', moved: { graphNodes: 6, graphRelationships: 0, traffic: 2, schedulesPaused: 1, conversations: 1 } }),
    })])
    expect(h.invalidate).toHaveBeenCalledWith(P)
  })

  test('schedules paused: the old owner\'s wait for a confirmation; another collaborator\'s and another project\'s keep running', async () => {
    await offer()
    await accept()
    expect(rows('scanSchedule').map((s) => [s.id, s.enabled, s.pausedReason])).toEqual([
      ['sch-old', false, 'ownership_transferred'], ['sch-other', true, null], ['sch-old-2', true, null],
    ])
  })

  test('a co-owner old owner keeps their own conversations; inherited ones (a deleted author) follow the project', async () => {
    await offer()
    await accept()
    expect(rows('conversation').map((c) => [c.id, c.userId, c.formerAuthorId])).toEqual([
      ['c-old', OLD, null], ['c-inherited', NEW, 'gone-user'], ['c-collab', OTHER, null], ['c-elsewhere', OLD, null],
    ])
  })

  test('a leaving old owner loses the project; their conversations there stay with it, naming who wrote them', async () => {
    await offer({ toUserId: NEW, oldOwnerRole: 'leave', stepUpPassword: 'pw' })
    expect((await accept()).status).toBe(200)
    expect(rows('projectCollaborator').filter((c) => c.projectId === P).map((c) => c.userId)).toEqual([OTHER])
    expect(rows('conversation').map((c) => [c.id, c.userId, c.formerAuthorId, c.formerAuthorLabel])).toEqual([
      ['c-old', NEW, OLD, 'Olga Owner'], ['c-inherited', NEW, 'gone-user', 'Gone'], ['c-collab', OTHER, null, null], ['c-elsewhere', OLD, null, null],
    ])
  })

  test('catalog references cleared, Nuclei selections of the old owner included and listed for the banner', async () => {
    await offer()
    const { cleared } = await (await accept()).json()
    const p = project()
    expect(p.agentOpenaiModel).toBe('claude-opus-4-6')
    expect(p.aiPipelineModel).toBe('custom/prov-new')
    expect(p.cypherfixLlmModel).toBe('claude-opus-4-6')
    expect(p.jevProviderId).toBeNull()
    expect(p.attackSkillConfig).toEqual({ builtIn: { xss: true }, user: {} })
    expect(p.nucleiSelectedCustomTemplates).toEqual(['shared/instance.yaml'])
    expect(p.nucleiTemplates).toEqual(['cves/'])
    expect(p.cypherfixGithubToken).toBe('')
    expect(cleared).toEqual([
      { field: 'agentOpenaiModel', label: 'Agent model', values: ["Olga's OpenAI-compatible"] },
      { field: 'jevProviderId', label: 'TypeSafe Jev provider', values: ["Olga's Jev"] },
      { field: 'attackSkillConfig', label: 'Agent skills of the previous owner that were on', values: ['Olga skill A'] },
      { field: 'nucleiSelectedCustomTemplates', label: 'Nuclei custom templates selected', values: ['old/own.yaml'] },
      { field: 'nucleiTemplates', label: 'Nuclei templates', values: ['/custom-templates/old/own.yaml'] },
      { field: 'cypherfixGithubToken', label: 'CypherFix GitHub token' },
    ])
    expect(readClearedSettings(transfer().clearedSettings)).toEqual(cleared)
    // The token's value is never in the record, the answer or the audit.
    expect(JSON.stringify([cleared, rows('auditLog')])).not.toContain('ghp_')
  })

  test('the new owner sees the list until they dismiss it; nothing to re-pick shows nothing', async () => {
    await offer()
    await accept()
    const state = await (await transferStateFor(NEW, P)).json()
    expect(state).toMatchObject({ role: 'owner', offer: null, cleared: { project: { id: P }, from: { id: OLD } } })
    expect(state.cleared.cleared).toHaveLength(6)
    expect((await transfersForAccount(NEW)).cleared).toHaveLength(1)
    const auth = { ...ownerAuth(NEW), access: { project: { id: P, userId: NEW }, level: 'owner', via: 'owner' } } as unknown as PermissionContext
    expect(await (await acknowledgeCleared(auth)).json()).toEqual({ acknowledged: 1 })
    expect((await (await transferStateFor(NEW, P)).json()).cleared).toBeNull()
    expect((await transfersForAccount(NEW)).cleared).toEqual([])
  })

  test('the default each model column is set back to is its Prisma default', () => {
    const schema = readFileSync(path.resolve(__dirname, '../../../prisma/schema.prisma'), 'utf8')
    for (const column of MODEL_COLUMNS) {
      const line = schema.split('\n').find((l) => new RegExp(`^\\s+${column.field}\\s`).test(l))!
      expect([column.field, line.match(/@default\("([^"]*)"\)/)?.[1]]).toEqual([column.field, column.reset])
    }
  })

  test('the access the move reduced goes through the revocation path once it committed', async () => {
    await offer()
    await accept()
    // The old owner stays as a co-owner whose run toggles wait for the new owner's consent; the other
    // collaborator lost the consent their toggles spent; the new owner is never named.
    expect(h.reduced.mock.calls).toEqual([
      [P, OLD, 'share_reduced', { ownerId: NEW }],
      [P, OTHER, 'consent_withdrawn', { ownerId: NEW }],
    ])
  })

  test('a leaving owner: share_left; no consent to clear: nobody else is touched; a failed move calls nothing', async () => {
    rows('projectAccessPolicy')[0].ownerCredentialConsentAt = null
    await offer({ toUserId: NEW, oldOwnerRole: 'leave', stepUpPassword: 'pw' })
    h.state.failNextWrite = 'conversation'
    await accept()
    expect(h.reduced).not.toHaveBeenCalled()
    await accept()
    expect(h.reduced.mock.calls).toEqual([[P, OLD, 'share_left', { ownerId: NEW }]])
  })

  test('notices to both people; a notice that cannot be written leaves the transfer standing', async () => {
    await offer()
    h.notice.mockRejectedValueOnce(new Error('gone'))
    expect((await accept()).status).toBe(200)
    const calls = h.notice.mock.calls as unknown as Array<[string, { direction: string; cleared: number }]>
    expect(calls.map(([user, n]) => [user, n.direction, n.cleared]))
      .toEqual([[OLD, 'given', 0], [NEW, 'received', 6]])
    expect(project().userId).toBe(NEW)
  })

  test('the recipient accepts with their own password, never while acted as; nobody else accepts', async () => {
    await offer()
    h.stepUp.mockResolvedValueOnce(Response.json({ code: 'step_up_failed' }, { status: 403 }))
    expect((await accept()).status).toBe(403)
    h.acting.mockResolvedValueOnce(Response.json({ code: 'not_while_acting_as' }, { status: 403 }))
    const acted = await accept()
    expect([acted.status, await acted.json()]).toEqual([403, { code: 'not_while_acting_as' }])
    expect((await (await accept(OTHER)).json()).code).toBe('no_transfer_offer')
    expect((await accept('stranger')).status).toBe(404)
    expect(project().userId).toBe(OLD)
    expect(h.state.retenantCalls).toEqual([])
  })

  test('a recipient whose share ended before accepting gets nothing', async () => {
    await offer()
    rows('projectCollaborator')[0].expiresAt = new Date(Date.now() - 1)
    expect((await accept()).status).toBe(404)
    expect(project().userId).toBe(OLD)
  })
})

describe('accept refused with project_busy while live work runs (the offer stays open)', () => {
  test.each([
    ['a scan (the graph writers)', () => { h.writers.mockResolvedValue('a full recon scan is running') }, 'a full recon scan is running'],
    ['a triage run (the graph writers)', () => { h.writers.mockResolvedValue('a triage run is in progress') }, 'a triage run is in progress'],
    ['an agent run the agent holds', () => { h.state.liveWork = { session_ids: ['s1'], codefix_sockets: 0, triage_run: false } }, 'an agent session is running'],
    ['a CodeFix run', () => { h.state.liveWork = { session_ids: [], codefix_sockets: 1, triage_run: false } }, 'a CodeFix run is in progress'],
    ['the agent\'s triage run', () => { h.state.liveWork = { session_ids: [], codefix_sockets: 0, triage_run: true } }, 'a triage run is in progress'],
    ['a queued job', () => { rows('jobQueue').push({ id: 'job-q', projectId: P, status: 'queued' }) }, 'a queued scan is waiting to run'],
    ['an agent that cannot answer (fail closed)', () => { h.state.liveWork = null }, "the agent's live work could not be verified"],
    ['an agent answer without the CodeFix count (an older agent)', () => { h.state.liveWork = { session_ids: [], triage_run: false } }, "the agent's live work could not be verified"],
  ])('%s', async (_what, arrange, busy) => {
    await offer()
    arrange()
    const res = await accept()
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'project_busy', busy })
    expect(transfer().status).toBe('pending')
    expect(project().userId).toBe(OLD)
    expect(h.state.retenantCalls).toEqual([])
    expect(h.closeSockets).not.toHaveBeenCalled()
    expect(project().activationState).toBe('idle')
  })

  test('transferBusy is null on an idle project (a finished job does not count)', async () => {
    expect(await transferBusy(P)).toBeNull()
  })
})

describe('failures: either everywhere or nothing', () => {
  test('graph step failure leaves Postgres untouched; the offer can be accepted again', async () => {
    await offer()
    h.state.retenantFail.push({ status: 500, body: { code: 'retenant_failed', error: 'x' } })
    const res = await accept()
    expect(res.status).toBe(502)
    expect((await res.json()).code).toBe('retenant_failed')
    expect(project()).toMatchObject({ userId: OLD, agentOpenaiModel: 'custom/prov-old' })
    expect(rows('projectCollaborator').map((c) => c.userId)).toEqual([NEW, OTHER])
    expect(rows('scanSchedule')[0].enabled).toBe(true)
    expect(transfer()).toMatchObject({ status: 'failed', error: 'retenant_failed' })
    expect(audits('project.transfer.failed')).toEqual([expect.objectContaining({ after: { transferId: transfer().id, error: 'retenant_failed' } })])
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] transfer retenant_failed project=proj-1/))
    expect(project().activationState).toBe('idle')
    // Retry.
    expect((await accept()).status).toBe(200)
    expect(project().userId).toBe(NEW)
    expect(owners()).toEqual([NEW])
  })

  test('a key collision under the new owner is refused with nothing moved', async () => {
    await offer()
    h.state.retenantFail.push({ status: 409, body: { code: 'retenant_conflict', conflicts: { Domain: 1 } } })
    const res = await accept()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('retenant_conflict')
    expect(project().userId).toBe(OLD)
  })

  test('Postgres failure runs the graph back: the graph and the project as they were', async () => {
    await offer()
    h.state.failNextWrite = 'capturedHttpTransaction'
    const res = await accept()
    expect(res.status).toBe(500)
    expect((await res.json()).code).toBe('postgres_failed')
    expect(h.state.retenantCalls.map((c) => [c.from_user_id, c.to_user_id])).toEqual([[OLD, NEW], [NEW, OLD]])
    expect(owners()).toEqual([OLD])
    expect(project()).toMatchObject({ userId: OLD, agentOpenaiModel: 'custom/prov-old', cypherfixGithubToken: expect.stringMatching(/^ghp_/) })
    expect(rows('projectCollaborator').map((c) => c.userId)).toEqual([NEW, OTHER])
    expect(rows('conversation')[0].userId).toBe(OLD)
    expect(rows('projectAccessPolicy')[0].ownerCredentialConsentById).toBe(OLD)
    expect(transfer()).toMatchObject({ status: 'failed', error: 'postgres_failed' })
    expect(audits('project.transfer.completed')).toEqual([])
    expect(h.notice).not.toHaveBeenCalled()
  })

  test('a failed run back says the graph may be split; accepting again completes the transfer', async () => {
    await offer()
    h.state.failNextWrite = 'scanSchedule'
    h.state.retenantFail.push('ok', 'network')
    const res = await accept()
    expect(res.status).toBe(500)
    expect((await res.json()).code).toBe('rollback_failed')
    expect(transfer()).toMatchObject({ status: 'failed', error: 'rollback_failed' })
    expect(owners()).toEqual([NEW])
    expect(project().userId).toBe(OLD)
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/\[rbac\] transfer rollback_failed project=proj-1/))
    // Such an offer never lapses on its own, and accepting again completes it.
    vi.useFakeTimers({ now: Date.now() + 8 * DAY, toFake: ['Date'] })
    expect((await accept()).status).toBe(200)
    expect(project().userId).toBe(NEW)
    expect(owners()).toEqual([NEW])
  })

  test('the sockets not confirmed closed: nothing moves', async () => {
    await offer()
    h.closeSockets.mockResolvedValueOnce({ ok: false, reason: 'agent_unreachable' })
    const res = await accept()
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('socket_close_failed')
    expect(h.state.retenantCalls).toEqual([])
    expect(project().userId).toBe(OLD)
    expect(transfer()).toMatchObject({ status: 'failed', error: 'socket_close_failed' })
  })

  test('the recipient losing the share during the move rolls Postgres back and runs the graph back', async () => {
    await offer()
    const orig = (db.projectTransfer as { updateMany: (a: unknown) => Promise<{ count: number }> }).updateMany
    // Revoke the share right after the attempt starts (status in_progress).
    const spy = vi.spyOn(db.projectTransfer as { updateMany: (a: never) => Promise<{ count: number }> }, 'updateMany').mockImplementation(async (a: never) => {
      const out = await orig(a)
      if ((a as { data: { status?: string } }).data.status === 'in_progress') rows('projectCollaborator')[0].expiresAt = new Date(Date.now() - 1)
      return out
    })
    const res = await accept()
    spy.mockRestore()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('recipient_not_collaborator')
    expect(project().userId).toBe(OLD)
    expect(owners()).toEqual([OLD])
  })
})

describe('two accepts make one transfer; the lock refuses meanwhile', () => {
  test('two accepts at once: one transfer, the other 409, the graph moved once', async () => {
    await offer()
    const [a, b] = await Promise.all([accept(), accept()])
    expect([a.status, b.status].sort()).toEqual([200, 409])
    const refused = [a, b].find((r) => r.status === 409)!
    expect(['project_transfer_in_progress', 'no_transfer_offer']).toContain((await refused.json()).code)
    expect(h.state.retenantCalls).toHaveLength(1)
    expect(audits('project.transfer.completed')).toHaveLength(1)
    // The same accept later finds no offer.
    expect((await (await accept()).json()).code).toBe('no_transfer_offer')
  })

  test('another holder of the project lock (an activation) refuses the accept as busy', async () => {
    await offer()
    Object.assign(project(), { activationState: 'activating', activationStartedAt: new Date() })
    const res = await accept()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('project_busy')
    expect(transfer().status).toBe('pending')
  })
})

describe('decline, cancel, expire', () => {
  test('the recipient declines: declined, audited, nothing moves', async () => {
    await offer()
    const res = await declineTransfer(identity(NEW), P)
    expect(await res.json()).toEqual({ withdrawn: true, status: 'declined' })
    expect(transfer()).toMatchObject({ status: 'declined', decidedAt: expect.any(Date) })
    expect(audits('project.transfer.decline')).toEqual([expect.objectContaining({ actorId: NEW, targetId: NEW })])
    expect((await (await accept()).json()).code).toBe('no_transfer_offer')
    expect((await (await declineTransfer(identity(OTHER), P)).json()).code).toBe('no_transfer_offer')
  })

  test('the owner cancels: cancelled, audited; a new offer can be made', async () => {
    await offer()
    const res = await cancelTransfer(ownerAuth())
    expect(await res.json()).toEqual({ withdrawn: true, status: 'cancelled' })
    expect(audits('project.transfer.cancel')).toEqual([expect.objectContaining({ actorId: OLD })])
    expect((await offer({ toUserId: OTHER, oldOwnerRole: 'leave', stepUpPassword: 'pw' })).status).toBe(201)
  })

  test('an offer lapses after 7 days: expired, audited, refused, no longer listed', async () => {
    await offer()
    vi.useFakeTimers({ now: Date.now() + TRANSFER_OFFER_DAYS * DAY + 1000, toFake: ['Date'] })
    expect((await (await accept()).json()).code).toBe('no_transfer_offer')
    expect(transfer().status).toBe('expired')
    expect(audits('project.transfer.expired')).toEqual([expect.objectContaining({ actorId: null, source: 'system' })])
    expect(await transfersForAccount(NEW)).toEqual({ incoming: [], outgoing: [], cleared: [] })
    expect(project().userId).toBe(OLD)
  })

  test('cancelling an attempt whose graph may have moved runs it back first', async () => {
    await offer()
    // The lost answer: the agent did move the graph.
    h.state.retenantFail.push('moved-network')
    await accept()
    expect(transfer()).toMatchObject({ status: 'failed', error: 'agent_unreachable' })
    expect(owners()).toEqual([NEW])
    expect((await (await cancelTransfer(ownerAuth())).json()).status).toBe('cancelled')
    expect(h.state.retenantCalls.at(-1)).toMatchObject({ from_user_id: NEW, to_user_id: OLD, lockHeld: 'transfer_split' })
    expect(owners()).toEqual([OLD])
  })

  test('a run back that fails keeps the offer open and the project held, and says so', async () => {
    await offer()
    h.state.retenantFail.push('network')
    await accept()
    h.state.retenantFail.push({ status: 503, body: { code: 'graph_unavailable' } })
    const res = await declineTransfer(identity(NEW), P)
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ code: 'run_back_failed', cause: 'graph_unavailable' })
    expect(transfer().status).toBe('failed')
    expect(project().activationState).toBe('transfer_split')
  })
})

describe('what each person is shown', () => {
  test('the owner and the recipient see the offer; another collaborator sees nothing; a stranger gets 404', async () => {
    await offer()
    expect((await (await transferStateFor(OLD, P)).json())).toMatchObject({ role: 'owner', offer: { status: 'pending', to: { id: NEW } } })
    expect((await (await transferStateFor(NEW, P)).json())).toMatchObject({ role: 'recipient', offer: { from: { id: OLD } } })
    expect((await (await transferStateFor(OTHER, P)).json())).toEqual({ role: 'none', offer: null, cleared: null })
    expect((await transferStateFor('stranger', P)).status).toBe(404)
  })

  test('the banner feed: incoming for the recipient, outgoing for the owner; a project gone ends its offer', async () => {
    await offer()
    expect((await transfersForAccount(NEW)).incoming.map((o) => o.project.name)).toEqual(['Client X'])
    expect((await transfersForAccount(OLD)).outgoing.map((o) => o.to.id)).toEqual([NEW])
    expect((await transfersForAccount(OTHER))).toEqual({ incoming: [], outgoing: [], cleared: [] })
    // The schema cascades the offer with its project (cascade.test.ts); a reader never shows a project that is gone.
    h.state.tables.project = rows('project').filter((p) => p.id !== P)
    expect(await transfersForAccount(NEW)).toEqual({ incoming: [], outgoing: [], cleared: [] })
  })
})

// Review of 5.12 (findings 1, 2, 4, 5, 6): once the graph move started the project may sit partly under each owner.
// The project then stays held (split hold) until the move completes (inside the Postgres move) or is run back; no TTL
// frees it, so no writer resumes under the old owner and creates twins that would block both ways out.
describe('a graph that may be split keeps the project held until completed or run back (review of 5.12)', () => {
  const graphHold = async () => (await import('@/lib/activationLock')).graphHold(P)

  test('the agent restarts mid-move: half the nodes moved, the project stays held days later, re-accept completes', async () => {
    await offer()
    h.state.retenantFail.push('partial-network')
    const res = await accept()
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ code: 'agent_unreachable', graphMayBeSplit: true })
    expect(owners()).toEqual([OLD, NEW].sort())
    expect(project()).toMatchObject({ userId: OLD, activationState: 'transfer_split', activationStartedAt: null })
    vi.useFakeTimers({ now: Date.now() + 8 * DAY, toFake: ['Date'] })
    // Every writer asks the lock: refused with project_transfer_in_progress, however old the hold.
    expect(await graphHold()).toBe('transferring')
    expect(transfer()).toMatchObject({ status: 'failed', error: 'agent_unreachable' })
    expect((await transfersForAccount(NEW)).incoming).toEqual([expect.objectContaining({ status: 'failed', graphMayBeSplit: true })])
    expect((await (await transferStateFor(OLD, P)).json()).offer).toMatchObject({ graphMayBeSplit: true })
    const done = await accept()
    expect(done.status).toBe(200)
    expect(owners()).toEqual([NEW])
    expect(project()).toMatchObject({ userId: NEW, activationState: 'idle', activationVersionId: null })
    expect(audits('project.transfer.accept').at(-1)).toMatchObject({ before: expect.objectContaining({ graphMayBeSplit: true }) })
  })

  test('or the owner cancels: the run back waits for live work, then the graph is whole under the owner and the hold ends', async () => {
    await offer()
    h.state.retenantFail.push('partial-network')
    await accept()
    h.writers.mockResolvedValueOnce('a full recon scan is running')
    const busy = await cancelTransfer(ownerAuth())
    expect(busy.status).toBe(409)
    expect((await busy.json()).code).toBe('project_busy')
    expect(project().activationState).toBe('transfer_split')
    expect(transfer().status).toBe('failed')
    expect(await (await cancelTransfer(ownerAuth())).json()).toEqual({ withdrawn: true, status: 'cancelled' })
    expect(owners()).toEqual([OLD])
    expect(project()).toMatchObject({ userId: OLD, activationState: 'idle', activationVersionId: null })
    expect(audits('project.transfer.cancel')[0]).toMatchObject({ before: expect.objectContaining({ graphRunBack: true }) })
  })

  test('the split marker survives retries that fail with a clean code; the offer never lapses; a decline runs it back', async () => {
    await offer()
    h.state.retenantFail.push('rollback-failed')
    expect(await (await accept()).json()).toMatchObject({ code: 'retenant_rollback_failed', graphMayBeSplit: true })
    for (const [code, status] of [['graph_unavailable', 503], ['retenant_conflict', 409], ['project_busy', 409], ['retenant_failed', 500]] as const) {
      h.state.retenantFail.push({ status, body: { code } })
      const res = await accept()
      expect([code, await res.json()]).toEqual([code, expect.objectContaining({ code, graphMayBeSplit: true })])
      expect(project().activationState).toBe('transfer_split')
      expect(transfer()).toMatchObject({ status: 'failed', error: code })
    }
    h.closeSockets.mockResolvedValueOnce({ ok: false, reason: 'agent_unreachable' })
    expect(await (await accept()).json()).toMatchObject({ code: 'socket_close_failed', graphMayBeSplit: true })
    vi.useFakeTimers({ now: Date.now() + 8 * DAY, toFake: ['Date'] })
    expect((await transfersForAccount(NEW)).incoming).toHaveLength(1)
    expect(transfer().status).toBe('failed')
    expect(await (await declineTransfer(identity(NEW), P)).json()).toEqual({ withdrawn: true, status: 'declined' })
    expect(owners()).toEqual([OLD])
    expect(project().activationState).toBe('idle')
  })

  test('a clean failure of a first attempt ends the hold at once (nothing moved)', async () => {
    await offer()
    h.state.retenantFail.push({ status: 503, body: { code: 'graph_unavailable' } })
    expect(await (await accept()).json()).toMatchObject({ code: 'graph_unavailable' })
    expect(project().activationState).toBe('idle')
    expect((await (await transferStateFor(OLD, P)).json()).offer).toMatchObject({ status: 'failed', graphMayBeSplit: false })
  })

  test('an attempt a crashed copy left mid-move (heartbeat a TTL old, never parked) is resumed by the next accept', async () => {
    await offer()
    const t = transfer()
    t.status = 'in_progress'
    Object.assign(project(), { activationState: 'transfer_split', activationVersionId: `transfer:${t.id}`, activationStartedAt: new Date(Date.now() - 16 * 60 * 1000) })
    for (const n of h.state.graph.get(P)!.slice(0, 3)) n.owner = NEW
    expect((await accept()).status).toBe(200)
    expect(owners()).toEqual([NEW])
    expect(project()).toMatchObject({ userId: NEW, activationState: 'idle' })
  })

  test('a live attempt elsewhere (fresh heartbeat on the split hold) refuses a second accept and a cancel', async () => {
    await offer()
    const t = transfer()
    t.status = 'in_progress'
    Object.assign(project(), { activationState: 'transfer_split', activationVersionId: `transfer:${t.id}`, activationStartedAt: new Date() })
    expect((await (await accept()).json()).code).toBe('project_transfer_in_progress')
    expect((await (await cancelTransfer(ownerAuth())).json()).code).toBe('project_transfer_in_progress')
    expect(h.state.retenantCalls).toEqual([])
  })

  test('an attempt a crashed copy left before the graph moved: once its lock is stale a cancel ends it, no run back', async () => {
    await offer()
    const t = transfer()
    t.status = 'in_progress'
    Object.assign(project(), { activationState: 'transferring', activationVersionId: `transfer:${t.id}`, activationStartedAt: new Date(Date.now() - 16 * 60 * 1000) })
    expect(await (await cancelTransfer(ownerAuth())).json()).toEqual({ withdrawn: true, status: 'cancelled' })
    expect(h.state.retenantCalls).toEqual([])
    expect(project().activationState).toBe('idle')
  })

  test('a cancel or decline while an accept runs answers project_transfer_in_progress and changes nothing', async () => {
    await offer()
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    h.closeSockets.mockImplementationOnce(async () => { await gate; return { ok: true, closed: 0, stoppedRuns: 0 } })
    const accepting = accept()
    await vi.waitFor(() => expect(transfer().status).toBe('in_progress'))
    for (const res of [await cancelTransfer(ownerAuth()), await declineTransfer(identity(NEW), P)]) {
      expect(res.status).toBe(409)
      expect((await res.json()).code).toBe('project_transfer_in_progress')
    }
    release()
    expect((await accepting).status).toBe(200)
    expect(transfer().status).toBe('completed')
    expect(audits('project.transfer.cancel')).toEqual([])
  })

  test('a settings write landing inside the move aborts it (updatedAt compare-and-swap): run back, the retry completes', async () => {
    await offer()
    h.state.beforeProjectUpdate = () => { project().updatedAt = new Date(Date.now() + 99_999) }
    const res = await accept()
    expect(await res.json()).toMatchObject({ code: 'project_changed' })
    expect(owners()).toEqual([OLD])
    expect(project()).toMatchObject({ userId: OLD, activationState: 'idle' })
    expect(transfer()).toMatchObject({ status: 'failed', error: 'project_changed' })
    expect((await accept()).status).toBe(200)
    expect(project().userId).toBe(NEW)
  })
})

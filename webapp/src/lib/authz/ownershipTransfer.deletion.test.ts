/**
 * The deletion plan's transfers (step 5.13; SH-17; lib/authz/ownershipTransfer.ts): the admin deleting an
 * account offers each of its shared projects to a collaborator, who accepts it as any offer; Root forces
 * one without the acceptance (audited `project.transfer.forced`, the offer keeps `forced`, both people
 * get the transfer notice); the admin withdraws an offer. The owner leaves with the account, so the old
 * owner's role is always `leave`. A forced transfer goes through the acceptance's own path: refused while
 * work runs (before any offer is made), the graph first, then one Postgres transaction.
 *
 * Over the in-memory deletionDb (transactions roll back), a double of the agent (its live-work answer and
 * the graph re-tenant), of the project lock and of the notices; the route's checks (users:delete, the
 * account owns the project, the passwords) are the route test's.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/ownershipTransfer.deletion.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown,
  graphOwner: new Map<string, string>(),
  lock: new Map<string, string>(),
  liveWork: { session_ids: [] as string[], codefix_sockets: 0, triage_run: false },
  retenantCalls: [] as Array<Record<string, unknown>>,
  writers: vi.fn(async (): Promise<string | null> => null),
  closeSockets: vi.fn(async () => ({ ok: true, closed: 1, stoppedRuns: 0 })),
  notice: vi.fn(async () => undefined),
  reduced: vi.fn(async () => ({ sockets: { closed: 0 }, failed: [] })),
}))

vi.mock('@/lib/prisma', async () => {
  const { createDeletionDb } = await import('./__testing__/deletionDb')
  h.db = createDeletionDb()
  return { default: h.db }
})
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: async (url: string, init: { body?: string } = {}) => {
    if (url.startsWith('/agent-sessions/project-work')) return new Response(JSON.stringify(h.liveWork), { status: 200 })
    if (url === '/graph/retenant') {
      const body = JSON.parse(init.body ?? '{}')
      h.retenantCalls.push(body)
      if (h.graphOwner.get(body.project_id) === body.from_user_id) h.graphOwner.set(body.project_id, body.to_user_id)
      return new Response(JSON.stringify({ total_nodes: 12, relationships: 3 }), { status: 200 })
    }
    throw new Error(`unexpected agent call ${url}`)
  },
}))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: () => h.closeSockets() }))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: () => h.writers() }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: () => undefined }))
vi.mock('@/lib/activationLock', () => ({
  acquireTransferLock: async (projectId: string, _transferId: string, ownerId: string) => {
    const db = h.db as import('./__testing__/deletionDb').DeletionDb
    const project = db.rows('project').find((p) => p.id === projectId)
    if (!project || project.userId !== ownerId || h.lock.has(projectId)) return false
    h.lock.set(projectId, 'transferring')
    return true
  },
  refreshTransferLock: async () => undefined,
  releaseTransferLock: async (projectId: string) => { h.lock.delete(projectId) },
  graphHold: async (projectId: string) => h.lock.get(projectId) ?? null,
}))
vi.mock('./revocation', () => ({ onAccessReduced: (...a: unknown[]) => h.reduced(...(a as [])) }))
vi.mock('./accountNotices', async (orig) => ({
  ...(await orig<typeof import('./accountNotices')>()),
  appendNotice: (...a: unknown[]) => h.notice(...(a as [])),
}))
vi.mock('./stepUp', () => ({ requireStepUp: async () => null }))
vi.mock('./actAsRefusals', () => ({ refuseWhileActingAs: async () => null }))
vi.mock('./projectAccess', async (orig) => ({
  ...(await orig<typeof import('./projectAccess')>()),
  projectAccess: async ({ userId }: { userId: string }, projectId: string) => {
    const db = h.db as import('./__testing__/deletionDb').DeletionDb
    const project = db.rows('project').find((p) => p.id === projectId)
    if (!project) return null
    if (project.userId === userId) return { project: { id: projectId, userId }, level: 'owner', toggles: {}, via: 'owner' }
    const share = db.rows('projectCollaborator').find((c) => c.projectId === projectId && c.userId === userId)
    return share ? { project: { id: projectId, userId: project.userId }, level: share.access, toggles: {}, via: 'share' } : null
  },
}))

import type { DeletionDb } from './__testing__/deletionDb'
import type { AuthzIdentity } from '@/lib/session'
import {
  acceptTransfer, cancelForDeletion, forceTransferForDeletion, offerForDeletion, openOffersOf, FORCE_PERMISSION,
} from './ownershipTransfer'

const db = () => h.db as DeletionDb
const ADMIN = 'admin-1'
const GONE = 'user-being-deleted'
const BOB = 'user-bob'
const CARLA = 'user-carla'
const P = 'proj-shared'
const admin = { session: { userId: ADMIN, role: 'admin' } } as unknown as Pick<AuthzIdentity, 'session'>
const identity = (userId: string): AuthzIdentity => ({
  session: { userId, role: 'standard' } as unknown as AuthzIdentity['session'],
  principal: { id: userId } as AuthzIdentity['principal'], actingAs: null,
})
const audits = (action: string) => db().rows('auditLog').filter((r) => r.action === action)
const transfers = () => db().rows('projectTransfer')
const project = () => db().rows('project').find((p) => p.id === P)!

beforeEach(() => {
  db().seed({
    user: [
      { id: ADMIN, name: 'Ada', email: 'ada@e2e.local', status: 'active' },
      { id: GONE, name: 'Gina', email: 'gina@e2e.local', status: 'active' },
      { id: BOB, name: 'Bob', email: 'bob@e2e.local', status: 'active' },
      { id: CARLA, name: 'Carla', email: 'carla@e2e.local', status: 'active' },
    ],
    project: [
      { id: P, userId: GONE, name: 'Client shared', attackSkillConfig: null, jevProviderId: null, agentOpenaiModel: 'claude-opus-4-6',
        aiPipelineModel: 'claude-opus-4-6', cypherfixLlmModel: '', cypherfixGithubToken: '', nucleiSelectedCustomTemplates: [],
        nucleiTemplates: [], nucleiCustomTemplates: [] },
    ],
    projectCollaborator: [
      { projectId: P, userId: BOB, access: 'write', expiresAt: null },
      { projectId: P, userId: CARLA, access: 'read', expiresAt: null },
    ],
    projectTransfer: [],
    capturedHttpTransaction: [{ id: 'tx-1', projectId: P, userId: GONE }],
    scanSchedule: [],
    projectAccessPolicy: [],
    projectAuthProfile: [],
    conversation: [],
    jobQueue: [],
    auditLog: [],
  })
  h.graphOwner = new Map([[P, GONE]])
  h.lock = new Map()
  h.liveWork = { session_ids: [], codefix_sockets: 0, triage_run: false }
  h.retenantCalls = []
  for (const f of [h.writers, h.closeSockets, h.notice, h.reduced]) f.mockClear()
  h.writers.mockResolvedValue(null)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('the deletion plan offers a project to a collaborator, who accepts it', () => {
  test('a pending offer, the old owner leaving; audited with the admin as actor and the account named', async () => {
    const res = await offerForDeletion(admin, P, GONE, BOB)
    expect(res.status).toBe(201)
    const { offer } = await res.json()
    expect(offer).toMatchObject({ project: { id: P, name: 'Client shared' }, from: { id: GONE }, to: { id: BOB }, oldOwnerRole: 'leave', status: 'pending' })
    expect(transfers()).toEqual([expect.objectContaining({ fromUserId: GONE, toUserId: BOB, oldOwnerRole: 'leave', status: 'pending' })])
    expect(audits('project.transfer.offer')).toEqual([
      expect.objectContaining({ actorId: ADMIN, projectId: P, targetId: BOB, permission: 'users:delete', after: expect.objectContaining({ accountDeleted: GONE }) }),
    ])
    expect(project().userId).toBe(GONE)
  })

  test('the recipient accepts it as any offer: the project and its graph are theirs, the old owner keeps no share', async () => {
    await offerForDeletion(admin, P, GONE, BOB)
    const res = await acceptTransfer(new Request('http://x', { method: 'POST' }), identity(BOB), P, 'pw')
    expect(res.status).toBe(200)
    expect(project().userId).toBe(BOB)
    expect(h.graphOwner.get(P)).toBe(BOB)
    expect(db().rows('projectCollaborator').map((c) => c.userId)).toEqual([CARLA])
    expect(audits('project.transfer.accept')).toEqual([expect.objectContaining({ actorId: BOB })])
  })

  test('refused: the account itself, someone without a share, a second open offer', async () => {
    expect((await offerForDeletion(admin, P, GONE, GONE)).status).toBe(400)
    const stranger = await offerForDeletion(admin, P, GONE, ADMIN)
    expect([stranger.status, (await stranger.json()).code]).toEqual([409, 'recipient_not_collaborator'])
    expect((await offerForDeletion(admin, P, GONE, BOB)).status).toBe(201)
    const second = await offerForDeletion(admin, P, GONE, CARLA)
    expect([second.status, (await second.json()).code]).toEqual([409, 'transfer_already_offered'])
    expect(transfers()).toHaveLength(1)
  })

  test('openOffersOf lists the open offer of each project that has one', async () => {
    expect((await openOffersOf([P])).size).toBe(0)
    await offerForDeletion(admin, P, GONE, BOB)
    const offers = await openOffersOf([P, 'proj-none'])
    expect([...offers.keys()]).toEqual([P])
    expect(offers.get(P)).toMatchObject({ to: { id: BOB, name: 'Bob' }, status: 'pending' })
  })

  test('the admin withdraws it: cancelled, audited with the admin as actor', async () => {
    await offerForDeletion(admin, P, GONE, BOB)
    const res = await cancelForDeletion(admin, P)
    expect([res.status, await res.json()]).toEqual([200, { withdrawn: true, status: 'cancelled' }])
    expect(transfers()[0]).toMatchObject({ status: 'cancelled' })
    expect(audits('project.transfer.cancel')).toEqual([expect.objectContaining({ actorId: ADMIN, targetId: BOB })])
    expect((await cancelForDeletion(admin, P)).status).toBe(409)
  })
})

describe('a forced transfer (projects:administer): without the acceptance, through the acceptance\'s own path', () => {
  test('completes now: graph and Postgres moved, audited forced then completed, the row keeps forced, both notified', async () => {
    const res = await forceTransferForDeletion(admin, P, GONE, BOB)
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ transferred: { projectId: P, from: GONE, to: BOB, oldOwnerRole: 'leave' } })
    expect(project().userId).toBe(BOB)
    expect(h.graphOwner.get(P)).toBe(BOB)
    expect(db().rows('capturedHttpTransaction')[0]).toMatchObject({ userId: BOB })
    expect(transfers()).toEqual([expect.objectContaining({ status: 'completed', forced: true })])
    expect(audits('project.transfer.forced')).toEqual([
      expect.objectContaining({ actorId: ADMIN, permission: FORCE_PERMISSION, targetId: BOB, after: { status: 'in_progress', forced: true } }),
    ])
    expect(audits('project.transfer.completed')).toEqual([expect.objectContaining({ actorId: ADMIN })])
    expect(audits('project.transfer.accept')).toEqual([])
    expect(h.notice).toHaveBeenCalledTimes(2)
    expect(h.reduced).toHaveBeenCalledWith(P, GONE, 'share_left', { ownerId: BOB })
    expect(h.lock.size).toBe(0)
  })

  test("forces the open offer to the same collaborator; refuses while one is open to someone else", async () => {
    await offerForDeletion(admin, P, GONE, CARLA)
    const other = await forceTransferForDeletion(admin, P, GONE, BOB)
    expect([other.status, (await other.json()).code]).toEqual([409, 'transfer_already_offered'])
    expect(project().userId).toBe(GONE)
    expect((await forceTransferForDeletion(admin, P, GONE, CARLA)).status).toBe(200)
    expect(transfers()).toEqual([expect.objectContaining({ toUserId: CARLA, status: 'completed', forced: true })])
  })

  test('refused with project_busy while work runs: no offer made, nothing moved', async () => {
    h.writers.mockResolvedValue('a full recon scan is running')
    const res = await forceTransferForDeletion(admin, P, GONE, BOB)
    expect([res.status, (await res.json()).code]).toEqual([409, 'project_busy'])
    expect(transfers()).toEqual([])
    expect(h.retenantCalls).toEqual([])
    expect(project().userId).toBe(GONE)
  })

  test('refused for someone without a share, before anything moves', async () => {
    const res = await forceTransferForDeletion(admin, P, GONE, ADMIN)
    expect([res.status, (await res.json()).code]).toEqual([409, 'recipient_not_collaborator'])
    expect(h.retenantCalls).toEqual([])
  })
})

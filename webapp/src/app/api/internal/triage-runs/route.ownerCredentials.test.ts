/**
 * POST /api/internal/triage-runs (step 5.6, C1; GV-12): a collaborator's triage run spends the
 * project owner's model and keys, so it starts only after a `credits.used` row naming the
 * collaborator is written (no row, no run); the owner's run writes none. A run the agent starts for
 * an admin acting as the actor is judged as can() judged its ticket (`actingAs`, D-22).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  refuse: vi.fn(),
  audit: [] as Array<Record<string, unknown>>,
  auditFails: false,
  runCreate: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ isInternalRequest: () => true }))
vi.mock('@/lib/triageRun', () => ({ refuseTriageStart: (...a: unknown[]) => h.refuse(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async ({ where }: { where: { id: string } }) => (where.id === 'P1' ? { userId: 'owner-1' } : null) },
    triageRun: { create: (...a: unknown[]) => h.runCreate(...a) },
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

const start = (body: Record<string, unknown>) => POST(new NextRequest('http://x/api/internal/triage-runs', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
}))
const spends = () => h.audit.filter((r) => r.action === 'credits.used')

beforeEach(() => {
  h.refuse.mockReset().mockResolvedValue(null)
  h.audit = []
  h.auditFails = false
  h.runCreate.mockReset().mockResolvedValue({ id: 'run-1', startedAt: new Date('2026-11-13T12:00:00Z') })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('a triage run spends the owner\'s credentials', () => {
  test('spend attributed to the actor: a collaborator\'s run writes credits.used first, then starts', async () => {
    let rowsAtCreate = -1
    h.runCreate.mockImplementationOnce(async () => {
      rowsAtCreate = spends().length
      return { id: 'run-1', startedAt: new Date() }
    })
    const res = await start({ projectId: 'P1', actorUserId: 'collab-1', model: 'm' })
    expect(res.status).toBe(201)
    expect(rowsAtCreate).toBe(1)
    expect(spends()).toEqual([expect.objectContaining({
      actorId: 'collab-1', projectId: 'P1', permission: 'triage:run', after: { feature: 'triage_run', actor: 'collab-1' }, source: 'system',
    })])
    expect(h.refuse).toHaveBeenCalledWith('P1', 'collab-1', { actingAs: false })
  })

  test("the owner's run writes no credits.used row", async () => {
    expect((await start({ projectId: 'P1', actorUserId: 'owner-1', model: 'm' })).status).toBe(201)
    expect(spends()).toEqual([])
  })

  test('no credits.used row, no run: 503 spend_not_recorded and nothing created', async () => {
    h.auditFails = true
    const res = await start({ projectId: 'P1', actorUserId: 'collab-1', model: 'm' })
    expect(res.status).toBe(503)
    expect((await res.json()).code).toBe('spend_not_recorded')
    expect(h.runCreate).not.toHaveBeenCalled()
  })

  test('a run under act-as is judged with actingAs, and the row names the admin with the account acted as', async () => {
    expect((await start({ projectId: 'P1', actorUserId: 'collab-1', realActorUserId: 'admin-1', model: 'm' })).status).toBe(201)
    expect(h.refuse).toHaveBeenCalledWith('P1', 'collab-1', { actingAs: true })
    expect(spends()[0]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'collab-1', after: { actor: 'collab-1' } })
  })
})

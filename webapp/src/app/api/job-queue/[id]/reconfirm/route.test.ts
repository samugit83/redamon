/**
 * Re-confirming a held AI attack job voids its RoE confirmation: the settings it
 * was confirmed under changed, a replaced RoE among them.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ row: null as Record<string, unknown> | null, updates: [] as unknown[] }))

vi.mock('@/lib/prisma', () => ({
  default: {
    jobQueue: {
      findUnique: async () => h.row,
      update: async (a: unknown) => { h.updates.push(a); return {} },
    },
    project: { findUnique: async () => ({ id: 'p1' }) },
  },
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/jobFingerprint', () => ({ currentFingerprintFor: async () => 'new-hash' }))

import { POST } from './route'

const post = (body?: unknown) => POST(
  new NextRequest('http://x/api/job-queue/j1/reconfirm', { method: 'POST', ...(body ? { body: JSON.stringify(body) } : {}) }),
  { params: Promise.resolve({ id: 'j1' }) },
)

beforeEach(() => {
  h.updates = []
  h.row = {
    id: 'j1', projectId: 'p1', kind: 'ai_attack', status: 'needs_review', blockedCode: 'settings_changed',
    payload: { tool: 'garak', roe_confirmed: true },
  }
})

describe('reconfirm and the AI attack RoE confirmation', () => {
  test('without a fresh confirmation the flag is cleared and the job stays held', async () => {
    const res = await post()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('roe_confirmation_required')
    expect(h.updates).toEqual([{ where: { id: 'j1' }, data: { payload: { tool: 'garak', roe_confirmed: false } } }])
  })

  test('with one, it is re-queued confirmed', async () => {
    const res = await post({ roeConfirmed: true })
    expect(res.status).toBe(200)
    expect(h.updates[0]).toMatchObject({ data: { status: 'queued', settingsHash: 'new-hash', payload: { tool: 'garak', roe_confirmed: true } } })
  })

  test('another kind of job re-confirms as before', async () => {
    h.row = { ...h.row!, kind: 'full_recon', payload: { mode: 'new' } }
    const res = await post()
    expect(res.status).toBe(200)
    expect(h.updates[0]).toMatchObject({ data: { status: 'queued', payload: { mode: 'new' } } })
  })
})

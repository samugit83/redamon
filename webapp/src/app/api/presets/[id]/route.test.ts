/**
 * DELETE /api/presets/[id] from the project form's preset drawer.
 *
 * C-10: deleting a preset clears the "Preset applied" badge of every project
 * that loaded it, in the same transaction as the delete, and for the preset
 * owner's projects only. Another user's preset is refused before anything is
 * written.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  eff: vi.fn(),
  findUnique: vi.fn(),
  del: vi.fn(),
  clear: vi.fn(),
  inTransaction: false,
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.eff(),
  assertOwner: (eff: { userId: string }, owner: string) =>
    eff.userId === owner ? null : NextResponse.json({ error: 'Forbidden' }, { status: 403 }),
}))
vi.mock('@/lib/prisma', () => {
  const client = {
    userProjectPreset: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      delete: (...a: unknown[]) => h.del(...a),
    },
    $transaction: async (fn: (tx: unknown) => unknown) => {
      h.inTransaction = true
      try { return await fn(client) } finally { h.inTransaction = false }
    },
  }
  return { default: client }
})
vi.mock('@/lib/reconPresets/badges', () => ({
  clearPresetBadges: (...a: unknown[]) => h.clear(...a),
}))

import { DELETE } from './route'

const params = (id = 'up1') => ({ params: Promise.resolve({ id }) })
const req = () => new NextRequest('http://x/api/presets/up1', { method: 'DELETE' })

beforeEach(() => {
  vi.clearAllMocks()
  h.eff.mockResolvedValue({ userId: 'owner' })
  h.findUnique.mockResolvedValue({ id: 'up1', userId: 'owner', name: 'Mine' })
  h.del.mockResolvedValue({})
  h.clear.mockImplementation(async () => {
    expect(h.inTransaction).toBe(true)
    return 2
  })
})

describe('DELETE /api/presets/[id]', () => {
  test('deletes the preset and clears its badges in one transaction', async () => {
    const res = await DELETE(req(), params())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ success: true, badgesCleared: 2 })
    expect(h.del).toHaveBeenCalledWith({ where: { id: 'up1' } })
    expect(h.clear.mock.calls[0].slice(1)).toEqual(['owner', 'up1'])
  })

  test('another user\'s preset is refused, and nothing is deleted or cleared', async () => {
    h.findUnique.mockResolvedValue({ id: 'up1', userId: 'someone-else', name: 'Theirs' })
    const res = await DELETE(req(), params())
    expect(res.status).toBe(403)
    expect(h.del).not.toHaveBeenCalled()
    expect(h.clear).not.toHaveBeenCalled()
  })

  test('a missing preset is a 404', async () => {
    h.findUnique.mockResolvedValue(null)
    expect((await DELETE(req(), params())).status).toBe(404)
    expect(h.clear).not.toHaveBeenCalled()
  })
})

/**
 * PUT /api/users/[id]/settings persists extra keys for every Key Rotation tool.
 *
 * The PUT used to loop over a private tool list that lacked wpscan,
 * securitytrails and viewdns: the page offered Key Rotation for them, the save
 * answered 200, and the rows were never written, so recon never rotated the
 * SecurityTrails and ViewDNS keys it builds rotators for.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { ROTATION_TOOL_NAMES } from '@/lib/rotationTools'

type Row = { userId: string; toolName: string; extraKeys: string; rotateEveryN: number }

const h = vi.hoisted(() => ({
  rows: new Map<string, { userId: string; toolName: string; extraKeys: string; rotateEveryN: number }>(),
}))

const rowKey = (userId: string, toolName: string) => `${userId}|${toolName}`

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: async () => null,
      upsert: async ({ create }: { create: Record<string, unknown> }) => ({ ...create }),
    },
    apiKeyRotationConfig: {
      findMany: async ({ where }: { where: { userId: string } }) =>
        [...h.rows.values()].filter(r => r.userId === where.userId),
      findUnique: async ({ where }: { where: { userId_toolName: { userId: string; toolName: string } } }) =>
        h.rows.get(rowKey(where.userId_toolName.userId, where.userId_toolName.toolName)) ?? null,
      upsert: async ({ where, create, update }: {
        where: { userId_toolName: { userId: string; toolName: string } }
        create: Row
        update: Partial<Row>
      }) => {
        const k = rowKey(where.userId_toolName.userId, where.userId_toolName.toolName)
        const next = h.rows.has(k) ? { ...h.rows.get(k)!, ...update } : { ...create }
        h.rows.set(k, next)
        return next
      },
      update: async ({ where, data }: {
        where: { userId_toolName: { userId: string; toolName: string } }
        data: Partial<Row>
      }) => {
        const k = rowKey(where.userId_toolName.userId, where.userId_toolName.toolName)
        h.rows.set(k, { ...h.rows.get(k)!, ...data })
        return h.rows.get(k)
      },
      deleteMany: async ({ where }: { where: { userId: string; toolName: string } }) => {
        h.rows.delete(rowKey(where.userId, where.toolName))
        return { count: 1 }
      },
    },
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: async () => null,
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  getSession: async () => ({ userId: 'u1', role: 'standard' }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { PUT } from './route'

const put = (body: unknown) => new NextRequest('http://x', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  h.rows.clear()
})

describe('rotation rows on PUT', () => {
  test.each(['wpscan', 'securitytrails', 'viewdns'])('%s extra keys are persisted', async tool => {
    const res = await PUT(put({ rotationConfigs: { [tool]: { extraKeys: 'extra-A\nextra-B', rotateEveryN: 4 } } }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.rows.get(rowKey('u1', tool))).toMatchObject({ extraKeys: 'extra-A\nextra-B', rotateEveryN: 4 })
    const body = await res.json()
    expect(body.rotationConfigs[tool]).toEqual({ extraKeyCount: 2, rotateEveryN: 4 })
    // Counts only on the way out, never the keys.
    expect(JSON.stringify(body)).not.toContain('extra-A')
  })

  test('every shared tool round-trips in one save', async () => {
    const rotationConfigs = Object.fromEntries(ROTATION_TOOL_NAMES.map(t => [t, { extraKeys: `k1-${t}\nk2-${t}`, rotateEveryN: 2 }]))
    const res = await PUT(put({ rotationConfigs }), params('u1'))
    expect(res.status).toBe(200)
    for (const t of ROTATION_TOOL_NAMES) {
      expect(h.rows.get(rowKey('u1', t))?.extraKeys, t).toBe(`k1-${t}\nk2-${t}`)
    }
  })

  test('a masked marker keeps the stored keys and updates only rotateEveryN', async () => {
    h.rows.set(rowKey('u1', 'viewdns'), { userId: 'u1', toolName: 'viewdns', extraKeys: 'stored-1\nstored-2', rotateEveryN: 10 })
    const res = await PUT(put({ rotationConfigs: { viewdns: { extraKeys: '••••', rotateEveryN: 5 } } }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.rows.get(rowKey('u1', 'viewdns'))).toMatchObject({ extraKeys: 'stored-1\nstored-2', rotateEveryN: 5 })
  })

  test('an empty list clears the row', async () => {
    h.rows.set(rowKey('u1', 'securitytrails'), { userId: 'u1', toolName: 'securitytrails', extraKeys: 'old', rotateEveryN: 10 })
    await PUT(put({ rotationConfigs: { securitytrails: { extraKeys: '', rotateEveryN: 10 } } }), params('u1'))
    expect(h.rows.has(rowKey('u1', 'securitytrails'))).toBe(false)
  })

  test('a tool outside the shared list is ignored, and an existing row of it is left alone', async () => {
    h.rows.set(rowKey('u1', 'censys'), { userId: 'u1', toolName: 'censys', extraKeys: 'legacy', rotateEveryN: 10 })
    const res = await PUT(put({ rotationConfigs: { censys: { extraKeys: 'new', rotateEveryN: 3 }, bogus: { extraKeys: 'x', rotateEveryN: 1 } } }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.rows.get(rowKey('u1', 'censys'))?.extraKeys).toBe('legacy')
    expect(h.rows.has(rowKey('u1', 'bogus'))).toBe(false)
    // Still reported, so the state the page shows matches what is stored.
    expect((await res.json()).rotationConfigs.censys).toEqual({ extraKeyCount: 1, rotateEveryN: 10 })
  })
})

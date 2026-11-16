/**
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { clearChoicesForResource } from './projectChoices'

describe('clearChoicesForResource', () => {
  test("forgets every project's choice for that resource, and only for it", async () => {
    h.db = createTradecraftDb()
    for (const [projectId, resourceId] of [['p1', 'r1'], ['p2', 'r1'], ['p1', 'r2']]) h.db.seed('tradecraftProjectChoice', { projectId, resourceId })
    expect(await clearChoicesForResource(h.db.prisma as never, 'r1')).toBe(2)
    expect(h.db.rows('tradecraftProjectChoice').map(c => [c.projectId, c.resourceId])).toEqual([['p1', 'r2']])
  })
})

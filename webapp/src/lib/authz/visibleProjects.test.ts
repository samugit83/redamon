/**
 * Which projects a person sees (visibleProjects.ts), the list form of projectAccess(): a project is
 * listed exactly when projectAccess() answers for it, so a list never names a project its detail
 * route answers 404 for. Owner-only, like projectAccess().
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))

import { visibleProjectIds, visibleProjectsWhere } from './visibleProjects'
import { projectAccess } from './projectAccess'

let db: FakePrisma

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  db.seed('project', [
    { id: 'p1', userId: 'u1', name: 'one', createdAt: new Date(1) },
    { id: 'p2', userId: 'u2', name: 'two', createdAt: new Date(2) },
    { id: 'p3', userId: 'u1', name: 'three', createdAt: new Date(3) },
    { id: 'p4', userId: '', name: 'blank owner', createdAt: new Date(4) },
  ])
})

describe('visibleProjectsWhere', () => {
  test("the owner's projects, as the filter the owner lists always used", () => {
    expect(visibleProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
  })

  test('carries nothing but the person', () => {
    expect(visibleProjectsWhere({ userId: 'u1', role: 'admin' } as { userId: string })).toEqual({ userId: 'u1' })
  })

  // Prisma drops an undefined filter: `{userId: undefined}` would list every account's projects.
  test.each([[''], [undefined], [null], [42]])('a person without an id (%j) sees nothing (fail closed)', async (userId) => {
    const where = visibleProjectsWhere({ userId } as unknown as { userId: string })
    expect(where).toEqual({ id: { in: [] } })
    expect(await db.project.findMany({ where })).toEqual([])
  })
})

describe('visibleProjectIds', () => {
  test("the person's projects, oldest first", async () => {
    expect(await visibleProjectIds({ userId: 'u1' })).toEqual(['p1', 'p3'])
    expect(await visibleProjectIds({ userId: 'u2' })).toEqual(['p2'])
    expect(await visibleProjectIds({ userId: 'nobody' })).toEqual([])
  })

  test('a person without an id sees nothing, not the blank-owner rows', async () => {
    expect(await visibleProjectIds({ userId: '' })).toEqual([])
  })

  test('the list and projectAccess() agree on every project', async () => {
    for (const userId of ['u1', 'u2', 'nobody']) {
      const listed = new Set(await visibleProjectIds({ userId }))
      for (const id of ['p1', 'p2', 'p3', 'p4', 'missing']) {
        expect(listed.has(id)).toBe((await projectAccess({ userId }, id)) !== null)
      }
    }
  })

  test('a failed read throws', async () => {
    h.db = { project: { findMany: async () => { throw new Error('db down') } } }
    await expect(visibleProjectIds({ userId: 'u1' })).rejects.toThrow('db down')
  })
})

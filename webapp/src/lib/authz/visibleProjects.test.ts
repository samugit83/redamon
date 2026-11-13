/**
 * Which projects a person sees (visibleProjects.ts), the list form of projectAccess(): the projects
 * they own and, with sharing in force (step 4.3), those shared with them by a live share (not
 * expired on the clock, their account active), so a list never names a project its detail route
 * answers 404 for. Oversight and break-glass open a project by its id, never a list.
 * `ownedProjectsWhere` stays the owner's projects whatever is shared (the api-usage view, T9).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))

import { ownedProjectsWhere, visibleProjectIds, visibleProjectsWhere } from './visibleProjects'
import { projectAccess } from './projectAccess'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')

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
  setFlagsForTests({})
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('visibleProjectsWhere, sharing not in force', () => {
  test("the owner's projects, as the filter the owner lists always used", async () => {
    expect(await visibleProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
  })

  test('carries nothing but the person', async () => {
    expect(await visibleProjectsWhere({ userId: 'u1', role: 'admin' } as { userId: string })).toEqual({ userId: 'u1' })
  })

  // Prisma drops an undefined filter: `{userId: undefined}` would list every account's projects.
  test.each([[''], [undefined], [null], [42]])('a person without an id (%j) sees nothing (fail closed)', async (userId) => {
    const where = await visibleProjectsWhere({ userId } as unknown as { userId: string })
    expect(where).toEqual({ id: { in: [] } })
    expect(await db.project.findMany({ where })).toEqual([])
  })
})

describe('ownedProjectsWhere', () => {
  test("the owner's projects, with sharing in force or not", () => {
    expect(ownedProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(ownedProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
  })

  test.each([[''], [undefined], [null], [42]])('a person without an id (%j) owns nothing (fail closed)', (userId) => {
    expect(ownedProjectsWhere({ userId } as unknown as { userId: string })).toEqual({ id: { in: [] } })
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

describe('owned ∪ shared, sharing in force (step 4.3)', () => {
  type Share = { projectId: string; userId: string; access: string; rawData: boolean; expiresAt: Date | null; status: string }
  const projects = [
    { id: 'p1', userId: 'u1', createdAt: new Date(1) },
    { id: 'p2', userId: 'u2', createdAt: new Date(2) },
    { id: 'p3', userId: 'u2', createdAt: new Date(3) },
    { id: 'p4', userId: 'u2', createdAt: new Date(4) },
    { id: 'p5', userId: 'u2', createdAt: new Date(5) },
  ]
  let shares: Share[] = []

  /**
   * The Prisma semantics of exactly the filter shapes visibleProjectsWhere builds, over the rows
   * above: the person's own column, `OR`, and the share relation filter with its expiry and status.
   */
  function matches(row: { id: string; userId: string }, where: Record<string, unknown>): boolean {
    return Object.entries(where).every(([key, value]) => {
      if (key === 'userId') return row.userId === value
      if (key === 'id') return ((value as { in: string[] }).in).includes(row.id)
      if (key === 'OR') return (value as Record<string, unknown>[]).some((w) => matches(row, w))
      if (key === 'collaborators') {
        const some = (value as { some: Record<string, unknown> }).some
        return shares.some((s) => s.projectId === row.id && Object.entries(some).every(([k, v]) => {
          if (k === 'userId') return s.userId === v
          if (k === 'access') return (v as { in: string[] }).in.includes(s.access)
          if (k === 'user') return s.status === (v as { status: string }).status
          if (k === 'OR') {
            return (v as Array<{ expiresAt: null | { gt: Date } }>).some((alt) =>
              alt.expiresAt === null ? s.expiresAt === null : s.expiresAt !== null && s.expiresAt.getTime() > alt.expiresAt.gt.getTime())
          }
          throw new Error(`unexpected share filter key ${k}`)
        }))
      }
      throw new Error(`unexpected filter key ${key}`)
    })
  }

  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    shares = [
      { projectId: 'p2', userId: 'u1', access: 'read', rawData: false, expiresAt: null, status: 'active' },
      { projectId: 'p3', userId: 'u1', access: 'write', rawData: true, expiresAt: new Date(NOW.getTime() + 1000), status: 'active' },
      { projectId: 'p4', userId: 'u1', access: 'read', rawData: false, expiresAt: new Date(NOW.getTime() - 1), status: 'active' },
      { projectId: 'p5', userId: 'u9', access: 'read', rawData: false, expiresAt: null, status: 'disabled' },
      { projectId: 'p5', userId: 'u1', access: 'manage', rawData: true, expiresAt: null, status: 'active' },
    ]
    h.db = {
      instanceSettings: { findUnique: async () => ({ sharingPolicy: { enabled: true } }) },
      project: {
        findMany: async ({ where }: { where: Record<string, unknown> }) =>
          projects.filter((p) => matches(p, where)).sort((a, b) => +a.createdAt - +b.createdAt).map((p) => ({ id: p.id })),
        findUnique: async ({ where }: { where: { id: string } }) => projects.find((p) => p.id === where.id) ?? null,
      },
      projectCollaborator: {
        findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
          const s = shares.find((r) => r.projectId === where.projectId_userId.projectId && r.userId === where.projectId_userId.userId)
          return s ? { access: s.access, rawData: s.rawData, expiresAt: s.expiresAt, user: { status: s.status } } : null
        },
      },
      projectBreakGlass: { findFirst: async () => null },
      // Members only here: no oversight, so the list and the detail answer the same.
      user: {
        findUnique: async ({ where }: { where: { id: string } }) => ({
          id: where.id, email: `${where.id}@example.test`, name: where.id, role: 'standard', password: 'x', createdAt: new Date(0),
          legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
          lastLoginAt: null, permissionSets: [], permissionOverrides: [],
        }),
      },
      permissionSet: { findMany: async () => [] },
    }
  })

  test('the filter: owned, or a live share of the person (unexpired on the clock, the account active)', async () => {
    expect(await visibleProjectsWhere({ userId: 'u1' })).toEqual({
      OR: [
        { userId: 'u1' },
        { collaborators: { some: { userId: 'u1', access: { in: ['read', 'write'] }, user: { status: 'active' }, OR: [{ expiresAt: null }, { expiresAt: { gt: NOW } }] } } },
      ],
    })
  })

  test('list includes shared: owned first by age, then the live shares; expired and other people\'s shares left out', async () => {
    expect(await visibleProjectIds({ userId: 'u1' })).toEqual(['p1', 'p2', 'p3'])
    expect(await visibleProjectIds({ userId: 'u9' })).toEqual([])
  })

  test('expired share disappears from the list when the clock passes it', async () => {
    setNowForTests(() => new Date(NOW.getTime() + 1000))
    expect(await visibleProjectIds({ userId: 'u1' })).toEqual(['p1', 'p2'])
  })

  test('the list and projectAccess() agree on every project, shares included', async () => {
    for (const at of [NOW, new Date(NOW.getTime() + 1000)]) {
      setNowForTests(() => at)
      for (const userId of ['u1', 'u2', 'u9', 'nobody']) {
        const listed = new Set(await visibleProjectIds({ userId }))
        for (const { id } of projects) {
          expect([at.toISOString(), userId, id, listed.has(id)]).toEqual([at.toISOString(), userId, id, (await projectAccess({ userId }, id)) !== null])
        }
      }
    }
  })

  test('a person without an id still sees nothing', async () => {
    expect(await visibleProjectsWhere({ userId: '' })).toEqual({ id: { in: [] } })
  })

  test('the policy disabled: back to owned only', async () => {
    h.db = { ...h.db, instanceSettings: { findUnique: async () => ({ sharingPolicy: { enabled: false } }) } }
    expect(await visibleProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
  })

  test('a failed policy read throws: the list never widens or narrows on a guess', async () => {
    h.db = { ...h.db, instanceSettings: { findUnique: async () => { throw new Error('db down') } } }
    await expect(visibleProjectsWhere({ userId: 'u1' })).rejects.toThrow('db down')
  })
})

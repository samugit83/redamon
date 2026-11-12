/**
 * The project layer of the policy (step 3.5; feature document §4.2, §6.1): how far a person may go
 * on one project. Owner-only in Phase 3 (Phase 4 adds shares); the person is the effective user, so
 * under act-as it is the account acted as, exactly as `getEffectiveUser` answers today.
 *
 * Prisma is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const projects = vi.hoisted(() => new Map<string, { id: string; userId: string }>())
const findUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  const row = projects.get(where.id)
  return row ? { ...row } : null
})
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (a: { where: { id: string } }) => findUnique(a) } },
}))

import { projectAccess, meetsLevel } from './projectAccess'
import { PROJECT_LEVELS } from './permissions'

beforeEach(() => {
  projects.clear()
  projects.set('P', { id: 'P', userId: 'owner-1' })
  findUnique.mockClear()
})

describe('projectAccess (owner-only in Phase 3)', () => {
  test('the owner sees the project as its owner', async () => {
    const access = await projectAccess({ userId: 'owner-1' }, 'P')
    expect(access).toEqual({ project: { id: 'P', userId: 'owner-1' }, level: 'owner' })
    expect(Object.isFrozen(access)).toBe(true)
    expect(Object.isFrozen(access!.project)).toBe(true)
  })

  test('one read by primary key, the id and the owner only', async () => {
    await projectAccess({ userId: 'owner-1' }, 'P')
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(findUnique).toHaveBeenCalledWith({ where: { id: 'P' }, select: { id: true, userId: true } })
  })

  test('anyone else does not see it: null, the same answer as a project that does not exist (anti-enumeration)', async () => {
    expect(await projectAccess({ userId: 'other' }, 'P')).toBeNull()
    expect(await projectAccess({ userId: 'other' }, 'missing')).toBeNull()
    expect(await projectAccess({ userId: 'owner-1' }, 'missing')).toBeNull()
  })

  test('no project id: null, and nothing is read', async () => {
    expect(await projectAccess({ userId: 'owner-1' }, '')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('no person: null, and nothing is read', async () => {
    expect(await projectAccess({ userId: '' }, 'P')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a failed read throws: it never reads as access', async () => {
    findUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(projectAccess({ userId: 'owner-1' }, 'P')).rejects.toMatchObject({ code: 'P1001' })
  })

  test('the owner holds every project level (§6.1: the owner can do everything)', async () => {
    const access = (await projectAccess({ userId: 'owner-1' }, 'P'))!
    for (const level of PROJECT_LEVELS) expect([level, meetsLevel(access, level)]).toEqual([level, true])
  })

  test('an access level the policy does not know meets nothing (fail closed until Phase 4 adds shares)', () => {
    const unknown = { project: { id: 'P', userId: 'owner-1' }, level: 'viewer' } as unknown as Parameters<typeof meetsLevel>[0]
    for (const level of PROJECT_LEVELS) expect(meetsLevel(unknown, level)).toBe(false)
  })
})

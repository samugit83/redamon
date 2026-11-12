/**
 * The owner check of a per-user row (step 3.6): a preset, a mute-rule preset, a conversation or a
 * user-scope override set names its owner's id, and only that account (the effective user,
 * under act-as the account acted as) may use it. Strict: nothing but an exact, non-empty match.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { ownsRow, rowOwnerFilter } from './rowOwner'
import { createFakePrisma } from '@/lib/plugins/__testing__/fakePrisma'

describe('ownsRow', () => {
  test('the owner owns the row', () => {
    expect(ownsRow({ userId: 'u1' }, 'u1')).toBe(true)
  })

  test("another account's row is not owned", () => {
    expect(ownsRow({ userId: 'u1' }, 'u2')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, 'U1')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, ' u1')).toBe(false)
  })

  test('an empty id on either side owns nothing (fail closed)', () => {
    expect(ownsRow({ userId: '' }, '')).toBe(false)
    expect(ownsRow({ userId: '' }, 'u1')).toBe(false)
    expect(ownsRow({ userId: 'u1' }, '')).toBe(false)
  })

  test('a row without an owner id owns nothing', () => {
    expect(ownsRow({ userId: 'u1' }, null)).toBe(false)
    expect(ownsRow({ userId: 'u1' }, undefined)).toBe(false)
    expect(ownsRow({ userId: 'u1' }, 42)).toBe(false)
  })
})

describe('rowOwnerFilter', () => {
  test("scopes a list query to the account's own rows", () => {
    expect(rowOwnerFilter({ userId: 'u9' })).toEqual({ userId: 'u9' })
  })

  test('carries nothing but the user id', () => {
    const subject = { userId: 'u9', role: 'admin', realUserId: 'a1' } as { userId: string }
    expect(rowOwnerFilter(subject)).toEqual({ userId: 'u9' })
  })

  // Prisma drops a filter whose value is undefined, so `{userId: undefined}` would list every
  // account's rows. A subject without an id must get a filter that matches nothing.
  test.each([[''], [undefined], [null], [42]])('a subject without an id (%j) matches no row (fail closed)', (userId) => {
    const filter = rowOwnerFilter({ userId } as unknown as { userId: string })
    expect(filter).toEqual({ userId: { in: [] } })
    const db = createFakePrisma()
    db.seed('project', [
      { id: 'p1', userId: 'u1', name: 'one' },
      { id: 'p2', userId: 'u2', name: 'two' },
      { id: 'p3', userId: '', name: 'blank owner' },
    ])
    return expect(db.project.findMany({ where: filter })).resolves.toEqual([])
  })

  test("an account's filter lists its own rows only", async () => {
    const db = createFakePrisma()
    db.seed('project', [
      { id: 'p1', userId: 'u1', name: 'one' },
      { id: 'p2', userId: 'u2', name: 'two' },
    ])
    const rows = (await db.project.findMany({ where: rowOwnerFilter({ userId: 'u1' }) })) as Array<{ id: string }>
    expect(rows.map((r) => r.id)).toEqual(['p1'])
  })
})

/**
 * The AI Navigator owner policy (plan §5.4, D3): the owner always; a share only with the owner's
 * toggle on; oversight and break-glass never; a missing row is off and a failed read throws.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { navigatorAllowedFor, writeNavigatorPolicy, navigatorCollaboratorsAllowed } from './navigatorPolicy'
import type { ProjectAccess } from './projectAccess'

vi.mock('@/lib/prisma', () => ({ default: {} }))

const access = (level: ProjectAccess['level'], via: ProjectAccess['via']): ProjectAccess => ({
  project: { id: 'P1', userId: 'owner' }, level, toggles: { rawData: false }, via,
})
function db(row: { collaboratorsAllowed: boolean } | null | 'throw') {
  const upsert = vi.fn(async () => ({}))
  return {
    upsert,
    navigatorProjectPolicy: {
      findUnique: vi.fn(async () => {
        if (row === 'throw') throw Object.assign(new Error('connection lost'), { code: 'P1001' })
        return row
      }),
      upsert,
    },
  }
}
type Db = NonNullable<Parameters<typeof navigatorAllowedFor>[1]>

describe('navigatorAllowedFor', () => {
  test('the owner, without reading the table', async () => {
    const d = db('throw')
    expect(await navigatorAllowedFor(access('owner', 'owner'), d as unknown as Db)).toBe(true)
  })

  test.each([
    [null, false],
    [{ collaboratorsAllowed: false }, false],
    [{ collaboratorsAllowed: true }, true],
  ])('a share with row %j: %s', async (row, expected) => {
    expect(await navigatorAllowedFor(access('read', 'share'), db(row) as unknown as Db)).toBe(expected)
    expect(await navigatorAllowedFor(access('write', 'share'), db(row) as unknown as Db)).toBe(expected)
  })

  test.each(['oversight', 'break_glass'] as const)('%s never, even with the toggle on', async (via) => {
    expect(await navigatorAllowedFor(access('read', via), db({ collaboratorsAllowed: true }) as unknown as Db)).toBe(false)
  })

  test('a failed read throws, never a pass', async () => {
    await expect(navigatorAllowedFor(access('read', 'share'), db('throw') as unknown as Db)).rejects.toThrow()
  })
})

describe('writeNavigatorPolicy', () => {
  test('an unchanged value writes nothing', async () => {
    const d = db({ collaboratorsAllowed: true })
    expect(await writeNavigatorPolicy(d as unknown as Db, 'P1', true, 'owner')).toBe(false)
    expect(d.upsert).not.toHaveBeenCalled()
  })

  test('a change upserts with who made it', async () => {
    const d = db(null)
    expect(await writeNavigatorPolicy(d as unknown as Db, 'P1', true, 'owner')).toBe(true)
    expect(d.upsert).toHaveBeenCalledWith(expect.objectContaining({
      where: { projectId: 'P1' },
      create: { projectId: 'P1', collaboratorsAllowed: true, updatedById: 'owner' },
    }))
  })

  test('reads off with no row', async () => {
    expect(await navigatorCollaboratorsAllowed('P1', db(null) as unknown as Db)).toBe(false)
  })
})

/**
 * Per-project choices (R-059, R-061, R-062, §6.6): a row turns a resource off in one project; a
 * save writes only what the viewer may change; a change of Enabled clears every project's choice.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import {
  MAX_TRADECRAFT_OFF, clearChoicesForResource, enabledImpact, offIdsForProject, parseTradecraftOff, writeProjectChoices,
} from './projectChoices'

const OWNER = 'owner-1'
const OWNER_VIEW = { personId: OWNER, actorId: null }
const COLLAB_VIEW = { personId: 'collab-1', actorId: null }
const ACTING_VIEW = { personId: OWNER, actorId: 'admin-1' }

const off = (projectId = 'p1') => h.db.rows('tradecraftProjectChoice', { projectId }).map(c => c.resourceId).sort()
const tx = () => h.db.prisma as never

beforeEach(() => {
  h.db = createTradecraftDb()
  for (const [id, enabled, hasLogin] of [['r1', true, false], ['r2', true, false], ['r3', false, false], ['r4', true, true]] as const) {
    h.db.seed('userTradecraftResource', { id, userId: OWNER, name: id, slug: id, url: `https://${id}.tc-fixture.test/`, enabled, hasLogin })
  }
  h.db.seed('userTradecraftResource', { id: 'foreign', userId: 'someone-else', name: 'f', slug: 'f', url: 'https://f.tc-fixture.test/' })
})

describe('clearChoicesForResource', () => {
  test("forgets every project's choice for that resource, and only for it", async () => {
    for (const [projectId, resourceId] of [['p1', 'r1'], ['p2', 'r1'], ['p1', 'r2']]) h.db.seed('tradecraftProjectChoice', { projectId, resourceId })
    expect(await clearChoicesForResource(tx(), 'r1')).toBe(2)
    expect(h.db.rows('tradecraftProjectChoice').map(c => [c.projectId, c.resourceId])).toEqual([['p1', 'r2']])
  })
})

describe('writeProjectChoices', () => {
  test('missing_row_means_on: nothing turned off writes no row, and an empty list turns every changeable one back on', async () => {
    expect(await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: [], viewer: OWNER_VIEW })).toEqual([])
    expect(h.db.rows('tradecraftProjectChoice')).toEqual([])
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r1', 'r2'], viewer: OWNER_VIEW })
    expect(off()).toEqual(['r1', 'r2'])
    expect(await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r2'], viewer: OWNER_VIEW })).toEqual(['r2'])
    expect(off()).toEqual(['r2'])
  })

  test('drops_foreign_ids: another account\'s resource and an unknown id write nothing', async () => {
    expect(await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['foreign', 'ghost', 'r1'], viewer: OWNER_VIEW })).toEqual(['r1'])
    expect(off()).toEqual(['r1'])
  })

  test('cannot_turn_on_globally_disabled: a disabled resource is neither added nor removed by a save (R-061)', async () => {
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r3'], viewer: OWNER_VIEW })
    expect(off()).toEqual([])
    h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: 'r3' })
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: [], viewer: OWNER_VIEW })
    expect(off()).toEqual(['r3'])
  })

  test('a resource with a login: only the owner\'s own session changes it; a collaborator and an acting admin leave it as it is', async () => {
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r4'], viewer: COLLAB_VIEW })
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r4'], viewer: ACTING_VIEW })
    expect(off()).toEqual([])
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r4'], viewer: OWNER_VIEW })
    expect(off()).toEqual(['r4'])
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: [], viewer: COLLAB_VIEW })
    expect(off()).toEqual(['r4'])
  })

  test('a collaborator changes the public resources like the owner', async () => {
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r1'], viewer: COLLAB_VIEW })
    expect(off()).toEqual(['r1'])
    expect(h.db.rows('tradecraftProjectChoice')[0].createdById).toBe('collab-1')
  })

  test('two saves turning the same resource off at once write one row, and neither fails', async () => {
    const save = () => writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r1'], viewer: OWNER_VIEW })
    // Both read "no row" before either writes, as two transactions at READ COMMITTED would.
    const reads = h.db.prisma.tradecraftProjectChoice as { findMany: (a: unknown) => Promise<unknown> }
    const realFind = reads.findMany
    let gate!: () => void
    const both = new Promise<void>(r => { gate = r })
    let waiting = 0
    reads.findMany = async (a: unknown) => {
      const result = await realFind(a)
      if (++waiting === 2) gate()
      await both
      return result
    }
    await Promise.all([save(), save()])
    expect(h.db.rows('tradecraftProjectChoice', { projectId: 'p1' })).toHaveLength(1)
  })

  test('only the named project changes', async () => {
    h.db.seed('tradecraftProjectChoice', { projectId: 'p2', resourceId: 'r1' })
    await writeProjectChoices(tx(), { projectId: 'p1', ownerId: OWNER, off: ['r2'], viewer: OWNER_VIEW })
    expect(off('p2')).toEqual(['r1'])
    expect(await offIdsForProject(tx(), 'p1')).toEqual(['r2'])
  })
})

describe('parseTradecraftOff', () => {
  test('a list of ids, de-duplicated; anything else is null', () => {
    expect(parseTradecraftOff(['a', 'b', 'a'])).toEqual(['a', 'b'])
    expect(parseTradecraftOff([])).toEqual([])
    for (const bad of [null, 'a', { a: 1 }, [1], [''], ['x'.repeat(201)], Array(MAX_TRADECRAFT_OFF + 1).fill('a')]) {
      expect(parseTradecraftOff(bad)).toBeNull()
    }
  })
})

describe('enabledImpact', () => {
  test('enabled-impact numbers: the account\'s projects, and those where the resource is off', async () => {
    for (const id of ['p1', 'p2', 'p3']) h.db.seed('project', { id, userId: OWNER })
    h.db.seed('project', { id: 'p9', userId: 'someone-else' })
    h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: 'r1' })
    h.db.seed('tradecraftProjectChoice', { projectId: 'p2', resourceId: 'r1' })
    h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: 'r2' })
    expect(await enabledImpact(tx(), OWNER, 'r1')).toEqual({ projects: 3, turnedOffIn: 2 })
    expect(await enabledImpact(tx(), OWNER, 'r3')).toEqual({ projects: 3, turnedOffIn: 0 })
  })
})

/**
 * The list helpers of visibleProjects.ts (step 4.5, SH-39): a project list reads each row's own
 * access (`myAccess`, the project GET's view) from the same query, and the scan activity view sees
 * the jobs of every project the person sees, its anonymous count being their complement.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/visibleProjects.lists.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from './__testing__/projectListDb'

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))

import { jobQueueScope, myShareSelect, visibleProjects, visibleProjectsWhere, withMyAccess } from './visibleProjects'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'

const NOW = new Date('2026-11-13T12:00:00Z')
const ON = { identity: true, permissions: true, sharing: true }
const ALICE = { id: 'alice', name: 'Alice', email: 'alice@example.test' }

let state: ProjectListState

beforeEach(() => {
  state = emptyProjectListState()
  h.db = projectListPrisma(state)
  setFlagsForTests({})
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('visibleProjects: the filter and whether shares widened it', () => {
  test('sharing not in force: the owned filter, no shares', async () => {
    expect(await visibleProjects({ userId: 'bob' })).toEqual({ where: { userId: 'bob' }, withShares: false })
    setFlagsForTests(ON)
    state.policy = {}
    clearSharingPolicyCacheForTests()
    expect(await visibleProjects({ userId: 'bob' })).toEqual({ where: { userId: 'bob' }, withShares: false })
  })

  test('sharing in force: owned or shared, and visibleProjectsWhere is the same filter', async () => {
    setFlagsForTests(ON)
    const scope = await visibleProjects({ userId: 'bob' })
    expect(scope.withShares).toBe(true)
    expect(scope.where).toEqual(await visibleProjectsWhere({ userId: 'bob' }))
    expect(scope.where).toMatchObject({ OR: [{ userId: 'bob' }, { collaborators: { some: { userId: 'bob' } } }] })
  })

  test('a person without an id sees nothing, shares or not', async () => {
    setFlagsForTests(ON)
    expect(await visibleProjects({ userId: '' })).toEqual({ where: { id: { in: [] } }, withShares: false })
  })
})

describe('myShareSelect', () => {
  test("only with shares listed: the person's own share of the row, its Raw data toggle", () => {
    expect(myShareSelect({ userId: 'bob' }, { where: { userId: 'bob' }, withShares: false })).toEqual({})
    expect(myShareSelect({ userId: 'bob' }, { where: {}, withShares: true })).toEqual({
      collaborators: { where: { userId: 'bob' }, select: { rawData: true } },
    })
    expect(myShareSelect({ userId: '' }, { where: {}, withShares: true })).toEqual({})
  })
})

describe('withMyAccess', () => {
  const owned = { id: 'p-bob', userId: 'bob', name: 'mine', user: { id: 'bob', name: 'Bob', email: 'bob@example.test' } }
  const sharedRead = { id: 'p-alice', userId: 'alice', name: 'theirs', user: ALICE, collaborators: [{ rawData: false }] }
  const sharedRaw = { id: 'p-alice-2', userId: 'alice', name: 'raw', user: ALICE, collaborators: [{ rawData: true }] }

  test('RBAC_SHARING_ENABLED off: the rows as they were, no myAccess key (DV-30)', () => {
    const rows = [owned]
    const out = withMyAccess({ userId: 'bob' }, rows)
    expect(out).toBe(rows)
    expect(out[0]).not.toHaveProperty('myAccess')
  })

  test('the owner reads its own row as the owner, with its own identity', () => {
    setFlagsForTests(ON)
    expect(withMyAccess({ userId: 'bob' }, [owned])).toEqual([{
      ...owned,
      myAccess: { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: 'bob@example.test' } },
    }])
  })

  test('a shared row reads as read, with Raw data as the share says and the owner who shared it', () => {
    setFlagsForTests(ON)
    const [read, raw] = withMyAccess({ userId: 'bob' }, [sharedRead, sharedRaw])
    expect(read.myAccess).toEqual({ level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' } })
    expect(raw.myAccess).toEqual({ level: 'read', toggles: { rawData: true }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' } })
    expect(read).not.toHaveProperty('collaborators')
    expect(raw).not.toHaveProperty('collaborators')
  })

  test('a row neither owned nor shared with the person is left out (fail closed)', () => {
    setFlagsForTests(ON)
    const stray = { id: 'p-carol', userId: 'carol', name: 'stray', user: null, collaborators: [] }
    expect(withMyAccess({ userId: 'bob' }, [stray, owned]).map((r) => r.id)).toEqual(['p-bob'])
    expect(withMyAccess({ userId: 'bob' }, [{ id: 'p-x', userId: 'carol', name: 'x', user: null }])).toEqual([])
  })

  test('with the switch on but the policy disabled every listed row is owned: the owner view only', async () => {
    setFlagsForTests(ON)
    state.policy = {}
    const scope = await visibleProjects({ userId: 'bob' })
    expect(myShareSelect({ userId: 'bob' }, scope)).toEqual({})
    expect(withMyAccess({ userId: 'bob' }, [owned])[0].myAccess?.level).toBe('owner')
  })
})

describe('jobQueueScope', () => {
  test('sharing not in force: the rows the person queued, and everyone else\'s as the count (as before)', () => {
    expect(jobQueueScope({ userId: 'bob' }, { where: { userId: 'bob' }, withShares: false })).toEqual({
      mine: { userId: 'bob' },
      others: { userId: { not: 'bob' } },
    })
  })

  test('sharing in force: also every job of a project the person sees; the count is the exact complement', async () => {
    setFlagsForTests(ON)
    const scope = await visibleProjects({ userId: 'bob' })
    expect(jobQueueScope({ userId: 'bob' }, scope)).toEqual({
      mine: { OR: [{ userId: 'bob' }, { project: scope.where }] },
      others: { userId: { not: 'bob' }, project: { NOT: scope.where } },
    })
  })

  test('the two never overlap and together cover every row (evaluated)', async () => {
    setFlagsForTests(ON)
    state.users = [{ ...ALICE, status: 'active' }, { id: 'bob', status: 'active' }, { id: 'carol', status: 'active' }]
    state.projects = [
      { id: 'p-alice', userId: 'alice' }, { id: 'p-bob', userId: 'bob' }, { id: 'p-carol', userId: 'carol' },
    ]
    state.shares = [{ projectId: 'p-alice', userId: 'bob', access: 'read', rawData: false, expiresAt: null }]
    state.jobQueue = [
      { id: 'j1', projectId: 'p-alice', userId: 'alice' },
      { id: 'j2', projectId: 'p-bob', userId: 'bob' },
      { id: 'j3', projectId: 'p-carol', userId: 'carol' },
      { id: 'j4', projectId: 'p-carol', userId: 'bob' },
      { id: 'j5', projectId: 'p-bob', userId: 'carol' },
    ]
    const { mine, others } = jobQueueScope({ userId: 'bob' }, await visibleProjects({ userId: 'bob' }))
    const db = h.db as ReturnType<typeof projectListPrisma>
    const mineIds = (await db.jobQueue.findMany({ where: mine as Record<string, unknown> })).map((r) => r.id)
    const otherIds = (await db.jobQueue.findMany({ where: others as Record<string, unknown> })).map((r) => r.id)
    expect(mineIds.sort()).toEqual(['j1', 'j2', 'j4', 'j5'])
    expect(otherIds).toEqual(['j3'])
  })

  test('a person without an id queued nothing', () => {
    expect(jobQueueScope({ userId: '' }, { where: { id: { in: [] } }, withShares: false }).mine).toEqual({ id: { in: [] } })
  })
})

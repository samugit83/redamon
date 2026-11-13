/**
 * A Read + Write share on the screens (step 5.2; SH-02, SH-03, UI-07 write part): the browser's level
 * table (`myAccessMeets`) answers every level as `meetsLevel` does for the same access, so a write
 * share's controls open at W and at each toggle's level and never at O; the words name the toggle a
 * control needs; the poll re-renders when a toggle changes; the list badge names the toggles; and the
 * lists (`visibleProjects` + `withMyAccess`) show a write share as `write` only when projectAccess()
 * would, never under act-as (D-22).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/readOnlyProject.write.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import type { MyAccess, ProjectAccess, ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { PROJECT_LEVELS, type ProjectLevel } from '@/lib/authz/permissions'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from '@/lib/authz/__testing__/projectListDb'

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))

import { meetsLevel, myAccessView } from '@/lib/authz/projectAccess'
import { levelRefusalText, myAccessMeets, readAccessNotice, sameMyAccess } from './readOnlyProject'
import { accessBadge } from './sharedProjects'
import { myShareSelect, visibleProjects, withMyAccess, type ListedShare } from '@/lib/authz/visibleProjects'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const BY = 'shared by Alice (alice@e2e.local)'
const NO_TOGGLES = { runScans: false, useAgent: false, exploit: false, manage: false }

function write(toggles: Partial<typeof NO_TOGGLES> = {}): MyAccess {
  return { level: 'write', toggles: { rawData: true, ...NO_TOGGLES, ...toggles }, via: 'share', owner: OWNER }
}

/** The server's access behind a MyAccess, for comparing the two tables. */
function serverAccess(access: MyAccess): ProjectAccess {
  return { project: { id: 'P1', userId: 'alice' }, level: access.level, toggles: access.toggles as ProjectAccessToggles, via: access.via }
}

describe('myAccessMeets: the write rows (one table with meetsLevel)', () => {
  const CASES: Array<[string, MyAccess]> = [
    ['editor (no toggle)', write()],
    ['operator (Run scans)', write({ runScans: true })],
    ['assistant (Use AI agent)', write({ useAgent: true })],
    ['red-teamer (Exploitation & shells)', write({ exploit: true })],
    ['co-owner (Manage)', write({ manage: true })],
    ['every toggle', write({ runScans: true, useAgent: true, exploit: true, manage: true })],
  ]

  test.each(CASES)('%s: every level answers as the server table does', (_what, access) => {
    for (const level of PROJECT_LEVELS) {
      expect([level, myAccessMeets(access, level)]).toEqual([level, meetsLevel(serverAccess(access), level)])
    }
  })

  test('an editor reaches R, R* and W; no toggled level, never O', () => {
    const editor = write()
    expect((['R', 'R*', 'W'] as ProjectLevel[]).every(l => myAccessMeets(editor, l))).toBe(true)
    expect((['W+S', 'W+A', 'W+X', 'M', 'O'] as ProjectLevel[]).some(l => myAccessMeets(editor, l))).toBe(false)
  })

  test('each toggle opens its own level only; every toggle together still never reaches O', () => {
    expect(myAccessMeets(write({ runScans: true }), 'W+S')).toBe(true)
    expect(myAccessMeets(write({ runScans: true }), 'W+A')).toBe(false)
    expect(myAccessMeets(write({ manage: true }), 'M')).toBe(true)
    expect(myAccessMeets(write({ manage: true }), 'W+X')).toBe(false)
    expect(myAccessMeets(write({ runScans: true, useAgent: true, exploit: true, manage: true }), 'O')).toBe(false)
  })

  test('a toggle the answer lacks is off (fails closed)', () => {
    const partial = { level: 'write', toggles: { rawData: true }, via: 'share', owner: OWNER } as MyAccess
    expect(myAccessMeets(partial, 'W')).toBe(true)
    expect(myAccessMeets(partial, 'M')).toBe(false)
  })
})

describe('the words for a Read + Write share', () => {
  test('a control needing a toggle the share lacks names it; an owner-only control says so', () => {
    expect(readAccessNotice(write(), 'W+S')).toBe(`Read + Write access without Run scans, ${BY}`)
    expect(readAccessNotice(write(), 'W+A')).toBe(`Read + Write access without Use AI agent, ${BY}`)
    expect(readAccessNotice(write(), 'W+X')).toBe(`Read + Write access without Exploitation & shells, ${BY}`)
    expect(readAccessNotice(write(), 'M')).toBe(`Read + Write access without Manage, ${BY}`)
    expect(readAccessNotice(write({ manage: true }), 'O')).toBe(`Read + Write access, ${BY}; only the owner can do this`)
  })

  test('levelRefusalText: null where the share reaches the permission, the words where it does not', () => {
    const editor = write()
    expect(levelRefusalText(editor, 'project:settings')).toBeNull()
    expect(levelRefusalText(editor, 'triage:mute')).toBeNull()
    expect(levelRefusalText(editor, 'traffic:read')).toBeNull()
    expect(levelRefusalText(editor, 'recon:scan')).toBe(`Read + Write access without Run scans, ${BY}`)
    expect(levelRefusalText(editor, 'graph:edit')).toBe(`Read + Write access without Manage, ${BY}`)
    expect(levelRefusalText(write({ manage: true }), 'graph:edit')).toBeNull()
    expect(levelRefusalText(write({ manage: true }), 'project:delete')).toBe(`Read + Write access, ${BY}; only the owner can do this`)
  })

  test('the read words are unchanged', () => {
    const read: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
    expect(readAccessNotice(read)).toBe(`Read access, ${BY}`)
    expect(readAccessNotice(read, 'R*')).toBe(`Read access without Raw data & files, ${BY}`)
  })
})

describe('sameMyAccess and the badge', () => {
  test('a changed write toggle is a different answer (the poll re-renders); the same toggles are the same', () => {
    expect(sameMyAccess(write(), write())).toBe(true)
    expect(sameMyAccess(write(), write({ manage: true }))).toBe(false)
    expect(sameMyAccess(write({ runScans: true }), write())).toBe(false)
    expect(sameMyAccess(write(), { ...write(), level: 'read', toggles: { rawData: true } })).toBe(false)
  })

  test('the badge names Read + Write and the toggles that are on', () => {
    expect(accessBadge(write())).toBe('Read + Write')
    expect(accessBadge(write({ manage: true }))).toBe('Read + Write + Manage')
    expect(accessBadge(write({ runScans: true, exploit: true }))).toBe('Read + Write + Run scans + Exploitation')
  })

  test('myAccessView of a write access and the browser table agree for every level', () => {
    const server: ProjectAccess = {
      project: { id: 'P1', userId: 'alice' }, level: 'write', via: 'share',
      toggles: { rawData: true, runScans: false, useAgent: true, exploit: false, manage: true },
    }
    const view = myAccessView(server, OWNER)
    for (const level of PROJECT_LEVELS) expect([level, myAccessMeets(view, level)]).toEqual([level, meetsLevel(server, level)])
  })
})

describe('the lists: a write share lists as write only when projectAccess() would answer write', () => {
  const NOW = new Date('2026-11-13T12:00:00Z')
  let state: ProjectListState
  const ROW = (share: ListedShare) => ({
    id: 'P1', userId: 'alice', user: { name: 'Alice', email: 'alice@e2e.local' }, collaborators: [share],
  })
  const WRITE_SHARE = { rawData: false, access: 'write', runScans: true, useAgent: true, exploit: true, manage: true }

  beforeEach(() => {
    state = emptyProjectListState()
    h.db = projectListPrisma(state)
    setNowForTests(() => NOW)
    clearSharingPolicyCacheForTests()
  })
  afterEach(() => {
    setFlagsForTests(null)
    setNowForTests(null)
  })

  test("write sharing in force: the share's level and toggles are selected, and it lists as write", async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    state.policy = { enabled: true, maxLevel: 'write' }
    const visible = await visibleProjects({ userId: 'bob' })
    expect(visible.writeShares).toBe(true)
    expect(myShareSelect({ userId: 'bob' }, visible)).toEqual({
      collaborators: {
        where: { userId: 'bob' },
        select: { rawData: true, access: true, runScans: true, useAgent: true, exploit: true, manage: true },
      },
    })
    const [row] = await withMyAccess({ userId: 'bob' }, [ROW(WRITE_SHARE)])
    // No owner consent stored: the run toggles read off, as projectAccess() answers (effectiveToggles).
    expect(row.myAccess).toEqual({
      level: 'write', via: 'share', owner: { name: 'Alice', email: 'alice@e2e.local' },
      toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: true },
    })
    expect('collaborators' in row).toBe(false)
  })

  test('under act-as a write share lists as read with its own Raw data (D-22)', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    const [row] = await withMyAccess({ userId: 'bob' }, [ROW(WRITE_SHARE)], { actingAs: true })
    expect(row.myAccess).toEqual({ level: 'read', via: 'share', owner: { name: 'Alice', email: 'alice@e2e.local' }, toggles: { rawData: false } })
  })

  test.each([
    ['the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["Root's policy at read", { identity: true, permissions: true, sharing: true, sharingWrite: true }, { enabled: true, maxLevel: 'read' }],
  ])('%s: Phase 4 select and answer, no writeShares key', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    state.policy = policy
    const visible = await visibleProjects({ userId: 'bob' })
    expect(visible).toEqual({ where: expect.anything(), withShares: true })
    expect(myShareSelect({ userId: 'bob' }, visible)).toEqual({ collaborators: { where: { userId: 'bob' }, select: { rawData: true } } })
    // A row read with Phase 4's select carries no level: it lists as read.
    const [row] = await withMyAccess({ userId: 'bob' }, [ROW({ rawData: true })])
    expect(row.myAccess?.level).toBe('read')
  })
})

/**
 * The account acted as is told (step 3.14; IM-10, AU-03): an `acted_as` notice (who, when, why, the
 * time limit), shown once at its next sign-in, and My activity's act-as lines, which carry the
 * reason, the duration and how the impersonation ended. With Root's `impersonationNotifyTarget` off
 * the account is not shown them. The notice is written without moving the account's `updated_at`
 * and without losing a notice written at the same moment.
 *
 * The database is the in-memory accountDb (plus the audit log read My activity makes).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  Object.assign(db, { auditLog: { ...db.auditLog, findMany: async () => [] } })
  h.db = db
  return { default: db, prisma: db }
})

import type { AccountDb } from './__testing__/accountDb'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { accountActivity } from './accountActivity'
import { actedAsNotice, appendNotice, noticeView, pendingNotices, readNotices } from './accountNotices'

const db = () => h.db as AccountDb
const BY = { id: 'admin-1', name: 'Laura', email: 'admin-1@e2e.local' }

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin', name: 'Laura' }, { id: 'member-1', name: 'Marco' }])
  db().seedInstance({ impersonationMaxMinutes: 720, impersonationReasonRequired: false, impersonationNotifyTarget: true })
  setFlagsForTests({ identity: true, permissions: true })
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('target notice', () => {
  test('appended to the account\'s notices, pending until a sign-in shows it; the view hides the admin\'s id', async () => {
    const notice = actedAsNotice({ by: BY, at: new Date('2026-11-12T09:00:00Z'), reason: 'ticket #42', durationMinutes: 35 })
    await appendNotice('member-1', notice)
    const stored = db().account('member-1')!.pendingNotices
    expect(pendingNotices(stored)).toEqual([notice])
    expect(noticeView(notice)).toEqual({
      id: notice.id, type: 'acted_as', at: '2026-11-12T09:00:00.000Z', by: { name: 'Laura', email: 'admin-1@e2e.local' },
      reason: 'ticket #42', durationMinutes: 35,
    })
    // A raw, conditional write: updated_at does not move.
    expect(db().account('member-1')!.updatedAt).toEqual(new Date(0))
  })

  test('a notice written meanwhile is kept: the write reads again', async () => {
    const other = actedAsNotice({ by: BY, at: new Date('2026-11-12T08:00:00Z'), reason: null, durationMinutes: 60 })
    const mine = actedAsNotice({ by: BY, at: new Date('2026-11-12T09:00:00Z'), reason: null, durationMinutes: 60 })
    const original = db().$executeRaw
    let first = true
    vi.spyOn(db(), '$executeRaw').mockImplementation(async (strings: TemplateStringsArray, ...values: unknown[]) => {
      if (first) {
        first = false
        await appendNotice('member-1', other)
      }
      return original(strings, ...values)
    })
    await appendNotice('member-1', mine)
    expect(readNotices(db().account('member-1')!.pendingNotices).map((n) => n.id)).toEqual([other.id, mine.id])
    vi.restoreAllMocks()
  })

  test('a gone account throws: the caller decides (the act-as route logs it)', async () => {
    await expect(appendNotice('ghost', actedAsNotice({ by: BY, at: new Date(), reason: null, durationMinutes: 5 }))).rejects.toThrow()
  })

  test('only well-formed act-as notices are read', () => {
    const ok = actedAsNotice({ by: BY, at: new Date(), reason: null, durationMinutes: 5 })
    expect(readNotices([ok, { ...ok, durationMinutes: 0 }, { ...ok, reason: 7 }, { ...ok, durationMinutes: 1.5 }])).toEqual([ok])
  })
})

describe('My activity: the act-as lines', () => {
  beforeEach(() => {
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date('2026-11-12T09:00:00Z'), reason: 'ticket #42', durationMinutes: 35 })
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'end', createdAt: new Date('2026-11-12T09:20:00Z'), endedBy: 'stopped' })
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date('2026-01-01T09:00:00Z') })
  })

  test('each line carries what its row holds: reason and duration, how it ended; an old row nothing', async () => {
    const { events } = await accountActivity('member-1')
    expect(events.map((e) => [e.action, e.details])).toEqual([
      ['act_as.end', { endedBy: 'stopped' }],
      ['act_as.start', { reason: 'ticket #42', durationMinutes: 35 }],
      ['act_as.start', {}],
    ])
    expect(events[0].by).toEqual({ name: 'Laura', email: 'admin-1@e2e.local' })
  })

  test('an impersonation whose time ran out is ended before the list is read', async () => {
    db().seedActAs({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', createdAt: new Date('2026-11-12T10:00:00Z'), durationMinutes: 30 })
    setNowForTests(() => new Date('2026-11-12T11:00:00Z'))
    const { events } = await accountActivity('member-1')
    expect(events[0]).toMatchObject({ action: 'act_as.end', details: { endedBy: 'expired' } })
  })

  test('the act-as notice is a sign-in notice, not a My activity notice (the lines above are its record)', async () => {
    await appendNotice('member-1', actedAsNotice({ by: BY, at: new Date(), reason: null, durationMinutes: 5 }))
    expect((await accountActivity('member-1')).notices).toEqual([])
  })

  test('Root turned the notice off: no act-as line either', async () => {
    db().seedInstance({ impersonationNotifyTarget: false })
    expect((await accountActivity('member-1')).events).toEqual([])
  })

  test('switch off: the lines as before, whatever the setting', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    db().seedInstance({ impersonationNotifyTarget: false })
    expect((await accountActivity('member-1')).events.map((e) => e.action)).toEqual(['act_as.end', 'act_as.start', 'act_as.start'])
  })
})

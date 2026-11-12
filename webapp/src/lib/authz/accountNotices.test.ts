/**
 * One-time notices to an account (step 2.10, ID-19; feature document §7.1 "the person is told at
 * their next sign-in and in their feed"): a credentials reset leaves a notice in the account's
 * `pendingNotices`. The next sign-in hands the pending ones to the person once and marks them
 * shown; the account keeps them (its activity list, step 2.11 reads them), the newest few only.
 * The first sign-in after a reset is the one whose account last signed in before that reset.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ executeRaw: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: { $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => h.executeRaw(strings, ...values) },
}))

import {
  NOTICE_LIMIT,
  credentialsResetNotice,
  firstSignInAfterReset,
  handOverNotices,
  pendingNotices,
  readNotices,
  withNotice,
} from './accountNotices'
import { setNowForTests } from './clock'

const BY = { id: 'admin-1', name: 'Laura', email: 'laura@e2e.local' }
const AT = new Date('2026-11-12T10:00:00Z')
const reset = (over: Partial<Parameters<typeof credentialsResetNotice>[0]> = {}) =>
  credentialsResetNotice({ by: BY, at: AT, reason: 'Locked out', mode: 'link', ...over })

beforeEach(() => {
  h.executeRaw.mockReset()
  h.executeRaw.mockResolvedValue(1)
})
afterEach(() => setNowForTests(null))

describe('the credentials reset notice', () => {
  test('names who, when, why and how; it is pending until a sign-in shows it', () => {
    const n = reset()
    expect(n).toEqual({
      id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      type: 'credentials_reset',
      at: '2026-11-12T10:00:00.000Z',
      by: BY,
      reason: 'Locked out',
      mode: 'link',
    })
    expect(reset().id).not.toBe(n.id)
    expect(pendingNotices([n])).toEqual([n])
  })

  test('joins the list; only the newest are kept', () => {
    let list: unknown = []
    for (let i = 0; i < NOTICE_LIMIT + 5; i++) list = withNotice(list, reset({ reason: `r${i}` }))
    const kept = readNotices(list)
    expect(kept).toHaveLength(NOTICE_LIMIT)
    expect(kept[0].reason).toBe('r5')
    expect(kept.at(-1)!.reason).toBe(`r${NOTICE_LIMIT + 4}`)
  })

  test('a stored value that is not a list of notices reads as none (never throws)', () => {
    for (const v of [null, undefined, 'x', 3, {}, [null, 1, 'x', { type: 'other' }, { type: 'credentials_reset' }]]) {
      expect(readNotices(v)).toEqual([])
    }
    expect(withNotice('garbage', reset())).toHaveLength(1)
  })
})

describe('the first sign-in after a reset', () => {
  test('an account that never signed in, or last signed in before the reset', () => {
    expect(firstSignInAfterReset(null, [reset()])).toBe(true)
    expect(firstSignInAfterReset(new Date('2026-11-12T09:59:59Z'), [reset()])).toBe(true)
  })

  test('later sign-ins are not', () => {
    expect(firstSignInAfterReset(new Date('2026-11-12T10:00:01Z'), [reset()])).toBe(false)
  })

  test('no reset, no first sign-in after one', () => {
    expect(firstSignInAfterReset(null, [])).toBe(false)
    expect(firstSignInAfterReset(null, 'garbage')).toBe(false)
  })

  test('the latest reset counts', () => {
    const older = credentialsResetNotice({ by: BY, at: new Date('2026-11-01T00:00:00Z'), reason: null, mode: 'temporary' })
    expect(firstSignInAfterReset(new Date('2026-11-05T00:00:00Z'), [older, reset()])).toBe(true)
  })
})

describe('handing the pending notices over at a sign-in', () => {
  test('shown once: returned, then marked shown with a raw write that keeps updated_at', async () => {
    setNowForTests(() => new Date('2026-11-12T11:00:00Z'))
    const stored = [reset()]
    const shown = await handOverNotices('u1', stored)
    expect(shown).toEqual([{
      id: stored[0].id, type: 'credentials_reset', at: stored[0].at, by: { name: 'Laura', email: 'laura@e2e.local' },
      reason: 'Locked out', mode: 'link',
    }])
    expect(h.executeRaw).toHaveBeenCalledTimes(1)
    const sql = (h.executeRaw.mock.calls[0][0] as string[]).join('$')
    expect(sql).toMatch(/^\s*UPDATE users SET pending_notices = \$::jsonb WHERE id = \$ AND pending_notices = \$::jsonb\s*$/)
    const [next, id, before] = h.executeRaw.mock.calls[0].slice(1) as [string, string, string]
    expect(id).toBe('u1')
    expect(JSON.parse(before)).toEqual(stored)
    expect(JSON.parse(next)).toEqual([{ ...stored[0], shownAt: '2026-11-12T11:00:00.000Z' }])
    // Shown: the next sign-in has nothing to show.
    expect(await handOverNotices('u1', JSON.parse(next))).toEqual([])
    expect(h.executeRaw).toHaveBeenCalledTimes(1)
  })

  test('nothing pending: nothing written', async () => {
    expect(await handOverNotices('u1', [])).toEqual([])
    expect(await handOverNotices('u1', null)).toEqual([])
    expect(h.executeRaw).not.toHaveBeenCalled()
  })

  test('a failed write never fails the sign-in: the notices are still shown, the code logged', async () => {
    h.executeRaw.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED 10.0.0.5'), { code: 'P1001' }))
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      expect(await handOverNotices('u1', [reset()])).toHaveLength(1)
      expect(err).toHaveBeenCalledWith('[rbac] notice write failed user=u1 code=P1001')
    } finally {
      err.mockRestore()
    }
  })

  test("the person never sees the admin's account id", async () => {
    const [shown] = await handOverNotices('u1', [reset()])
    expect(JSON.stringify(shown)).not.toContain('admin-1')
  })
})

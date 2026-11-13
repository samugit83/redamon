/**
 * The pure parts of the share writers (step 4.4): who may change a co-owner's share (OQ-34), who
 * cannot receive one, the email hash the lookup's audit row keeps, and the per-person lookup
 * ceiling (DV-05). The routes are tested with the real writers in
 * app/api/projects/[id]/collaborators/route.test.ts, .../[userId]/route.test.ts and leave/route.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'

vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))

import { coOwnerRefusal, emailSha256, recipientRefusal } from './projectShares'
import { resetInviteLimitsForTests, SHARE_LOOKUPS_PER_MINUTE, takeLookup, takeShareLookup } from './inviteLimits'
import { setNowForTests } from './clock'

const T0 = new Date('2026-11-13T12:00:00Z')
let clock = T0

beforeEach(() => {
  clock = T0
  setNowForTests(() => clock)
  resetInviteLimitsForTests()
})
afterEach(() => setNowForTests(null))

describe('a co-owner never removes or downgrades another co-owner (OQ-34)', () => {
  test('the owner may change or remove a co-owner\'s share', () => {
    expect(coOwnerRefusal({ level: 'owner' }, { manage: true })).toBeNull()
  })

  test('anyone below the owner who reached the route is refused on a co-owner\'s share', async () => {
    const res = coOwnerRefusal({ level: 'read' }, { manage: true })
    expect(res?.status).toBe(403)
    expect(await res?.json()).toMatchObject({ code: 'owner_only', permission: 'project:share' })
  })

  test('a share without Manage is not protected by this check', () => {
    expect(coOwnerRefusal({ level: 'read' }, { manage: false })).toBeNull()
  })
})

describe('who cannot receive a share', () => {
  test('oneself: 400 share_with_self', async () => {
    const res = recipientRefusal('alice', { actorId: 'alice', ownerId: 'alice' })
    expect(res?.status).toBe(400)
    expect(await res?.json()).toMatchObject({ code: 'share_with_self' })
  })

  test('the owner, by a co-owner: 400 share_with_owner', async () => {
    const res = recipientRefusal('alice', { actorId: 'cora', ownerId: 'alice' })
    expect(res?.status).toBe(400)
    expect(await res?.json()).toMatchObject({ code: 'share_with_owner' })
  })

  test('anyone else passes', () => {
    expect(recipientRefusal('bob', { actorId: 'alice', ownerId: 'alice' })).toBeNull()
  })
})

describe('the lookup\'s audit row keeps a hash, never the email', () => {
  test('sha-256 of the normalised email', () => {
    const expected = createHash('sha256').update('bob@example.test', 'utf8').digest('hex')
    expect(emailSha256('bob@example.test')).toBe(expected)
    expect(emailSha256('  BOB@Example.Test ')).toBe(expected)
    expect(emailSha256('bob@example.test')).not.toContain('bob')
  })
})

describe('share lookups: per person, sliding over a minute (DV-05)', () => {
  test(`${SHARE_LOOKUPS_PER_MINUTE} a minute each; the next is refused with the seconds to wait, and not counted`, () => {
    for (let i = 0; i < SHARE_LOOKUPS_PER_MINUTE; i++) {
      clock = new Date(T0.getTime() + i * 1000)
      expect(takeShareLookup('alice'), `lookup ${i + 1}`).toEqual({ ok: true })
    }
    clock = new Date(T0.getTime() + 30_000)
    expect(takeShareLookup('alice')).toEqual({ ok: false, retryAfterSeconds: 30 })
    expect(takeShareLookup('bob')).toEqual({ ok: true })
    clock = new Date(T0.getTime() + 60_000)
    expect(takeShareLookup('alice')).toEqual({ ok: true })
  })

  test('the share ceiling and the invite link ceiling count apart', () => {
    for (let i = 0; i < SHARE_LOOKUPS_PER_MINUTE; i++) takeShareLookup('alice')
    expect(takeLookup()).toEqual({ ok: true })
  })

  test('the people tracked are bounded: the least recent is forgotten first', () => {
    for (let i = 0; i < SHARE_LOOKUPS_PER_MINUTE; i++) takeShareLookup('first')
    for (let i = 0; i < 10_000; i++) takeShareLookup(`p${i}`)
    expect(takeShareLookup('first')).toEqual({ ok: true })
  })
})

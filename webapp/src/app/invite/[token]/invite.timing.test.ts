/**
 * HD-26 (invite part, step 2.9): opening a link costs the same whatever the token, so the timing
 * of the answer tells nothing about which tokens exist. A valid, an unknown, an expired and a
 * malformed token each take one hash and one indexed read (`user_invites.token_hash`), with the
 * same query shape, and nothing else is read; all four get the same status and Location.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createHash } from 'node:crypto'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { resetInviteLimitsForTests } from '@/lib/authz/inviteLimits'
import { createLink, newLinkToken } from '@/lib/authz/invites'
import { GET } from './route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'invited-1', status: 'invited', password: '' }])
  db().seedInstance({ inviteTtlHours: 1 })
  setFlagsForTests({ identity: true })
  setNowForTests(() => T0)
  resetInviteLimitsForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('the same work for every token', () => {
  test('unknown token does the same work: one hash, one indexed read, the same answer', async () => {
    const valid = await db().$transaction((tx) => createLink(tx as never, { userId: 'invited-1', kind: 'invite', createdById: 'admin-1' }))
    const expiredRow = await db().$transaction((tx) => createLink(tx as never, { userId: 'invited-1', kind: 'reset', createdById: 'admin-1' }))
    await db().userInvite.updateMany({ where: { id: expiredRow.linkId }, data: { expiresAt: new Date(0) } })
    const tokens = {
      valid: valid.link.slice(valid.link.lastIndexOf('/') + 1),
      unknown: newLinkToken(),
      expired: expiredRow.link.slice(expiredRow.link.lastIndexOf('/') + 1),
      malformed: '%%not-base64%%'.repeat(40),
    }
    const reads = vi.spyOn(db().userInvite, 'findUnique')
    const userReads = vi.spyOn(db().user, 'findUnique')
    const shapes: string[] = []
    for (const [name, token] of Object.entries(tokens)) {
      reads.mockClear()
      const res = await GET(new NextRequest(`http://redamon.test/invite/x`), { params: Promise.resolve({ token }) })
      expect(res.status, name).toBe(303)
      expect(res.headers.get('location'), name).toBe('/invite')
      expect(reads, name).toHaveBeenCalledTimes(1)
      const arg = reads.mock.calls[0][0] as { where: Record<string, unknown>; select: unknown }
      expect(arg.where, name).toEqual({ tokenHash: sha256(token) })
      shapes.push(JSON.stringify({ where: Object.keys(arg.where), select: arg.select }))
    }
    expect(new Set(shapes).size).toBe(1)
    expect(userReads).not.toHaveBeenCalled()
  })
})

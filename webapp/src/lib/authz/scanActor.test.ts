/**
 * Which account stops a deferred scan (step 2.3, DV-39): the account that scheduled or queued
 * it, then the project's owner; a missing account counts as `deleted`; nothing is read with
 * the identity switch off.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ users: {} as Record<string, string>, project: vi.fn(), findMany: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.project(...a) },
    user: { findMany: (...a: unknown[]) => h.findMany(...a) },
  },
}))

import { setFlagsForTests } from './flags'
import { inactiveScanAccount, inactiveScanReason } from './scanActor'

beforeEach(() => {
  vi.clearAllMocks()
  setFlagsForTests({ identity: true })
  h.users = { actor: 'active', owner: 'active' }
  h.project.mockResolvedValue({ userId: 'owner' })
  h.findMany.mockImplementation(async ({ where }: { where: { id: { in: string[] } } }) =>
    where.id.in.filter((id) => id in h.users).map((id) => ({ id, status: h.users[id] })))
})
afterEach(() => setFlagsForTests(null))

describe('inactiveScanAccount', () => {
  test('both active: null', async () => {
    expect(await inactiveScanAccount({ actorUserId: 'actor', projectId: 'p1' })).toBeNull()
  })

  test('the actor is judged before the owner', async () => {
    h.users = { actor: 'disabled', owner: 'disabled' }
    expect(await inactiveScanAccount({ actorUserId: 'actor', projectId: 'p1' })).toEqual({ userId: 'actor', as: 'actor', status: 'disabled' })
  })

  test('a given owner is not read again from the project', async () => {
    h.users = { actor: 'active', owner: 'disabled' }
    expect(await inactiveScanAccount({ actorUserId: 'actor', ownerUserId: 'owner' })).toEqual({ userId: 'owner', as: 'owner', status: 'disabled' })
    expect(h.project).not.toHaveBeenCalled()
  })

  test('an actor that is the owner is read once', async () => {
    await inactiveScanAccount({ actorUserId: 'owner', projectId: 'p1' })
    expect(h.findMany.mock.calls[0][0].where.id.in).toEqual(['owner'])
  })

  test('a project that is gone judges the actor alone', async () => {
    h.project.mockResolvedValue(null)
    expect(await inactiveScanAccount({ actorUserId: 'actor', projectId: 'gone' })).toBeNull()
    expect(h.findMany.mock.calls[0][0].where.id.in).toEqual(['actor'])
  })

  test('an account that is gone is not active', async () => {
    h.users = { owner: 'active' }
    expect(await inactiveScanAccount({ actorUserId: 'actor', projectId: 'p1' })).toEqual({ userId: 'actor', as: 'actor', status: 'deleted' })
  })

  test('switch off: nothing is read, nothing refused', async () => {
    setFlagsForTests({ identity: false })
    h.users = {}
    expect(await inactiveScanAccount({ actorUserId: 'actor', projectId: 'p1' })).toBeNull()
    expect(h.project).not.toHaveBeenCalled()
    expect(h.findMany).not.toHaveBeenCalled()
  })

  test('the reason names whose account it is', () => {
    expect(inactiveScanReason({ userId: 'a', as: 'actor', status: 'disabled' }, 'queued')).toBe('the account that queued it is disabled')
    expect(inactiveScanReason({ userId: 'o', as: 'owner', status: 'deleted' }, 'scheduled')).toBe("the project owner's account is deleted")
  })
})

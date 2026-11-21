/**
 * A deleted account's Kali sandboxes end with it whatever the sharing switch (group 1, S14; OQ-G1-8
 * default A: its output folders are deleted on account deletion). With sharing in force the revocation
 * path's `account_deleted` plan stops them (its sandbox step); with sharing off that path is skipped
 * (nobody reaches another person's project), so the deletion asks the sandbox stop itself. Either way
 * it is asked exactly once.
 *
 * The revocation path and the lifecycle hook are doubles; the switches are set per test.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/userDeletion.sandbox.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  onAccessReduced: vi.fn(),
  accountEnded: vi.fn(),
}))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('./revocation', () => ({ onAccessReduced: (...a: unknown[]) => h.onAccessReduced(...a) }))
vi.mock('@/lib/sandbox/lifecycle', () => ({ sandboxAccountEnded: (...a: unknown[]) => h.accountEnded(...a) }))

import { setFlagsForTests, type RbacFlags } from './flags'
import { endDeletedAccountWork } from './userDeletion'

const WORK = { sockets: { closed: 0 }, failed: [] }

beforeEach(() => {
  h.onAccessReduced.mockReset().mockResolvedValue(WORK)
  h.accountEnded.mockReset().mockResolvedValue({ mode: 'per_user', stopped: 1 })
})
afterEach(() => setFlagsForTests(null))

describe("a deleted account's sandboxes end with it", () => {
  test.each<[string, Partial<RbacFlags>]>([
    ['every switch off', {}],
    ['identity and permissions on, sharing off', { identity: true, permissions: true }],
  ])('%s: the sandbox stop is asked once with account_deleted; the revocation path is not', async (_what, flags) => {
    setFlagsForTests(flags)
    expect(await endDeletedAccountWork('bob')).toBeNull()
    expect(h.accountEnded).toHaveBeenCalledTimes(1)
    expect(h.accountEnded).toHaveBeenCalledWith('bob', 'account_deleted')
    expect(h.onAccessReduced).not.toHaveBeenCalled()
  })

  test('sharing in force: the revocation path stops them (its account_deleted plan), never a second stop here', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(await endDeletedAccountWork('bob')).toBe(WORK)
    expect(h.onAccessReduced).toHaveBeenCalledWith(null, 'bob', 'account_deleted')
    expect(h.accountEnded).not.toHaveBeenCalled()
  })

  test('a stop that could not be done does not fail the deletion (the hook keeps it for a retry)', async () => {
    setFlagsForTests({})
    h.accountEnded.mockResolvedValue({ error: 'orchestrator_unreachable', stopped: 0 })
    await expect(endDeletedAccountWork('bob')).resolves.toBeNull()
  })
})

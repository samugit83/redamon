/**
 * `conversationSharedWithProject` (step 5.10): the one fact the plugin platform asks before it hands
 * another person's session to a plugin ("author, or an explicit conversation share"). It reads the
 * ConversationShare row only while write sharing is in force (the switch, sharing and Root's policy at
 * Read + Write); otherwise it answers false and reads nothing, as the rest of step 5.8's module does.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  reads: [] as unknown[],
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))

import { resetSharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'
import { setFlagsForTests } from './flags'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'
import { conversationSharedWithProject } from './conversationAccess'

const ALL_ON = { identity: true, permissions: true, sharing: true, sharingWrite: true }

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.reads.length = 0
  h.db.policy = { enabled: true, maxLevel: 'write' }
  h.db.models.conversationShare = {
    findUnique: (args: unknown) => {
      h.reads.push(args)
      const { where } = args as { where: { conversationId: string } }
      return where.conversationId === 'conv-shared' ? { id: 'share-1' } : null
    },
  }
  clearSharingPolicyCacheForTests()
})
afterEach(() => setFlagsForTests(null))

describe('write sharing in force', () => {
  test('a shared conversation is shared; another is not', async () => {
    setFlagsForTests(ALL_ON)
    expect(await conversationSharedWithProject('conv-shared')).toBe(true)
    expect(await conversationSharedWithProject('conv-private')).toBe(false)
    expect(h.reads).toEqual([
      { where: { conversationId: 'conv-shared' }, select: { id: true } },
      { where: { conversationId: 'conv-private' }, select: { id: true } },
    ])
  })

  test('an empty id is no conversation, read nothing', async () => {
    setFlagsForTests(ALL_ON)
    expect(await conversationSharedWithProject('')).toBe(false)
    expect(h.reads).toEqual([])
  })
})

describe('write sharing not in force: false, and no Phase 5 table read', () => {
  test.each([
    ['the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["Root's policy at Read", ALL_ON, { enabled: true, maxLevel: 'read' }],
    ['sharing disabled', ALL_ON, {}],
  ])('%s', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    h.db.policy = policy
    expect(await conversationSharedWithProject('conv-shared')).toBe(false)
    expect(h.reads).toEqual([])
  })
})

/**
 * Deferred work re-checks its actor's access when it fires (step 5.5, DV-38, SH-12): the queue
 * dispatch and the schedule run ask `actorScanRefusal` whether the person who queued or scheduled
 * the scan still holds the kind's permission on the project, at its level, now. The owner always
 * passes (owner schedules and queued jobs unchanged, with the switches on or off); a collaborator
 * whose share is revoked, expired, read-only, or whose sharing was switched off is refused, and so
 * is an owner whose own permission was taken away.
 *
 * Real can(), projectAccess(), capabilities and sharing policy; Prisma is sharedProjectDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))

import { setFlagsForTests } from './flags'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { clearPrincipalCacheForTests } from './principal'
import { QUEUED_KIND_PERMISSION } from './queuedJobPermissions'
import {
  COLLABORATOR, OWNER, SHARED_PROJECT, STRANGER, account, resetSharedProjectDb, shareWith,
} from './__testing__/sharedProjectDb'
import { actorScanRefusal, actorScanRefusalReason } from './scanActor'

const EVERY_SCAN_PERMISSION = [...new Set([...Object.values(QUEUED_KIND_PERMISSION), 'recon:overwrite' as const])]

function clearCaches() {
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
}

beforeEach(() => {
  resetSharedProjectDb(h.db)
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearCaches()
})
afterEach(() => {
  setFlagsForTests(null)
  clearCaches()
})

describe('the owner', () => {
  test.each([
    ['every switch on', { identity: true, permissions: true, sharing: true }],
    ['every switch off', null],
  ] as const)('passes every scan kind with %s (owner schedules unchanged)', async (_name, flags) => {
    setFlagsForTests(flags)
    clearCaches()
    for (const permission of EVERY_SCAN_PERMISSION) {
      expect(await actorScanRefusal(OWNER, SHARED_PROJECT, [permission])).toBeNull()
    }
  })

  test('whose own permission was taken away is refused, naming it', async () => {
    h.db.models.user = {
      findUnique: (args: unknown) => {
        const id = (args as { where: { id: string } }).where.id
        return account(id, id === OWNER
          ? { permissionOverrides: [{ permission: 'recon:overwrite', effect: 'deny', expiresAt: null, reason: null }] }
          : {})
      },
    }
    expect(await actorScanRefusal(OWNER, SHARED_PROJECT, ['recon:scan'])).toBeNull()
    expect(await actorScanRefusal(OWNER, SHARED_PROJECT, ['recon:scan', 'recon:overwrite']))
      .toEqual({ userId: OWNER, permission: 'recon:overwrite', reason: 'capability' })
  })
})

describe('a collaborator', () => {
  test.each([
    ['a Read share', {}],
    ['a Read share with Raw data & files', { rawData: true }],
    ['a share stored as write while the write switch is off', { access: 'write', rawData: true }],
  ])('with %s is refused at the scan level', async (_name, row) => {
    shareWith(h.db, COLLABORATOR, row)
    for (const permission of EVERY_SCAN_PERMISSION) {
      expect(await actorScanRefusal(COLLABORATOR, SHARED_PROJECT, [permission]))
        .toEqual({ userId: COLLABORATOR, permission, reason: 'project_level' })
    }
  })

  test('whose share was revoked reaches nothing', async () => {
    expect(await actorScanRefusal(COLLABORATOR, SHARED_PROJECT, ['recon:scan']))
      .toEqual({ userId: COLLABORATOR, permission: 'recon:scan', reason: 'project_not_visible' })
    expect(await actorScanRefusal(STRANGER, SHARED_PROJECT, ['scan:gvm']))
      .toEqual({ userId: STRANGER, permission: 'scan:gvm', reason: 'project_not_visible' })
  })

  test('whose share expired before the work fired reaches nothing (late)', async () => {
    shareWith(h.db, COLLABORATOR, { expiresAt: new Date(Date.now() - 60_000) })
    expect((await actorScanRefusal(COLLABORATOR, SHARED_PROJECT, ['recon:scan']))?.reason).toBe('project_not_visible')
  })

  test('with sharing switched off reaches nothing', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write', rawData: true })
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    clearCaches()
    expect((await actorScanRefusal(COLLABORATOR, SHARED_PROJECT, ['recon:scan']))?.reason).toBe('project_not_visible')
  })
})

describe('the answer', () => {
  test('an account that no longer exists is refused as deleted', async () => {
    h.db.models.user = { findUnique: () => null }
    expect(await actorScanRefusal('gone', SHARED_PROJECT, ['recon:scan']))
      .toEqual({ userId: 'gone', permission: 'recon:scan', reason: 'deleted' })
  })

  test('nothing to check reads nothing', async () => {
    h.db.models.user = { findUnique: () => { throw new Error('read') } }
    expect(await actorScanRefusal(COLLABORATOR, SHARED_PROJECT, [])).toBeNull()
  })

  test('a failed read throws, never reads as allowed', async () => {
    h.db.models.user = { findUnique: () => { throw Object.assign(new Error('db down'), { code: 'P1001' }) } }
    await expect(actorScanRefusal(COLLABORATOR, SHARED_PROJECT, ['recon:scan'])).rejects.toThrow('db down')
  })

  test('is told in words for the run history', () => {
    expect(actorScanRefusalReason({ userId: 'u', permission: 'recon:scan', reason: 'project_not_visible' }, 'queued'))
      .toBe('the account that queued it no longer has access to this project')
    expect(actorScanRefusalReason({ userId: 'u', permission: 'recon:overwrite', reason: 'capability' }, 'scheduled'))
      .toBe('the account that scheduled it no longer holds recon:overwrite')
    expect(actorScanRefusalReason({ userId: 'u', permission: 'scan:gvm', reason: 'project_level' }, 'queued'))
      .toBe('the account that queued it no longer has the access to this project that scan:gvm needs')
  })
})

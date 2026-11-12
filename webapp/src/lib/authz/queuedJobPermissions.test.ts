/**
 * Every kind of scan the queue takes maps to the permission that starts it directly (step 3.8): a
 * kind added to QUEUEABLE_KINDS without one fails here, instead of being queued on recon:schedule
 * alone.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { QUEUEABLE_KINDS } from '@/lib/enqueueJob'
import { PERMISSIONS } from './permissions'
import { QUEUED_KIND_PERMISSION, queuedJobPermissions } from './queuedJobPermissions'

describe('queuedJobPermissions', () => {
  test('every queueable kind has the member permission that starts a scan on a project (level W+S)', () => {
    expect(Object.keys(QUEUED_KIND_PERMISSION).sort()).toEqual([...QUEUEABLE_KINDS].sort())
    for (const kind of QUEUEABLE_KINDS) {
      const meta = PERMISSIONS[QUEUED_KIND_PERMISSION[kind]]
      expect([kind, meta.kind, meta.scope, meta.level]).toEqual([kind, 'member', 'project', 'W+S'])
    }
  })

  test("a full recon in overwrite mode also needs recon:overwrite; another mode or kind does not", () => {
    expect(queuedJobPermissions('full_recon', { mode: 'overwrite' })).toEqual(['recon:scan', 'recon:overwrite'])
    expect(queuedJobPermissions('full_recon', { mode: 'new' })).toEqual(['recon:scan'])
    expect(queuedJobPermissions('full_recon', null)).toEqual(['recon:scan'])
    expect(queuedJobPermissions('partial_recon', { mode: 'overwrite' })).toEqual(['recon:partial'])
  })

  test('an unknown kind needs nothing here (the enqueue refuses it), and no inherited name is a kind', () => {
    expect(queuedJobPermissions('mystery', {})).toEqual([])
    expect(queuedJobPermissions('toString', {})).toEqual([])
    expect(queuedJobPermissions('__proto__', {})).toEqual([])
  })
})

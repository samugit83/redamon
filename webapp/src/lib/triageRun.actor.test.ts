/**
 * A triage run starts when its actor's access reaches `triage:run`'s level (step 5.3).
 *
 * The agent now sends the ticket's `sub` as the run's actor, who may be a collaborator, while the
 * run reads the owner's graph. refuseTriageStart asks the actor's access for the level the
 * registry gives `triage:run` (the level the ticket route and the MCP start asked of the
 * permission), no longer the owner's alone; below it the answer stays one "Not found".
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ projectAccess: vi.fn(), meetsLevel: vi.fn() }))

vi.mock('@/lib/authz/projectAccess', () => ({
  projectAccess: (...a: unknown[]) => h.projectAccess(...a),
  meetsLevel: (...a: unknown[]) => h.meetsLevel(...a),
}))
vi.mock('@/lib/prisma', () => ({ default: { triageRun: { findMany: async () => [] } } }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: async () => false }))

import { refuseTriageStart } from './triageRun'
import { PERMISSIONS } from '@/lib/authz/permissions'

const ACCESS = { project: { id: 'p1', userId: 'owner-1' }, level: 'read', toggles: { rawData: false }, via: 'share' }

beforeEach(() => {
  h.projectAccess.mockReset().mockResolvedValue(ACCESS)
  h.meetsLevel.mockReset()
})

describe('refuseTriageStart for a run\'s actor', () => {
  test('asks the actor\'s access for triage:run\'s level, and starts when it reaches it', async () => {
    h.meetsLevel.mockReturnValue(true)
    expect(await refuseTriageStart('p1', 'collab-1')).toBeNull()
    expect(h.projectAccess).toHaveBeenCalledWith({ userId: 'collab-1' }, 'p1')
    expect(PERMISSIONS['triage:run'].level).toBe('W+A')
    expect(h.meetsLevel).toHaveBeenCalledWith(ACCESS, 'W+A')
  })

  test('a run started while an admin acts as the actor reaches through a share no further than read (D-22, step 5.6)', async () => {
    h.meetsLevel.mockReturnValue(true)
    expect(await refuseTriageStart('p1', 'collab-1', { actingAs: true })).toBeNull()
    expect(h.projectAccess).toHaveBeenCalledWith({ userId: 'collab-1' }, 'p1', { actingAs: true })
  })

  test('below that level, or with no access, the one "Not found"', async () => {
    h.meetsLevel.mockReturnValue(false)
    expect(await refuseTriageStart('p1', 'collab-1')).toEqual({ reason: 'Not found' })
    h.projectAccess.mockResolvedValue(null)
    expect(await refuseTriageStart('p1', 'collab-1')).toEqual({ reason: 'Not found' })
  })
})

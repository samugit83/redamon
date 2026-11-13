/**
 * The `cap` claim follows the project toggles by itself (step 5.4; SH-34): `agentTicketCap` asks
 * can() on the project for each permission, and meetsLevel gives a write share `W+X` with
 * Exploitation & shells and `W+A` with Use AI agent. So `agent:approve_phase`,
 * `agent:approve_dangerous` and `agent:kali_exec` need Exploitation, `agent:fireteam` Use AI agent,
 * with no code of its own.
 *
 * projectAccess() is stubbed with the write answers step 5.6 will give (today `effectiveToggles`
 * holds the run toggles off: agentCap.test.ts proves a write share holds none); can(), meetsLevel,
 * the registry and the resolution are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ access: null as Record<string, unknown> | null }))
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: async () => null },
    instanceSettings: { findUnique: async () => ({ rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }) },
    permissionSet: { findMany: async () => [] },
  },
}))
vi.mock('./projectAccess', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./projectAccess')>()),
  projectAccess: vi.fn(async () => h.access),
}))

import { agentTicketCap } from './agentCap'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'

const bob: CapabilityPrincipal = { id: 'bob', role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [] }
const OFF = { runScans: false, useAgent: false, exploit: false, manage: false }
const writeShare = (toggles: Partial<typeof OFF>) =>
  ({ project: { id: 'P-alice', userId: 'alice' }, level: 'write', toggles: { rawData: true, ...OFF, ...toggles }, via: 'share' })
const cap = () => agentTicketCap({ principal: bob, actingAs: null }, 'P-alice')

beforeEach(() => {
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => setFlagsForTests(null))

describe('agentTicketCap follows the write toggles (step 5.4)', () => {
  test('no toggle: none of the four', async () => {
    h.access = writeShare({ runScans: true, manage: true })
    expect(await cap()).toEqual([])
  })

  test('Exploitation & shells alone: both approvals and Kali exec, no Fireteam', async () => {
    h.access = writeShare({ exploit: true })
    expect(await cap()).toEqual(['agent:approve_phase', 'agent:approve_dangerous', 'agent:kali_exec'])
  })

  test('Use AI agent alone: Fireteam only', async () => {
    h.access = writeShare({ useAgent: true })
    expect(await cap()).toEqual(['agent:fireteam'])
  })

  test('both: all four', async () => {
    h.access = writeShare({ useAgent: true, exploit: true })
    expect(await cap()).toEqual(['agent:approve_phase', 'agent:approve_dangerous', 'agent:fireteam', 'agent:kali_exec'])
  })
})

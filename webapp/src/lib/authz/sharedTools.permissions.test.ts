/**
 * sharedToolAccess with RBAC_PERMISSIONS_ENABLED on (step 3.9, PE-31): each shared tool is its
 * platform permission, asked through can(), so the account type alone no longer decides. An
 * admin profile that holds it (`admin`; Root every one), a member's override (`override`) or a
 * legacy grant before step 3.15's conversion (`legacy`) admit the person; a User manager or a
 * member without one does not, unless the escape hatch admits a pre-upgrade account (`compat`,
 * which stays the call sites' with the switch either way). With the switch off the answers are
 * Phase 1's (sharedTools.test.ts, sharedToolsCompat.test.ts).
 *
 * Real capability resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown, audit: [] as { action: string; createdAt: Date }[] }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb() as unknown as Record<string, Record<string, unknown>>
  // The escape hatch's cutoff row and step 3.15's conversion marker.
  db.auditLog.findFirst = async ({ where }: { where: { action: string } }) =>
    h.audit.find((r) => r.action === where.action) ?? null
  h.db = db
  return { default: db, prisma: db }
})

import type { AccountDb, AccountSeed } from './__testing__/accountDb'
import {
  LEGACY_GRANTS_CUTOFF_ACTION, SHARED_TOOLS, SHARED_TOOL_PERMISSIONS, resetSharedToolsForTests, sharedToolAccess, type SharedTool,
} from './sharedTools'
import { LEGACY_OVERRIDES_MARKER, clearLegacyConversionCacheForTests } from './legacyOverrides'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests, loadPrincipal } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'

const db = () => h.db as AccountDb
const ALLOWED = (via: string) => ({ allowed: true, via })
const DENIED = { allowed: false, via: null }

async function access(userId: string, tool: SharedTool) {
  const principal = await loadPrincipal(userId)
  return sharedToolAccess(principal!, tool)
}

async function each(userId: string) {
  return Object.fromEntries(await Promise.all(SHARED_TOOLS.map(async (t) => [t, await access(userId, t)])))
}

beforeEach(() => {
  db().reset()
  h.audit.length = 0
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-full', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-po', role: 'admin', adminProfileId: 'builtin:platform-operator' },
    { id: 'member-1' },
    { id: 'member-kali' },
    { id: 'member-legacy', legacyGrants: ['tunnels'] },
    { id: 'member-denied', legacyGrants: ['tunnels'] },
    // An account created after the upgrade's cutoff row: never under the escape hatch.
    { id: 'member-new', createdAt: new Date('2026-11-12T09:00:00Z') } as AccountSeed,
  ])
  db().seedOverride({ userId: 'member-kali', permission: 'platform:kali_terminal', effect: 'grant', reason: 'kept from 7.7.x' })
  db().seedOverride({ userId: 'member-denied', permission: 'platform:tunnels', effect: 'deny', reason: 'incident' })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  clearLegacyConversionCacheForTests()
  resetSharedToolsForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('sharedToolAccess asks the platform permission (switch on)', () => {
  test('each tool names its §5.2 platform permission', () => {
    expect(SHARED_TOOL_PERMISSIONS).toEqual({
      kali_terminal: 'platform:kali_terminal',
      shell_sessions_all: 'platform:shell_sessions',
      tunnels: 'platform:tunnels',
      emergency_stop_all: 'platform:emergency_stop',
      nuclei_templates_all: 'platform:nuclei_templates',
    })
  })

  test('Root and a Full admin hold every tool, as an admin', async () => {
    for (const id of ['root-1', 'admin-full']) {
      expect(await each(id), id).toEqual(Object.fromEntries(SHARED_TOOLS.map((t) => [t, ALLOWED('admin')])))
    }
  })

  test('an admin whose profile lacks the permission is refused: a User manager holds none', async () => {
    expect(await each('admin-um')).toEqual(Object.fromEntries(SHARED_TOOLS.map((t) => [t, DENIED])))
  })

  test('a Platform operator holds every tool but the Kali terminal (§4.5 does not list it)', async () => {
    const got = await each('admin-po')
    expect(got.kali_terminal).toEqual(DENIED)
    for (const t of SHARED_TOOLS.filter((x) => x !== 'kali_terminal')) expect(got[t], t).toEqual(ALLOWED('admin'))
  })

  test("a member's override admits its tool and no other (D-20, a kept grant after 3.15)", async () => {
    const got = await each('member-kali')
    expect(got.kali_terminal).toEqual(ALLOWED('override'))
    for (const t of SHARED_TOOLS.filter((x) => x !== 'kali_terminal')) expect(got[t], t).toEqual(DENIED)
  })

  test('a legacy grant counts until the conversion marker exists, then lapses', async () => {
    expect(await access('member-legacy', 'tunnels')).toEqual(ALLOWED('legacy'))
    h.audit.push({ action: LEGACY_OVERRIDES_MARKER, createdAt: new Date('2026-11-12T10:00:00Z') })
    clearLegacyConversionCacheForTests()
    clearCapabilityCachesForTests()
    expect(await access('member-legacy', 'tunnels')).toEqual(DENIED)
  })

  test('a deny override wins over a legacy grant', async () => {
    expect(await access('member-denied', 'tunnels')).toEqual(DENIED)
  })

  test('a member with nothing gets no tool', async () => {
    expect(await each('member-1')).toEqual(Object.fromEntries(SHARED_TOOLS.map((t) => [t, DENIED])))
  })

  test('the escape hatch still admits a pre-upgrade account the permission refuses, and records the use', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharedToolsCompat: true })
    h.audit.push({ action: LEGACY_GRANTS_CUTOFF_ACTION, createdAt: new Date('2026-11-01T00:00:00Z') })
    expect(await access('admin-um', 'kali_terminal')).toEqual(ALLOWED('compat'))
    expect(await access('member-1', 'emergency_stop_all')).toEqual(ALLOWED('compat'))
    expect(await access('member-new', 'kali_terminal')).toEqual(DENIED)
    expect(db().audit().filter((a) => a.action === 'rbac.compat_used').map((a) => [a.actorId, a.targetId]))
      .toEqual([['admin-um', 'kali_terminal'], ['member-1', 'emergency_stop_all']])
  })

  test('a caller that passes only the account columns gets the account read with its sets', async () => {
    const thin = { id: 'member-kali', role: 'standard', legacyGrants: [], createdAt: new Date(0) }
    expect(await sharedToolAccess(thin, 'kali_terminal')).toEqual(ALLOWED('override'))
    expect(await sharedToolAccess({ ...thin, id: 'gone' }, 'kali_terminal')).toEqual(DENIED)
  })

  test('with the switch off overrides count for nothing and admins hold every tool by role', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    clearPrincipalCacheForTests()
    expect(await access('member-kali', 'kali_terminal')).toEqual(DENIED)
    expect(await each('admin-um')).toEqual(Object.fromEntries(SHARED_TOOLS.map((t) => [t, ALLOWED('admin')])))
    expect(await access('member-legacy', 'tunnels')).toEqual(ALLOWED('legacy'))
  })
})

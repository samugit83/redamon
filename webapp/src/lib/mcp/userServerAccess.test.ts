/**
 * Whose stdio MCP servers run (step 3.9, OQ-48): the OWNER must hold platform:agent_mcp, which
 * replaces step 1.9's administrator role. With RBAC_PERMISSIONS_ENABLED off that is every admin
 * and no member (today's answer); with it on an admin profile that holds it, or a member's
 * override (D-20), and never a User manager. A gone account runs nothing.
 *
 * Real capability resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { ownerRunsStdio } from './userServerAccess'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'

const db = () => h.db as AccountDb

async function runs() {
  const out: Record<string, boolean> = {}
  for (const id of ['root-1', 'admin-full', 'admin-um', 'member-1', 'member-mcp', 'gone']) out[id] = await ownerRunsStdio(id)
  return out
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-full', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'member-1' },
    { id: 'member-mcp' },
  ])
  db().seedOverride({ userId: 'member-mcp', permission: 'platform:agent_mcp', effect: 'grant', reason: 'runs the MCP servers' })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
})
afterEach(() => setFlagsForTests(null))

describe('ownerRunsStdio asks platform:agent_mcp of the owner', () => {
  test('switch on: the profile or the override decides, not the account type', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    expect(await runs()).toEqual({ 'root-1': true, 'admin-full': true, 'admin-um': false, 'member-1': false, 'member-mcp': true, gone: false })
  })

  test('switch off: every admin and no member, as before (the override counts for nothing)', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    expect(await runs()).toEqual({ 'root-1': true, 'admin-full': true, 'admin-um': true, 'member-1': false, 'member-mcp': false, gone: false })
  })
})

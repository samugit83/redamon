/**
 * The `cap` claim of an `agent` ticket (step 3.9b; SH-34): which of the four agent permissions the
 * agent itself enforces (`agent:approve_phase`, `agent:approve_dangerous`, `agent:fireteam`,
 * `agent:kali_exec`) the person holds on the ticket's project, decided by can() on that project
 * and, under act-as, held by both the admin and the account acted as (§4.7). The agent refuses an
 * approval, a dangerous-tool confirmation or a Fireteam member confirmation the claim lacks
 * (agentic/tests/test_approval_cap.py).
 *
 * Step 5.2a: with write sharing in force a write share reaches none of the four either, until step
 * 5.6 turns the run toggles on (`effectiveToggles`), whatever toggles its row holds.
 *
 * Prisma (projects, the instance row, custom sets) is a double; the registry, the built-in sets,
 * the resolution and can() are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const db = vi.hoisted(() => ({
  projects: new Map<string, { id: string; userId: string }>(),
  instance: null as Record<string, unknown> | null,
  failProjects: false,
  bobShare: null as Record<string, unknown> | null,
}))
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
const projectFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  if (db.failProjects) throw Object.assign(new Error('db down'), { code: 'P1001' })
  const row = db.projects.get(where.id)
  return row ? { ...row } : null
})
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: async () => null },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: async () => [] },
    project: { findUnique: (a: { where: { id: string } }) => projectFindUnique(a) },
    // Step 4.3: bob holds a share of alice's project with Raw data, at the stored `write` level.
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) =>
        where.projectId_userId.projectId === 'P-alice' && where.projectId_userId.userId === 'bob'
          ? { access: 'write', rawData: true, expiresAt: null, user: { status: 'active' }, ...db.bobShare }
          : null,
    },
    projectBreakGlass: { findFirst: async () => null },
  },
}))

import { AGENT_TICKET_CAPS, agentTicketCap } from './agentCap'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { PERMISSIONS } from './permissions'

function member(id: string, over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return { id, role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [], ...over }
}
function admin(id: string): CapabilityPrincipal {
  return member(id, { role: 'admin' })
}
const RECON_OPERATOR = { permissionSets: ['builtin:recon-operator'] }
const alone = (principal: CapabilityPrincipal) => ({ principal, actingAs: null })

beforeEach(() => {
  db.projects.clear()
  db.projects.set('P-alice', { id: 'P-alice', userId: 'alice' })
  db.projects.set('P-bob', { id: 'P-bob', userId: 'bob' })
  db.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }
  db.failProjects = false
  db.bobShare = null
  instanceFindUnique.mockClear()
  projectFindUnique.mockClear()
  setFlagsForTests({ identity: true, permissions: true })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
})

describe('the four permissions the agent enforces', () => {
  test('the same four, in the order of agentic/ws_ticket.py AGENT_CAPS', () => {
    expect([...AGENT_TICKET_CAPS]).toEqual(['agent:approve_phase', 'agent:approve_dangerous', 'agent:fireteam', 'agent:kali_exec'])
    for (const p of AGENT_TICKET_CAPS) expect(PERMISSIONS[p].scope).toBe('project')
  })
})

describe('agentTicketCap (switch on)', () => {
  test('a member never assigned a set (Default member) holds all four on their project', async () => {
    expect(await agentTicketCap(alone(member('alice')), 'P-alice')).toEqual([...AGENT_TICKET_CAPS])
  })

  test('a Recon operator holds Fireteam only: no approval into exploitation, no dangerous tools, no Kali (E2E P3-05)', async () => {
    expect(await agentTicketCap(alone(member('alice', RECON_OPERATOR)), 'P-alice')).toEqual(['agent:fireteam'])
  })

  test('a Read-only analyst holds none', async () => {
    expect(await agentTicketCap(alone(member('alice', { permissionSets: ['builtin:read-only-analyst'] })), 'P-alice')).toEqual([])
  })

  test('a deny override takes its permission out', async () => {
    const denied = member('alice', { permissionOverrides: [{ permission: 'agent:approve_dangerous', effect: 'deny', expiresAt: null, reason: null }] })
    expect(await agentTicketCap(alone(denied), 'P-alice')).toEqual(['agent:approve_phase', 'agent:fireteam', 'agent:kali_exec'])
  })

  test('each permission is asked of the project: one read per permission, by the ticket\'s project', async () => {
    await agentTicketCap(alone(member('alice')), 'P-alice')
    expect(projectFindUnique).toHaveBeenCalledTimes(AGENT_TICKET_CAPS.length)
    for (const [arg] of projectFindUnique.mock.calls) expect(arg.where.id).toBe('P-alice')
  })

  test('a project the person cannot see holds nothing (fail closed)', async () => {
    expect(await agentTicketCap(alone(member('alice')), 'P-bob')).toEqual([])
    expect(await agentTicketCap(alone(member('alice')), 'P-none')).toEqual([])
  })

  test('a failed read throws: never a cap by default', async () => {
    db.failProjects = true
    await expect(agentTicketCap(alone(member('alice')), 'P-alice')).rejects.toThrow('db down')
  })

  test('a critical read: the instance default set changed a moment ago counts at once', async () => {
    expect(await agentTicketCap(alone(member('alice')), 'P-alice')).toEqual([...AGENT_TICKET_CAPS])
    db.instance = { ...db.instance, defaultMemberSetId: 'builtin:recon-operator' }
    expect(await agentTicketCap(alone(member('alice')), 'P-alice')).toEqual(['agent:fireteam'])
  })
})

describe('agentTicketCap on a shared project (step 4.3): a read share holds none', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true } }
  })

  test('each of the four needs a write level, which a share at read (even with Raw data) never reaches', async () => {
    for (const p of AGENT_TICKET_CAPS) expect([p, ['W+A', 'W+X'].includes(PERMISSIONS[p].level as string)]).toEqual([p, true])
    // bob holds all four as a Default member and sees the project through the share: still none.
    expect(await agentTicketCap(alone(member('bob')), 'P-alice')).toEqual([])
    // An admin acting as bob gets none either; and oversight (the admin's own) never applies while acting.
    expect(await agentTicketCap({ principal: admin('admin-1'), actingAs: member('bob') }, 'P-alice')).toEqual([])
    expect(await agentTicketCap(alone(admin('admin-1')), 'P-alice')).toEqual([])
  })
})

describe('agentTicketCap on a shared project with write sharing in force (step 5.2a)', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true, maxLevel: 'write' } }
  })

  test('run toggles read false until 5.6: a write share holds none of the four, whatever its row says', async () => {
    db.bobShare = { runScans: true, useAgent: true, exploit: true, manage: true }
    expect(await agentTicketCap(alone(member('bob')), 'P-alice')).toEqual([])
    db.bobShare = { runScans: false, useAgent: false, exploit: false, manage: false }
    expect(await agentTicketCap(alone(member('bob')), 'P-alice')).toEqual([])
  })

  test('an admin acting as the collaborator holds none (D-22), and the owner holds all four as before', async () => {
    db.bobShare = { runScans: true, useAgent: true, exploit: true, manage: true }
    expect(await agentTicketCap({ principal: admin('admin-1'), actingAs: member('bob') }, 'P-alice')).toEqual([])
    expect(await agentTicketCap(alone(member('alice')), 'P-alice')).toEqual([...AGENT_TICKET_CAPS])
  })
})

describe('agentTicketCap under act-as: what both people hold (§4.7, IM-09)', () => {
  test('an admin acting as a Recon operator gets the member\'s cap, on the member\'s project', async () => {
    const cap = await agentTicketCap({ principal: admin('admin-1'), actingAs: member('alice', RECON_OPERATOR) }, 'P-alice')
    expect(cap).toEqual(['agent:fireteam'])
  })

  test('an admin acting as a Default member gets all four', async () => {
    expect(await agentTicketCap({ principal: admin('admin-1'), actingAs: member('alice') }, 'P-alice')).toEqual([...AGENT_TICKET_CAPS])
  })

  test('an admin denied a permission does not borrow it from the account acted as', async () => {
    const denied = member('admin-1', { role: 'admin', permissionOverrides: [{ permission: 'agent:approve_phase', effect: 'deny', expiresAt: null, reason: null }] })
    const cap = await agentTicketCap({ principal: denied, actingAs: member('alice') }, 'P-alice')
    expect(cap).not.toContain('agent:approve_phase')
    expect(cap).toContain('agent:approve_dangerous')
  })
})

describe('agentTicketCap with the permissions switch off: today\'s product (PE-27)', () => {
  for (const identity of [true, false]) {
    test(`identity ${identity ? 'on' : 'off'}: a member and an admin hold all four on their project`, async () => {
      setFlagsForTests({ identity, permissions: false })
      db.projects.set('P-admin', { id: 'P-admin', userId: 'admin-1' })
      expect(await agentTicketCap(alone(member('alice', RECON_OPERATOR)), 'P-alice')).toEqual([...AGENT_TICKET_CAPS])
      expect(await agentTicketCap(alone(admin('admin-1')), 'P-admin')).toEqual([...AGENT_TICKET_CAPS])
    })
  }
})

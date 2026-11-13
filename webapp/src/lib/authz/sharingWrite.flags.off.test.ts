/**
 * Write sharing off (RBAC_SHARING_WRITE_ENABLED, Phase 5): every project route answers as after
 * Phase 4 (master plan §9.4, DV-30). The switch requires sharing (and so permissions and identity),
 * and Root's `sharingPolicy.maxLevel` is its second key: with either off a share stored at `write`
 * reads as Phase 4 read it, every write level is refused to it, and no Phase 5 table is read. Each
 * Phase 5 step adds its part here, append-only (5.2, 5.6, 5.8, 5.12, 5.13, 5.14). Steps 5.3 and 5.5
 * run whatever the switch says; their own tests prove that nothing changes for the owner.
 *
 * Step 5.2a adds the write level to projectAccess() and `meetsLevel`. With write sharing not in
 * force (the switch off, set without sharing, or on with Root's policy at read) a collaborator whose
 * row is `write` with every toggle on gets the Phase 4 answer, byte for byte: `read` with the row's
 * Raw data, the share read without its toggle columns, `myAccess` with Raw data alone. Every
 * permission above R and R* is refused to them, the agent ticket's `cap` holds nothing, and the
 * owner's answers do not change. Write grants answer 409 `write_sharing_off` (step 4.4: the
 * collaborators routes' tests pin it); /api/auth/me reports `maxLevel: 'read'` (sharingInForce).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/sharingWrite.flags.off.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'

const db = vi.hoisted(() => {
  const fn = vi.fn
  return {
    policy: { enabled: true, maxLevel: 'write' } as Record<string, unknown>,
    // A write share with every toggle on and Raw data off, so a Phase 4 answer and a write answer differ in each field.
    share: { access: 'write', rawData: false, runScans: true, useAgent: true, exploit: true, manage: true } as Record<string, unknown>,
    instanceFindUnique: fn(),
    projectFindUnique: fn(async ({ where }: { where: { id: string } }) => (where.id === 'P-owner' ? { id: 'P-owner', userId: 'owner' } : null)),
    collaboratorFindUnique: fn(),
    breakGlassFindFirst: fn(async () => null),
    userFindUnique: fn(async () => null),
    setFindMany: fn(async () => []),
  }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: { findUnique: db.instanceFindUnique },
    project: { findUnique: db.projectFindUnique },
    projectCollaborator: { findUnique: db.collaboratorFindUnique },
    projectBreakGlass: { findFirst: db.breakGlassFindFirst },
    user: { findUnique: db.userFindUnique },
    permissionSet: { findMany: db.setFindMany },
  },
}))

import { rbacFlags, setFlagsForTests, type RbacFlags } from './flags'
import { clearSharingPolicyCacheForTests, sharingInForce } from './sharingPolicy'
import { myAccessView, projectAccess } from './projectAccess'
import { can } from './can'
import { agentTicketCap } from './agentCap'
import { classifyChange } from './settingsRisk'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'
import { clearPrincipalCacheForTests } from './principal'
import { clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'

const WEBAPP = path.resolve(__dirname, '../../..')

/** Every production source of the webapp (src/ and scripts/), tests and test helpers left out. */
function productionFiles(): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name)
      if (statSync(full).isDirectory()) {
        if (name !== 'node_modules' && name !== '__testing__' && name !== '__fixtures__') walk(full)
      } else if (/\.(ts|tsx|mjs|js)$/.test(name) && !/\.test\.(ts|tsx|mjs)$/.test(name)) {
        out.push(full)
      }
    }
  }
  walk(path.join(WEBAPP, 'src'))
  walk(path.join(WEBAPP, 'scripts'))
  return out
}

const readersOf = (names: RegExp): string[] =>
  productionFiles().filter((f) => names.test(readFileSync(f, 'utf8'))).map((f) => path.relative(WEBAPP, f)).sort()

function member(id: string): CapabilityPrincipal {
  return { id, role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [] }
}

const PHASE4_SHARE_SELECT = { access: true, rawData: true, expiresAt: true, user: { select: { status: true } } }
const PROJECT_PERMISSIONS = PERMISSION_IDS.filter((p) => PERMISSIONS[p].level !== null)
const ABOVE_READ = PROJECT_PERMISSIONS.filter((p) => !['R', 'R*'].includes(PERMISSIONS[p].level as string))

beforeEach(() => {
  db.policy = { enabled: true, maxLevel: 'write' }
  db.share = { access: 'write', rawData: false, runScans: true, useAgent: true, exploit: true, manage: true }
  db.instanceFindUnique.mockImplementation(async () => ({
    id: 'instance', sharingPolicy: db.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
  }))
  db.collaboratorFindUnique.mockImplementation(async ({ where }: { where: { projectId_userId: { userId: string } } }) =>
    (where.projectId_userId.userId === 'collab' ? { expiresAt: null, user: { status: 'active' }, ...db.share } : null))
  for (const f of [db.instanceFindUnique, db.projectFindUnique, db.collaboratorFindUnique, db.breakGlassFindFirst, db.userFindUnique, db.setFindMany]) f.mockClear()
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const ALL_ON: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true, sharingWrite: true }

describe('RBAC_SHARING_WRITE_ENABLED off (step 5.2a)', () => {
  test('the switch is off unless set, and off while sharing is off', () => {
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_WRITE_ENABLED', '')
    expect(rbacFlags().sharingWrite).toBe(false)
    vi.stubEnv('RBAC_SHARING_ENABLED', 'false')
    vi.stubEnv('RBAC_SHARING_WRITE_ENABLED', 'true')
    expect(rbacFlags().sharingWrite).toBe(false)
  })

  // Sharing not in force: the collaborator sees nothing, as before sharing.
  const NOT_SHARING: Array<[string, Partial<RbacFlags>]> = [
    ['every switch off', {}],
    ['identity + permissions on', { identity: true, permissions: true }],
    ['the write switch set without sharing', { identity: true, permissions: true, sharingWrite: true }],
  ]
  // Sharing in force, write not: the collaborator reads as Phase 4.
  const READ_ONLY: Array<[string, Partial<RbacFlags>, Record<string, unknown>]> = [
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ]

  test.each(NOT_SHARING)('%s: a write share is not read, the collaborator gets 404 everywhere, the owner is unchanged', async (_what, flags) => {
    setFlagsForTests(flags)
    expect(await projectAccess({ userId: 'collab' }, 'P-owner')).toBeNull()
    for (const p of ['project:settings', 'graph:edit', 'recon:read'] as PermissionId[]) {
      expect([p, await can(member('collab'), p, { projectId: 'P-owner' })]).toEqual([p, expect.objectContaining({ allowed: false, status: 404 })])
    }
    expect(await agentTicketCap({ principal: member('collab'), actingAs: null }, 'P-owner')).toEqual([])
    expect(await projectAccess({ userId: 'owner' }, 'P-owner')).toEqual({ project: { id: 'P-owner', userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' })
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    expect((await sharingInForce()).maxLevel).toBe('read')
  })

  test.each(READ_ONLY)('%s: a write share with every toggle reads exactly as Phase 4 read it', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    const access = await projectAccess({ userId: 'collab' }, 'P-owner')
    expect(access).toEqual({ project: { id: 'P-owner', userId: 'owner' }, level: 'read', toggles: { rawData: false }, via: 'share' })
    expect(myAccessView(access!, { name: 'O', email: 'o@example.test' })).toEqual({
      level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'O', email: 'o@example.test' },
    })
    // The share is read as Phase 4 read it: no toggle column.
    for (const [arg] of db.collaboratorFindUnique.mock.calls) expect((arg as { select: unknown }).select).toEqual(PHASE4_SHARE_SELECT)
    db.share = { ...db.share, rawData: true }
    expect(await projectAccess({ userId: 'collab' }, 'P-owner')).toEqual({ project: { id: 'P-owner', userId: 'owner' }, level: 'read', toggles: { rawData: true }, via: 'share' })
    expect((await sharingInForce()).maxLevel).toBe('read')
  })

  test.each(READ_ONLY)('%s: every permission above R and R* is refused to the collaborator; the owner keeps every one', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    expect(ABOVE_READ.length).toBeGreaterThan(30)
    // A Default member holds most of them (the level refuses); the opt-in ones (agent:loop) the capability refuses too.
    let byLevel = 0
    for (const p of ABOVE_READ) {
      const d = await can(member('collab'), p, { projectId: 'P-owner' })
      expect([p, d]).toEqual([p, expect.objectContaining({ allowed: false, status: 403 })])
      if (!d.allowed && d.status === 403 && d.reason === 'project_level') byLevel += 1
    }
    expect(byLevel).toBeGreaterThan(30)
    expect((await can(member('collab'), 'recon:read', { projectId: 'P-owner' })).allowed).toBe(true)
    expect(await agentTicketCap({ principal: member('collab'), actingAs: null }, 'P-owner')).toEqual([])
    expect(classifyChange({ naabuRateLimit: 10 }, { naabuRateLimit: 7 }, await projectAccess({ userId: 'collab' }, 'P-owner')).ok).toBe(false)
    for (const p of ['project:delete', 'graph:edit', 'project:settings', 'recon:scan'] as PermissionId[]) {
      expect([p, (await can(member('owner'), p, { projectId: 'P-owner' })).allowed]).toEqual([p, true])
    }
  })

  test('contrast, write sharing in force: the same row reaches write (the cases above are not vacuous)', async () => {
    setFlagsForTests(ALL_ON)
    expect(await projectAccess({ userId: 'collab' }, 'P-owner')).toMatchObject({ level: 'write', toggles: { rawData: true, manage: true } })
    expect((await can(member('collab'), 'project:settings', { projectId: 'P-owner' })).allowed).toBe(true)
    expect(classifyChange({ naabuRateLimit: 10 }, { naabuRateLimit: 7 }, await projectAccess({ userId: 'collab' }, 'P-owner')).ok).toBe(true)
    expect((await sharingInForce()).maxLevel).toBe('write')
  })

  test('no production code reads the write switch outside the named files', () => {
    const WRITE_SWITCH_READERS = [
      // Step 5.6: the consent route exists only with write sharing in force (404 otherwise, block below).
      'src/app/api/projects/[id]/access-policy/route.ts',
      // Step 4.12: the share dialog offers the Read + Write presets disabled whatever the switch says;
      // off, their note reads "Coming when write sharing is on" (sharePresets.test.ts, ShareDialog.test.tsx).
      'src/components/sharing/sharePresets.ts',
      // Step 5.8: conversation sharing, the managers policy and the reassignment of a deleted collaborator's
      // conversations read anything only with the switch on (the conversations block below).
      'src/lib/authz/conversationAccess.ts',
      // The switch itself and its chain (sharingWrite requires sharing).
      'src/lib/authz/flags.ts',
      // Step 5.6: a share route reads the consent only with write in force (maxShareLevel); the usage report's
      // breakdown is read only with the switch on (block below).
      'src/lib/authz/ownerConsent.ts',
      'src/lib/authz/ownerCredentials.ts',
      // Step 5.12: every transfer route answers 404 with the switch off, nothing read, and with Root's policy at
      // read (maxShareLevel) once its guard ran (the transfers block below).
      'src/lib/authz/ownershipTransfer.ts',
      // Step 5.2a: a share stored at write is `write` only with the switch on (through maxShareLevel), tests above.
      'src/lib/authz/projectAccess.ts',
      // Step 4.4: write grants answer 409 write_sharing_off with the switch off (collaborators route tests).
      'src/lib/authz/projectShares.ts',
      // maxShareLevel and sharingInForce: `read` with the switch off (tests above).
      'src/lib/authz/sharingPolicy.ts',
      // Step 5.13: with the switch off the deletion plan answers 404 and the user DELETE asks no plan, tearing every
      // project down as Phase 1 did (the deletion block below; users/[id]/route.delete.wizard.test.ts).
      'src/lib/authz/userDeletion.ts',
      // Step 5.2b: the lists select a share's level and toggles only with write in force (maxShareLevel), so
      // with the switch off they read Phase 4's columns and list a write row as read (readOnlyProject.write.test.ts).
      'src/lib/authz/visibleProjects.ts',
    ]
    expect(readersOf(/\bsharingWrite\b|\bRBAC_SHARING_WRITE_ENABLED\b|\bmaxShareLevel\b/)).toEqual(WRITE_SWITCH_READERS)
  })

  test('no production code names a Phase 5 table or column outside the named readers', () => {
    // Steps 5.6 (ProjectAccessPolicy), 5.8 (ConversationShare, Conversation.formerAuthor*) and 5.12
    // (ProjectTransfer) add each reader with how it stays silent with the switch off. ScanSchedule's
    // `pausedReason` (5.5) is not here: 5.5 runs whatever the switch says.
    const PHASE5_TABLE_READERS: string[] = [
      // Step 7.2: the `--downgrade` report counts the Phase 5 rows and columns a downgrade drops, read-only,
      // whatever the switch; it reads no share or consent for an access decision.
      'scripts/rbac-upgrade-preview.mjs',
      // Step 5.8: the one reader and writer of ConversationShare, of the managers flag on ProjectAccessPolicy and of
      // Conversation.formerAuthor*, each read only with the switch on (and the shares with write in force; block below).
      'src/lib/authz/conversationAccess.ts',
      // Step 5.6: the one reader and writer of ProjectAccessPolicy, asked by projectAccess() only for a write answer
      // (write in force), by the share routes only with write in force, by the access-policy route only past its 404.
      'src/lib/authz/ownerConsent.ts',
      // Step 5.12: the one reader and writer of ProjectTransfer; on completion it also clears the consent and moves the
      // conversations that follow the owner. Reached only past the transfer routes' 404 (the transfers block below).
      'src/lib/authz/ownershipTransfer.ts',
    ]
    const NAMES = new RegExp(
      '\\b(projectAccessPolicy|ProjectAccessPolicy|project_access_policies|accessPolicy|conversationShares?|ConversationShare|' +
      'conversation_shares|projectTransfers?|ProjectTransfer|project_transfers|formerAuthorId|former_author_id|formerAuthorLabel|' +
      'former_author_label)\\b',
    )
    expect(readersOf(NAMES)).toEqual(PHASE5_TABLE_READERS)
  })
})

// Step 5.7a: GET /api/projects/[id]/owner-catalog, the owner's catalogs for a collaborator's project form
// (names and presence, lib/ownerCatalog.ts, mocked here: its own test proves no value leaves it). With write
// sharing not in force a write share with Manage reads the catalog as a Read share does, and the model options
// (`?models=1`, level M: the co-owner's pickers) are refused to it; the owner's answer does not change; with
// sharing off the route does not exist. The real guard, can() and projectAccess() decide.
const catalogDoubles = vi.hoisted(() => ({
  identity: vi.fn(),
  ownerCatalog: vi.fn(async (ownerId: string) => ({ ownerCatalogOf: ownerId })),
  ownerModelOptions: vi.fn(async () => ({ models: { Group: [] } })),
}))
vi.mock('@/lib/session', () => ({ getAuthzIdentity: (...a: unknown[]) => catalogDoubles.identity(...a), mayActAs: async () => false }))
vi.mock('@/lib/ownerCatalog', () => ({
  ownerCatalog: (...a: [string]) => catalogDoubles.ownerCatalog(...a),
  ownerModelOptions: () => catalogDoubles.ownerModelOptions(),
}))

describe('GET /api/projects/[id]/owner-catalog with write sharing not in force (step 5.7a)', () => {
  const signIn = (id: string) =>
    catalogDoubles.identity.mockResolvedValue({ session: { userId: id, role: 'standard' }, principal: member(id), actingAs: null })
  const get = async (query = '') => {
    const [{ NextRequest }, { GET }] = await Promise.all([import('next/server'), import('@/app/api/projects/[id]/owner-catalog/route')])
    return GET(new NextRequest(`http://x/api/projects/P-owner/owner-catalog${query}`), { params: Promise.resolve({ id: 'P-owner' }) })
  }
  beforeEach(() => {
    catalogDoubles.identity.mockReset()
    catalogDoubles.ownerCatalog.mockClear()
    catalogDoubles.ownerModelOptions.mockClear()
  })

  test.each([
    ['every switch off', {}],
    ['identity + permissions on', { identity: true, permissions: true }],
    ['the write switch set without sharing', { identity: true, permissions: true, sharingWrite: true }],
  ] as Array<[string, Partial<RbacFlags>]>)('%s: 404 for the owner and the write share, nothing read', async (_what, flags) => {
    setFlagsForTests(flags)
    for (const who of ['owner', 'collab']) {
      signIn(who)
      const res = await get('?models=1')
      expect([who, res.status, await res.json()]).toEqual([who, 404, { error: 'Not found' }])
    }
    expect(catalogDoubles.identity).not.toHaveBeenCalled()
    expect(catalogDoubles.ownerCatalog).not.toHaveBeenCalled()
    expect(db.projectFindUnique).not.toHaveBeenCalled()
  })

  test.each([
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ] as Array<[string, Partial<RbacFlags>, Record<string, unknown>]>)(
    '%s: the write share with Manage reads the catalog, its model options are refused, the owner keeps both',
    async (_what, flags, policy) => {
      setFlagsForTests(flags)
      db.policy = policy
      signIn('collab')
      const read = await get()
      expect([read.status, await read.json()]).toEqual([200, { ownerCatalogOf: 'owner' }])
      const models = await get('?models=1')
      expect(models.status).toBe(403)
      expect(await models.json()).toEqual(expect.objectContaining({ code: 'forbidden', permission: 'recon:read', level: 'M' }))
      expect(catalogDoubles.ownerModelOptions).not.toHaveBeenCalled()
      signIn('owner')
      const own = await get('?models=1')
      expect([own.status, await own.json()]).toEqual([200, { ownerCatalogOf: 'owner', models: { Group: [] } }])
      expect(catalogDoubles.ownerCatalog.mock.calls.map(([ownerId]) => ownerId)).toEqual(['owner', 'owner'])
    },
  )

  test('contrast, write sharing in force: the same Manage row gets the model options', async () => {
    setFlagsForTests(ALL_ON)
    signIn('collab')
    expect((await get('?models=1')).status).toBe(200)
    expect(catalogDoubles.ownerModelOptions).toHaveBeenCalledTimes(1)
  })
})

// Step 5.1b: every settings writer (the project PUT, the RoE replace and remove, the MCP settings, preset and scope
// tools) judges a collaborator's change with classifyChange, and the owner's not at all. With write sharing not in
// force no collaborator holds a level any of them asks, and the owner's change of every class passes in every state,
// so no save answers differently.
describe('the settings writers with write sharing not in force (step 5.1b)', () => {
  const STATES: Array<[string, Partial<RbacFlags>, Record<string, unknown>]> = [
    ['every switch off', {}, { enabled: true, maxLevel: 'write' }],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ]
  // An ordinary column, a gate loosened, the scope widened, an owner's secret and who the target belongs to.
  const STORED = { naabuRateLimit: 10, agentRequireToolConfirmation: true, targetDomain: 'example.test', httpxCustomHeaders: ['X-Fake: 1'], engagementKind: 'internal' }
  const EVERY_CLASS = { naabuRateLimit: 7, agentRequireToolConfirmation: false, targetDomain: 'other.example.test', httpxCustomHeaders: [], engagementKind: 'third_party' }

  test.each(STATES)("%s: the owner's change of every class passes; a write share reaches no writer", async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    expect(classifyChange(STORED, EVERY_CLASS, await projectAccess({ userId: 'owner' }, 'P-owner'))).toMatchObject({ ok: true, refused: [] })
    for (const p of ['project:settings', 'preset:apply', 'project:rescope', 'roe:manage', 'engagement:authorize'] as PermissionId[]) {
      expect([p, (await can(member('collab'), p, { projectId: 'P-owner' })).allowed]).toEqual([p, false])
    }
    const collab = await projectAccess({ userId: 'collab' }, 'P-owner')
    expect(classifyChange(STORED, EVERY_CLASS, collab).refused.map(c => c.key)).toEqual(Object.keys(EVERY_CLASS).sort())
  })
})

// Step 5.11: the second-writer check (projectWriters.ts) refuses a start only while ANOTHER person writes the project.
// With write sharing not in force no collaborator reaches a level that starts a writer (the scans W+S, the agent and
// triage W+A), so every live writer is the owner's and the owner's starts and agent tickets answer as before; with
// sharing not in force the check reads nothing at all, whatever runs (DV-30).
const writersOrchestrator = vi.hoisted(() => vi.fn())
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => writersOrchestrator(...a) }))

describe('the second-writer check with write sharing not in force (step 5.11)', () => {
  const WRITER_STARTS: PermissionId[] = ['recon:scan', 'recon:partial', 'scan:gvm', 'scan:secrets', 'scan:supply_chain', 'scan:ai_attack', 'agent:chat', 'triage:run']

  test.each([
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ] as Array<[string, Partial<RbacFlags>, Record<string, unknown>]>)('%s: a write-stored share with every toggle starts no writer', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    for (const p of WRITER_STARTS) {
      expect([p, (await can(member('collab'), p, { projectId: 'P-owner' })).allowed]).toEqual([p, false])
    }
  })

  test("sharing not in force: nothing is read and nothing refused, another person's scan listed or not", async () => {
    const { secondWriterRefusal } = await import('./projectWriters')
    writersOrchestrator.mockResolvedValue({ ok: true, status: 200, json: async () => ({ scans: [{ kind: 'gvm', project_id: 'P-owner', status: 'running', actor_user_id: 'collab' }] }) })
    for (const flags of [{}, { identity: true, permissions: true }] as Array<Partial<RbacFlags>>) {
      setFlagsForTests(flags)
      expect(await secondWriterRefusal({ projectId: 'P-owner', personId: 'owner' })).toBeNull()
      expect(await secondWriterRefusal({ projectId: 'P-owner', personId: 'collab' })).toBeNull()
    }
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    db.policy = { enabled: false }
    clearSharingPolicyCacheForTests()
    expect(await secondWriterRefusal({ projectId: 'P-owner', personId: 'owner' })).toBeNull()
    expect(writersOrchestrator).not.toHaveBeenCalled()
    expect(db.projectFindUnique).not.toHaveBeenCalled()
  })
})

// Step 5.6 (C1): the owner's consent (ProjectAccessPolicy, ownerConsent.ts) and the record of a collaborator's spend of
// the owner's credentials. With write sharing not in force no share is write (above), so no collaborator reaches Run
// scans, Use AI agent or Exploitation & shells and nothing spends the owner's keys: projectAccess() never asks the
// consent; the access-policy route does not exist (404 for GET and POST, the consent not read, nothing written); a share
// route's run toggle meets step 4.4's write refusal, not the consent; with the switch off the usage report carries no
// breakdown and reads no audit row. The owner's own use writes no credits.used row whatever the switches say.
describe('owner credentials with write sharing not in force (step 5.6)', () => {
  const STATES: Array<[string, Partial<RbacFlags>, Record<string, unknown>]> = [
    ['every switch off', {}, { enabled: true, maxLevel: 'write' }],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ]
  const consentRead = vi.fn(async () => ({ ownerCredentialConsentAt: new Date('2026-11-01T00:00:00Z'), ownerCredentialConsentById: 'owner' }))
  const auditRead = vi.fn(async () => [])
  const auditWrite = vi.fn(async ({ data }: { data: unknown }) => data)

  beforeEach(async () => {
    const prisma = (await import('@/lib/prisma')).default as unknown as Record<string, unknown>
    prisma.projectAccessPolicy = { findUnique: consentRead, upsert: vi.fn() }
    prisma.auditLog = { findMany: auditRead, create: auditWrite }
    for (const f of [consentRead, auditRead, auditWrite]) f.mockClear()
  })
  afterEach(async () => {
    const prisma = (await import('@/lib/prisma')).default as unknown as Record<string, unknown>
    delete prisma.projectAccessPolicy
    delete prisma.auditLog
  })

  test.each(STATES)('%s: a consent kept in the table opens nothing and is never read', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    const access = await projectAccess({ userId: 'collab' }, 'P-owner')
    expect(access === null || access.level === 'read').toBe(true)
    for (const p of ['recon:scan', 'agent:chat', 'agent:assistants', 'triage:run', 'agent:sessions'] as PermissionId[]) {
      expect([p, (await can(member('collab'), p, { projectId: 'P-owner' })).allowed]).toEqual([p, false])
    }
    const { spendToggleConsentRefusal } = await import('./ownerConsent')
    expect(await spendToggleConsentRefusal('P-owner', policy as never, { access: 'write', useAgent: true })).toBeNull()
    // With the switch off the report has no breakdown and reads nothing; with Root's policy at read it still
    // lists what collaborators spent while it allowed write (history, the audit table only).
    if (!flags.sharingWrite) {
      const { collaboratorSpends } = await import('./ownerCredentials')
      expect(await collaboratorSpends('owner')).toBeNull()
      expect(auditRead).not.toHaveBeenCalled()
    }
    expect(consentRead).not.toHaveBeenCalled()
  })

  test.each(STATES)('%s: the access-policy route answers 404 for GET and POST, nothing read or written', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    catalogDoubles.identity.mockResolvedValue({ session: { userId: 'owner', role: 'standard' }, principal: member('owner'), actingAs: null })
    const [{ NextRequest }, { GET, POST }] = await Promise.all([import('next/server'), import('@/app/api/projects/[id]/access-policy/route')])
    const params = { params: Promise.resolve({ id: 'P-owner' }) }
    expect((await GET(new NextRequest('http://x/api/projects/P-owner/access-policy'), params)).status).toBe(404)
    const post = await POST(new NextRequest('http://x/api/projects/P-owner/access-policy', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ownerCredentialConsent: false }),
    }), params)
    expect(post.status).toBe(404)
    expect(consentRead).not.toHaveBeenCalled()
    expect(auditWrite).not.toHaveBeenCalled()
  })

  test("the owner's own spend writes no credits.used row, whatever the switches", async () => {
    const { recordOwnerCredentialSpend } = await import('./ownerSpend')
    for (const [, flags] of STATES) {
      setFlagsForTests(flags)
      expect(await recordOwnerCredentialSpend({ projectId: 'P-owner', ownerId: 'owner', userId: 'owner', feature: 'scan' })).toBe(false)
    }
    expect(auditWrite).not.toHaveBeenCalled()
  })
})

// Step 5.2b: the MCP write tools ask their permissions' levels of a shared project (W, W+S, M; lib/mcp/
// writeLevels.shares.test.ts) and the Kali terminal ticket asks W+X. With write sharing not in force a share
// stored as write with every toggle reads as Read, so every one of those levels is refused to an opted-in
// token, naming Read access as before step 5.2; the owner's token reaches every level. Real mcpProjectAccess
// and projectAccess over this file's Prisma double.
describe('MCP write tools with write sharing not in force (step 5.2b)', () => {
  const COLLAB_TOKEN = { userId: 'collab', sharedProjects: { allowlist: [] } }
  test.each([
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ] as Array<[string, Partial<RbacFlags>, Record<string, unknown>]>)('%s: every write level refused as Read; the owner unchanged', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    const { mcpProjectAccess, McpLevelDenied } = await import('@/lib/mcpAuth')
    for (const level of ['W', 'W+S', 'W+X', 'M'] as const) {
      const refused = mcpProjectAccess(COLLAB_TOKEN, 'P-owner', level)
      await expect(refused, level).rejects.toBeInstanceOf(McpLevelDenied)
      await expect(refused, level).rejects.toThrow(/at Read access/)
    }
    await expect(mcpProjectAccess(COLLAB_TOKEN, 'P-owner', 'R')).resolves.toMatchObject({ access: { level: 'read' } })
    for (const level of ['W', 'W+S', 'M', 'O'] as const) {
      await expect(mcpProjectAccess({ userId: 'owner' }, 'P-owner', level)).resolves.toMatchObject({ access: { level: 'owner' } })
    }
  })
})

// Step 5.8 (SH-22, DV-23, T24): conversation privacy, sharing and retention (conversationAccess.ts). With write
// sharing not in force a conversation is its author's alone, as after Phase 4: no other person reads one (shared,
// the owner's co-owner policy, Root's break-glass), the share and policy routes answer 404, the list holds the
// person's own and nothing new, and no write route judges a reassignment. With the switch off a deleted
// collaborator's conversations go with the account as before and no Phase 5 table or column is read (this file's
// Prisma double has no conversation, share or policy table: any read would throw).
describe('conversations with write sharing not in force (step 5.8)', () => {
  const STATES: Array<[string, Partial<RbacFlags>, Record<string, unknown>]> = [
    ['every switch off', {}, { enabled: true, maxLevel: 'write' }],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["the write switch on, Root's policy at read", ALL_ON, { enabled: true, maxLevel: 'read' }],
  ]

  test.each(STATES)('%s: conversation sharing is not in force; another person reads nothing and the list is the own', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    const { conversationSharingInForce, readableConversationsWhere } = await import('./conversationAccess')
    expect(await conversationSharingInForce()).toBe(false)
    expect(await conversationSharingInForce({ fresh: true })).toBe(false)
    const owner = { project: { id: 'P-owner', userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' } as const
    expect(await readableConversationsWhere(owner, 'P-owner', 'owner')).toEqual({ projectId: 'P-owner', userId: 'owner' })
  })

  test.each(STATES.slice(0, 2))('%s: no reassignment and no read-only refusal, nothing read', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    const { readOnlyConversationRefusal, reassignConversationsOfDeletedAuthor } = await import('./conversationAccess')
    const tx = { conversation: { findMany: vi.fn(), updateMany: vi.fn() } }
    expect(await reassignConversationsOfDeletedAuthor(tx as never, 'collab', 'Collab')).toBeNull()
    expect(tx.conversation.findMany).not.toHaveBeenCalled()
    expect(await readOnlyConversationRefusal('c1')).toBeNull()
  })

  test.each(STATES)('%s: the share and policy routes answer 404, before any session or table is read', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.policy = policy
    catalogDoubles.identity.mockClear()
    const { NextRequest } = await import('next/server')
    const { POST: SHARE } = await import('@/app/api/conversations/[id]/share/route')
    const { GET, POST } = await import('@/app/api/conversations/policy/route')
    const json = (url: string, body: unknown) => new NextRequest(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    expect((await SHARE(json('http://x/api/conversations/c1/share', { shared: true }), { params: Promise.resolve({ id: 'c1' }) })).status).toBe(404)
    expect((await GET(new NextRequest('http://x/api/conversations/policy?projectId=P-owner'))).status).toBe(404)
    expect((await POST(json('http://x/api/conversations/policy?projectId=P-owner', { managersSeeAllConversations: true }))).status).toBe(404)
    expect(catalogDoubles.identity).not.toHaveBeenCalled()
  })
})

// Step 5.12: ownership transfer. With the write switch off every transfer route (the offer and its state, accept,
// decline, cancel, the re-pick dismissal and the account's banner feed) answers 404 before a session or a table is
// read; with Root's policy at read the owner's routes answer 404 once their guard ran, and nothing about a transfer
// is read (this file's Prisma double has no transfer table: a read would fail the route). The user deletion keeps
// the Phase 1 teardown (step 5.13 builds the wizard).
describe('ownership transfer with write sharing not in force (step 5.12)', () => {
  const json = async (url: string, body: unknown = {}) => {
    const { NextRequest } = await import('next/server')
    return new NextRequest(url, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://x' }, body: JSON.stringify(body) })
  }
  const params = { params: Promise.resolve({ id: 'P-owner' }) }

  test.each([
    ['every switch off', {}],
    ['sharing on, the write switch off', { identity: true, permissions: true, sharing: true }],
    ['the write switch set without sharing', { identity: true, permissions: true, sharingWrite: true }],
  ] as Array<[string, Partial<RbacFlags>]>)('%s: every transfer route answers 404, before any session or table is read', async (_what, flags) => {
    setFlagsForTests(flags)
    catalogDoubles.identity.mockClear()
    const { NextRequest } = await import('next/server')
    const offer = await import('@/app/api/projects/[id]/transfer/route')
    const routes = await Promise.all([
      import('@/app/api/projects/[id]/transfer/accept/route'), import('@/app/api/projects/[id]/transfer/decline/route'),
      import('@/app/api/projects/[id]/transfer/cancel/route'), import('@/app/api/projects/[id]/transfer/acknowledge/route'),
    ])
    const feed = await import('@/app/api/projects/transfers/route')
    expect((await offer.GET(new NextRequest('http://x/api/projects/P-owner/transfer'), params)).status).toBe(404)
    expect((await offer.POST(await json('http://x/api/projects/P-owner/transfer', { toUserId: 'collab', oldOwnerRole: 'leave' }), params)).status).toBe(404)
    for (const { POST } of routes) expect((await POST(await json('http://x/api/projects/P-owner/transfer/x'), params)).status).toBe(404)
    expect((await feed.GET(new NextRequest('http://x/api/projects/transfers'))).status).toBe(404)
    expect(catalogDoubles.identity).not.toHaveBeenCalled()
    expect(db.projectFindUnique).not.toHaveBeenCalled()
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
  })

  test("the write switch on, Root's policy at read: the owner's offer, cancel and dismissal answer 404 after the guard; nothing about a transfer is read", async () => {
    setFlagsForTests(ALL_ON)
    db.policy = { enabled: true, maxLevel: 'read' }
    catalogDoubles.identity.mockResolvedValue({ session: { userId: 'owner', role: 'standard' }, principal: member('owner'), actingAs: null })
    const offer = await import('@/app/api/projects/[id]/transfer/route')
    const { POST: CANCEL } = await import('@/app/api/projects/[id]/transfer/cancel/route')
    const { POST: DISMISS } = await import('@/app/api/projects/[id]/transfer/acknowledge/route')
    const res = await offer.POST(await json('http://x/api/projects/P-owner/transfer', { toUserId: 'collab', oldOwnerRole: 'leave', stepUpPassword: 'pw' }), params)
    expect([res.status, await res.json()]).toEqual([404, { error: 'Not found' }])
    expect((await CANCEL(await json('http://x/api/projects/P-owner/transfer/cancel'), params)).status).toBe(404)
    expect((await DISMISS(await json('http://x/api/projects/P-owner/transfer/acknowledge'), params)).status).toBe(404)
    const { writeSharingInForce } = await import('./ownershipTransfer')
    expect(await writeSharingInForce()).toBe(false)
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
  })

  test('contrast, write sharing in force: the same offer reaches the transfer writer (the cases above are not vacuous)', async () => {
    setFlagsForTests(ALL_ON)
    const { writeSharingInForce } = await import('./ownershipTransfer')
    expect(await writeSharingInForce()).toBe(true)
  })
})

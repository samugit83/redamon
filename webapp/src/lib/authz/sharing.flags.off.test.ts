/**
 * Sharing off (RBAC_SHARING_ENABLED, Phase 4): every project is private exactly as after Phase 3
 * (master plan §9.4, DV-30). The switch requires the permissions switch, and the instance policy
 * (`sharingPolicy.enabled`, Root's) is its second key: with either off no collaborator or
 * break-glass row is read and every list and answer is the owner-only one. Each Phase 4 step adds
 * its part here (4.3, 4.4, 4.5, 4.10, 4.11, 4.13, 4.14).
 *
 * Step 4.2 adds the tables, the token opt-in columns and the policy. With the switch off:
 *   - the policy reader reads nothing and "sharing in force" answers off;
 *   - /api/auth/me carries no `sharing` key (route.sharing.test.ts pins both switch states);
 *   - /api/admin/instance-settings neither shows the policy nor reads it from a body
 *     (route.sharingPolicy.test.ts, "RBAC_SHARING_ENABLED off");
 *   - no production file other than the named ones names a sharing table, the token opt-in
 *     columns or the policy column, and only the named ones read a row.
 *
 * Step 4.3 adds the readers: projectAccess() and the project lists. With sharing not in force (the
 * switch off, or on with the policy disabled) a person who holds a live share with Raw data, an
 * unexpired break-glass row and `projects:oversee` still gets null on someone else's project, no
 * share or break-glass row is read (nor, with the switch off, the policy), and the lists' filter is
 * Phase 3's `{userId}`.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/sharing.flags.off.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'

const db = vi.hoisted(() => {
  const fn = vi.fn
  const later = new Date(Date.now() + 3_600_000)
  const account = (id: string, role: string) => ({
    id, email: `${id}@example.test`, name: id, role, password: 'hash', createdAt: new Date(0), legacyGrants: [],
    status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
    permissionSets: [], permissionOverrides: [],
  })
  return {
    instanceFindUnique: fn(async () => ({ id: 'instance', sharingPolicy: { enabled: true } })),
    projectFindUnique: fn(async ({ where }: { where: { id: string } }) => (where.id === 'P-owner' ? { id: 'P-owner', userId: 'owner' } : null)),
    projectFindMany: fn(async () => []),
    // Every way in at once, so a reader that skipped the gate would let the stranger in.
    collaboratorFindUnique: fn(async () => ({ access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })),
    breakGlassFindFirst: fn(async () => ({ expiresAt: later })),
    userFindUnique: fn(async ({ where }: { where: { id: string } }) => account(where.id, 'admin')),
    setFindMany: fn(async () => []),
  }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: { findUnique: db.instanceFindUnique },
    project: { findUnique: db.projectFindUnique, findMany: db.projectFindMany },
    projectCollaborator: { findUnique: db.collaboratorFindUnique },
    projectBreakGlass: { findFirst: db.breakGlassFindFirst },
    user: { findUnique: db.userFindUnique },
    permissionSet: { findMany: db.setFindMany },
  },
}))

import { rbacFlags, setFlagsForTests } from './flags'
import { clearSharingPolicyCacheForTests, sharingInForce, sharingPolicyInForce } from './sharingPolicy'
import { projectAccess } from './projectAccess'
import { ownedProjectsWhere, visibleProjectIds, visibleProjectsWhere } from './visibleProjects'
import { clearPrincipalCacheForTests } from './principal'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'

const instanceFindUnique = db.instanceFindUnique

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

beforeEach(() => {
  for (const f of Object.values(db)) f.mockClear()
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
})

describe('RBAC_SHARING_ENABLED off (step 4.2)', () => {
  test('the switch is off unless set, and off while the permissions switch is off', () => {
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_ENABLED', '')
    expect(rbacFlags().sharing).toBe(false)
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'false')
    vi.stubEnv('RBAC_SHARING_ENABLED', 'true')
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(rbacFlags().sharing).toBe(false)
  })

  test.each([
    ['identity + permissions on', { identity: true, permissions: true }],
    ['sharing set without permissions', { identity: true, sharing: true }],
    ['every switch off', {}],
  ])('%s: the policy is never read, and sharing is not in force whatever the row says', async (_what, flags) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(await sharingPolicyInForce()).toBeNull()
    expect(await sharingPolicyInForce({ fresh: true })).toBeNull()
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('the switch on but the policy disabled (the stored {} after the upgrade): not in force', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    instanceFindUnique.mockResolvedValueOnce({ id: 'instance', sharingPolicy: {} } as never)
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
  })

  test('no production code names the sharing storage outside the named files', () => {
    const SHARING_STORAGE_READERS = [
      // Step 4.2: shows the policy to admins and takes Root's change only with the switch on.
      'src/app/api/admin/instance-settings/route.ts',
      // Step 4.15: the expiry sweep, which reads the sharing tables only with sharing in force.
      'src/lib/authz/expirySweep.ts',
      // Step 4.3: reads a share and the break-glass rows only with sharing in force (tests below).
      'src/lib/authz/projectAccess.ts',
      // Step 4.2: the policy's shape and reader; the reader reads only with the switch on.
      'src/lib/authz/sharingPolicy.ts',
    ]
    const NAMES = new RegExp(
      '\\b(projectCollaborators?|projectBreakGlass|project_collaborators|project_break_glass|includeSharedProjects|' +
      'include_shared_projects|projectAllowlist|project_allowlist|sharing_policy)\\b|[.]sharingPolicy\\b|\\bsharingPolicy\\s*:',
    )
    const files = productionFiles()
    expect(files).toContain(path.join(WEBAPP, 'src/lib/authz/sharingPolicy.ts'))
    const readers = files.filter((f) => NAMES.test(readFileSync(f, 'utf8'))).map((f) => path.relative(WEBAPP, f)).sort()
    expect(readers).toEqual(SHARING_STORAGE_READERS)
  })

  test('no production code reads a collaborator or break-glass row outside the named readers', () => {
    const ROW_READERS: string[] = [
      // Step 4.15: removes expired rows only with sharing in force (switch and policy); the switch
      // states are pinned in api/internal/rbac/sweep/route.test.ts.
      'src/lib/authz/expirySweep.ts',
      // Step 4.3: projectAccess() and the lists' share filter, both only with sharing in force (tests below).
      'src/lib/authz/projectAccess.ts',
      'src/lib/authz/visibleProjects.ts',
    ]
    const ACCESSORS = /\.(projectCollaborator|projectBreakGlass)\.|\b(collaborators|collaborations|breakGlass)\s*:\s*\{/
    const files = productionFiles()
    const readers = files.filter((f) => ACCESSORS.test(readFileSync(f, 'utf8'))).map((f) => path.relative(WEBAPP, f)).sort()
    expect(readers).toEqual(ROW_READERS)
  })
})

describe('projectAccess() and the project lists with sharing not in force (step 4.3)', () => {
  const NOT_IN_FORCE: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
    ['the switch on, the stored policy invalid (reads as disabled)', { identity: true, permissions: true, sharing: true }, { enabled: 'yes' }],
  ]

  test.each(NOT_IN_FORCE)('%s: a live raw share, a break-glass row and oversight give nothing; no share row is read', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    expect(await projectAccess({ userId: 'stranger' }, 'P-owner')).toBeNull()
    expect(await projectAccess({ userId: 'stranger' }, 'P-owner', { fresh: true })).toBeNull()
    expect(await projectAccess({ userId: 'owner' }, 'P-owner')).toEqual({
      project: { id: 'P-owner', userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner',
    })
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    expect(db.breakGlassFindFirst).not.toHaveBeenCalled()
    // The account (for oversight) is never read either: Phase 3's answer is one project read.
    expect(db.userFindUnique).not.toHaveBeenCalled()
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test.each(NOT_IN_FORCE)('%s: the lists keep the filter of the projects one owns', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    expect(await visibleProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
    await visibleProjectIds({ userId: 'u1' })
    expect(db.projectFindMany).toHaveBeenCalledWith({ where: { userId: 'u1' }, select: { id: true }, orderBy: { createdAt: 'asc' } })
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test('the owned-only filter never follows sharing, in force or not', async () => {
    for (const flags of [{}, { identity: true, permissions: true, sharing: true }]) {
      setFlagsForTests(flags)
      expect(ownedProjectsWhere({ userId: 'u1' })).toEqual({ userId: 'u1' })
    }
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })
})

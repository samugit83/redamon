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
 * Step 4.4 adds the share routes (collaborators, change, revoke, leave), whose writers live in
 * projectShares.ts: with sharing not in force their policy gate answers null, reading no policy with
 * the switch off, so every share route answers 404 having read no share (each route test pins the
 * 404 in the three states, and that no share is read or written).
 *
 * Step 4.5 adds what the lists show with shares (visibleProjects.ts): each project row's own access
 * and the scan activity view's split of the job queue. With sharing not in force no share is
 * selected, the queue split is the person's own rows against everyone else's, and with the switch
 * off GET /api/projects answers its rows without `myAccess` (route.list.shared.test.ts, and the
 * reports and system/jobs route.shared.test.ts, pin the routes in both states).
 *
 * Step 4.14 adds oversight and Root's break-glass (oversight.ts, breakGlass.ts): with sharing not in
 * force no break-glass row and no other account's project is read (projectAccess answers null, so the
 * guard writes no `project.oversee` row), and the break-glass routes and the oversight list answer
 * 404 having read nothing (below; their route tests pin the three states).
 *
 * Step 4.10 adds the MCP token's opt-in to shared projects (mcpAuth.ts, the token routes and screen):
 * with sharing not in force an opted-in token reaches only its owner's projects, no share row is read,
 * and the token routes neither read the opt-in from a body nor list it (route.shares.test.ts,
 * McpTokensTab.shares.test.tsx, sharedTenant.test.ts pin the list and the screen).
 *
 * Step 6.2 adds the admin users directory (lib/authz/userDirectory.ts): with sharing not in force it
 * selects no collaborator count (shared counts read null) and lists no user's shares; with it in force
 * a user's shares are listed only while Root's policy lets admins see every share
 * (api/admin/users/route.test.ts, with the real policy reader for the switch off).
 *
 * Step 6.4 adds the admin projects and shares overviews (lib/authz/adminProjects.ts, adminShares.ts):
 * with sharing not in force the projects list counts no share (counts read null) and offers neither
 * the oversight read nor break-glass, and GET /api/admin/shares and Root's force-revoke answer 404
 * through the share routes' gate before any share is read (below; both route.test.ts files pin the
 * states).
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
import { sharingPolicyForRoutes } from './projectShares'
import { projectAccess } from './projectAccess'
import { ownedProjectsWhere, visibleProjectIds, visibleProjectsWhere } from './visibleProjects'
import { jobQueueScope, myShareSelect, visibleProjects } from './visibleProjects'
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
      // Step 4.4: the live matrix's fixtures (Read shares on a synthetic project), run by hand only.
      'scripts/e2e-rbac-seed.mjs',
      // Step 6.1: the admin console reads `sharingPolicy.adminsSeeAllShares` (GET /api/admin/instance-settings)
      // only while /api/auth/me reports sharing in force; with the switch off auth/me has no `sharing` key, the
      // policy is never asked and the Shares item stays hidden (test at the end; AdminConsole.test.tsx).
      'src/app/admin/AdminConsole.tsx',
      // Step 6.7: the Instance page's sharing panel shows and saves Root's policy only when GET
      // /api/admin/instance-settings carries `sharingPolicy`, which the route sends only with the switch on;
      // without it the page shows no sharing panel and sends no `sharingPolicy` (test at the end;
      // admin/instance/page.test.tsx "no sharing policy in the answer").
      'src/app/admin/instance/SharingPolicyPanel.tsx',
      // Step 4.2: shows the policy to admins and takes Root's change only with the switch on.
      'src/app/api/admin/instance-settings/route.ts',
      // Step 4.10: the token routes read and list the opt-in to shared projects only with the switch on
      // (route.shares.test.ts, "RBAC_SHARING_ENABLED off").
      'src/app/api/users/[id]/mcp-tokens/[tokenId]/route.ts',
      'src/app/api/users/[id]/mcp-tokens/route.ts',
      // Step 4.10: the token screen offers and sends the opt-in only while /api/auth/me reports sharing in force.
      'src/components/settings/mcp-tokens/McpTokensTab.tsx',
      // Step 6.4: the shares overview and Root's force-revoke, reached only past sharingPolicyForRoutes (below).
      'src/lib/authz/adminShares.ts',
      // Step 4.14: Root's break-glass writers, behind the break-glass routes' gate (below).
      'src/lib/authz/breakGlass.ts',
      // Step 4.15: the expiry sweep, which reads the sharing tables only with sharing in force.
      'src/lib/authz/expirySweep.ts',
      // Step 4.14: the oversight list's own shares and break-glass rows, behind its route's gate (below).
      'src/lib/authz/oversight.ts',
      // Step 4.3: reads a share and the break-glass rows only with sharing in force (tests below).
      'src/lib/authz/projectAccess.ts',
      // Step 4.4: the share writers, behind the share routes' gate (sharingPolicyForRoutes, below).
      'src/lib/authz/projectShares.ts',
      // Step 4.2: the policy's shape and reader; the reader reads only with the switch on.
      'src/lib/authz/sharingPolicy.ts',
      // Step 6.2: the admin users directory counts and lists a person's shares only with sharing in
      // force (the policy read through sharingPolicyInForce; api/admin/users/route.test.ts pins both).
      'src/lib/authz/userDirectory.ts',
      // Step 4.10: reads a token's opt-in, which reaches nothing while projectAccess() answers no share (below).
      'src/lib/mcpAuth.ts',
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
      // Step 4.4: the live matrix's fixtures write the Read shares the p4 rows sign in with (run by hand).
      'scripts/e2e-rbac-seed.mjs',
      // Step 6.4: the projects overview counts live shares only with sharing in force (api/admin/projects/route.test.ts).
      'src/lib/authz/adminProjects.ts',
      // Step 6.4: the shares overview and Root's force-revoke, reached only past sharingPolicyForRoutes (below).
      'src/lib/authz/adminShares.ts',
      // Step 4.14: opens and closes break-glass rows, reached only past the break-glass routes' gate (below).
      'src/lib/authz/breakGlass.ts',
      // Step 4.15: removes expired rows only with sharing in force (switch and policy); the switch
      // states are pinned in api/internal/rbac/sweep/route.test.ts.
      'src/lib/authz/expirySweep.ts',
      // Step 4.14: the oversight list's shares and break-glass rows, reached only past its route's gate (below).
      'src/lib/authz/oversight.ts',
      // Step 4.3: projectAccess() and the lists' share filter, both only with sharing in force (tests below).
      'src/lib/authz/projectAccess.ts',
      // Step 4.4: the share writers, reached only past the share routes' gate (below).
      'src/lib/authz/projectShares.ts',
      // Step 6.2: the users directory's shared counts and a user's shares, only with sharing in force (above).
      'src/lib/authz/userDirectory.ts',
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

describe('the share routes with sharing not in force (step 4.4)', () => {
  const NOT_IN_FORCE: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
  ]

  test.each(NOT_IN_FORCE)('%s: the routes\' gate answers null (404), no share read, no policy read with the switch off', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    expect(await sharingPolicyForRoutes()).toBeNull()
    expect(await sharingPolicyForRoutes({ fresh: true })).toBeNull()
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test('each share route answers 404 before anything else while the switch is off', () => {
    const ROUTES = [
      'src/app/api/projects/[id]/collaborators/route.ts',
      'src/app/api/projects/[id]/collaborators/[userId]/route.ts',
      'src/app/api/projects/[id]/leave/route.ts',
    ]
    for (const file of ROUTES) {
      const handlers = readFileSync(path.join(WEBAPP, file), 'utf8').split(/^export const /m).slice(1)
      expect(handlers.length, file).toBeGreaterThan(0)
      for (const handler of handlers) {
        expect(handler, `${file} ${handler.slice(0, 6)}`).toMatch(/^[A-Z]+ = withRouteErrors\([^\n]*\n\s*(?:[^\n]*\n\s*){0,3}if \(!rbacFlags\(\)\.sharing\) return routeNotFound\(\)/)
      }
    }
  })
})

// A person's own access (review of 4.3): the project GET's `myAccess` and GET /my-access exist only
// with the switch on. requireEffectiveUser and requirePermission are doubles; vi.mock is hoisted,
// so they stand for the whole file, but every other export of both modules stays real and only the
// two routes below call them. The switch and projectAccess() are the real ones.
const ownAccess = vi.hoisted(() => ({ eff: { userId: 'owner' } as { userId: string } | null }))
vi.mock('@/lib/access', async () => ({
  ...(await vi.importActual<typeof import('@/lib/access')>('@/lib/access')),
  requireEffectiveUser: async () => {
    const { NextResponse } = await import('next/server')
    return ownAccess.eff ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  },
}))
vi.mock('@/lib/authz/guards', async () => ({
  ...(await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')),
  requirePermission: async (_r: Request, permission: string, opts: { projectId?: string } = {}) => ({
    session: { userId: 'owner', role: 'standard' },
    principal: { id: 'owner', role: 'standard' },
    actingAs: null,
    effective: { userId: 'owner' },
    permission,
    access: { project: { id: opts.projectId, userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' },
  }),
}))

describe("a person's own access with RBAC_SHARING_ENABLED off: no myAccess, no /my-access (review of 4.3)", () => {
  const OFF: Array<[string, Parameters<typeof setFlagsForTests>[0]]> = [
    ['every switch off', {}],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }],
  ]
  const ROW = {
    id: 'P-owner', userId: 'owner', name: 'p', targetDomain: 'example.test', ipMode: false, domainBatchMode: false,
    nucleiSelectedCustomTemplates: [], nucleiTemplates: [], nucleiCustomTemplates: [], authProfile: null,
    user: { id: 'owner', name: 'Owner', email: 'owner@example.test' },
  }

  async function projectGet() {
    const { NextRequest } = await import('next/server')
    const { GET } = await import('@/app/api/projects/[id]/route')
    db.projectFindUnique.mockResolvedValueOnce(ROW as never)
    return GET(new NextRequest('http://x/api/projects/P-owner'), { params: Promise.resolve({ id: 'P-owner' }) })
  }
  async function myAccessGet() {
    const { NextRequest } = await import('next/server')
    const { GET } = await import('@/app/api/projects/[id]/my-access/route')
    return GET(new NextRequest('http://x/api/projects/P-owner/my-access'), { params: Promise.resolve({ id: 'P-owner' }) })
  }

  beforeEach(() => {
    ownAccess.eff = { userId: 'owner' }
  })

  test.each(OFF)('%s: the project GET answers the owner the row and its user as before, without myAccess', async (_what, flags) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await projectGet()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).not.toHaveProperty('myAccess')
    expect(body.user).toEqual(ROW.user)
  })

  test.each(OFF)('%s: GET /my-access does not exist: 404 for the owner and a stranger, nothing read', async (_what, flags) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const eff of [{ userId: 'owner' }, { userId: 'stranger' }, null]) {
      ownAccess.eff = eff
      const res = await myAccessGet()
      expect([eff, res.status]).toEqual([eff, 404])
      expect(await res.json()).toEqual({ error: 'Not found' })
    }
    expect(db.projectFindUnique).not.toHaveBeenCalled()
    expect(db.userFindUnique).not.toHaveBeenCalled()
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('the contrast, the switch on: the owner reads both', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    const mine = { level: 'owner', toggles: { rawData: true }, via: 'owner' }
    expect((await (await projectGet()).json()).myAccess).toEqual({ ...mine, owner: { name: 'Owner', email: 'owner@example.test' } })
    const res = await myAccessGet()
    expect(res.status).toBe(200)
    expect((await res.json()).myAccess).toEqual({ ...mine, owner: { name: 'owner', email: 'owner@example.test' } })
  })
})

describe('the admin console with sharing off (step 6.1)', () => {
  test('it asks the sharing policy only when /api/auth/me reports sharing in force, so the Shares item stays hidden', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/app/admin/AdminConsole.tsx'), 'utf8')
    // One policy read, behind the `sharing` key auth/me omits with the switch off (route.sharing.test.ts);
    // not asked, the answer is 'no' and the Shares section closes.
    expect(src.match(/\/api\/admin\/instance-settings/g)).toHaveLength(1)
    expect(src).toMatch(/useAllSharesView\(user\?\.sharing\?\.enabled === true[ )]/)
    expect(src).toMatch(/return ask \? answer : 'no'/)
  })
})

describe('the project lists with sharing not in force (step 4.5)', () => {
  const NOT_IN_FORCE: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
    ['the switch on, the stored policy invalid (reads as disabled)', { identity: true, permissions: true, sharing: true }, { enabled: 'yes' }],
  ]
  const OWNED_ROW = { id: 'P-owner', userId: 'owner', name: 'p', user: { id: 'owner', name: 'Owner', email: 'owner@example.test' } }

  async function listProjects() {
    const { GET } = await import('@/app/api/projects/route')
    db.projectFindMany.mockResolvedValueOnce([OWNED_ROW] as never)
    return GET()
  }

  beforeEach(() => {
    ownAccess.eff = { userId: 'owner' }
  })

  test.each(NOT_IN_FORCE)('%s: no share is selected and the job queue split is the person\'s own rows', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    const visible = await visibleProjects({ userId: 'u1' })
    expect(visible).toEqual({ where: { userId: 'u1' }, withShares: false })
    expect(myShareSelect({ userId: 'u1' }, visible)).toEqual({})
    expect(jobQueueScope({ userId: 'u1' }, visible)).toEqual({ mine: { userId: 'u1' }, others: { userId: { not: 'u1' } } })
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test.each(NOT_IN_FORCE.slice(0, 3))('%s: GET /api/projects answers the owned rows as before, without myAccess', async (_what, flags) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await listProjects()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual([OWNED_ROW])
    const args = (db.projectFindMany.mock.calls.at(-1) as unknown[] | undefined)?.[0] as { where: unknown; select: Record<string, unknown> }
    expect(args.where).toEqual({ userId: 'owner' })
    expect(args.select).not.toHaveProperty('collaborators')
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('the switch on, the policy disabled: the owned rows, each as the owner (as the project GET), no share selected', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: {} } as never)
    const rows = await (await listProjects()).json()
    expect(rows).toEqual([{ ...OWNED_ROW, myAccess: { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Owner', email: 'owner@example.test' } } }])
    const args = (db.projectFindMany.mock.calls.at(-1) as unknown[] | undefined)?.[0] as { where: unknown; select: Record<string, unknown> }
    expect(args.where).toEqual({ userId: 'owner' })
    expect(args.select).not.toHaveProperty('collaborators')
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })
})

// Step 4.13: the project activity feed (GET /api/projects/[id]/activity, lib/authz/projectActivity.ts).
// With sharing not in force it does not exist: 404 before any audit row is read, and with the switch off
// before the policy is read. The prisma double here has no audit log and requirePermission stands for
// the owner, so a gate that let the request through would answer 500, not 404. The settings page links
// to it only while /api/auth/me reports sharing in force (the page test pins both states).
describe('the project activity feed with sharing not in force (step 4.13)', () => {
  const NOT_IN_FORCE: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
  ]

  test.each(NOT_IN_FORCE)('%s: GET /activity answers the owner 404, reading no audit row', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    const { NextRequest } = await import('next/server')
    const { GET } = await import('@/app/api/projects/[id]/activity/route')
    const res = await GET(new NextRequest('http://x/api/projects/P-owner/activity'), { params: Promise.resolve({ id: 'P-owner' }) })
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Not found' })
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test('its handler answers 404 before anything else while the switch is off', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/app/api/projects/[id]/activity/route.ts'), 'utf8')
    const handlers = src.split(/^export const /m).slice(1)
    expect(handlers).toHaveLength(1)
    expect(handlers[0]).toMatch(/^GET = withRouteErrors\([^\n]*\n\s*if \(!rbacFlags\(\)\.sharing\) return routeNotFound\(\)/)
  })

  test('the settings page offers the Activity link only when /api/auth/me reports sharing in force', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/app/projects/[id]/settings/page.tsx'), 'utf8')
    expect(src).toMatch(/const sharingInForce = useOptionalAuth\(\)\?\.user\?\.sharing\?\.enabled === true/)
    expect(src).toMatch(/const showActivity = sharingInForce && /)
    expect(src.match(/\/activity`/g)).toHaveLength(1)
  })
})

// Step 6.7: the Instance page's sharing panel (app/admin/instance/SharingPolicyPanel.tsx). It reads the policy
// only from GET /api/admin/instance-settings, which carries `sharingPolicy` only with the switch on
// (route.sharingPolicy.test.ts, "RBAC_SHARING_ENABLED off"); without it the page shows no panel and so
// sends no `sharingPolicy`.
describe('the Instance page with sharing off (step 6.7)', () => {
  test('no policy in the instance settings answer: no sharing panel, and the panel reads nothing on its own', async () => {
    const { sharingPolicyOf } = await import('@/app/admin/instance/SharingPolicyPanel')
    expect(sharingPolicyOf(null)).toBeNull()
    expect(sharingPolicyOf({ securityPolicy: {}, canManageSecurityPolicy: true, canManageTunnels: true })).toBeNull()
    // Control: the switch on, the route's answer carries it and the panel shows it.
    expect(sharingPolicyOf({ sharingPolicy: { enabled: true }, canManageSharingPolicy: true })).toMatchObject({ enabled: true })
    const panel = readFileSync(path.join(WEBAPP, 'src/app/admin/instance/SharingPolicyPanel.tsx'), 'utf8')
    expect(panel).not.toMatch(/\bfetch\(/)
    const page = readFileSync(path.join(WEBAPP, 'src/app/admin/instance/page.tsx'), 'utf8')
    expect(page).toMatch(/sharingPolicyShown: sharingPolicyOf\(settings\) !== null/)
  })
})

// Step 4.14: oversight and Root's break-glass. With sharing not in force the break-glass routes and the
// oversight list do not exist: 404 before any project, share or break-glass row is read (requirePermission
// stands for the owner here, so a gate that let the request through would read the project or fail).
describe('oversight and break-glass with sharing not in force (step 4.14)', () => {
  const NOT_IN_FORCE: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
  ]

  test.each(NOT_IN_FORCE)('%s: break-glass open and close and the oversight list answer 404, nothing read', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    const { NextRequest } = await import('next/server')
    const glass = await import('@/app/api/projects/[id]/breakglass/route')
    const list = await import('@/app/api/projects/oversight/route')
    const params = { params: Promise.resolve({ id: 'P-owner' }) }
    const json = { 'Content-Type': 'application/json', Origin: 'http://x' }
    const body = JSON.stringify({ reason: 'r', durationMinutes: 10, stepUpPassword: 'p' })
    expect((await glass.POST(new NextRequest('http://x/api/projects/P-owner/breakglass', { method: 'POST', headers: json, body }), params)).status).toBe(404)
    expect((await glass.DELETE(new NextRequest('http://x/api/projects/P-owner/breakglass', { method: 'DELETE', headers: { Origin: 'http://x' } }), params)).status).toBe(404)
    expect((await list.GET(new NextRequest('http://x/api/projects/oversight'))).status).toBe(404)
    expect(db.projectFindUnique).not.toHaveBeenCalled()
    expect(db.projectFindMany).not.toHaveBeenCalled()
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    expect(db.breakGlassFindFirst).not.toHaveBeenCalled()
    if (!rbacFlags().sharing) expect(instanceFindUnique).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test('each of their handlers answers 404 before anything else while the switch is off', () => {
    for (const file of ['src/app/api/projects/[id]/breakglass/route.ts', 'src/app/api/projects/oversight/route.ts']) {
      const handlers = readFileSync(path.join(WEBAPP, file), 'utf8').split(/^export const /m).slice(1)
      expect(handlers.length, file).toBeGreaterThan(0)
      for (const handler of handlers) {
        expect(handler, `${file} ${handler.slice(0, 6)}`).toMatch(/^[A-Z]+ = withRouteErrors\([^\n]*\n\s*if \(!rbacFlags\(\)\.sharing\) return routeNotFound\(\)/)
      }
    }
  })

  test('the projects page offers the oversight filter only when /api/auth/me reports sharing in force', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/app/projects/page.tsx'), 'utf8')
    expect(src).toMatch(/const showOversight = sharingInForce && canOversee && !auth\?\.user\?\.actingAs/)
    expect(src).toMatch(/useOversightProjects\(showOversight && listFilter === 'oversight'\)/)
    expect(src.match(/\/breakglass`/g)).toHaveLength(2)
  })
})

describe('MCP tokens with sharing not in force (step 4.10)', () => {
  const NOT_IN_FORCE_MCP: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {} after the upgrade)', { identity: true, permissions: true, sharing: true }, {}],
  ]

  test.each(NOT_IN_FORCE_MCP)('%s: an opted-in token reaches only its own projects, and no share row is read', async (_what, flags, stored) => {
    const { McpAccessDenied, assertMcpProjectAccess } = await import('@/lib/mcpAuth')
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    instanceFindUnique.mockResolvedValue({ id: 'instance', sharingPolicy: stored } as never)
    const optedIn = (userId: string) => ({ userId, sharedProjects: { allowlist: [] } })
    for (const level of ['R', 'R*'] as const) {
      await expect(assertMcpProjectAccess(optedIn('stranger'), 'P-owner', level)).rejects.toThrow(new McpAccessDenied())
    }
    expect(await assertMcpProjectAccess(optedIn('owner'), 'P-owner')).toEqual({ id: 'P-owner', userId: 'owner' })
    expect(db.collaboratorFindUnique).not.toHaveBeenCalled()
    expect(db.breakGlassFindFirst).not.toHaveBeenCalled()
    instanceFindUnique.mockReset().mockResolvedValue({ id: 'instance', sharingPolicy: { enabled: true } } as never)
  })

  test('list_projects widens past the owned filter only for a token that opted in', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/lib/mcp/tools.ts'), 'utf8')
    expect(src).toMatch(/const visible = reach\s*\n\s*\? await visibleProjects\(subject\)\s*\n\s*: \{ where: ownedProjectsWhere\(subject\), withShares: false \}/)
  })
})

// Step 4.11: the read-only project screens and the stale-access poll. With the switch off no project read
// carries `myAccess` (the project GET and the list rows: the 4.3 and 4.5 blocks above), so the browser's
// level table refuses nothing, a project summary carries none, and ProjectProvider never asks /my-access
// (readOnlyProject.test.tsx, "switch off: no poll, owner unchanged", renders it).
describe('the read-only project screens with sharing off (step 4.11)', () => {
  test('without myAccess the level table refuses nothing, at any level and for any permission', async () => {
    const { myAccessMeets, levelRefusalText } = await import('@/lib/readOnlyProject')
    const { PERMISSIONS } = await import('./permissions')
    for (const level of ['R', 'R*', 'W', 'W+S', 'W+A', 'W+X', 'M', 'O'] as const) {
      expect(myAccessMeets(undefined, level)).toBe(true)
      expect(myAccessMeets(null, level)).toBe(true)
    }
    for (const id of Object.keys(PERMISSIONS)) expect(levelRefusalText(undefined, id as never)).toBeNull()
  })

  test('a project read without myAccess makes a summary without it', async () => {
    const { toProjectSummary } = await import('@/lib/projectSummary')
    expect(toProjectSummary({ id: 'P', name: 'N', targetDomain: 'example.test' })).not.toHaveProperty('myAccess')
  })

  test('ProjectProvider polls only while the open project carries myAccess, and confirms a 404 with the project read', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/providers/ProjectProvider.tsx'), 'utf8')
    expect(src).toMatch(/const pollProjectId = currentProject\?\.myAccess \? currentProject\.id : null/)
    expect(src).toMatch(/if \(!pollProjectId\) return\n/)
    expect(src).toMatch(/if \(res\.status !== 404\) return \{ kind: 'retry' \}\n\s*const project = await fetch\(`\/api\/projects\/\$\{id\}`/)
  })
})

// Step 6.4: the admin shares overview and Root's force-revoke read a share only past the share routes'
// gate (sharingPolicyForRoutes, null with sharing not in force: the 4.4 block above), and the projects
// overview selects a share count only with sharing in force.
describe('the admin projects and shares overviews with sharing not in force (step 6.4)', () => {
  test('both shares routes ask the share routes\' gate before they read or remove a share', () => {
    for (const [file, reader] of [
      ['src/app/api/admin/shares/route.ts', 'readSharesPage('],
      ['src/app/api/admin/shares/[projectId]/[userId]/route.ts', 'forceRevokeShare('],
    ]) {
      const src = readFileSync(path.join(WEBAPP, file), 'utf8')
      const gate = src.indexOf('if (!policy) return routeNotFound()') >= 0
        ? src.indexOf('if (!policy) return routeNotFound()')
        : src.indexOf('if (!(await sharingPolicyForRoutes({ fresh: true }))) return routeNotFound()')
      expect(gate, file).toBeGreaterThan(0)
      expect(src.indexOf(reader), file).toBeGreaterThan(gate)
    }
  })

  test('the projects overview selects a share count only with sharing in force', () => {
    const src = readFileSync(path.join(WEBAPP, 'src/lib/authz/adminProjects.ts'), 'utf8')
    expect(src).toMatch(/\.\.\.\(sharing \? \{ _count: \{ select: \{ collaborators: \{ where: liveShare\(\) \} \} \} \} : \{\}\)/)
    expect(src).toMatch(/const inForce = policy\?\.enabled === true\n/)
    expect(src).toMatch(/select: rowSelect\(inForce\)/)
    expect(src).toMatch(/openReadOnly: inForce && !actingAs,\n\s*breakGlass: root && inForce && !actingAs,/)
  })
})

// Step 4.12: the share dialog and Leave. With sharing not in force no share control is offered: the
// projects page and the header ask shareActions() with /api/auth/me's `sharing.enabled` (absent with the
// switch off, false with the policy disabled), which then answers neither, and the dialog is mounted only
// from a Share click; the routes it would call answer 404 (the 4.4 block above). The passwordless offer
// of the two create forms changes only with sharing in force (ID-12; page.sharing.test.tsx and
// page.share.test.tsx render both states).
describe('the share dialog and Leave with sharing not in force (step 4.12)', () => {
  test('shareActions offers neither Share nor Leave, whatever the row says', async () => {
    const { shareActions } = await import('@/components/sharing/sharePresets')
    const owner = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'o', email: 'o@example.test' } } as const
    const share = { level: 'read', toggles: { rawData: true }, via: 'share', owner: { name: 'o', email: 'o@example.test' } } as const
    for (const row of [{ myAccess: owner }, { myAccess: share }, {}, null]) {
      expect(shareActions(row, false)).toEqual({ share: false, leave: false })
    }
  })

  test('the projects page and the header ask it with sharing in force, and mount the dialog only from Share', () => {
    const page = readFileSync(path.join(WEBAPP, 'src/app/projects/page.tsx'), 'utf8')
    expect(page).toMatch(/const sharingInForce = auth\?\.user\?\.sharing\?\.enabled === true/)
    expect(page).toMatch(/const actions = shareActions\(project, sharingInForce\)/)
    expect(page).toMatch(/\{shareTarget && <ShareDialog /)
    expect(page.match(/setShareTarget\(\{/g)).toHaveLength(1)
    const header = readFileSync(path.join(WEBAPP, 'src/components/layout/GlobalHeader/ProjectSelector/ProjectSelector.tsx'), 'utf8')
    expect(header).toMatch(/const sharingInForce = useOptionalAuth\(\)\?\.user\?\.sharing\?\.enabled === true/)
    expect(header).toMatch(/const actions = shareActions\(currentProject, sharingInForce\)/)
    expect(header).toMatch(/\{shareOpen && currentProject && actions\.share && \(/)
  })

  test('the create forms keep offering passwordless accounts unless sharing is in force', () => {
    const users = readFileSync(path.join(WEBAPP, 'src/app/settings/users/page.tsx'), 'utf8')
    expect(users).toMatch(/const sharingInForce = authUser\?\.sharing\?\.enabled === true/)
    expect(users).toMatch(/if \(sharingInForce && !password\) \{/)
    const page = readFileSync(path.join(WEBAPP, 'src/app/projects/page.tsx'), 'utf8')
    expect(page).toMatch(/\{canCreateUsers && \(sharingInForce \? \(/)
    expect(page).toMatch(/\{canCreateUsers && showUserModal && !sharingInForce && \(/)
  })
})

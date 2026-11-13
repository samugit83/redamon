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
 *     columns or the policy column, and none of those reads a row yet.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/sharing.flags.off.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'

const instanceFindUnique = vi.hoisted(() => vi.fn(async () => ({ id: 'instance', sharingPolicy: { enabled: true } })))
vi.mock('@/lib/prisma', () => ({ default: { instanceSettings: { findUnique: instanceFindUnique } } }))

import { rbacFlags, setFlagsForTests } from './flags'
import { clearSharingPolicyCacheForTests, sharingInForce, sharingPolicyInForce } from './sharingPolicy'

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
  instanceFindUnique.mockClear()
  clearSharingPolicyCacheForTests()
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

  test('no production code reads a collaborator or break-glass row yet (step 4.3 adds the first reader)', () => {
    const ROW_READERS: string[] = []
    const ACCESSORS = /\.(projectCollaborator|projectBreakGlass)\.|\b(collaborators|collaborations|breakGlass)\s*:\s*\{/
    const files = productionFiles()
    const readers = files.filter((f) => ACCESSORS.test(readFileSync(f, 'utf8'))).map((f) => path.relative(WEBAPP, f)).sort()
    expect(readers).toEqual(ROW_READERS)
  })
})

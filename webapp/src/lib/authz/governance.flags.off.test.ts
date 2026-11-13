/**
 * The governance switch (RBAC_GOVERNANCE_ENABLED, Phase 6) off: everything behaves as after the
 * earlier phases (master plan §9.4, DV-30). It requires the permissions switch, so it also reads off
 * while that one is off. With it off there is no /admin page (the Users page of Phases 2-3 stays), no
 * quota is enforced, plugin allowlists are ignored, device sessions are not checked, instance
 * providers are neither offered nor resolved, and audit retention deletes nothing. Each Phase 6 step
 * appends its part here (OD-6: append-only hunks).
 *
 * Step 6.1 adds the admin console shell. With the switch off:
 *   - /admin and every page under it do not exist: the layout answers Next's 404 before it renders
 *     anything or reads the session, whatever the person holds;
 *   - /settings/users stays where it is for everyone (no redirect to /admin/users), and its
 *     change-password entry works as before (settings/users/layout.test.tsx pins both states);
 *   - the header keeps "Users" for users:read and shows no "Admin" link
 *     (GlobalHeader.test.tsx, "off: \"Users\" stays");
 *   - no production file other than the named readers reads the switch, so every reader is reviewed
 *     against it (GOVERNANCE_READERS below; a later step that adds one names it there).
 *
 * Step 6.9 adds per-plugin allowlists. With the switch off the rules are ignored and not even read:
 * every plugin is available to everyone holding plugins:use (lib/plugins/accessRules.ts, its two
 * readers in GOVERNANCE_READERS; pluginAllowlist.test.ts and pluginAllowlist.routes.test.ts pin the
 * Gateway, the action start and the plugin screens in both states).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/governance.flags.off.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createElement } from 'react'
import { render, screen, cleanup } from '@testing-library/react'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'

const nav = vi.hoisted(() => ({
  replace: vi.fn(),
  search: '',
  notFound: vi.fn(() => { throw new Error('NEXT_NOT_FOUND') }),
}))
vi.mock('next/navigation', () => ({
  notFound: nav.notFound,
  useRouter: () => ({ replace: nav.replace, push: vi.fn() }),
  useSearchParams: () => new URLSearchParams(nav.search),
  usePathname: () => '/admin',
}))

import { rbacFlags, setFlagsForTests } from './flags'
import AdminLayout from '@/app/admin/layout'
import UsersLayout from '@/app/settings/users/layout'

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

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  nav.replace.mockReset()
  nav.notFound.mockClear()
  nav.search = ''
  fetchMock = vi.fn(async () => new Response('{}'))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  setFlagsForTests(null)
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.1)', () => {
  test('the switch is off unless set, and off while the permissions switch is off', () => {
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
    expect(rbacFlags().governance).toBe(false)
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', 'true')
    expect(rbacFlags().governance).toBe(true)
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'false')
    expect(rbacFlags().governance).toBe(false)
  })

  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
    ['governance asked without permissions', { identity: true, governance: true }],
  ])('/admin does not exist (%s): 404 before anything renders or is read', (_name, flags) => {
    setFlagsForTests(flags)
    expect(() => AdminLayout({ children: createElement('p', null, 'section body') })).toThrow('NEXT_NOT_FOUND')
    expect(nav.notFound).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('/settings/users stays for a users:read holder, and the change-password entry too', () => {
    for (const search of ['', 'changePassword=true']) {
      nav.search = search
      render(createElement(AuthContext.Provider, { value: fakeAuth(FLAGS_ON, ['users:read', 'audit:read']) },
        createElement(UsersLayout, null, createElement('p', null, 'users page'))))
      expect(screen.getByText('users page')).toBeInTheDocument()
      cleanup()
    }
    expect(nav.replace).not.toHaveBeenCalled()
  })

  test('no production code reads the governance switch outside the named readers', () => {
    const GOVERNANCE_READERS = [
      'src/app/admin/layout.tsx',
      'src/app/plugins/[pluginId]/[[...screen]]/page.tsx',
      'src/app/settings/users/layout.tsx',
      'src/components/layout/GlobalHeader/GlobalHeader.tsx',
      'src/lib/plugins/accessRules.ts',
    ]
    // A property read (`flags.governance`, `rbacFlags().governance`, `useRbacFlags()?.governance`)
    // or a destructuring of the flags; flags.ts itself defines the switch.
    const READS = /\.governance\b|\{[^}]*\bgovernance\b[^}]*\}\s*=\s*(?:use)?[rR]bacFlags\(/
    const readers = productionFiles()
      .filter((f) => !f.endsWith(path.join('lib', 'authz', 'flags.ts')))
      .filter((f) => READS.test(readFileSync(f, 'utf8')))
      .map((f) => path.relative(WEBAPP, f))
      .sort()
    expect(readers).toEqual(GOVERNANCE_READERS)
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.9): plugin allowlists are ignored', () => {
  test('a plugin limited to a set the person lacks stays available, and no rule is read', async () => {
    const readAccessRules = vi.fn(async (pluginId?: string) =>
      [{ pluginId: 'echo', setId: 'builtin:red-team-operator' }].filter((r) => pluginId === undefined || r.pluginId === pluginId))
    vi.resetModules()
    vi.doMock('@/lib/plugins/accessRuleStore', () => ({ readAccessRules }))
    const { pluginAccessFor, pluginAllowedFor } = await import('@/lib/plugins/accessRules')
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect(await pluginAllowedFor('user-1', 'echo')).toBe(true)
      expect((await pluginAccessFor('user-1')).allows('echo')).toBe(true)
    }
    expect(readAccessRules).not.toHaveBeenCalled()
    // Control: the double is the store accessRules reads once the switch is on.
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', 'true')
    expect(await pluginAllowedFor('user-1', 'other')).toBe(true)
    expect(readAccessRules).toHaveBeenCalledWith('other')
    vi.doUnmock('@/lib/plugins/accessRuleStore')
  })
})

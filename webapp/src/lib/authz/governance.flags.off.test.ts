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
 * Gateway, the action start and the plugin screens in both states). The rules cannot be managed
 * either: /api/plugins/[pluginId]/access-rules answers 404 (its route.test.ts, "switch off") and the
 * plugin drawer shows no "Who may use it" section (PluginAccessRules.test.tsx, the third reader).
 *
 * Step 6.2 adds the users directory and one account's detail. With the switch off GET /api/admin/users
 * and GET /api/admin/users/[id] answer 404 before they read the session or the database (both route
 * files are readers in GOVERNANCE_READERS; the test at the end, and api/admin/users/route.test.ts), and
 * their pages sit under /admin, which does not exist.
 *
 * Step 6.12 adds audit forwarding, which is its own setting (AUDIT_FORWARD, default off) and reads no
 * switch: unset, no `[audit-forward]` line is printed and `auditedTransaction` hands each transaction
 * to Prisma untouched, with this switch off or on (the test at the end; lib/auditForward.test.ts).
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
      'src/app/api/admin/users/[id]/route.ts',
      'src/app/api/admin/users/route.ts',
      'src/app/plugins/[pluginId]/[[...screen]]/page.tsx',
      'src/app/settings/users/layout.tsx',
      'src/components/layout/GlobalHeader/GlobalHeader.tsx',
      'src/components/plugins/PluginDetailsDrawer.tsx',
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

describe('RBAC_GOVERNANCE_ENABLED off (step 6.2): the users directory routes do not exist', () => {
  test('GET /api/admin/users and /api/admin/users/[id] answer 404 and read neither the session nor the database', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({ requireSession: vi.fn(async () => { touched('session'); return { userId: 'adm-a', role: 'admin' } }) }))
    const { GET: list } = await import('@/app/api/admin/users/route')
    const { GET: detail } = await import('@/app/api/admin/users/[id]/route')
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect((await list(new Request('http://redamon.test/api/admin/users') as never)).status).toBe(404)
      expect((await detail(new Request('http://redamon.test/api/admin/users/m-1') as never, { params: Promise.resolve({ id: 'm-1' }) })).status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
  })
})

describe('audit forwarding is its own setting (step 6.12): AUDIT_FORWARD, default off, whatever this switch', () => {
  test('unset, no [audit-forward] line and the transaction goes to Prisma untouched, switch off or on', async () => {
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => ({ default: {}, prisma: {} }))
    const { auditedTransaction } = await import('@/lib/auditForward')
    const { writeAuditTx } = await import('@/lib/audit')
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    const tx = { auditLog: { create: vi.fn(async ({ data }: { data: object }) => ({ id: 'al-1', ...data })) } }
    const client = { $transaction: vi.fn(async (fn: (t: unknown) => Promise<unknown>) => fn(tx)) }
    const write = async (t: unknown) => writeAuditTx(t as never, { actorId: 'adm-a', action: 'user.update', targetType: 'user', targetId: 'm-1' })
    const forwarded = () => info.mock.calls.filter((c: unknown[]) => String(c[0]).startsWith('[audit-forward] ')).length
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    for (const governance of ['', 'true']) {
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', governance)
      await auditedTransaction(client as never, write as never)
      expect(forwarded()).toBe(0)
    }
    expect(client.$transaction.mock.calls).toEqual([[write], [write]])
    expect(tx.auditLog.create).toHaveBeenCalledTimes(2)
    // Control: the same write forwards once AUDIT_FORWARD asks it, with the switch still off.
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
    vi.stubEnv('AUDIT_FORWARD', 'stdout')
    await auditedTransaction(client as never, write as never)
    expect(forwarded()).toBe(1)
    info.mockRestore()
    vi.doUnmock('@/lib/prisma')
  })
})

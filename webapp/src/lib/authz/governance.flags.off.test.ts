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
 * Step 6.7 adds the Instance page (/admin/instance), which sits under /admin and so does not exist with
 * the switch off. Global Settings' Tunneling tab then keeps its controls for whoever may change the
 * tunnel, with no link to the console (components/settings/InstanceTunnelSection.tsx, a reader in
 * GOVERNANCE_READERS; the test at the end, and InstanceTunnelSection.test.tsx).
 *
 * Step 6.3 adds the permission sets and admin profiles pages (/admin/permission-sets,
 * /admin/admin-profiles). They sit under /admin, so with the switch off they do not exist and read
 * nothing (the test at the end); the Phase 3 APIs they call keep answering behind the permissions
 * switch alone, as before (permissions.flags.off.test.ts), and neither page reads this switch.
 *
 * Step 6.6 adds the audit viewer and its export. With the switch off GET /api/admin/audit,
 * /api/admin/audit/[id] and /api/admin/audit/export answer 404 before they read the session or the
 * database (the three route files are readers in GOVERNANCE_READERS; the test at the end, and
 * api/admin/audit/route.test.ts), and /admin/audit sits under /admin, which does not exist. Audit
 * retention deletes nothing: lib/authz/auditRetention.ts (a reader) reads neither the instance row nor
 * an audit row, whatever retention Root set while the switch was on (auditRetention.test.ts). Root's
 * retention setting is neither shown nor read from a body of /api/admin/instance-settings (a reader;
 * api/admin/instance-settings/route.auditRetention.test.ts).
 *
 * Step 6.8 adds quotas. With the switch off none is enforced and none is read: lib/authz/quotas.ts
 * (a reader in GOVERNANCE_READERS, and the only one of the step) answers every account unlimited
 * before it reads the instance row or an account, so a project create, an import and a scan start
 * go on as before, and GET /api/users/[id]/quota answers 404 before it reads the session (the test at
 * the end); the instance settings show and take no quotas (instance-settings/route.quotas.test.ts); My
 * account shows no Quota section and reads none (app/account/page.tsx, a reader; page.quota.test.tsx);
 * the token screen offers every expiry (no `tokenQuota` in the list; McpTokensTab.quota.test.tsx).
 *
 * Step 6.11 adds instance LLM providers. With the switch off none is offered or resolved and nothing
 * of them is read: the agent's provider list (GET /api/users/[id]/llm-providers?internal=true) is the
 * account's own rows, bring-your-own providers are never withheld, /api/models refuses an account
 * without self:llm_providers as before, and Root's routes /api/admin/llm-providers (+ /[providerId],
 * /policy) and the account's /api/account/llm-providers answer 404 before the session or the database
 * is read (lib/instanceProviders/entitlement.ts, the one reader in GOVERNANCE_READERS; the test at the
 * end, instanceProviders.test.ts and the routes' tests). A project saved on an `instance/` model then
 * fails closed in the agent (instance_provider_unavailable, agentic/tests/test_instance_providers.py).
 * Global Settings lists no instance provider and reads none (components/settings/InstanceLlmProviders.tsx,
 * a reader; its test).
 *
 * Step 6.10 adds device sessions. With the switch off a sign-in writes no `UserSession` row and its token
 * carries no `sid`; getSession ignores a `sid` claim and reads no row (session.deviceSessions.test.ts); a
 * sign-out touches no row; the expiry sweep reads no device session and its answer has no `devices` key
 * (sweep/route.test.ts); /api/account/sessions[/[sid]] and /api/users/[id]/sessions[/[sid]] answer 404
 * before they read the session or the database (the four route files are readers in GOVERNANCE_READERS;
 * the test at the end); My account shows no device list (AccountSections.tsx, a reader).
 *
 * Step 6.4 adds the projects and shares overviews, Root's forced delete and Root's force-revoke. With
 * the switch off GET /api/admin/projects, DELETE /api/admin/projects/[id], GET /api/admin/shares and
 * DELETE /api/admin/shares/[projectId]/[userId] answer 404 before they read the session, the sharing
 * policy or the database (the four route files are readers in GOVERNANCE_READERS; the test at the end,
 * and both route.test.ts files), and /admin/projects and /admin/shares sit under /admin, which does
 * not exist.
 *
 * Step 6.5 adds the operations view. With the switch off GET /api/admin/operations and POST
 * /api/admin/operations/agent-runs/stop answer 404 before they read the session, the database, the
 * agent or the orchestrator (both route files are readers in GOVERNANCE_READERS; the test at the end,
 * and api/admin/operations/route.test.ts), and /admin/operations sits under /admin, which does not
 * exist. The members' memory meter (/api/system/stats), their scan activity (/api/system/jobs) and the
 * emergency stop (/api/agent/emergency-stop-all) read no switch and stay as they were.
 *
 * The traffic page links its Settings to the Instance page's TrafficMind panel with the switch on (UI-04,
 * after 6.7). Off, the button opens the TrafficMind dialog in place, as before (app/traffic/page.tsx, a
 * reader in GOVERNANCE_READERS; app/traffic/page.test.tsx).
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
      'src/app/account/AccountSections.tsx',
      'src/app/account/page.tsx',
      'src/app/admin/layout.tsx',
      'src/app/api/account/sessions/[sid]/route.ts',
      'src/app/api/account/sessions/route.ts',
      'src/app/api/admin/audit/[id]/route.ts',
      'src/app/api/admin/audit/export/route.ts',
      'src/app/api/admin/audit/route.ts',
      'src/app/api/admin/instance-settings/route.ts',
      'src/app/api/admin/operations/agent-runs/stop/route.ts',
      'src/app/api/admin/operations/route.ts',
      'src/app/api/admin/projects/[id]/route.ts',
      'src/app/api/admin/projects/route.ts',
      'src/app/api/admin/shares/[projectId]/[userId]/route.ts',
      'src/app/api/admin/shares/route.ts',
      'src/app/api/admin/users/[id]/route.ts',
      'src/app/api/admin/users/route.ts',
      'src/app/api/users/[id]/sessions/[sid]/route.ts',
      'src/app/api/users/[id]/sessions/route.ts',
      'src/app/plugins/[pluginId]/[[...screen]]/page.tsx',
      'src/app/settings/users/layout.tsx',
      'src/app/traffic/page.tsx',
      'src/components/layout/GlobalHeader/GlobalHeader.tsx',
      'src/components/plugins/PluginDetailsDrawer.tsx',
      'src/components/settings/InstanceLlmProviders.tsx',
      'src/components/settings/InstanceTunnelSection.tsx',
      'src/lib/authz/auditRetention.ts',
      'src/lib/authz/deviceSessions.ts',
      'src/lib/authz/expirySweep.ts',
      'src/lib/authz/quotas.ts',
      'src/lib/instanceProviders/entitlement.ts',
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

describe('RBAC_GOVERNANCE_ENABLED off (step 6.7): the Tunneling tab keeps its controls', () => {
  test('whoever may change the tunnel gets the controls in Global Settings, and no link to the Instance page', async () => {
    const { ToastProvider } = await import('@/components/ui/Toast/Toast')
    const { InstanceTunnelSection } = await import('@/components/settings/InstanceTunnelSection')
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({
      tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', canManageTunnels: true,
    })))
    for (const flags of [FLAGS_ON, { ...FLAGS_ON, governance: false, sharing: true }]) {
      render(createElement(AuthContext.Provider, { value: fakeAuth(flags, ['platform:tunnels']) },
        createElement(ToastProvider, null, createElement(InstanceTunnelSection))))
      expect(await screen.findByRole('button', { name: 'Save tunnel settings' })).toBeInTheDocument()
      expect(screen.queryByRole('link', { name: 'Open the tunnel settings' })).toBeNull()
      cleanup()
    }
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.3): the permission sets and admin profiles pages do not exist', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('/admin/permission-sets and /admin/admin-profiles: 404 before the page renders or reads a set (%s)', async (_name, flags) => {
    const { default: PermissionSetsPage } = await import('@/app/admin/permission-sets/page')
    const { default: AdminProfilesPage } = await import('@/app/admin/admin-profiles/page')
    setFlagsForTests(flags)
    for (const page of [PermissionSetsPage, AdminProfilesPage]) {
      expect(() => AdminLayout({ children: createElement(page) })).toThrow('NEXT_NOT_FOUND')
    }
    expect(nav.notFound).toHaveBeenCalledTimes(2)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.6): the audit viewer and its export do not exist', () => {
  test('GET /api/admin/audit, /api/admin/audit/[id] and /api/admin/audit/export answer 404 and read neither the session nor the database', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({
      requireSession: vi.fn(async () => { touched('session'); return { userId: 'aud-1', role: 'admin' } }),
      getSession: vi.fn(async () => { touched('session'); return { userId: 'aud-1', role: 'admin' } }),
    }))
    const { GET: list } = await import('@/app/api/admin/audit/route')
    const { GET: row } = await import('@/app/api/admin/audit/[id]/route')
    const { GET: exported } = await import('@/app/api/admin/audit/export/route')
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect((await list(new Request('http://redamon.test/api/admin/audit') as never)).status).toBe(404)
      expect((await row(new Request('http://redamon.test/api/admin/audit/al-1') as never, { params: Promise.resolve({ id: 'al-1' }) })).status).toBe(404)
      expect((await exported(new Request('http://redamon.test/api/admin/audit/export?format=csv') as never)).status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.8): no quota is enforced or read', () => {
  test('every account is unlimited, and neither the instance row nor an account is read', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      const quotas = await import('@/lib/authz/quotas')
      expect(await quotas.quotaFor('m-1')).toMatchObject({ enforced: false, quota: quotas.UNLIMITED })
      expect(await quotas.projectQuotaRefusal('m-1')).toBeNull()
      expect(await quotas.actorScanCap('m-1')).toEqual({})
      expect(await quotas.quotaLimit('m-1', 'llmDailyCalls')).toBeNull()
      expect(await quotas.readQuotaStore()).toBeNull()
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
  })

  test('GET /api/users/[id]/quota answers 404 and reads neither the session nor the database', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => { touched('session'); return null }) }))
    const { GET } = await import('@/app/api/users/[id]/quota/route')
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      const res = await GET(new Request('http://redamon.test/api/users/m-1/quota') as never, { params: Promise.resolve({ id: 'm-1' }) })
      expect(res.status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.11): instance LLM providers are neither offered nor resolved', () => {
  test("the agent list is the account's own rows, nothing of the providers is read, and their routes answer 404", async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({
      requireSession: vi.fn(async () => { touched('session'); return { userId: 'root-1', role: 'admin' } }),
      getEffectiveUser: vi.fn(async () => { touched('session'); return { userId: 'root-1' } }),
    }))
    vi.doMock('@/lib/instanceProviders/store', async (orig) => {
      const actual = (await orig()) as Record<string, unknown>
      return Object.fromEntries(Object.entries(actual).map(([k, v]) =>
        [k, typeof v === 'function' && /^(read|create|update|delete|write|providers)/.test(k) ? (...a: unknown[]) => { touched(`store.${k}`); return (v as (...x: unknown[]) => unknown)(...a) } : v]))
    })
    const { agentProviderList } = await import('@/lib/instanceProviders/entitlement')
    const { GET: list, POST: create } = await import('@/app/api/admin/llm-providers/route')
    const { PUT: change, DELETE: remove } = await import('@/app/api/admin/llm-providers/[providerId]/route')
    const { PUT: policy } = await import('@/app/api/admin/llm-providers/policy/route')
    const { GET: mine } = await import('@/app/api/account/llm-providers/route')
    const own = [{ id: 'own-1', providerType: 'openai', apiKey: 'sk-own' }]
    const write = (method: string) => new Request('http://redamon.test/api/admin/llm-providers', {
      method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stepUpPassword: 'x' }),
    }) as never
    const params = { params: Promise.resolve({ providerId: 'p1' }) }
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect(await agentProviderList('owner-1', own)).toEqual(own)
      const answers = [await list(), await create(write('POST')), await change(write('PUT'), params), await remove(write('DELETE'), params),
        await policy(write('PUT')), await mine()]
      expect(answers.map((r) => r.status)).toEqual([404, 404, 404, 404, 404, 404])
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
    vi.doUnmock('@/lib/instanceProviders/store')
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.10): device sessions are neither written, checked nor listed', () => {
  test('the four device session routes answer 404 and read neither the session nor the database', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({
      requireSession: vi.fn(async () => { touched('session'); return { userId: 'adm-a', role: 'admin' } }),
      requireAdmin: vi.fn(async () => { touched('session'); return { userId: 'adm-a', role: 'admin' } }),
    }))
    const { GET: mine } = await import('@/app/api/account/sessions/route')
    const { DELETE: endMine } = await import('@/app/api/account/sessions/[sid]/route')
    const { GET: theirs } = await import('@/app/api/users/[id]/sessions/route')
    const { DELETE: endTheirs } = await import('@/app/api/users/[id]/sessions/[sid]/route')
    const del = (path: string) => new Request(`http://redamon.test${path}`, { method: 'DELETE' }) as never
    for (const [identity, permissions] of [['', ''], ['true', 'true']]) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect((await mine()).status).toBe(404)
      expect((await endMine(del('/api/account/sessions/s-1'), { params: Promise.resolve({ sid: 's-1' }) })).status).toBe(404)
      expect((await theirs(new Request('http://redamon.test/api/users/m-1/sessions'), { params: Promise.resolve({ id: 'm-1' }) })).status).toBe(404)
      expect((await endTheirs(del('/api/users/m-1/sessions/s-1') as never, { params: Promise.resolve({ id: 'm-1', sid: 's-1' }) })).status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
  })

  test('a sign-in names no device session and writes no row', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => ({
      default: {
        instanceSettings: { findUnique: async () => null },
        userSession: new Proxy({}, { get: (_t, name) => { touched(`userSession.${String(name)}`); return async () => ({ id: 'x' }) } }),
      },
    }))
    const createToken = vi.fn(async () => 'token')
    vi.doMock('@/lib/auth', () => ({ createToken }))
    const { issueLoginToken } = await import('@/lib/authz/sessionLifetime')
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
    const meta = { ip: '192.0.2.1', ipTrusted: false, userAgent: 'Firefox' }
    await issueLoginToken({ id: 'm-1', role: 'standard', sessionVersion: 0 }, { device: { meta } })
    expect(createToken).toHaveBeenCalledTimes(1)
    expect(createToken.mock.calls[0]).toEqual(['m-1', 'standard', 0, expect.not.objectContaining({ sid: expect.anything() })])
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/auth')
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.4): the projects and shares overviews do not exist', () => {
  test("the four routes answer 404 and read neither the session, the sharing policy nor the database", async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({
      requireSession: vi.fn(async () => { touched('session'); return { userId: 'root-1', role: 'admin' } }),
      getSession: vi.fn(async () => { touched('session'); return { userId: 'root-1', role: 'admin' } }),
    }))
    const { GET: projects } = await import('@/app/api/admin/projects/route')
    const { DELETE: deleteProject } = await import('@/app/api/admin/projects/[id]/route')
    const { GET: shares } = await import('@/app/api/admin/shares/route')
    const { DELETE: revoke } = await import('@/app/api/admin/shares/[projectId]/[userId]/route')
    const write = (url: string) => new Request(url, {
      method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ stepUpPassword: 'x' }),
    }) as never
    for (const on of ['', 'true']) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', on)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', on)
      vi.stubEnv('RBAC_SHARING_ENABLED', on)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect((await projects(new Request('http://redamon.test/api/admin/projects') as never)).status).toBe(404)
      expect((await deleteProject(write('http://redamon.test/api/admin/projects/p-1'), { params: Promise.resolve({ id: 'p-1' }) })).status).toBe(404)
      expect((await shares(new Request('http://redamon.test/api/admin/shares') as never)).status).toBe(404)
      expect((await revoke(write('http://redamon.test/api/admin/shares/p-1/m-1'), { params: Promise.resolve({ projectId: 'p-1', userId: 'm-1' }) })).status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
  })

  test.each([
    ['every switch off', {}],
    ['identity, permissions and sharing on', { identity: true, permissions: true, sharing: true }],
  ])('/admin/projects and /admin/shares: 404 before the page renders or reads anything (%s)', async (_name, flags) => {
    const { default: ProjectsPage } = await import('@/app/admin/projects/page')
    const { default: SharesPage } = await import('@/app/admin/shares/page')
    setFlagsForTests(flags)
    for (const page of [ProjectsPage, SharesPage]) {
      expect(() => AdminLayout({ children: createElement(page) })).toThrow('NEXT_NOT_FOUND')
    }
    expect(nav.notFound).toHaveBeenCalledTimes(2)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('RBAC_GOVERNANCE_ENABLED off (step 6.5): the operations view does not exist', () => {
  test('GET /api/admin/operations and POST /api/admin/operations/agent-runs/stop answer 404 and read neither the session, the database, the agent nor the orchestrator', async () => {
    const touched = vi.fn()
    vi.resetModules()
    vi.doMock('@/lib/prisma', () => {
      const db = new Proxy({}, { get: (_t, name) => { touched(`prisma.${String(name)}`); return {} } })
      return { default: db, prisma: db }
    })
    vi.doMock('@/lib/session', () => ({
      requireSession: vi.fn(async () => { touched('session'); return { userId: 'ops-1', role: 'admin' } }),
      getSession: vi.fn(async () => { touched('session'); return { userId: 'ops-1', role: 'admin' } }),
    }))
    vi.doMock('@/lib/agentFetch', () => ({ agentFetch: vi.fn(async () => { touched('agent'); return new Response('{}') }), AgentUnreachableError: Error }))
    vi.doMock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn(async () => { touched('orchestrator'); return new Response('{}') }) }))
    const { GET: operations } = await import('@/app/api/admin/operations/route')
    const { POST: stopRun } = await import('@/app/api/admin/operations/agent-runs/stop/route')
    for (const on of ['', 'true']) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', on)
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', on)
      vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '')
      expect((await operations(new Request('http://redamon.test/api/admin/operations') as never)).status).toBe(404)
      expect((await stopRun(new Request('http://redamon.test/api/admin/operations/agent-runs/stop', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: 'm-1', projectId: 'p-1', sessionId: 's-1' }),
      }) as never)).status).toBe(404)
    }
    expect(touched).not.toHaveBeenCalled()
    vi.doUnmock('@/lib/prisma')
    vi.doUnmock('@/lib/session')
    vi.doUnmock('@/lib/agentFetch')
    vi.doUnmock('@/lib/orchestrator')
  })

  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('/admin/operations: 404 before the page renders or reads anything (%s)', async (_name, flags) => {
    const { default: OperationsPage } = await import('@/app/admin/operations/page')
    setFlagsForTests(flags)
    expect(() => AdminLayout({ children: createElement(OperationsPage) })).toThrow('NEXT_NOT_FOUND')
    expect(nav.notFound).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

/**
 * The admin console shell (step 6.1, UI-10, OQ-44; DV-06, DV-19): the layout exists only with
 * RBAC_GOVERNANCE_ENABLED on (off: governance.flags.off.test.ts), its left navigation lists the
 * sections the person's permissions open, each section shows the denied state to whoever lacks its
 * permission, and the shell has its loading, error, signed-out and empty states. The navigation is
 * a labelled landmark of plain links, the current one marked for assistive technology.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/AdminConsole.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { BUILTIN_ADMIN_PROFILES } from '@/lib/authz/builtinSets'
import { ApiError } from '@/lib/apiError'
import { setFlagsForTests } from '@/lib/authz/flags'

const nav = vi.hoisted(() => ({ pathname: '/admin', notFound: vi.fn(() => { throw new Error('NEXT_NOT_FOUND') }) }))
vi.mock('next/navigation', () => ({
  usePathname: () => nav.pathname,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  notFound: nav.notFound,
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import AdminLayout from './layout'
import AdminIndexPage from './page'
import { AdminConsole } from './AdminConsole'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const profile = (slug: string) => BUILTIN_ADMIN_PROFILES.find((s) => s.id === `builtin:${slug}`)!.permissions

let fetchMock: ReturnType<typeof vi.fn>
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

beforeEach(() => {
  nav.pathname = '/admin'
  nav.notFound.mockClear()
  fetchMock = vi.fn(async () => json({ sharingPolicy: { adminsSeeAllShares: true } }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  setFlagsForTests(null)
})

function adminAuth(held: readonly PermissionId[], over: Partial<AuthContextValue> = {}): AuthContextValue {
  const base = fakeAuth(FLAGS_GOV, [...held])
  return { ...base, user: { ...base.user!, name: 'Admin A', role: 'admin', email: 'adm-a@e2e.local' }, ...over }
}

function renderConsole(auth: AuthContextValue, children: ReactNode = <p>section body</p>) {
  return render(
    <AuthContext.Provider value={auth}>
      <AdminConsole>{children}</AdminConsole>
    </AuthContext.Provider>,
  )
}

const navLinks = () => {
  const landmark = screen.queryByRole('navigation', { name: 'Admin console' })
  return landmark ? within(landmark).getAllByRole('link').map((a) => a.textContent) : []
}

describe('the layout', () => {
  test('with the switch on it renders the console around the page', () => {
    setFlagsForTests({ identity: true, permissions: true, governance: true })
    render(
      <AuthContext.Provider value={adminAuth(['users:read'])}>
        <AdminLayout><p>section body</p></AdminLayout>
      </AuthContext.Provider>,
    )
    expect(nav.notFound).not.toHaveBeenCalled()
    expect(screen.getByRole('navigation', { name: 'Admin console' })).toBeInTheDocument()
  })
})

describe('nav shows only permitted sections', () => {
  test('User manager: Users only, and the Shares policy is never read without sharing in force', () => {
    renderConsole(adminAuth(profile('user-manager')))
    expect(navLinks()).toEqual(['Overview', 'Users'])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('Full admin: every section but Admin profiles', () => {
    renderConsole(adminAuth(profile('full-admin')))
    expect(navLinks()).toEqual(['Overview', 'Users', 'Permission sets', 'Projects', 'Operations', 'Audit', 'Instance'])
  })

  test('Root, sharing in force and the policy letting admins see every share: all eight, Shares once the policy is read', async () => {
    const base = adminAuth(PERMISSION_IDS)
    renderConsole({ ...base, user: { ...base.user!, sharing: { enabled: true, maxLevel: 'read' } } })
    expect(navLinks()).not.toContain('Shares')
    await waitFor(() => expect(navLinks()).toContain('Shares'))
    expect(navLinks()).toEqual([
      'Overview', 'Users', 'Permission sets', 'Admin profiles', 'Projects', 'Shares', 'Operations', 'Audit', 'Instance',
    ])
    expect(fetchMock).toHaveBeenCalledWith('/api/admin/instance-settings', { cache: 'no-store' })
  })

  test('sharing in force but the policy hides other shares from admins: no Shares', async () => {
    fetchMock.mockResolvedValue(json({ sharingPolicy: { adminsSeeAllShares: false } }))
    const base = adminAuth(['users:read'])
    renderConsole({ ...base, user: { ...base.user!, sharing: { enabled: true, maxLevel: 'read' } } })
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await new Promise((r) => setTimeout(r, 0))
    expect(navLinks()).toEqual(['Overview', 'Users'])
  })

  test('the policy read fails: no Shares (fails closed)', async () => {
    fetchMock.mockResolvedValue(json({ error: 'nope', code: 'forbidden' }, 403))
    const base = adminAuth(['users:read'])
    renderConsole({ ...base, user: { ...base.user!, sharing: { enabled: true, maxLevel: 'read' } } })
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await new Promise((r) => setTimeout(r, 0))
    expect(navLinks()).toEqual(['Overview', 'Users'])
  })

  test('the index lists the open sections with what each holds, as links', () => {
    render(
      <AuthContext.Provider value={adminAuth(profile('security-auditor'))}>
        <AdminConsole><AdminIndexPage /></AdminConsole>
      </AuthContext.Provider>,
    )
    expect(screen.getByRole('heading', { level: 1, name: 'Admin console' })).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Sections' })
    const cards = within(list).getAllByRole('link')
    expect(cards.map((a) => a.getAttribute('href'))).toEqual(['/admin/users', '/admin/projects', '/admin/audit'])
    expect(cards[2]).toHaveTextContent(/Audit/)
    expect(cards[2]).toHaveTextContent(/export/)
  })
})

describe('denied state', () => {
  test('a section the person may not open shows the permission it needs instead of the page', () => {
    nav.pathname = '/admin/audit'
    renderConsole(adminAuth(profile('user-manager')))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('You do not have the permission this needs.')
    expect(alert).toHaveTextContent('audit:read')
    expect(screen.queryByText('section body')).toBeNull()
    // The navigation stays, so the person can go where they may.
    expect(navLinks()).toEqual(['Overview', 'Users'])
  })

  test('Instance names every permission that would open it', () => {
    nav.pathname = '/admin/instance'
    renderConsole(adminAuth(['users:read']))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('instance:settings')
    expect(alert).toHaveTextContent('instance:quotas')
    expect(alert).toHaveTextContent('platform:tunnels')
  })

  test("Admin profiles is the confirmed Root's: Full admin is refused", () => {
    nav.pathname = '/admin/admin-profiles/builtin:full-admin'
    renderConsole(adminAuth(profile('full-admin')))
    expect(screen.getByRole('alert')).toHaveTextContent('admin_profiles:manage')
  })

  test('Shares with users:read but sharing not in force: the policy reason, not a permission', () => {
    nav.pathname = '/admin/shares'
    renderConsole(adminAuth(['users:read']))
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent(/sharing is in force/i)
    expect(alert).not.toHaveTextContent('users:read')
  })

  test('Shares while the policy is read: a status, then the page', async () => {
    nav.pathname = '/admin/shares'
    const base = adminAuth(['users:read'])
    renderConsole({ ...base, user: { ...base.user!, sharing: { enabled: true, maxLevel: 'read' } } })
    expect(screen.getByRole('status')).toHaveTextContent(/checking/i)
    expect(await screen.findByText('section body')).toBeInTheDocument()
  })

  test('a member holding no console permission: the console says so, no navigation', () => {
    renderConsole(fakeAuth(FLAGS_GOV, ['recon:scan', 'agent:chat']), <AdminIndexPage />)
    expect(screen.getByRole('alert')).toHaveTextContent(/administration permission/i)
    expect(screen.queryByRole('navigation', { name: 'Admin console' })).toBeNull()
    expect(screen.queryByRole('heading', { level: 1, name: 'Admin console' })).toBeNull()
  })

  test('a permitted section renders its page', () => {
    nav.pathname = '/admin/users/u1'
    renderConsole(adminAuth(['users:read']))
    expect(screen.getByText('section body')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('the shell states', () => {
  test('loading: a status, no navigation and no page yet', () => {
    renderConsole(fakeAuth(null, [], { isLoading: true }))
    expect(screen.getByRole('status')).toHaveTextContent('Loading the admin console')
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.queryByText('section body')).toBeNull()
  })

  test('the session could not be read: the cause and a Retry button', () => {
    const reload = vi.fn()
    vi.stubGlobal('location', { ...window.location, reload })
    renderConsole(fakeAuth(null, [], { sessionError: new ApiError({ reason: 'Could not read your session', status: 503, code: 'P1001' }) }))
    expect(screen.getByRole('alert')).toHaveTextContent('Could not read your session (P1001 · HTTP 503)')
    screen.getByRole('button', { name: 'Retry' }).click()
    expect(reload).toHaveBeenCalled()
  })

  test('signed out: a link to sign in', () => {
    renderConsole(fakeAuth(null, []))
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login')
    expect(screen.queryByText('section body')).toBeNull()
  })
})

describe('keyboard and labels', () => {
  test('a labelled navigation of links in reading order, the current section marked', () => {
    nav.pathname = '/admin/audit'
    renderConsole(adminAuth(profile('security-auditor')))
    const landmark = screen.getByRole('navigation', { name: 'Admin console' })
    const links = within(landmark).getAllByRole('link')
    expect(links.map((a) => a.getAttribute('href'))).toEqual(['/admin', '/admin/users', '/admin/projects', '/admin/audit'])
    expect(links.filter((a) => a.getAttribute('aria-current') === 'page').map((a) => a.textContent)).toEqual(['Audit'])
    // Plain anchors with an href: reachable with Tab, opened with Enter; nothing removed from the tab order.
    for (const a of links) {
      expect(a.tagName).toBe('A')
      expect(a.getAttribute('tabindex')).toBeNull()
    }
  })

  test('the overview link is current on /admin only', () => {
    renderConsole(adminAuth(['users:read']))
    const landmark = screen.getByRole('navigation', { name: 'Admin console' })
    expect(within(landmark).getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page')
    expect(within(landmark).getByRole('link', { name: 'Users' })).not.toHaveAttribute('aria-current')
  })
})

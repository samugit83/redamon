/**
 * DV-34 (§14.12 "communication sized to each audience"): a member sees a notice only at the
 * place where something changed for them, and a single-operator install sees no card, no
 * banner and no notice beyond the update's own output.
 *
 * - the Tunneling section of Global Settings says who manages the tunnel only to an account
 *   that may no longer change it (step 1.10); an admin sees the controls and no notice;
 * - the emergency stop's tooltip names "your own" runs only for a member's scope (1.11);
 * - the admin cards and banners (this step) render nothing for a member, and nothing for the
 *   only admin of an install with nothing to review: no grant, the switch off, the update
 *   notes not applying.
 *
 * The Kali terminal's "shared environment" line (1.14) is the terminal's own warning, shown to
 * whoever opens it; its test is KaliTerminal.banner.test.tsx.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import React from 'react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const who = vi.hoisted(() => ({ isAdmin: false }))
const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }))

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams('tab=keys'),
  useRouter: () => router,
  usePathname: () => '/settings',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({
    user: { id: 'user-1', name: 'U', email: 'u@e2e.local', role: who.isAdmin ? 'admin' : 'standard' },
    isAdmin: who.isAdmin,
    isLoading: false,
  }),
}))
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'user-1', name: 'U', email: 'u@e2e.local', role: 'admin', hasPassword: true, _count: { projects: 0 } }], isLoading: false, error: null }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

const SettingsPage = (await import('@/app/settings/page')).default
const UsersPage = (await import('@/app/settings/users/page')).default
const { AdminBanners } = await import('./CompatBanner')
const { emergencyPauseTitle } = await import('@/app/graph/components/GraphToolbar/emergencyStopScope')

const BASE = '/api/users/user-1'
const MANAGED_BY_ADMIN = 'The tunnel is managed by an administrator.'
let answers: Record<string, unknown>
const fetchMock = vi.fn()

beforeEach(() => {
  who.isAdmin = false
  answers = {
    [`GET ${BASE}/settings`]: { tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '', rotationConfigs: {}, canManageTunnels: false },
    [`GET ${BASE}/settings/api-usage`]: { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] },
    'GET /api/agent/tunnel-status': { ngrok: { active: false }, chisel: { active: false } },
    'GET /api/admin/legacy-grants': { holders: [], pending: 0 },
    'GET /api/admin/whats-new': { dismissed: false, applies: false, stdioMembers: [] },
  }
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${url}`
    if (key in answers) return new Response(JSON.stringify(answers[key]), { status: 200 })
    return new Response('[]', { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const adminCalls = () => fetchMock.mock.calls.map(c => String(c[0])).filter(u => u.startsWith('/api/admin/'))

describe('a member sees a notice where something changed for them', () => {
  test('Tunneling: the member who may not change it reads who manages it', async () => {
    render(<ToastProvider><SettingsPage /></ToastProvider>)
    expect(await screen.findByText(MANAGED_BY_ADMIN)).toBeInTheDocument()
  })

  test('the emergency stop tooltip names the member\'s own runs', () => {
    expect(emergencyPauseTitle('own')).toMatch(/Stop your own agent runs \(other users' runs keep going\)/)
  })

  test('and no admin card, banner or admin request anywhere', async () => {
    const banners = render(<AdminBanners isAdmin={false} rbac={{ compat: true, legacyGrantsPending: 4 }} pathname="/graph" />)
    expect(banners.container.textContent).toBe('')
    banners.unmount()
    const users = render(<UsersPage />)
    await waitFor(() => expect(router.push).toHaveBeenCalledWith('/graph'))
    expect(users.container.textContent).toBe('')
    expect(adminCalls()).toEqual([])
  })
})

describe('single-operator install sees nothing', () => {
  test('the admin\'s Tunneling section has the controls and no notice', async () => {
    who.isAdmin = true
    answers[`GET ${BASE}/settings`] = { ...(answers[`GET ${BASE}/settings`] as object), canManageTunnels: true }
    render(<ToastProvider><SettingsPage /></ToastProvider>)
    expect(await screen.findByPlaceholderText('e.g. http://your-vps.com:9090')).toBeInTheDocument()
    expect(screen.queryByText(MANAGED_BY_ADMIN)).toBeNull()
  })

  test('the admin\'s emergency stop tooltip announces no change for anyone', () => {
    expect(emergencyPauseTitle('all')).not.toMatch(/your own|keep going/)
  })

  test('no banner, and the Users page shows only the users: no review card, no update card', async () => {
    who.isAdmin = true
    const banners = render(<AdminBanners isAdmin rbac={{ compat: false, legacyGrantsPending: 0 }} pathname="/graph" />)
    expect(banners.container.textContent).toBe('')
    banners.unmount()
    render(<UsersPage />)
    expect(await screen.findByRole('heading', { name: 'User Management' })).toBeInTheDocument()
    await waitFor(() => expect(adminCalls().sort()).toEqual(['/api/admin/legacy-grants', '/api/admin/whats-new']))
    await new Promise(r => setTimeout(r, 0))
    expect(screen.queryByRole('region')).toBeNull()
    expect(screen.queryByText(/previous version/)).toBeNull()
    expect(screen.queryByText('What changed in this update')).toBeNull()
  })
})

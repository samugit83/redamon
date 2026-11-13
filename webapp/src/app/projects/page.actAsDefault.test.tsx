/**
 * The projects page never starts an act-as the admin did not ask for (step 3.16c). With RBAC on,
 * choosing another account in the page's User select starts an impersonation (ProjectProvider owns
 * the act-as dialog since step 3.14), so the page's own default must not choose one:
 *
 * - identity on (permissions off): loading the page posts no act-as, whether /api/auth/me or the
 *   user list answers first; the select shows the admin's own account; a stale selection falls back
 *   to the admin, never to another listed account; creating an account does not switch to it;
 * - permissions on: loading the page makes no act-as request and opens no dialog;
 * - an explicit pick still switches, and with permissions on the dialog names the account (name,
 *   email, type), not its id;
 * - switches off (DV-30): the first listed account is selected as before (`8b51c1d9`) when the user
 *   list answers before or with /api/auth/me; when the session answers first the provider already
 *   holds the admin and nothing is chosen; a stale selection falls back to the first listed account,
 *   and a new account is switched to;
 * - the identity switch turned on after the switches-off default saved the newest account: the next
 *   load posts nothing (review of 3.16c: only an explicit pick by the signed-in admin is restored).
 *
 * The real page under the real ProjectProvider; the session, the lists and the network are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.actAsDefault.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import type { RbacFlags } from '@/lib/authz/flags'
import { FLAGS_OFF, FLAGS_ON } from '@/providers/__testing__/fakeAuth'

const FLAGS_IDENTITY: RbacFlags = { ...FLAGS_OFF, identity: true }
const ADMIN = { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin' as const }
// Newest first, as GET /api/users orders them: the account the old default picked.
const USERS = [
  { id: 'member-9', name: 'Newest', email: 'newest@e2e.local', role: 'standard', createdAt: '', updatedAt: '', hasPassword: true },
  { id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', createdAt: '', updatedAt: '', hasPassword: true },
]

type Auth = {
  user: (typeof ADMIN & { flags: RbacFlags; actingAs?: { id: string } | null; impersonation?: { maxMinutes: number; reasonRequired: boolean } }) | null
  isLoading: boolean
  flags: RbacFlags | null
  refresh: () => Promise<void>
}

const h = vi.hoisted(() => ({
  auth: null as unknown as Auth,
  users: { data: undefined as unknown, isLoading: false },
  create: vi.fn(),
  granted: new Set<string>(),
  // Stable across renders, as Next's are: the provider's callbacks depend on them.
  router: { push: () => {}, replace: () => {} },
  searchParams: new URLSearchParams(''),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.searchParams,
  usePathname: () => '/projects',
}))
vi.mock('next/link', () => ({ default: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth, useOptionalAuth: () => h.auth }))
vi.mock('@/hooks/useCan', () => ({
  useCan: (p: string) => !h.auth.isLoading && h.granted.has(p),
  useRbacFlags: () => h.auth.flags,
}))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useDeleteProject: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => h.users,
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/components/ui', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/components/ui')>()),
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: vi.fn() }),
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  WikiInfoButton: () => null,
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('./page.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))

import { ProjectProvider } from '@/providers/ProjectProvider'
import { rememberActAsPick } from '@/lib/actAsPick'
import ProjectsPage from './page'

type Call = { url: string; method: string; body: string }
let calls: Call[]

function signedIn(flags: RbacFlags, over: Partial<NonNullable<Auth['user']>> = {}): Auth {
  return {
    user: { ...ADMIN, flags, actingAs: null, impersonation: { maxMinutes: 120, reasonRequired: false }, ...over },
    isLoading: false,
    flags,
    refresh: async () => {},
  }
}
const LOADING: Auth = { user: null, isLoading: true, flags: null, refresh: async () => {} }

const page = () => <ProjectProvider><ProjectsPage /></ProjectProvider>
const userSelect = () => screen.getByRole('combobox', { name: 'User' }) as HTMLSelectElement
const actAsCalls = () => calls.filter((c) => c.url === '/api/auth/act-as')
const actAsPosts = () => actAsCalls().filter((c) => c.method === 'POST')
const settle = () => new Promise((r) => setTimeout(r, 30))

beforeEach(() => {
  calls = []
  localStorage.clear()
  h.users = { data: USERS, isLoading: false }
  h.create.mockReset().mockResolvedValue({ id: 'user-new' })
  h.granted = new Set(['users:read', 'users:impersonate', 'users:create'])
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    calls.push({ url: String(url), method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
    return {
      ok: true, status: 200, statusText: '', headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({}), text: async () => '{}', clone() { return this },
    } as unknown as Response
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('identity on, permissions off: loading the page starts no act-as', () => {
  test('the session already read: no act-as is posted, the select shows the admin', async () => {
    h.auth = signedIn(FLAGS_IDENTITY)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsPosts()).toEqual([])
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })

  test('the user list answers before /api/auth/me: still nothing posted, then the admin', async () => {
    h.auth = LOADING
    const { rerender } = render(page())
    await settle()
    h.auth = signedIn(FLAGS_IDENTITY)
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsPosts()).toEqual([])
    expect(calls.some((c) => c.body.includes('member-9'))).toBe(false)
  })

  test('a selection no longer listed falls back to the admin, never to another account', async () => {
    h.auth = signedIn(FLAGS_IDENTITY)
    h.users = { data: undefined, isLoading: true }
    // An explicit pick of this admin's, the only kind restored with identity on (review of 3.16c).
    rememberActAsPick('ghost', ADMIN.id, true)
    const { rerender } = render(page())
    await settle()
    h.users = { data: USERS, isLoading: false }
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(calls.some((c) => c.body.includes('member-9'))).toBe(false)
  })

  test('an explicit pick still acts as the account (Phase 2)', async () => {
    h.auth = signedIn(FLAGS_IDENTITY)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    fireEvent.change(userSelect(), { target: { value: 'member-9' } })
    await waitFor(() => expect(actAsPosts().map((c) => JSON.parse(c.body).targetUserId)).toContain('member-9'))
  })

  test('creating an account does not act as it', async () => {
    h.auth = signedIn(FLAGS_IDENTITY)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    fireEvent.click(screen.getByRole('button', { name: /New User/ }))
    fireEvent.change(screen.getByPlaceholderText('Enter user name'), { target: { value: 'New' } })
    fireEvent.change(screen.getByPlaceholderText('Enter email address'), { target: { value: 'new@e2e.local' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    await settle()
    expect(actAsPosts()).toEqual([])
    expect(userSelect().value).toBe('admin-1')
  })
})

describe('permissions on: loading the page makes no act-as request and opens no dialog', () => {
  test('the session already read', async () => {
    h.auth = signedIn(FLAGS_ON)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsCalls()).toEqual([])
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('the user list answers before /api/auth/me', async () => {
    h.auth = LOADING
    const { rerender } = render(page())
    await settle()
    h.auth = signedIn(FLAGS_ON)
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsCalls()).toEqual([])
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('acting as an account that is gone: it is stopped, no dialog, nobody else chosen', async () => {
    h.auth = signedIn(FLAGS_ON, { actingAs: { id: 'ghost' } })
    render(page())
    await waitFor(() => expect(actAsCalls()).toEqual([{ url: '/api/auth/act-as', method: 'DELETE', body: '' }]))
    await settle()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(actAsPosts()).toEqual([])
  })

  test('creating an account opens no dialog', async () => {
    h.auth = signedIn(FLAGS_ON)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    fireEvent.click(screen.getByRole('button', { name: /New User/ }))
    fireEvent.change(screen.getByPlaceholderText('Enter user name'), { target: { value: 'New' } })
    fireEvent.change(screen.getByPlaceholderText('Enter email address'), { target: { value: 'new@e2e.local' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    await settle()
    expect(screen.queryByRole('dialog', { name: 'Act as another account' })).toBeNull()
    expect(actAsCalls()).toEqual([])
  })

  test('an explicit pick opens the dialog naming the account, never its id', async () => {
    h.auth = signedIn(FLAGS_ON)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    fireEvent.change(userSelect(), { target: { value: 'member-9' } })
    const dialog = await screen.findByRole('dialog', { name: 'Act as another account' })
    expect(screen.getByRole('group', { name: 'Newest, newest@e2e.local, Member' })).toBeInTheDocument()
    expect(dialog).not.toHaveTextContent('member-9')
    expect(screen.getByRole('button', { name: 'Act as Newest' })).toBeInTheDocument()
    expect(actAsCalls()).toEqual([])
  })
})

describe('switches off: the first listed account is the default, as before (DV-30)', () => {
  test('the session already read: the newest account is selected and acted as', async () => {
    h.auth = signedIn(FLAGS_OFF)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('member-9'))
    expect(actAsPosts().map((c) => JSON.parse(c.body).targetUserId)).toContain('member-9')
  })

  test('the user list answers before /api/auth/me: the newest account once the session is read', async () => {
    h.auth = LOADING
    const { rerender } = render(page())
    await settle()
    h.auth = signedIn(FLAGS_OFF)
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('member-9'))
    expect(actAsPosts().map((c) => JSON.parse(c.body).targetUserId)).toContain('member-9')
  })

  // The default runs only while no user is held: once the provider holds the admin it never does,
  // as before 3.16c (the order decides what a live check sees).
  test('/api/auth/me answers before the user list: the admin stays selected, nothing is posted', async () => {
    h.auth = signedIn(FLAGS_OFF)
    h.users = { data: undefined, isLoading: true }
    const { rerender } = render(page())
    await waitFor(() => expect(actAsCalls().map((c) => c.method)).toEqual(['DELETE']))
    h.users = { data: USERS, isLoading: false }
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsPosts()).toEqual([])
  })

  test('a selection no longer listed falls back to the first listed account', async () => {
    h.auth = signedIn(FLAGS_OFF)
    h.users = { data: undefined, isLoading: true }
    localStorage.setItem('redamon-current-user', 'ghost')
    const { rerender } = render(page())
    await settle()
    h.users = { data: USERS, isLoading: false }
    rerender(page())
    await waitFor(() => expect(userSelect().value).toBe('member-9'))
  })

  test('a new account is switched to', async () => {
    h.auth = signedIn(FLAGS_OFF)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('member-9'))
    fireEvent.click(screen.getByRole('button', { name: /New User/ }))
    fireEvent.change(screen.getByPlaceholderText('Enter user name'), { target: { value: 'New' } })
    fireEvent.change(screen.getByPlaceholderText('Enter email address'), { target: { value: 'new@e2e.local' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(actAsPosts().map((c) => JSON.parse(c.body).targetUserId)).toContain('user-new'))
  })
})

describe('the identity switch turned on after the switches-off default ran', () => {
  test('the newest account the default saved is not posted at the next load; the admin is shown', async () => {
    h.auth = signedIn(FLAGS_OFF)
    render(page())
    await waitFor(() => expect(actAsPosts().map((c) => JSON.parse(c.body).targetUserId)).toContain('member-9'))
    await settle()
    cleanup()
    calls = []
    h.auth = signedIn(FLAGS_IDENTITY)
    render(page())
    await waitFor(() => expect(userSelect().value).toBe('admin-1'))
    await settle()
    expect(actAsPosts()).toEqual([])
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })
})

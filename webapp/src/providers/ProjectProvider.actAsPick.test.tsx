/**
 * Whom an admin chose to act as is remembered by the browser (`redamon-current-user`) and re-posted
 * at the next page load while the permissions switch is off (Phase 2). The key belongs to the
 * browser, not to an account (review of step 3.16c):
 *
 * - identity on, permissions off: only a pick the signed-in admin made is restored. A member's id
 *   left on a shared browser, another admin's pick, or a bare id saved with the switches off is never
 *   posted (it would start an act-as audited in the name of whoever signed in next) and is dropped;
 * - sign-out forgets the pick, so nothing resumes at the next sign-in (the logout route ends the
 *   act-as cookie for the same reason);
 * - permissions on: nothing is restored and no dialog opens (step 3.14);
 * - switches off (DV-30): the bare id is saved, kept at sign-out and re-posted, as before.
 *
 * The real AuthProvider, ProjectProvider and useCan; /api/auth/me, the act-as and logout routes, the
 * router and window.location are doubles. One render is one full page load; localStorage is the
 * browser's and survives between them.
 *
 * Run: npx vitest run --no-file-parallelism src/providers/ProjectProvider.actAsPick.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import type { RbacFlags } from '@/lib/authz/flags'
import { FLAGS_OFF, FLAGS_ON } from '@/providers/__testing__/fakeAuth'

const h = vi.hoisted(() => ({
  // Stable across renders, as Next's are: the provider's callbacks depend on them.
  router: { push: () => {}, replace: () => {} },
  searchParams: new URLSearchParams(''),
}))
vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.searchParams,
  usePathname: () => '/graph',
}))

import { AuthProvider, useAuth } from './AuthProvider'
import { ProjectProvider, useProject } from './ProjectProvider'

const KEY = 'redamon-current-user'
const FLAGS_IDENTITY: RbacFlags = { ...FLAGS_OFF, identity: true }
type Person = { id: string; name: string; email: string; role: 'admin' | 'standard' }
const ADMIN_A: Person = { id: 'admin-a', name: 'Ada', email: 'ada@e2e.local', role: 'admin' }
const ADMIN_B: Person = { id: 'admin-b', name: 'Bea', email: 'bea@e2e.local', role: 'admin' }
const MEMBER_M: Person = { id: 'member-m', name: 'Marco', email: 'marco@e2e.local', role: 'standard' }

/** What /api/auth/me answers; null once signed out. */
let session: Record<string, unknown> | null
function signIn(person: Person, flags: RbacFlags) {
  const admin = person.role === 'admin'
  session = {
    ...person,
    flags,
    capabilities: admin ? ['users:read', 'users:impersonate'] : [],
    ...(admin && flags.permissions ? { actingAs: null, impersonation: { maxMinutes: 120, reasonRequired: false } } : {}),
  }
}

type Call = { url: string; method: string; body: string }
let calls: Call[]
const actAsCalls = () => calls.filter((c) => c.url === '/api/auth/act-as')
const actAsPosts = () => actAsCalls().filter((c) => c.method === 'POST').map((c) => JSON.parse(c.body).targetUserId)
const settle = () => new Promise((r) => setTimeout(r, 30))

function Probe() {
  const { userId, setUserId } = useProject()
  const { logout } = useAuth()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'none'}</span>
      <button onClick={() => void setUserId(MEMBER_M.id)}>Act as Marco</button>
      <button onClick={() => void logout()}>Sign out</button>
    </div>
  )
}

/** A full page load (/graph) for whoever /api/auth/me answers; resolves once the act-as is reconciled. */
async function load(expectedUserId: string) {
  render(<AuthProvider><ProjectProvider><Probe /></ProjectProvider></AuthProvider>)
  await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe(expectedUserId))
  await settle()
}

/** The signed-in admin picks Marco in a switcher (Phase 2: posted at once, no dialog). */
async function pickMarco() {
  fireEvent.click(screen.getByRole('button', { name: 'Act as Marco' }))
  await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe(MEMBER_M.id))
  expect(actAsPosts()).toContain(MEMBER_M.id)
  await settle()
}

async function signOut() {
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  await waitFor(() => expect(calls.some((c) => c.url === '/api/auth/logout')).toBe(true))
  await settle()
}

/** The next page load: the previous one is gone, the browser's storage stays. */
function nextLoad() {
  cleanup()
  calls = []
}

const realLocation = window.location
beforeEach(() => {
  calls = []
  session = null
  localStorage.clear()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, pathname: '/graph', replace: vi.fn() } })
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    const u = String(url)
    calls.push({ url: u, method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
    if (u === '/api/auth/me') return session ? json(200, session) : json(401, { error: 'Unauthorized' })
    if (u === '/api/auth/logout') {
      session = null
      return json(200, { success: true })
    }
    return json(200, {})
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

describe('identity on, permissions off: only a pick the signed-in admin made is restored', () => {
  test('a shared browser: member M signs in and out, admin B signs in: no act-as is posted, no dialog', async () => {
    signIn(MEMBER_M, FLAGS_IDENTITY)
    await load(MEMBER_M.id)
    expect(localStorage.getItem(KEY)).toBeNull()
    await signOut()
    nextLoad()
    signIn(ADMIN_B, FLAGS_IDENTITY)
    await load(ADMIN_B.id)
    expect(actAsPosts()).toEqual([])
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test("a member's id left on the browser (switches-off build, no sign-out) is not acted as by the next admin", async () => {
    signIn(MEMBER_M, FLAGS_OFF)
    await load(MEMBER_M.id)
    expect(localStorage.getItem(KEY)).toBe(MEMBER_M.id)
    nextLoad()
    signIn(ADMIN_B, FLAGS_IDENTITY)
    await load(ADMIN_B.id)
    expect(actAsPosts()).toEqual([])
    expect(calls.some((c) => c.body.includes(MEMBER_M.id))).toBe(false)
    expect(localStorage.getItem(KEY)).toBeNull()
  })

  test("another admin's pick is not restored: A picks M, A's session ends without a sign-out, B signs in", async () => {
    signIn(ADMIN_A, FLAGS_IDENTITY)
    await load(ADMIN_A.id)
    await pickMarco()
    nextLoad()
    signIn(ADMIN_B, FLAGS_IDENTITY)
    await load(ADMIN_B.id)
    expect(actAsPosts()).toEqual([])
    expect(localStorage.getItem(KEY)).toBeNull()
  })

  test('an explicit pick by the admin signed in is restored at the next load (Phase 2, step 3.14)', async () => {
    signIn(ADMIN_A, FLAGS_IDENTITY)
    await load(ADMIN_A.id)
    await pickMarco()
    nextLoad()
    await load(MEMBER_M.id)
    expect(actAsPosts()).toEqual([MEMBER_M.id])
  })
})

describe('sign-out forgets the pick', () => {
  test('identity on: nothing resumes at the next sign-in, the same admin included', async () => {
    signIn(ADMIN_A, FLAGS_IDENTITY)
    await load(ADMIN_A.id)
    await pickMarco()
    await signOut()
    expect(localStorage.getItem(KEY)).toBeNull()
    nextLoad()
    signIn(ADMIN_A, FLAGS_IDENTITY)
    await load(ADMIN_A.id)
    expect(actAsPosts()).toEqual([])
  })

  test('switches off: the bare id is saved, kept at sign-out and re-posted at the next load, as before (DV-30)', async () => {
    signIn(ADMIN_A, FLAGS_OFF)
    await load(ADMIN_A.id)
    await pickMarco()
    expect(localStorage.getItem(KEY)).toBe(MEMBER_M.id)
    await signOut()
    expect(localStorage.getItem(KEY)).toBe(MEMBER_M.id)
    nextLoad()
    signIn(ADMIN_A, FLAGS_OFF)
    await load(MEMBER_M.id)
    expect(actAsPosts()).toEqual([MEMBER_M.id])
  })
})

describe('permissions on: nothing is restored', () => {
  test("a member's id left on the browser: no act-as request, no dialog, the admin is themselves", async () => {
    signIn(MEMBER_M, FLAGS_OFF)
    await load(MEMBER_M.id)
    nextLoad()
    signIn(ADMIN_B, FLAGS_ON)
    await load(ADMIN_B.id)
    expect(actAsCalls()).toEqual([])
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

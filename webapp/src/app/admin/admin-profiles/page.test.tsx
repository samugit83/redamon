/**
 * The admin console's admin profiles page (step 6.3; GV-03; DV-06, DV-19): the confirmed Root's
 * (`admin_profiles:manage` is rootOnly), so the console shell denies it to a Full admin before it
 * renders or reads anything. Built-in profiles are read-only and clonable; a profile holds
 * administration and platform permissions and, of Root's own, only `admins:manage` (OQ-02). Every
 * write (create, clone, edit, delete) takes Root's password, as the routes' `requireRootPower` does;
 * a refused password keeps the dialog open, a profile some admin holds is refused with a count and
 * the page lists those admins through the users directory's `?set=` filter (step 6.2).
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/admin-profiles/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { AlertProvider } from '@/components/ui'
import { BUILTIN_ADMIN_PROFILES, builtinSet } from '@/lib/authz/builtinSets'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import type { DirectoryRow } from '@/lib/authz/userDirectory'
import { viewOf } from '@/components/admin/__testing__/permissionViews'
import type { SetRow } from '../permission-sets/setModel'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => '/admin/admin-profiles',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import AdminProfilesPage from './page'
import { AdminConsole } from '../AdminConsole'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const LIST = '/api/admin/admin-profiles'

function profileRow(id: string, holders = 0): SetRow {
  const b = builtinSet(id)!
  return {
    id, kind: 'admin', name: b.name, description: b.description, permissions: [...b.permissions], builtin: true,
    clonedFrom: null, createdAt: null, updatedAt: null, holders, instanceDefault: false,
  }
}

const AUDITORS: SetRow = {
  id: 'prof-aud', kind: 'admin', name: 'Auditors', description: null, permissions: ['users:read', 'audit:read'], builtin: false,
  clonedFrom: 'builtin:security-auditor', createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-02T00:00:00.000Z',
  holders: 1, instanceDefault: false,
}

const listOf = (customs: SetRow[] = [AUDITORS]) => ({
  kind: 'admin',
  sets: [...BUILTIN_ADMIN_PROFILES.map((p) => profileRow(p.id, p.id === 'builtin:full-admin' ? 3 : 0)), ...customs],
})

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

/** The confirmed Root holds every permission. */
const ROOT_VIEW = viewOf({
  userId: 'root-1', accountType: 'root',
  extra: PERMISSION_IDS.map((permission) => ({ permission, reason: { effect: 'grant', kind: 'root' } as const })),
})

let fetchMock: ReturnType<typeof vi.fn>
let routes: { list: () => Response; holders: (url: URL) => Response; write: (method: string, url: URL, body: unknown) => Response }

beforeEach(() => {
  routes = {
    list: () => json(listOf()),
    holders: () => json({ users: [], nextCursor: null, total: 0, setOptions: [], sharing: false }),
    write: (method) => (method === 'POST' ? json({ set: AUDITORS }, 201) : json({ id: 'x', deleted: true })),
  }
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    const method = init?.method ?? 'GET'
    if (method !== 'GET') return routes.write(method, url, init?.body ? JSON.parse(String(init.body)) : undefined)
    if (url.pathname === LIST) return routes.list()
    if (url.pathname === '/api/users/root-1/permissions') return json(ROOT_VIEW)
    if (url.pathname === '/api/admin/users') return routes.holders(url)
    if (url.pathname === '/api/admin/instance-settings') return json({ sharingPolicy: { adminsSeeAllShares: false } })
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const ROOT_HELD = [...PERMISSION_IDS]
const FULL_ADMIN_HELD = [...builtinSet('builtin:full-admin')!.permissions]

function authOf(held: PermissionId[], root: boolean): AuthContextValue {
  const base = fakeAuth(FLAGS_GOV, held)
  return {
    ...base,
    user: {
      ...base.user!, id: root ? 'root-1' : 'adm-a', name: root ? 'Root' : 'Admin A', role: 'admin', email: 'x@e2e.local',
      accountType: root ? 'root' : 'admin',
    },
  }
}

function renderInConsole(held: PermissionId[] = ROOT_HELD, root = true) {
  return render(
    <AuthContext.Provider value={authOf(held, root)}>
      <AlertProvider><AdminConsole><AdminProfilesPage /></AdminConsole></AlertProvider>
    </AuthContext.Provider>,
  )
}

const rowOf = (name: string) => screen.getByRole('rowheader', { name: new RegExp(`^${name}`) }).closest('tr')!
const sent = (method: string) => fetchMock.mock.calls
  .filter(([, init]) => (init?.method ?? 'GET') === method)
  .map(([u, init]) => ({ path: new URL(String(u), 'http://redamon.test').pathname, body: init?.body ? JSON.parse(String(init.body)) : undefined }))
const box = (dialog: HTMLElement, permission: string) => within(dialog).getByRole('checkbox', { name: new RegExp(`^${permission}\\b`) })

async function ready() {
  await screen.findByRole('table', { name: 'Custom profiles' })
}

describe('profiles page Root-only', () => {
  test('a Full admin gets the denied state naming admin_profiles:manage; the page neither renders nor reads the profiles', async () => {
    renderInConsole(FULL_ADMIN_HELD, false)
    expect((await screen.findByRole('alert')).textContent).toMatch(/admin_profiles:manage/)
    expect(screen.queryByRole('heading', { name: 'Admin profiles' })).toBeNull()
    expect(fetchMock.mock.calls.some(([u]) => String(u).startsWith(LIST))).toBe(false)
  })

  test('the confirmed Root gets the page: built-ins read-only and clonable, the custom profile editable, Full admin\'s holders explained', async () => {
    renderInConsole()
    await ready()
    expect(screen.getByRole('heading', { name: 'Admin profiles', level: 1 })).toBeInTheDocument()
    const full = within(rowOf('Full admin'))
    expect(full.getByText('Also held by every admin with no profile recorded.')).toBeInTheDocument()
    expect(full.getByRole('button', { name: 'Show who holds Full admin' }).textContent).toBe('3 holders')
    expect(full.getByRole('button', { name: 'Clone Full admin' })).toBeInTheDocument()
    expect(full.queryByRole('button', { name: /^(Edit|Delete)/ })).toBeNull()
    expect(full.queryByText('Default for new members')).toBeNull()
    const aud = within(rowOf('Auditors'))
    for (const verb of ['Edit', 'Clone', 'Delete']) expect(aud.getByRole('button', { name: `${verb} Auditors` })).toBeInTheDocument()
  })
})

describe('what a profile may hold, and Root\'s password on every write', () => {
  test('the editor lists administration and platform permissions, admins:manage the only Root-only one', async () => {
    renderInConsole()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'New profile' }))
    const dialog = await screen.findByRole('dialog')
    const listed = within(dialog).getAllByRole('checkbox').map((cb) => (cb.closest('label')!.textContent ?? '').trim())
    expect(listed).toContain('admins:manage')
    expect(listed.every((p) => PERMISSIONS[p as PermissionId]?.kind === 'admin')).toBe(true)
    expect(listed.filter((p) => PERMISSIONS[p as PermissionId].rootOnly)).toEqual(['admins:manage'])
    expect(within(dialog).queryByText(/you do not hold it/)).toBeNull()
  })

  test('create asks Root\'s password and sends it; a refused password keeps the dialog open', async () => {
    let refuse = true
    routes.write = () => (refuse
      ? json({ error: 'Password is incorrect', code: 'step_up_failed' }, 403)
      : json({ set: AUDITORS }, 201))
    renderInConsole()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'New profile' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Operators' } })
    fireEvent.click(box(dialog, 'platform:operations'))
    expect(within(dialog).getByText(/Every change to an admin profile is Root's and takes your password\./)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('Enter your password to confirm this change.')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'wrong' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    expect((await within(dialog).findByRole('alert')).textContent).toMatch(/Password is incorrect.*step_up_failed/)
    refuse = false
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('POST').map((c) => c.body)).toEqual([
      { name: 'Operators', description: null, permissions: ['platform:operations'], stepUpPassword: 'wrong' },
      { name: 'Operators', description: null, permissions: ['platform:operations'], stepUpPassword: 'root-passphrase' },
    ])
  })

  test('clone a built-in records its source; an edit sends only the change, with the password', async () => {
    routes.write = (method) => (method === 'POST' ? json({ set: AUDITORS }, 201)
      : json({ set: AUDITORS, changed: true, added: ['audit:export'], removed: [], signedOut: 0 }))
    renderInConsole()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Clone Security auditor' }))
    let dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByText(/Left out/)).toBeNull()
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('POST')[0].body).toEqual({
      name: 'Copy of Security auditor', description: builtinSet('builtin:security-auditor')!.description,
      permissions: [...builtinSet('builtin:security-auditor')!.permissions], cloneFrom: 'builtin:security-auditor',
      stepUpPassword: 'root-passphrase',
    })

    fireEvent.click(screen.getByRole('button', { name: 'Edit Auditors' }))
    dialog = await screen.findByRole('dialog')
    fireEvent.click(box(dialog, 'audit:export'))
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('PUT')).toEqual([{
      path: '/api/admin/admin-profiles/prof-aud',
      body: { permissions: ['users:read', 'audit:read', 'audit:export'], stepUpPassword: 'root-passphrase' },
    }])
    expect((await screen.findByText(/^Saved Auditors: 1 added, 0 removed\.$/))).toBeInTheDocument()
  })
})

describe('delete', () => {
  test('asks Root\'s password and sends it in the body', async () => {
    renderInConsole()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Auditors' }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Delete the admin profile Auditors\?/)
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('DELETE')).toEqual([{ path: '/api/admin/admin-profiles/prof-aud', body: { stepUpPassword: 'root-passphrase' } }])
    expect(await screen.findByText('Deleted Auditors.')).toBeInTheDocument()
  })

  test('a profile an admin holds is refused with a count: the dialog closes and the page lists the admins', async () => {
    routes.write = () => json({ error: '1 account(s) hold this admin profile: give them another first.', code: 'profile_in_use', holders: 1 }, 409)
    const admin: DirectoryRow = {
      id: 'adm-c', name: 'Admin C', email: 'adm-c@e2e.local', accountType: 'admin', status: 'active', mustChangePassword: false,
      lastLoginAt: null, createdAt: '2026-11-01T00:00:00.000Z', sets: null, profile: { id: 'prof-aud', name: 'Auditors' },
      projects: { owned: 0, shared: null }, self: false, actions: [],
    }
    routes.holders = () => json({ users: [admin], nextCursor: null, total: 1, setOptions: [], sharing: false })
    renderInConsole()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Auditors' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const panel = await screen.findByRole('region', { name: 'Who holds Auditors' })
    expect(within(panel).getByText(/1 account\(s\) hold this admin profile/)).toBeInTheDocument()
    expect(await within(panel).findByRole('link', { name: 'Admin C' })).toHaveAttribute('href', '/admin/users/adm-c')
    expect(within(panel).getByRole('link', { name: 'Open in the users directory' })).toHaveAttribute('href', '/admin/users?set=prof-aud')
  })
})

describe('states', () => {
  test('loading, then the route\'s refusal (an unconfirmed Root\'s root_only, for example) with Retry', async () => {
    routes.list = () => json({ error: 'Only Root can create or change admin profiles.', code: 'root_only' }, 403)
    renderInConsole()
    expect(screen.getByRole('status').textContent).toBe('Loading the admin profiles…')
    expect((await screen.findByRole('alert')).textContent).toMatch(/root_only/)
    routes.list = () => json(listOf([]))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No custom profile yet. Clone a built-in profile, or create one with New profile.')).toBeInTheDocument()
  })
})

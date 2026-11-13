/**
 * The admin console's permission sets page (step 6.3; GV-02; DV-06, DV-19): the built-in sets are
 * read-only and clonable, custom sets are created, cloned, edited and deleted through the Phase 3
 * API (step 3.11), and the editor offers only what the signed-in person may give (PE-11: a
 * permission they do not hold is listed disabled, a clone leaves it out and says so). Deleting a set
 * someone holds is refused by the server with a count; the page then lists the holders through the
 * users directory's `?set=` filter (step 6.2). Confirmations go through the app's dialog; loading,
 * error + Retry, denied and empty states; every control labelled. The console shell (6.1) denies the
 * page to anyone without roles:manage before it renders.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/permission-sets/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import { BUILTIN_MEMBER_SETS, builtinSet } from '@/lib/authz/builtinSets'
import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import type { DirectoryPage, DirectoryRow } from '@/lib/authz/userDirectory'
import { viewOf } from '@/components/admin/__testing__/permissionViews'
import type { SetRow } from './setModel'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => '/admin/permission-sets',
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import PermissionSetsPage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const LIST = '/api/admin/permission-sets'

function builtinRow(id: string, holders = 0): SetRow {
  const b = builtinSet(id)!
  return {
    id, kind: 'member', name: b.name, description: b.description, permissions: [...b.permissions], builtin: true,
    clonedFrom: null, createdAt: null, updatedAt: null, holders, instanceDefault: false,
  }
}

function custom(id: string, name: string, permissions: PermissionId[], over: Partial<SetRow> = {}): SetRow {
  return {
    id, kind: 'member', name, description: null, permissions, builtin: false, clonedFrom: null,
    createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-02T00:00:00.000Z', holders: 0, instanceDefault: false, ...over,
  }
}

const LAB = custom('set-lab', 'Lab readers', ['graph:read', 'reports:read', 'agent:kali_exec'], { holders: 2, description: 'Reads the lab' })
const NIGHT = custom('set-night', 'Night shift', ['graph:read'], { instanceDefault: true })

function listOf(customs: SetRow[] = [LAB, NIGHT], defaultId: string | null = 'set-night') {
  return {
    kind: 'member',
    sets: [...BUILTIN_MEMBER_SETS.map((s) => builtinRow(s.id, s.id === 'builtin:recon-operator' ? 4 : 0)), ...customs],
    instanceDefaultSetId: defaultId,
  }
}

function holder(id: string, over: Partial<DirectoryRow> = {}): DirectoryRow {
  return {
    id, name: `${id} name`, email: `${id}@e2e.local`, accountType: 'member', status: 'active', mustChangePassword: false,
    lastLoginAt: null, createdAt: '2026-11-01T00:00:00.000Z', sets: [], profile: null, projects: { owned: 0, shared: null },
    self: false, actions: [], ...over,
  }
}

function directory(users: DirectoryRow[], over: Partial<DirectoryPage> = {}): DirectoryPage {
  return { users, nextCursor: null, total: users.length, setOptions: [], sharing: false, ...over }
}

const inRegistryOrder = (ids: PermissionId[]) => [...ids].sort((a, b) => PERMISSION_IDS.indexOf(a) - PERMISSION_IDS.indexOf(b))
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const forbidden = (permission: string) => json({ error: 'You do not have the permission this needs.', code: 'forbidden', permission }, 403)

/** adm-a: Full admin, member side the Recon operator set (no exploitation approvals, no Kali). */
const ADMIN_A = viewOf({ userId: 'adm-a', accountType: 'admin', sets: [{ id: 'builtin:full-admin' }, { id: 'builtin:recon-operator' }] })

let fetchMock: ReturnType<typeof vi.fn>
let routes: {
  list: () => Response
  me: () => Response
  holders: (url: URL) => Response
  write: (method: string, url: URL, body: unknown) => Response
}

beforeEach(() => {
  routes = {
    list: () => json(listOf()),
    me: () => json(ADMIN_A),
    holders: () => json(directory([])),
    write: (method) => (method === 'POST' ? json({ set: custom('set-new', 'x', []) }, 201) : json({ id: 'x', deleted: true })),
  }
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(String(input), 'http://redamon.test')
    const method = init?.method ?? 'GET'
    if (method !== 'GET') return routes.write(method, url, init?.body ? JSON.parse(String(init.body)) : undefined)
    if (url.pathname === LIST) return routes.list()
    if (url.pathname === '/api/users/adm-a/permissions') return routes.me()
    if (url.pathname === '/api/admin/users') return routes.holders(url)
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage(held: PermissionId[] = ['roles:manage', 'users:read']) {
  const base = fakeAuth(FLAGS_GOV, held)
  const auth = { ...base, user: { ...base.user!, id: 'adm-a', name: 'Admin A', role: 'admin' as const, email: 'adm-a@e2e.local', accountType: 'admin' as const } }
  return render(
    <AuthContext.Provider value={auth}>
      <AlertProvider><PermissionSetsPage /></AlertProvider>
    </AuthContext.Provider>,
  )
}

const rowOf = (name: string) => screen.getByRole('rowheader', { name: new RegExp(`^${name}`) }).closest('tr')!
const calls = (method: string, path?: string) => fetchMock.mock.calls
  .filter(([u, init]) => (init?.method ?? 'GET') === method && (!path || new URL(String(u), 'http://redamon.test').pathname === path))
const listReads = () => calls('GET', LIST).length
const sent = (method: string) => calls(method).map(([u, init]) => ({
  path: new URL(String(u), 'http://redamon.test').pathname,
  body: init?.body ? JSON.parse(String(init.body)) : undefined,
}))
const box = (dialog: HTMLElement, permission: string) => within(dialog).getByRole('checkbox', { name: new RegExp(`^${permission}\\b`) })

async function ready() {
  await screen.findByRole('table', { name: 'Custom sets' })
}

describe('what the page lists', () => {
  test('built-ins are read-only and clonable; custom sets editable, with holders, permissions and the default tag', async () => {
    renderPage()
    await ready()
    const recon = within(rowOf('Recon operator'))
    expect(recon.getByRole('button', { name: 'Clone Recon operator' })).toBeInTheDocument()
    expect(recon.queryByRole('button', { name: /^Edit/ })).toBeNull()
    expect(recon.queryByRole('button', { name: /^Delete/ })).toBeNull()
    expect(recon.getByRole('button', { name: 'Show who holds Recon operator' }).textContent).toBe('4 holders')
    expect(within(screen.getByRole('table', { name: 'Built-in sets' })).getAllByRole('row')).toHaveLength(BUILTIN_MEMBER_SETS.length + 1)

    const lab = within(rowOf('Lab readers'))
    expect(lab.getByText('Reads the lab')).toBeInTheDocument()
    for (const verb of ['Edit', 'Clone', 'Delete']) expect(lab.getByRole('button', { name: `${verb} Lab readers` })).toBeInTheDocument()
    expect(lab.getByRole('button', { name: 'Show who holds Lab readers' }).textContent).toBe('2 holders')
    expect(lab.getByText('3 permissions')).toBeInTheDocument()
    expect(within(rowOf('Night shift')).getByText('Default for new members')).toBeInTheDocument()
    expect(within(rowOf('Default member')).queryByText('Default for new members')).toBeNull()
  })

  test('no stored default: the built-in Default member carries the tag', async () => {
    routes.list = () => json(listOf([LAB], null))
    renderPage()
    await ready()
    expect(within(rowOf('Default member')).getByText('Default for new members')).toBeInTheDocument()
  })

  test('a set\'s permissions open grouped by area', async () => {
    renderPage()
    await ready()
    const lab = within(rowOf('Lab readers'))
    fireEvent.click(lab.getByText('3 permissions'))
    expect(lab.getByText('agent:kali_exec')).toBeInTheDocument()
    expect(lab.getByText('Graph and analytics')).toBeInTheDocument()
  })
})

describe('clone', () => {
  test('starts from the source\'s permissions the editor holds, names the rest, and sends cloneFrom', async () => {
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Clone Red-team operator' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('Name')).toHaveValue('Copy of Red-team operator')
    expect(within(dialog).getByText(/Left out because you do not hold them:/).textContent).toMatch(/agent:kali_exec/)
    expect(box(dialog, 'agent:kali_exec')).not.toBeChecked()
    expect(box(dialog, 'agent:kali_exec')).toBeDisabled()
    expect(box(dialog, 'recon:scan')).toBeChecked()
    routes.write = () => json({ set: custom('set-copy', 'Copy of Red-team operator', []) }, 201)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    const [post] = sent('POST')
    expect(post.path).toBe(LIST)
    expect(post.body.cloneFrom).toBe('builtin:red-team-operator')
    expect(post.body.name).toBe('Copy of Red-team operator')
    const held = new Set(ADMIN_A.held)
    expect(post.body.permissions).toEqual(builtinSet('builtin:red-team-operator')!.permissions.filter((p) => held.has(p)))
    expect(post.body).not.toHaveProperty('stepUpPassword')
    expect((await screen.findByRole('status')).textContent).toBe('Created Copy of Red-team operator.')
    expect(listReads()).toBe(2)
  })
})

describe('edit, limited to what the editor holds (PE-11)', () => {
  test('a permission the editor lacks is listed disabled; one the set already holds may stay or go; only changes are sent', async () => {
    routes.write = () => json({ set: LAB, changed: true, added: [], removed: ['graph:read'], signedOut: 2 })
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Edit Lab readers' }))
    const dialog = await screen.findByRole('dialog')
    const save = within(dialog).getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    const approve = box(dialog, 'agent:approve_dangerous')
    expect(approve).toBeDisabled()
    expect(approve).not.toBeChecked()
    expect(within(dialog).getAllByText(/\(you do not hold it\)/).length).toBeGreaterThan(0)
    // Already in the set, not held by the editor: kept, and it may be removed.
    expect(box(dialog, 'agent:kali_exec')).toBeChecked()
    expect(box(dialog, 'agent:kali_exec')).toBeEnabled()
    fireEvent.click(box(dialog, 'graph:read'))
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Lab analysts' } })
    expect(within(dialog).queryByLabelText('Your password')).toBeNull()
    fireEvent.click(save)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('PUT')).toEqual([{ path: '/api/admin/permission-sets/set-lab', body: { name: 'Lab analysts', permissions: inRegistryOrder(['reports:read', 'agent:kali_exec']) } }])
    expect((await screen.findByRole('status')).textContent).toBe(
      'Saved Lab readers: 0 added, 1 removed. 2 holders lost a permission and were signed out.')
  })

  test('adding an exploitation permission asks for the editor\'s own password first and sends it', async () => {
    routes.me = () => json(viewOf({ userId: 'adm-a', accountType: 'admin', sets: [{ id: 'builtin:full-admin' }, { id: 'builtin:red-team-operator' }] }))
    routes.write = () => json({ set: LAB, changed: true, added: ['agent:approve_dangerous'], removed: [], signedOut: 0 })
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Edit Lab readers' }))
    const dialog = await screen.findByRole('dialog')
    await waitFor(() => expect(box(dialog, 'agent:approve_dangerous')).toBeEnabled())
    fireEvent.click(box(dialog, 'agent:approve_dangerous'))
    expect(within(dialog).getByText(/This change adds agent:approve_dangerous/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('Enter your password to confirm this change.')
    expect(sent('PUT')).toEqual([])
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'own-passphrase' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('PUT')[0].body).toEqual({
      permissions: inRegistryOrder(['agent:approve_dangerous', 'agent:kali_exec', 'graph:read', 'reports:read']),
      stepUpPassword: 'own-passphrase',
    })
  })

  test('a refusal is shown in the dialog and the choices are kept', async () => {
    routes.write = () => json({ error: 'Another set or profile already has this name.', code: 'name_taken' }, 409)
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Edit Lab readers' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Night shift' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect((await within(dialog).findByRole('alert')).textContent).toMatch(/already has this name.*name_taken/)
    expect(within(dialog).getByLabelText('Name')).toHaveValue('Night shift')
  })

  test('your own permissions cannot be read: what the session holds decides what is offered', async () => {
    routes.me = () => json({ error: 'down', code: 'P1001' }, 500)
    renderPage(['roles:manage', 'users:read', 'graph:read'])
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'New set' }))
    const dialog = await screen.findByRole('dialog')
    expect(box(dialog, 'graph:read')).toBeEnabled()
    expect(box(dialog, 'reports:read')).toBeDisabled()
  })
})

describe('new set', () => {
  test('a name is required; the ticked permissions are sent, no password asked', async () => {
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'New set' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('Give the set a name.')
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'Report readers' } })
    fireEvent.change(within(dialog).getByLabelText('Description'), { target: { value: 'Reads reports' } })
    fireEvent.click(box(dialog, 'reports:read'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('POST')).toEqual([{ path: LIST, body: { name: 'Report readers', description: 'Reads reports', permissions: ['reports:read'] } }])
  })
})

describe('delete', () => {
  test('asks in the app\'s dialog first: cancelled sends nothing, confirmed deletes and reads the list again', async () => {
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Night shift' }))
    let dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toMatch(/Delete the permission set Night shift\?/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('DELETE')).toEqual([])
    fireEvent.click(screen.getByRole('button', { name: 'Delete Night shift' }))
    dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(sent('DELETE')).toEqual([{ path: '/api/admin/permission-sets/set-night', body: undefined }]))
    expect((await screen.findByRole('status')).textContent).toBe('Deleted Night shift.')
    expect(listReads()).toBe(2)
  })

  test('a set in use is refused with a count: the page lists who holds it through the users directory', async () => {
    routes.write = () => json({ error: '2 account(s) hold this permission set: give them another first.', code: 'set_in_use', holders: 2 }, 409)
    routes.holders = () => json(directory([holder('mem-a'), holder('adm-b', { accountType: 'admin' })]))
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Lab readers' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' }))
    const panel = await screen.findByRole('region', { name: 'Who holds Lab readers' })
    expect(within(panel).getByText(/2 account\(s\) hold this permission set: give them another first\./)).toBeInTheDocument()
    expect(await within(panel).findByRole('link', { name: 'mem-a name' })).toHaveAttribute('href', '/admin/users/mem-a')
    expect(within(panel).getByRole('link', { name: 'adm-b name' })).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'Open in the users directory' })).toHaveAttribute('href', '/admin/users?set=set-lab')
    const asked = calls('GET', '/api/admin/users').map(([u]) => new URL(String(u), 'http://redamon.test').searchParams)
    expect(asked.map((q) => [q.get('set'), q.get('limit')])).toEqual([['set-lab', '100']])
    expect(listReads()).toBe(2)
  })

  test.each([
    ['set_is_default', 'This set is the default for new members: choose another default first.'],
    ['set_in_plugin_rules', 'Plugins are limited to this permission set (echo): remove it from their access rules first.'],
  ])('another refusal (%s) is shown in the app\'s alert', async (code, error) => {
    routes.write = () => json({ error, code }, 409)
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Night shift' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.getByRole('dialog').textContent).toContain(error))
    expect(screen.getByRole('dialog').textContent).toContain(code)
    expect(screen.queryByRole('region', { name: /Who holds/ })).toBeNull()
  })
})

describe('holders', () => {
  test('the holders button lists them; more than shown links to the directory; Close hides the list', async () => {
    routes.holders = () => json(directory([holder('mem-a')], { total: 140, nextCursor: 'c1' }))
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Show who holds Recon operator' }))
    const panel = await screen.findByRole('region', { name: 'Who holds Recon operator' })
    await within(panel).findByRole('link', { name: 'mem-a name' })
    expect(within(panel).getByText('Showing 1 of 140.')).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'See all 140 in the users directory' }))
      .toHaveAttribute('href', '/admin/users?set=builtin%3Arecon-operator')
    fireEvent.click(within(panel).getByRole('button', { name: 'Close' }))
    expect(screen.queryByRole('region', { name: /Who holds/ })).toBeNull()
  })

  test('nobody holds it; without users:read the notice; a failed read offers Retry', async () => {
    renderPage()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Show who holds Night shift' }))
    let panel = await screen.findByRole('region', { name: 'Who holds Night shift' })
    expect(await within(panel).findByText('Nobody holds this set now.')).toBeInTheDocument()

    routes.holders = () => forbidden('users:read')
    fireEvent.click(screen.getByRole('button', { name: 'Show who holds Lab readers' }))
    panel = await screen.findByRole('region', { name: 'Who holds Lab readers' })
    expect((await within(panel).findByRole('alert')).textContent).toMatch(/users:read/)

    let fail = true
    routes.holders = () => (fail ? json({ error: 'Could not list the accounts', code: 'P1001' }, 500) : json(directory([holder('mem-a')])))
    fireEvent.click(screen.getByRole('button', { name: 'Show who holds Recon operator' }))
    panel = await screen.findByRole('region', { name: 'Who holds Recon operator' })
    expect((await within(panel).findByRole('alert')).textContent).toMatch(/P1001/)
    fail = false
    fireEvent.click(within(panel).getByRole('button', { name: 'Retry' }))
    expect(await within(panel).findByRole('link', { name: 'mem-a name' })).toBeInTheDocument()
  })
})

describe('states', () => {
  test('loading, then the error with Retry', async () => {
    let fail = true
    routes.list = () => (fail ? json({ error: 'Could not list the permission sets', code: 'P1001' }, 500) : json(listOf()))
    renderPage()
    expect(screen.getByRole('status').textContent).toBe('Loading the permission sets…')
    expect((await screen.findByRole('alert')).textContent).toMatch(/P1001/)
    fail = false
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await ready()
  })

  test('denied: the route\'s 403 names the permission', async () => {
    routes.list = () => forbidden('roles:manage')
    renderPage()
    expect((await screen.findByRole('alert')).textContent).toMatch(/roles:manage/)
    expect(screen.queryByRole('button', { name: 'New set' })).toBeNull()
  })

  test('no custom set yet', async () => {
    routes.list = () => json(listOf([], null))
    renderPage()
    expect(await screen.findByText('No custom set yet. Clone a built-in set, or create one with New set.')).toBeInTheDocument()
  })

  test('labelled controls, reachable by keyboard (no tabindex removed)', async () => {
    const { container } = renderPage()
    await ready()
    expect(container.querySelector('[tabindex="-1"]')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Edit Lab readers' }))
    const dialog = await screen.findByRole('dialog')
    for (const cb of within(dialog).getAllByRole('checkbox')) {
      expect(cb).toHaveAccessibleName()
      expect(cb).toHaveAccessibleDescription()
    }
    expect(within(dialog).getByRole('group', { name: 'Permissions' })).toBeInTheDocument()
  })
})

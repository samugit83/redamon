/**
 * The Users page's permission panel (step 3.13; PE-15, PE-16, UI-12, DV-06, DV-19): an account's
 * member sets, overrides (picked by area, grant or deny, expiry, reason), an admin's profile, and
 * its effective permissions with the "because" lines. It mirrors the server's rules (step 3.11):
 * what the person does not hold is disabled with the reason, a change to an admin or one giving a
 * cross-tenant tool or an exploitation right asks for the person's password first, and a refusal is
 * shown as the server sent it. Loading, error (Retry), denied and empty states.
 *
 * The permission APIs are a fetch double answering step 3.11's shapes.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/UserPermissionsPanel.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import type { PermissionId } from '@/lib/authz/permissions'
import { UserPermissionsPanel } from './UserPermissionsPanel'
import { json, memberSetList, profileList, setsOf, viewOf } from './__testing__/permissionViews'

const FUTURE = '2026-12-31T10:00:00.000Z'
const h = vi.hoisted(() => ({
  fetch: vi.fn(),
  views: {} as Record<string, unknown>,
  status: {} as Record<string, number>,
  put: { status: 200, body: { id: 'member-1', changed: true, added: [] as string[], removed: [] as string[], signedOut: false } as unknown },
  sets: { status: 200, body: null as unknown },
}))

const marco = () => viewOf({
  userId: 'member-1',
  sets: [{ id: 'builtin:read-only-analyst' }],
  overrides: [{ permission: 'scan:gvm', effect: 'grant', expiresAt: FUTURE, reason: 'Q4 audit' }],
})
/** A User manager whose own member side is Recon operator: no exploitation, no platform tool. */
const userManager = () => viewOf({
  userId: 'admin-u', accountType: 'admin', profile: 'builtin:user-manager',
  sets: [{ id: 'builtin:user-manager' }, { id: 'builtin:recon-operator' }],
})
/** Full admin with Default member: platform tools and Kali exec. */
const fullAdmin = () => viewOf({
  userId: 'admin-1', accountType: 'admin',
  sets: [{ id: 'builtin:full-admin', via: 'default' }, { id: 'builtin:default-member', via: 'default' }],
})
const root = () => viewOf({
  userId: 'root-1', accountType: 'root',
  extra: [...setsOf('builtin:full-admin', 'builtin:default-member'), 'admins:manage', 'platform:plugins'].map((p) => ({
    permission: p as PermissionId, reason: { effect: 'grant', kind: 'root' } as const,
  })),
})

const puts = () => h.fetch.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')
const putBody = (i = 0) => JSON.parse(String((puts()[i][1] as RequestInit).body)) as Record<string, unknown>

beforeEach(() => {
  h.views = { 'member-1': marco(), 'admin-u': userManager() }
  h.status = {}
  h.put = { status: 200, body: { id: 'member-1', changed: true, added: [], removed: [], signedOut: false } }
  h.sets = { status: 200, body: memberSetList() }
  h.fetch.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    const m = /^\/api\/users\/([^/]+)\/permissions$/.exec(url)
    if (m && init?.method === 'PUT') return json(h.put.body, h.put.status)
    if (m) {
      const id = decodeURIComponent(m[1])
      return h.status[id] ? json(h.views[id], h.status[id]) : json(h.views[id])
    }
    if (url === '/api/admin/permission-sets') return json(h.sets.body, h.sets.status)
    if (url === '/api/admin/admin-profiles') return json(profileList())
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPanel(target = { id: 'member-1', name: 'Marco', email: 'marco@e2e.local' }, selfId = 'admin-u', onChanged = vi.fn()) {
  render(<UserPermissionsPanel user={target} selfId={selfId} onChanged={onChanged} />)
  return onChanged
}
const ready = () => screen.findByRole('group', { name: 'Member permission sets' })
const setBox = (name: string) => within(screen.getByRole('group', { name: 'Member permission sets' })).getByRole('checkbox', { name: new RegExp(`^${name}`) })

describe('panel shows sets and overrides', () => {
  test('the sets ticked, the overrides with expiry and reason, and what the account holds with the because lines', async () => {
    renderPanel()
    await ready()
    expect((setBox('Read-only analyst') as HTMLInputElement).checked).toBe(true)
    expect((setBox('Recon operator') as HTMLInputElement).checked).toBe(false)
    const overrides = screen.getByRole('list', { name: 'Overrides' })
    expect(overrides.textContent).toContain('Grant scan:gvm until')
    expect(overrides.textContent).toContain('Q4 audit')
    const gvm = screen.getByRole('listitem', { name: 'scan:gvm held' })
    expect(gvm.textContent).toContain('Because granted by an override until')
    expect(screen.getByRole('listitem', { name: 'graph:read held' }).textContent)
      .toContain('Because granted by the set Read-only analyst (assigned)')
    expect(screen.queryByRole('listitem', { name: 'recon:scan not held' })).toBeNull()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Show the permissions not held' }))
    expect(screen.getByRole('listitem', { name: 'recon:scan not held' }).textContent).toContain('No set in force holds it (Read-only analyst)')
  })

  test('an admin target shows its profile; a member has none', async () => {
    h.views['admin-x'] = viewOf({ userId: 'admin-x', accountType: 'admin', profile: 'builtin:security-auditor', sets: [{ id: 'builtin:security-auditor' }, { id: 'builtin:default-member', via: 'default' }] })
    h.views['root-1'] = root()
    renderPanel({ id: 'admin-x', name: 'Xena', email: 'x@e2e.local' }, 'root-1')
    const profile = await screen.findByRole('combobox', { name: 'Profile' }) as HTMLSelectElement
    expect(profile.value).toBe('builtin:security-auditor')
    cleanup()
    renderPanel()
    await ready()
    expect(screen.queryByRole('combobox', { name: 'Profile' })).toBeNull()
  })
})

describe('an admin cannot pick a permission they do not hold (PE-03, PE-10)', () => {
  test('a set holding what the person lacks is disabled, with the reason', async () => {
    renderPanel()
    await ready()
    const redTeam = setBox('Red-team operator') as HTMLInputElement
    expect(redTeam.disabled).toBe(true)
    expect(document.getElementById(redTeam.getAttribute('aria-describedby')!)!.textContent)
      .toMatch(/You do not hold agent:approve_phase.*: you can give only what you hold/)
    expect((setBox('Recon operator') as HTMLInputElement).disabled).toBe(false)
  })

  test('a grant of a permission the person lacks is listed disabled, a deny of it is not', async () => {
    renderPanel()
    await ready()
    const picker = screen.getByRole('combobox', { name: 'Permission' })
    const kali = within(picker).getByRole('option', { name: 'agent:kali_exec (you do not hold it)' }) as HTMLOptionElement
    expect(kali.disabled).toBe(true)
    expect((within(picker).getByRole('option', { name: 'recon:scan' }) as HTMLOptionElement).disabled).toBe(false)
    // Grouped by area; never an administration right.
    expect(within(picker).getAllByRole('group').map((g) => g.getAttribute('label'))).toContain('AI agent')
    expect(within(picker).queryByRole('option', { name: /^users:/ })).toBeNull()
    fireEvent.change(screen.getByRole('combobox', { name: 'Effect' }), { target: { value: 'deny' } })
    expect((within(picker).getByRole('option', { name: 'agent:kali_exec' }) as HTMLOptionElement).disabled).toBe(false)
  })

  test('a profile not strictly inside the person\'s own admin side is disabled; Root may give any', async () => {
    h.views['admin-x'] = viewOf({ userId: 'admin-x', accountType: 'admin', profile: 'builtin:security-auditor', sets: [{ id: 'builtin:security-auditor' }] })
    h.views['admin-m'] = viewOf({
      userId: 'admin-m', accountType: 'admin', sets: [{ id: 'builtin:user-manager' }],
      extra: [{ permission: 'admins:manage', reason: { effect: 'grant', kind: 'override', expiresAt: null, reason: null } }, { permission: 'audit:read', reason: { effect: 'grant', kind: 'phase1_admin' } }],
    })
    renderPanel({ id: 'admin-x', name: 'Xena', email: 'x@e2e.local' }, 'admin-m')
    const profile = await screen.findByRole('combobox', { name: 'Profile' })
    expect((within(profile).getByRole('option', { name: 'Full admin (not strictly inside your own admin permissions)' }) as HTMLOptionElement).disabled).toBe(true)
    expect((within(profile).getByRole('option', { name: 'Platform operator (not strictly inside your own admin permissions)' }) as HTMLOptionElement).disabled).toBe(true)
    // Strictly inside: users:* of User manager, and this admin also holds admins:manage and audit:read.
    expect((within(profile).getByRole('option', { name: 'User manager' }) as HTMLOptionElement).disabled).toBe(false)
    // The current profile stays selectable.
    expect((within(profile).getByRole('option', { name: 'Security auditor' }) as HTMLOptionElement).disabled).toBe(false)
  })

  test('a change the server finds not held is shown as it came', async () => {
    h.put = { status: 403, body: { error: 'You can give only permissions you hold yourself; you do not hold: recon:scan.', code: 'not_held', permissions: ['recon:scan'] } }
    renderPanel()
    await ready()
    fireEvent.click(setBox('Read-only analyst'))
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    expect(await screen.findByText(/you do not hold: recon:scan/)).toBeTruthy()
  })
})

describe('expiry and reason saved (PE-15)', () => {
  test('a new grant with an expiry and a reason goes in the PUT, with the other overrides', async () => {
    const onChanged = renderPanel()
    await ready()
    fireEvent.change(screen.getByRole('combobox', { name: 'Permission' }), { target: { value: 'recon:scan' } })
    fireEvent.change(screen.getByLabelText('Expires (optional)'), { target: { value: '2026-12-01T09:30' } })
    fireEvent.change(screen.getByLabelText('Reason (optional)'), { target: { value: 'Ticket 42' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add the override' }))
    expect(screen.getByRole('list', { name: 'Overrides' }).textContent).toContain('Ticket 42')
    h.put = { status: 200, body: { id: 'member-1', changed: true, added: ['recon:scan'], removed: [], signedOut: false } }
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(puts()[0][0]).toBe('/api/users/member-1/permissions')
    expect(putBody()).toEqual({
      overrides: [
        { permission: 'scan:gvm', effect: 'grant', expiresAt: FUTURE, reason: 'Q4 audit' },
        { permission: 'recon:scan', effect: 'grant', expiresAt: new Date('2026-12-01T09:30').toISOString(), reason: 'Ticket 42' },
      ],
    })
    expect(await screen.findByText('Saved: 1 permission added, 0 removed.')).toBeTruthy()
    expect(onChanged).toHaveBeenCalled()
  })

  test('an expiry in the past is refused before anything is sent; no permission chosen is too', async () => {
    renderPanel()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Add the override' }))
    expect(screen.getByRole('alert').textContent).toBe('Choose a permission.')
    fireEvent.change(screen.getByRole('combobox', { name: 'Permission' }), { target: { value: 'recon:scan' } })
    fireEvent.change(screen.getByLabelText('Expires (optional)'), { target: { value: '2001-01-01T00:00' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add the override' }))
    expect(screen.getByRole('alert').textContent).toBe('The expiry must be a date and time in the future.')
    expect(puts()).toHaveLength(0)
  })

  test('removing a set signs the account out: the panel says so; sets [] is the instance default', async () => {
    h.put = { status: 200, body: { id: 'member-1', changed: true, added: [], removed: ['graph:read'], signedOut: true } }
    renderPanel()
    await ready()
    fireEvent.click(setBox('Read-only analyst'))
    expect(screen.getByText(/None ticked: the account holds the instance default set, Default member/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(putBody()).toEqual({ sets: [] })
    expect(await screen.findByText(/signed out everywhere/)).toBeTruthy()
  })

  test('nothing changed: nothing sent', async () => {
    renderPanel()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    expect(screen.getByText('Nothing to save.')).toBeTruthy()
    expect(puts()).toHaveLength(0)
  })
})

describe('step-up prompted (ID-25)', () => {
  test('granting a crossTenant permission asks for the password first and sends it with the change', async () => {
    h.views['admin-1'] = fullAdmin()
    renderPanel(undefined, 'admin-1')
    await ready()
    fireEvent.change(screen.getByRole('combobox', { name: 'Permission' }), { target: { value: 'platform:tunnels' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add the override' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm with your password' })
    expect(dialog.textContent).toContain('This change gives platform:tunnels')
    expect(puts()).toHaveLength(0)
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-own-pass' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save the permissions' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(putBody()).toMatchObject({ stepUpPassword: 'my-own-pass' })
    expect((putBody().overrides as Array<{ permission: string }>).map((o) => o.permission)).toEqual(['scan:gvm', 'platform:tunnels'])
  })

  test('a set with Kali exec asks too; a wrong password keeps the dialog open with the server\'s message', async () => {
    h.views['admin-1'] = fullAdmin()
    h.put = { status: 403, body: { error: 'Password is incorrect', code: 'step_up_failed' } }
    renderPanel(undefined, 'admin-1')
    await ready()
    fireEvent.click(setBox('Red-team operator'))
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm with your password' })
    expect(dialog.textContent).toContain('agent:kali_exec')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'wrong' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save the permissions' }))
    expect(await within(dialog).findByText(/Password is incorrect/)).toBeTruthy()
  })

  test('any change to an admin asks for the password', async () => {
    h.views['admin-x'] = viewOf({ userId: 'admin-x', accountType: 'admin', profile: 'builtin:security-auditor', sets: [{ id: 'builtin:security-auditor' }] })
    h.views['root-1'] = root()
    renderPanel({ id: 'admin-x', name: 'Xena', email: 'x@e2e.local' }, 'root-1')
    fireEvent.change(await screen.findByRole('combobox', { name: 'Profile' }), { target: { value: 'builtin:user-manager' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm with your password' })
    expect(dialog.textContent).toContain('This account is an admin')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'root-pass' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save the permissions' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(putBody()).toEqual({ adminProfileId: 'builtin:user-manager', stepUpPassword: 'root-pass' })
  })

  test('the server asking for the password the mirror did not foresee opens the same dialog', async () => {
    let first = true
    h.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'PUT') {
        if (first) {
          first = false
          return json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, 403)
        }
        return json({ id: 'member-1', changed: true, added: [], removed: [], signedOut: false })
      }
      const m = /^\/api\/users\/([^/]+)\/permissions$/.exec(url)
      if (m) return json(h.views[m[1]])
      return json(memberSetList())
    })
    renderPanel()
    await ready()
    fireEvent.click(setBox('Recon operator'))
    fireEvent.click(screen.getByRole('button', { name: 'Save the permissions' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm with your password' })
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save the permissions' }))
    await waitFor(() => expect(puts()).toHaveLength(2))
    expect(putBody(1)).toMatchObject({ stepUpPassword: 'pw' })
  })
})

describe('states (DV-06)', () => {
  test('loading, then ready', async () => {
    renderPanel()
    expect(screen.getByRole('status').textContent).toBe('Loading the permissions…')
    await ready()
  })

  test('error with Retry', async () => {
    h.status['member-1'] = 500
    h.views['member-1'] = { error: 'Could not read the account\'s permissions', code: 'P1001' }
    renderPanel()
    expect((await screen.findByRole('alert')).textContent).toContain('P1001')
    h.status = {}
    h.views['member-1'] = marco()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await ready()
  })

  test('denied: a 403 naming a permission shows the notice; another refusal its message', async () => {
    h.status['member-1'] = 403
    h.views['member-1'] = { error: 'You do not hold the permission this action needs (users:assign_permissions).', code: 'forbidden', permission: 'users:assign_permissions' }
    renderPanel()
    expect((await screen.findByRole('alert')).textContent).toContain('users:assign_permissions')
    expect(screen.getByText('You do not have the permission this needs.')).toBeTruthy()
    cleanup()
    h.views['member-1'] = { error: "You manage only an admin whose profile is strictly inside your own admin permissions; this one's is not.", code: 'not_a_subset' }
    renderPanel()
    expect((await screen.findByRole('alert')).textContent).toMatch(/You cannot manage this account's permissions\. .*strictly inside/)
  })

  test('empty: no overrides, holds nothing; a set list refused shows its notice and the rest still works', async () => {
    h.views['member-1'] = viewOf({ userId: 'member-1', sets: [{ id: 'builtin:no-access' }] })
    h.sets = { status: 403, body: { error: 'Forbidden', code: 'forbidden', permission: 'roles:manage' } }
    renderPanel()
    await screen.findByRole('group', { name: 'Overrides' })
    expect(screen.getByText('No overrides.')).toBeTruthy()
    expect(screen.getByText('This account holds no permission.')).toBeTruthy()
    expect(within(screen.getByRole('group', { name: 'Member permission sets' })).getByRole('alert').textContent).toContain('roles:manage')
    expect(screen.getByRole('combobox', { name: 'Permission' })).toBeTruthy()
  })
})

describe('labelled controls (DV-19)', () => {
  test('every control is reachable by role and name', async () => {
    renderPanel()
    await ready()
    for (const name of ['Effect', 'Permission']) expect(screen.getByRole('combobox', { name })).toBeTruthy()
    expect(screen.getByLabelText('Expires (optional)')).toBeTruthy()
    expect(screen.getByLabelText('Reason (optional)')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Remove the override of scan:gvm' })).toBeTruthy()
    expect(screen.getByRole('checkbox', { name: 'Show the permissions not held' })).toBeTruthy()
  })
})

describe('seeing what a set holds, and what saving changes', () => {
  test('each set opens its permissions, with how it overlaps the other sets', async () => {
    renderPanel()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: '12 permissions in Read-only analyst' }))
    const dialog = within(await screen.findByRole('dialog', { name: 'Read-only analyst: 12 permissions' }))
    expect(dialog.getByText('graph:read')).toBeTruthy()
    expect(dialog.queryByText('recon:scan')).toBeNull()
    expect(dialog.getByRole('list', { name: 'How it overlaps the other sets' }).textContent).toContain('Fully inside Recon operator, Red-team operator')
    fireEvent.click(dialog.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  test('a change: the review lists it and what it gains; "With your changes" tags it; Discard puts the form back', async () => {
    renderPanel()
    await ready()
    expect(screen.queryByRole('region', { name: 'Review before saving' })).toBeNull()
    fireEvent.click(setBox('Recon operator'))
    const review = within(screen.getByRole('region', { name: 'Review before saving' }))
    expect(review.getByText(/ticked$/).textContent).toBe('Set Recon operator ticked')
    expect(review.getByRole('list', { name: 'Permissions gained' }).textContent).toContain('recon:scan')
    expect(review.queryByRole('list', { name: 'Permissions lost' })).toBeNull()

    expect(screen.queryByRole('listitem', { name: 'recon:scan held' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /^With your changes/ }))
    expect(screen.getByRole('listitem', { name: 'recon:scan held' }).textContent).toContain('added')
    fireEvent.click(screen.getByRole('button', { name: 'Saved' }))
    expect(screen.queryByRole('listitem', { name: 'recon:scan held' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }))
    expect(screen.queryByRole('region', { name: 'Review before saving' })).toBeNull()
    expect((setBox('Recon operator') as HTMLInputElement).checked).toBe(false)
    expect(puts()).toHaveLength(0)
  })

  test('removing a grant: the loss is listed and kept in view, with the sign-out warning', async () => {
    renderPanel()
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Remove the override of scan:gvm' }))
    const review = within(screen.getByRole('region', { name: 'Review before saving' }))
    expect(review.getByRole('list', { name: 'Permissions lost' }).textContent).toBe('scan:gvm')
    expect(review.getByText('Taking a permission away signs the account out when you save.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /^With your changes/ }))
    expect(screen.getByRole('listitem', { name: 'scan:gvm not held' }).textContent).toContain('removed')
  })
})

test('a disabled account: the review says the changes apply once it is active, not that nothing changes', async () => {
  h.views['member-1'] = viewOf({
    userId: 'member-1', assigned: ['builtin:read-only-analyst'],
    extra: [{ permission: 'graph:read', reason: { effect: 'deny', kind: 'inactive', status: 'disabled' } }],
  })
  renderPanel()
  await ready()
  fireEvent.click(setBox('Recon operator'))
  const review = within(screen.getByRole('region', { name: 'Review before saving' }))
  expect(review.getByText(/the account is disabled and holds nothing until it is active/)).toBeTruthy()
  expect(review.queryByRole('list', { name: 'Permissions gained' })).toBeNull()
})

test('Default member is not offered; an account that holds it still shows it, to untick', async () => {
  renderPanel()
  await ready()
  const group = within(screen.getByRole('group', { name: 'Member permission sets' }))
  expect(group.queryByRole('checkbox', { name: /^Default member/ })).toBeNull()
  expect(group.getByRole('checkbox', { name: /^Red-team operator/ })).toBeTruthy()
  cleanup()

  h.views['member-1'] = viewOf({ userId: 'member-1', sets: [{ id: 'builtin:default-member' }] })
  renderPanel()
  await ready()
  const box = setBox('Default member') as HTMLInputElement
  expect(box.checked).toBe(true)
  expect(box.closest('label')!.textContent).toContain('no longer offered')
  fireEvent.click(box)
  expect(setBox('Default member')).toBeTruthy()
})

/**
 * The invite dialog's set picker (step 3.13, ID-28: permissions are chosen at creation). With the
 * permissions switch on, a person holding `users:assign_permissions` chooses the set the invited
 * member starts with; the default is the instance default set (nothing sent: the account follows
 * it). A set holding what the person does not hold is disabled with the reason; one giving Kali
 * exec or an exploitation approval asks for the person's password, sent with the invite. Loading
 * and error states; with the switch off, or without the permission, no picker and no extra read.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/InviteUserModal.sets.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { json, memberSetList, viewOf } from './__testing__/permissionViews'

const h = vi.hoisted(() => ({
  flags: { permissions: true } as { permissions: boolean } | null,
  granted: new Set<string>(['users:create', 'users:assign_permissions']),
  fetch: vi.fn(),
  sets: { status: 200, body: null as unknown },
}))
vi.mock('@/hooks/useCan', () => ({
  useCan: (p: string) => h.granted.has(p),
  useRbacFlags: () => h.flags,
}))

import { InviteUserModal } from './InviteUserModal'

const LINK = 'https://redamon.example.com/invite/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
/** User manager with Recon operator as its member side: no exploitation rights. */
const ME = viewOf({ userId: 'admin-u', accountType: 'admin', sets: [{ id: 'builtin:user-manager' }, { id: 'builtin:recon-operator' }] })
/** Full admin + Default member: may give Red-team operator, with its password. */
const FULL = viewOf({
  userId: 'admin-u', accountType: 'admin',
  sets: [{ id: 'builtin:full-admin', via: 'default' }, { id: 'builtin:red-team-operator' }],
})

let me = ME
const invites = () => h.fetch.mock.calls.filter((c) => c[0] === '/api/users/invite')
const inviteBody = () => JSON.parse(String((invites()[0][1] as RequestInit).body)) as Record<string, unknown>
const setReads = () => h.fetch.mock.calls.filter((c) => c[0] === '/api/admin/permission-sets')

beforeEach(() => {
  h.flags = { permissions: true }
  h.granted = new Set(['users:create', 'users:assign_permissions'])
  h.sets = { status: 200, body: memberSetList([], 'builtin:recon-operator') }
  me = ME
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/admin/permission-sets') return json(h.sets.body, h.sets.status)
    if (url === '/api/users/admin-u/permissions') return json(me)
    if (url === '/api/users/invite') return json({ id: 'user-9', link: LINK, expiresAt: '2026-11-19T10:00:00.000Z', localhostWarning: false }, 201)
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal() {
  const onInvited = vi.fn()
  render(<InviteUserModal isOpen onClose={vi.fn()} onInvited={onInvited} selfId="admin-u" />)
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Nina' } })
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'nina@e2e.local' } })
  return onInvited
}
const picker = () => screen.findByRole('combobox', { name: 'Permission set' })
const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Create the invite link' }))

describe('set picker (ID-28)', () => {
  test('invite sends the chosen set', async () => {
    renderModal()
    fireEvent.change(await picker(), { target: { value: 'builtin:read-only-analyst' } })
    expect(screen.getByText(/Consumes results/)).toBeTruthy()
    submit()
    await waitFor(() => expect(invites()).toHaveLength(1))
    expect(inviteBody()).toEqual({ name: 'Nina', email: 'nina@e2e.local', sets: ['builtin:read-only-analyst'] })
    expect(await screen.findByLabelText('Invite link')).toBeTruthy()
  })

  test('the default is the instance default set: nothing sent, the account follows it', async () => {
    renderModal()
    const select = await picker() as HTMLSelectElement
    expect(select.value).toBe('')
    expect(within(select).getByRole('option', { name: 'Instance default: Recon operator' })).toBeTruthy()
    submit()
    await waitFor(() => expect(invites()).toHaveLength(1))
    expect(inviteBody()).toEqual({ name: 'Nina', email: 'nina@e2e.local' })
  })

  test('a set holding what the inviter does not hold is disabled, with the reason', async () => {
    renderModal()
    const select = await picker()
    const redTeam = within(select).getByRole('option', { name: 'Red-team operator (you do not hold 5 of its permissions)' }) as HTMLOptionElement
    expect(redTeam.disabled).toBe(true)
    expect((within(select).getByRole('option', { name: 'Recon operator' }) as HTMLOptionElement).disabled).toBe(false)
  })

  test('Default member is not offered on its own: the instance default and Red-team operator cover it', async () => {
    renderModal()
    const select = await picker()
    const names = within(select).getAllByRole('option').map((o) => o.textContent ?? '')
    expect(names.some((n) => n.startsWith('Default member'))).toBe(false)
    expect(names.some((n) => n.startsWith('Red-team operator'))).toBe(true)
  })

  test('a set giving Kali exec asks for the inviter\'s password, sent with the invite (ID-25)', async () => {
    me = FULL
    renderModal()
    fireEvent.change(await picker(), { target: { value: 'builtin:red-team-operator' } })
    const password = screen.getByLabelText('Your password')
    expect(document.getElementById(password.getAttribute('aria-describedby')!)!.textContent).toContain('agent:kali_exec')
    submit()
    expect(screen.getByRole('alert').textContent).toBe('Enter your password to give this permission set.')
    expect(invites()).toHaveLength(0)
    fireEvent.change(password, { target: { value: 'my-own-pass' } })
    submit()
    await waitFor(() => expect(invites()).toHaveLength(1))
    expect(inviteBody()).toEqual({
      name: 'Nina', email: 'nina@e2e.local', sets: ['builtin:red-team-operator'], stepUpPassword: 'my-own-pass',
    })
  })

  test('loading, then an error with Retry, then the picker', async () => {
    h.sets = { status: 500, body: { error: 'Could not list the permission sets', code: 'P1001' } }
    renderModal()
    expect(screen.getByRole('status').textContent).toBe('Loading the permission sets…')
    expect((await screen.findByRole('alert')).textContent).toContain('P1001')
    expect(screen.getByText(/The account gets the instance default set/)).toBeTruthy()
    h.sets = { status: 200, body: memberSetList() }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await picker()).toBeTruthy()
  })

  test('the sets could not be read: the invite still goes, with the default set', async () => {
    h.sets = { status: 403, body: { error: 'Forbidden', code: 'forbidden', permission: 'roles:manage' } }
    renderModal()
    expect(await screen.findByText('You do not have the permission this needs.')).toBeTruthy()
    submit()
    await waitFor(() => expect(invites()).toHaveLength(1))
    expect(inviteBody()).toEqual({ name: 'Nina', email: 'nina@e2e.local' })
  })

  test.each([
    ['the permissions switch off', () => { h.flags = { permissions: false } }],
    ['flags not read yet', () => { h.flags = null }],
    ['no users:assign_permissions', () => { h.granted = new Set(['users:create']) }],
  ])('%s: no picker, no read of the sets, the invite as before', async (_name, arrange) => {
    arrange()
    renderModal()
    expect(screen.queryByRole('combobox', { name: 'Permission set' })).toBeNull()
    submit()
    await waitFor(() => expect(invites()).toHaveLength(1))
    expect(inviteBody()).toEqual({ name: 'Nina', email: 'nina@e2e.local' })
    expect(setReads()).toHaveLength(0)
  })
})

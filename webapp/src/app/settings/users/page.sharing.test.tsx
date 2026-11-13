/**
 * The Users page's create form once sharing is in force (step 4.12, ID-12; feature document D-12):
 * passwordless (managed) accounts are no longer offered, so a new account needs a password; the
 * route still accepts a passwordless create (OQ-12), only the form stops offering it. With sharing
 * not in force the form offers them exactly as before (page.columns.test.tsx, "passwordless creation
 * stays available").
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/page.sharing.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  me: {} as Record<string, unknown>,
  create: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => ({ user: h.me, isLoading: false }) }))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

const PASSWORDLESS_HINT = 'Passwordless users can only be accessed via admin switching'

function signIn(sharing: undefined | null | { enabled: boolean; maxLevel: 'read' | 'write' }) {
  h.me = {
    id: 'admin-1', email: 'admin-1@x.z', accountType: 'admin',
    rbac: { compat: false, legacyGrantsPending: 0, identity: true, root: { email: 'root-1@x.z', confirmed: true, chosenAt: null } },
    ...(sharing !== undefined ? { sharing } : {}),
  }
}

function openCreate() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
  fireEvent.click(screen.getByRole('button', { name: /^(Create User|Create with a temporary password)$/ }))
  return within(screen.getByRole('dialog'))
}

beforeEach(() => {
  h.create.mockReset().mockResolvedValue({})
  h.fetch.mockReset().mockImplementation(async () => new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 }))
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('no passwordless when sharing on (ID-12)', () => {
  test('the password is required and the passwordless hint is gone', () => {
    signIn({ enabled: true, maxLevel: 'read' })
    const dialog = openCreate()
    expect(dialog.queryByText(PASSWORDLESS_HINT)).toBeNull()
    expect(dialog.getByLabelText('Password *')).toBeRequired()
    expect(dialog.getByLabelText('Password *')).not.toHaveAttribute('placeholder', 'Leave empty for passwordless user')
    expect(dialog.getByText(/Sharing is on: every new account signs in with its own password/)).toBeInTheDocument()
  })

  test('an empty password is refused before anything is sent', async () => {
    signIn({ enabled: true, maxLevel: 'read' })
    const dialog = openCreate()
    fireEvent.change(dialog.getByLabelText('Name *'), { target: { value: 'Managed' } })
    fireEvent.change(dialog.getByLabelText('Email *'), { target: { value: 'managed@x.z' } })
    fireEvent.click(dialog.getByRole('button', { name: 'Create User' }))
    expect(await dialog.findByText(/Enter a password: with sharing on, every new account signs in with its own password/)).toBeInTheDocument()
    expect(h.create).not.toHaveBeenCalled()
  })

  test('with a password the account is created as before', async () => {
    signIn({ enabled: true, maxLevel: 'read' })
    const dialog = openCreate()
    fireEvent.change(dialog.getByLabelText('Name *'), { target: { value: 'Member' } })
    fireEvent.change(dialog.getByLabelText('Email *'), { target: { value: 'member@x.z' } })
    fireEvent.change(dialog.getByLabelText('Password *'), { target: { value: 'violet-harbour-lantern-42' } })
    fireEvent.change(dialog.getByLabelText('Confirm Password'), { target: { value: 'violet-harbour-lantern-42' } })
    fireEvent.click(dialog.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalledTimes(1))
    expect(h.create.mock.calls[0][0]).toMatchObject({ name: 'Member', email: 'member@x.z', password: 'violet-harbour-lantern-42' })
  })

  test.each([
    ['the switch off (no sharing key)', undefined],
    ['the policy disabled', { enabled: false, maxLevel: 'read' as const }],
    ['the state unread', null],
  ])('%s: passwordless still offered', async (_what, sharing) => {
    signIn(sharing)
    const dialog = openCreate()
    expect(dialog.getByText(PASSWORDLESS_HINT)).toBeInTheDocument()
    expect(dialog.getByLabelText('Password')).not.toBeRequired()
    fireEvent.change(dialog.getByLabelText('Name *'), { target: { value: 'Managed' } })
    fireEvent.change(dialog.getByLabelText('Email *'), { target: { value: 'managed@x.z' } })
    fireEvent.click(dialog.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalledTimes(1))
    expect(h.create.mock.calls[0][0]).toMatchObject({ password: undefined })
  })
})

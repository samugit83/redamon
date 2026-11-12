/**
 * The projects page's "Create New User" dialog chooses the set the new member starts with (step
 * 3.13, ID-28), like the Users page's: with the permissions switch on and users:assign_permissions,
 * a picker whose default is the instance default set (nothing sent); a set giving Kali exec asks
 * for the person's own password. With the switch off the dialog is as before.
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.initialSet.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { json, memberSetList, viewOf } from '@/components/admin/__testing__/permissionViews'

const h = vi.hoisted(() => ({
  create: vi.fn(),
  alertError: vi.fn(),
  granted: new Set<string>(['users:read', 'users:create', 'users:assign_permissions']),
  flags: { permissions: true } as { permissions: boolean } | null,
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }))
vi.mock('next/link', () => ({ default: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
  useDeleteProject: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'admin-1', name: 'Ada', email: 'ada@e2e.local' }], isLoading: false }),
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => h.flags }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'admin-1', setUserId: vi.fn(), setCurrentProject: vi.fn() }),
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('./page.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: h.alertError, dangerConfirm: vi.fn() }),
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  WikiInfoButton: () => null,
}))

import ProjectsPage from './page'

const FULL = viewOf({
  userId: 'admin-1', accountType: 'admin',
  sets: [{ id: 'builtin:full-admin', via: 'default' }, { id: 'builtin:default-member', via: 'default' }],
})
const SESSION = { user: { id: 'admin-1' } } as unknown as AuthContextValue

beforeEach(() => {
  h.create.mockReset().mockResolvedValue({ id: 'user-9' })
  h.alertError.mockReset()
  h.granted = new Set(['users:read', 'users:create', 'users:assign_permissions'])
  h.flags = { permissions: true }
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/admin/permission-sets') return json(memberSetList())
    if (url === '/api/users/admin-1/permissions') return json(FULL)
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function openDialog() {
  render(<AuthContext.Provider value={SESSION}><ProjectsPage /></AuthContext.Provider>)
  fireEvent.click(screen.getByRole('button', { name: /New User/ }))
  fireEvent.change(screen.getByPlaceholderText('Enter user name'), { target: { value: 'Nina' } })
  fireEvent.change(screen.getByPlaceholderText('Enter email address'), { target: { value: 'nina@e2e.local' } })
}
const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Create User' }))

describe('Create New User chooses the set (ID-28)', () => {
  test('the chosen set goes with the new account', async () => {
    openDialog()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Permission set' }), { target: { value: 'builtin:read-only-analyst' } })
    submit()
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0]).toEqual({ name: 'Nina', email: 'nina@e2e.local', sets: ['builtin:read-only-analyst'] })
  })

  test('a set giving Kali exec needs the person\'s password: refused before sending without it', async () => {
    openDialog()
    fireEvent.change(await screen.findByRole('combobox', { name: 'Permission set' }), { target: { value: 'builtin:red-team-operator' } })
    submit()
    expect(h.alertError).toHaveBeenCalledWith('Enter your password to give this permission set.')
    expect(h.create).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-own-pass' } })
    submit()
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0]).toMatchObject({ sets: ['builtin:red-team-operator'], stepUpPassword: 'my-own-pass' })
  })

  test('the switch off: no picker, the account as before', async () => {
    h.flags = { permissions: false }
    openDialog()
    expect(screen.queryByRole('combobox', { name: 'Permission set' })).toBeNull()
    submit()
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0]).toEqual({ name: 'Nina', email: 'nina@e2e.local' })
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

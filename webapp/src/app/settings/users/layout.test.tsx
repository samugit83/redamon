/**
 * /settings/users moves under the admin console (step 6.1, OQ-44): with RBAC_GOVERNANCE_ENABLED on,
 * an account holding users:read is sent to /admin/users and one holding another console permission
 * to /admin, the query string and the anchor kept. A member stays, and so does anyone who came for
 * the change-password dialog (`?changePassword=true`, the user menu's entry), also after the page
 * strips the query. With the switch off nothing moves (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/layout.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { PermissionId } from '@/lib/authz/permissions'

const nav = vi.hoisted(() => ({ replace: vi.fn(), push: vi.fn(), search: '' }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: nav.replace, push: nav.push }),
  useSearchParams: () => new URLSearchParams(nav.search),
  usePathname: () => '/settings/users',
}))

import UsersLayout from './layout'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }

beforeEach(() => {
  nav.replace.mockReset()
  nav.push.mockReset()
  nav.search = ''
  window.history.replaceState(null, '', '/settings/users')
})
afterEach(() => cleanup())

function view(auth: AuthContextValue) {
  return (
    <AuthContext.Provider value={auth}>
      <UsersLayout><p>users page</p></UsersLayout>
    </AuthContext.Provider>
  )
}
const renderAs = (auth: AuthContextValue) => render(view(auth))
const holder = (held: PermissionId[], flags = FLAGS_GOV) => fakeAuth(flags, held)

describe('redirect only with the switch on', () => {
  test('on: a users:read holder goes to /admin/users, and the old page is not rendered meanwhile', () => {
    renderAs(holder(['users:read']))
    expect(nav.replace).toHaveBeenCalledWith('/admin/users')
    expect(nav.push).not.toHaveBeenCalled()
    expect(screen.queryByText('users page')).toBeNull()
    expect(screen.getByRole('status')).toHaveTextContent(/IAM console/)
  })

  test('on: the query string and the anchor are kept', () => {
    nav.search = 'tab=invites'
    window.history.replaceState(null, '', '/settings/users?tab=invites#legacy-review')
    renderAs(holder(['users:read']))
    expect(nav.replace).toHaveBeenCalledWith('/admin/users?tab=invites#legacy-review')
  })

  test('on: another console permission without users:read goes to the console overview', () => {
    renderAs(holder(['audit:read']))
    expect(nav.replace).toHaveBeenCalledWith('/admin')
  })

  test('on: a member holding no console permission stays on the page', () => {
    renderAs(holder(['recon:scan', 'self:mcp_tokens']))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })

  test('off (permissions on): nobody moves, whatever they hold', () => {
    renderAs(holder(['users:read', 'audit:read'], FLAGS_ON))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })

  test('off (every switch off): nobody moves', () => {
    renderAs(holder(['users:read'], FLAGS_OFF))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })

  test('while the session loads: no decision yet, the page decides its own loading state', () => {
    renderAs(fakeAuth(null, [], { isLoading: true }))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })
})

describe('change-password link still works', () => {
  test('?changePassword=true keeps a console holder on the page', () => {
    nav.search = 'changePassword=true'
    renderAs(holder(['users:read']))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })

  test('and keeps them there after the page strips the query to open its dialog', () => {
    nav.search = 'changePassword=true'
    const auth = holder(['users:read'])
    const { rerender } = renderAs(auth)
    // page.tsx opens the dialog, then router.replace('/settings/users'): the query is gone.
    nav.search = ''
    rerender(view(auth))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })

  test('a member with ?changePassword=true stays too', () => {
    nav.search = 'changePassword=true'
    renderAs(holder([]))
    expect(nav.replace).not.toHaveBeenCalled()
    expect(screen.getByText('users page')).toBeInTheDocument()
  })
})

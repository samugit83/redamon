/**
 * The Users page's Delete (step 5.13; SH-17, DV-30): with write sharing switched on it opens the deletion
 * wizard, which reads the deletion plan first; with the switch off it opens the Phase 1 confirmation
 * (an admin's with the deleter's own password) and no plan is asked.
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/page.deleteWizard.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  flags: null as Record<string, boolean> | null,
  fetch: vi.fn(),
  remove: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => h.flags }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'admin-1', email: 'admin-1@x.z', accountType: 'admin', role: 'admin' }, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [
      { id: 'admin-1', name: 'Ada', email: 'admin-1@x.z', role: 'admin', createdAt: '2026-01-01T00:00:00Z' },
      { id: 'alice', name: 'Alice', email: 'alice@x.z', role: 'standard', createdAt: '2026-01-02T00:00:00Z' },
    ],
    isLoading: false, error: null, refetch: vi.fn(),
  }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: h.remove, isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

beforeEach(() => {
  h.flags = null
  h.remove.mockReset().mockResolvedValue(undefined)
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/users/alice/deletion-plan') {
      return new Response(JSON.stringify({ plan: {
        account: { id: 'alice', name: 'Alice', email: 'alice@x.z', role: 'standard', status: 'active' },
        transfers: { available: true, mayForce: false }, sharedProjects: [], unsharedProjects: [], memberships: [],
        conversationsReassigned: 0, liveWork: { agentRuns: 0, queuedScans: 0, schedules: 0 },
        endsWithAccount: { mcpTokens: 0, deviceSessions: 0, nucleiTemplates: 0 },
      } }), { status: 200 })
    }
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 })
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const openDelete = () => {
  render(<AlertProvider><UsersPage /></AlertProvider>)
  const row = screen.getByText('alice@x.z').closest('tr')!
  fireEvent.click(within(row).getByRole('button', { name: 'Delete' }))
}
const planAsked = () => h.fetch.mock.calls.filter(([url]) => String(url).endsWith('/deletion-plan'))

describe('the Users page Delete', () => {
  test('write sharing switched on: the deletion wizard opens and reads the plan', async () => {
    h.flags = { identity: true, permissions: true, sharing: true, sharingWrite: true }
    openDelete()
    expect(await screen.findByRole('dialog', { name: 'Delete Alice' })).toBeInTheDocument()
    expect(await screen.findByText(/no project of this account is shared/)).toBeInTheDocument()
    expect(planAsked()).toHaveLength(1)
  })

  test('the switch off: the Phase 1 confirmation, no plan asked (DV-30)', async () => {
    h.flags = { identity: true, permissions: true, sharing: true, sharingWrite: false }
    openDelete()
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('This will also delete all their projects, conversations, and settings.')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete User' }))
    await vi.waitFor(() => expect(h.remove).toHaveBeenCalledWith('alice'))
    expect(planAsked()).toEqual([])
  })
})

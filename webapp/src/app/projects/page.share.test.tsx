/**
 * The projects page's share controls (step 4.12; UI-06, UI-07, SH-10, ID-12): with sharing in force
 * (/api/auth/me's `sharing.enabled`) the person's own cards offer Share (the dialog, which is
 * ShareDialog.test.tsx's) and the cards shared with them offer Leave; an owner whose set lacks
 * `project:share` sees Share refused up front. With sharing not in force no share control appears
 * (DV-30), and the page's quick "New User" form, which only makes passwordless accounts, gives way to
 * the Users page while sharing is in force (ID-12).
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.share.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'

const h = vi.hoisted(() => ({
  projects: { data: undefined as unknown, isLoading: false, error: null as unknown, refetch: vi.fn() },
  sharing: undefined as undefined | null | { enabled: boolean; maxLevel: 'read' | 'write' },
  can: new Set<string>(),
  push: vi.fn(),
  setCurrentProject: vi.fn(),
  currentProject: null as null | { id: string },
  checkAccessNow: vi.fn(async () => {}),
  dangerConfirm: vi.fn(async () => true),
  alertError: vi.fn(),
  toastSuccess: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: h.push, replace: vi.fn() }) }))
vi.mock('next/link', () => ({
  default: ({ children, href, title }: { children: React.ReactNode; href: string; title?: string }) => <a href={href} title={title}>{children}</a>,
}))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => h.projects,
  useDeleteProject: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'bob', name: 'Bob', email: 'bob@example.test' }], isLoading: false }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.can.has(p), useRbacFlags: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({
    userId: 'bob', setUserId: vi.fn(), setCurrentProject: h.setCurrentProject,
    currentProject: h.currentProject, checkAccessNow: h.checkAccessNow,
  }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useOptionalAuth: () => ({ user: { id: 'bob', name: 'Bob', email: 'bob@example.test', role: 'standard', sharing: h.sharing } }),
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: h.alertError, dangerConfirm: h.dangerConfirm, confirm: vi.fn() }),
  useToast: () => ({ success: h.toastSuccess, error: vi.fn() }),
  WikiInfoButton: () => null,
}))
vi.mock('@/components/sharing/ShareDialog', () => ({
  ShareDialog: ({ project, onClose }: { project: { id: string; name: string }; onClose: () => void }) => (
    <div role="dialog" aria-label={`Share "${project.name}"`}>
      <button type="button" onClick={onClose}>Close stub</button>
    </div>
  ),
}))

import ProjectsPage from './page'

const BOB = { id: 'bob', name: 'Bob', email: 'bob@example.test' }
const ALICE = { id: 'alice', name: 'Alice', email: 'alice@example.test' }
const row = (id: string, name: string, user: typeof BOB, myAccess?: Record<string, unknown>) => ({
  id, userId: user.id, name, description: null, targetDomain: `${id}.example.test`,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', user, ...(myAccess ? { myAccess } : {}),
})
const OWN = row('p-bob', 'Bob recon', BOB, { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: BOB.email } })
const READ = row('p-alice', 'Alice audit', ALICE, { level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: ALICE.email } })

const card = (name: string) => within(screen.getByRole('heading', { name, level: 3 }).closest('.card') as HTMLElement)

/** The auth context the refusal hooks read: the permissions switch on, the set as `capabilities`. */
function renderPage(capabilities: string[] = ['project:share']) {
  const value = {
    user: null, isLoading: false, capabilities: new Set(capabilities), flags: { identity: true, permissions: true, sharing: true, sharingWrite: false, governance: false },
    sessionError: null,
  } as never
  render(<AuthContext.Provider value={value}><ProjectsPage /></AuthContext.Provider>)
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const fetchMock = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  h.projects = { data: [OWN, READ], isLoading: false, error: null, refetch: vi.fn() }
  h.sharing = { enabled: true, maxLevel: 'read' }
  h.can = new Set()
  h.currentProject = null
  h.dangerConfirm.mockResolvedValue(true)
  fetchMock.mockReset().mockResolvedValue(json({ left: { projectId: 'p-alice' }, socketsClosed: true }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('sharing in force', () => {
  test('an owned card offers Share, which opens the dialog for that project without opening the project', () => {
    renderPage()
    expect(card('Alice audit').queryByRole('button', { name: /^Share / })).toBeNull()
    fireEvent.click(card('Bob recon').getByRole('button', { name: 'Share Bob recon' }))
    expect(screen.getByRole('dialog', { name: 'Share "Bob recon"' })).toBeInTheDocument()
    expect(h.push).not.toHaveBeenCalled()
    expect(h.setCurrentProject).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Close stub' }))
    expect(screen.queryByRole('dialog', { name: 'Share "Bob recon"' })).toBeNull()
  })

  test('leave: a shared card offers Leave (never on an owned card); after leaving the list is read again', async () => {
    renderPage()
    expect(card('Bob recon').queryByRole('button', { name: /^Leave / })).toBeNull()
    fireEvent.click(card('Alice audit').getByRole('button', { name: 'Leave Alice audit' }))
    await waitFor(() => expect(h.projects.refetch).toHaveBeenCalled())
    expect(h.dangerConfirm).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/p-alice/leave', expect.objectContaining({ method: 'POST' }))
    expect(h.toastSuccess).toHaveBeenCalledWith('You left "Alice audit".')
    expect(h.checkAccessNow).not.toHaveBeenCalled()
    expect(h.push).not.toHaveBeenCalled()
  })

  test('leaving the open project asks its access at once (the provider then leads out) instead of a toast', async () => {
    h.currentProject = { id: 'p-alice' }
    renderPage()
    fireEvent.click(card('Alice audit').getByRole('button', { name: 'Leave Alice audit' }))
    await waitFor(() => expect(h.checkAccessNow).toHaveBeenCalledTimes(1))
    expect(h.toastSuccess).not.toHaveBeenCalled()
  })

  test('an owner whose set lacks project:share: Share refused up front with the permission notice', () => {
    renderPage([])
    const share = card('Bob recon').getByRole('button', { name: 'Share Bob recon' })
    expect(share).toHaveAttribute('aria-disabled', 'true')
    expect(share.getAttribute('title')).toMatch(/You do not have the permission this needs\. project:share/)
    fireEvent.click(share)
    expect(screen.queryByRole('dialog', { name: 'Share "Bob recon"' })).toBeNull()
    expect(h.push).not.toHaveBeenCalled()
  })

  test('no passwordless account from the quick form: New User leads to the Users page (ID-12)', () => {
    h.can = new Set(['users:read', 'users:create'])
    renderPage()
    expect(screen.queryByRole('button', { name: /New User/ })).toBeNull()
    const link = screen.getByRole('link', { name: /New User/ })
    expect(link).toHaveAttribute('href', '/settings/users')
    expect(link.getAttribute('title')).toMatch(/with a password or an invite/)
  })
})

describe('sharing not in force: no share control (DV-30)', () => {
  test.each([
    ['the switch off (no sharing key, no myAccess)', undefined, false],
    ['the policy disabled', { enabled: false, maxLevel: 'read' as const }, true],
    ['the state unread', null, true],
  ])('%s', (_what, sharing, withAccess) => {
    h.sharing = sharing
    h.can = new Set(['users:read', 'users:create'])
    h.projects.data = withAccess ? [OWN, READ] : [row('p-bob', 'Bob recon', BOB)]
    renderPage()
    expect(screen.queryByRole('button', { name: /^Share / })).toBeNull()
    expect(screen.queryByRole('button', { name: /^Leave / })).toBeNull()
    // The quick form stays as before: a button that opens it.
    expect(screen.getByRole('button', { name: /New User/ })).toBeInTheDocument()
  })
})

/**
 * The projects page with shares (step 4.5; UI-06, SH-09): with sharing in force (/api/auth/me's
 * `sharing.enabled`, the switch and Root's policy) and something shared, the list splits into the
 * person's own projects and a "Shared with me" section, whose cards name the owner and the person's
 * level and offer no delete, with a filter between the two. Nothing shared, or sharing not in force:
 * the page as before. Under act-as the list is the target's, so its shares show at read (D-22).
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.shared.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'

const h = vi.hoisted(() => ({
  projects: { data: undefined as unknown, isLoading: false, error: null as unknown, refetch: vi.fn() },
  sharing: undefined as undefined | null | { enabled: boolean; maxLevel: 'read' | 'write' },
  push: vi.fn(),
  setCurrentProject: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: h.push, replace: vi.fn() }) }))
vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => h.projects,
  useDeleteProject: () => ({ mutateAsync: vi.fn() }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'bob', name: 'Bob', email: 'bob@example.test' }], isLoading: false }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: () => false, useRbacFlags: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'bob', setUserId: vi.fn(), setCurrentProject: h.setCurrentProject }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useOptionalAuth: () => ({ user: { id: 'bob', name: 'Bob', email: 'bob@example.test', role: 'standard', sharing: h.sharing } }),
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: vi.fn() }),
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  WikiInfoButton: () => null,
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
const RAW = row('p-alice-raw', 'Alice traffic', ALICE, { level: 'read', toggles: { rawData: true }, via: 'share', owner: { name: 'Alice', email: ALICE.email } })

const card = (name: string) => screen.getByRole('heading', { name, level: 3 }).closest('.card') as HTMLElement

beforeEach(() => {
  vi.clearAllMocks()
  h.projects = { data: [OWN, READ, RAW], isLoading: false, error: null, refetch: vi.fn() }
  h.sharing = { enabled: true, maxLevel: 'read' }
})
afterEach(cleanup)

describe('sharing in force, something shared', () => {
  test('shared section: the owner and my level on each shared card, no delete', () => {
    render(<ProjectsPage />)
    const shared = screen.getByRole('region', { name: 'Shared with me' })
    const mine = screen.getByRole('region', { name: 'My projects' })
    expect(within(shared).getAllByRole('heading', { level: 3 }).map((e) => e.textContent)).toEqual(['Alice audit', 'Alice traffic'])
    expect(within(mine).getAllByRole('heading', { level: 3 }).map((e) => e.textContent)).toEqual(['Bob recon'])

    expect(within(card('Alice audit')).getByText('Shared by Alice (alice@example.test)')).toBeInTheDocument()
    expect(within(card('Alice audit')).getByText('Read')).toBeInTheDocument()
    expect(within(card('Alice traffic')).getByText('Read + Raw data')).toBeInTheDocument()
    expect(within(card('Alice audit')).queryByTitle('Delete Project')).toBeNull()
    expect(within(card('Alice traffic')).queryByTitle('Delete Project')).toBeNull()
    expect(within(card('Bob recon')).getByTitle('Delete Project')).toBeInTheDocument()
    expect(within(card('Bob recon')).queryByText(/Shared by/)).toBeNull()
  })

  test('opening a shared project selects it like an owned one', () => {
    render(<ProjectsPage />)
    fireEvent.click(card('Alice audit'))
    expect(h.setCurrentProject).toHaveBeenCalledWith(expect.objectContaining({ id: 'p-alice', name: 'Alice audit' }))
    expect(h.push).toHaveBeenCalledWith('/graph?project=p-alice')
  })

  test('filter: My projects, Shared with me, All', () => {
    render(<ProjectsPage />)
    const filter = screen.getByRole('group', { name: 'Show projects' })
    fireEvent.click(within(filter).getByRole('button', { name: 'Shared with me' }))
    expect(within(filter).getByRole('button', { name: 'Shared with me' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.queryByRole('region', { name: 'My projects' })).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Bob recon' })).toBeNull()
    expect(screen.getByRole('heading', { name: 'Alice audit' })).toBeInTheDocument()

    fireEvent.click(within(filter).getByRole('button', { name: 'My projects' }))
    expect(screen.queryByRole('region', { name: 'Shared with me' })).toBeNull()
    expect(screen.getByRole('heading', { name: 'Bob recon' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Alice audit' })).toBeNull()

    fireEvent.click(within(filter).getByRole('button', { name: 'All' }))
    expect(screen.getByRole('heading', { name: 'Bob recon' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Alice audit' })).toBeInTheDocument()
  })

  test('empty state: no project of my own yet, the shared ones still listed (never "No Projects Yet")', () => {
    h.projects.data = [READ]
    render(<ProjectsPage />)
    expect(screen.queryByText('No Projects Yet')).toBeNull()
    const mine = screen.getByRole('region', { name: 'My projects' })
    expect(within(mine).getByText('You have no projects of your own yet.')).toBeInTheDocument()
    expect(within(mine).getByRole('link', { name: /Create Project/ })).toHaveAttribute('href', '/projects/new')
    expect(within(screen.getByRole('region', { name: 'Shared with me' })).getByRole('heading', { name: 'Alice audit' })).toBeInTheDocument()
  })
})

describe('the page as before', () => {
  test('sharing in force but nothing shared: one list, no section, no filter', () => {
    h.projects.data = [OWN]
    render(<ProjectsPage />)
    expect(screen.queryByRole('region', { name: 'Shared with me' })).toBeNull()
    expect(screen.queryByRole('group', { name: 'Show projects' })).toBeNull()
    expect(within(card('Bob recon')).getByTitle('Delete Project')).toBeInTheDocument()
  })

  test.each([
    ['the switch off (no sharing key)', undefined],
    ['the policy disabled', { enabled: false, maxLevel: 'read' as const }],
    ['the state unread', null],
  ])('%s: no section and no filter', (_what, sharing) => {
    h.sharing = sharing
    h.projects.data = [row('p-bob', 'Bob recon', BOB)]
    render(<ProjectsPage />)
    expect(screen.queryByRole('region', { name: 'Shared with me' })).toBeNull()
    expect(screen.queryByRole('group', { name: 'Show projects' })).toBeNull()
    expect(screen.queryByText(/Shared by/)).toBeNull()
  })

  test('nothing at all: "No Projects Yet", sharing in force or not', () => {
    h.projects.data = []
    render(<ProjectsPage />)
    expect(screen.getByText('No Projects Yet')).toBeInTheDocument()
  })

  test('shared rows while /api/auth/me reads sharing as not in force: one list, no section, but no delete on them', () => {
    for (const sharing of [null, { enabled: false, maxLevel: 'read' as const }]) {
      h.sharing = sharing
      render(<ProjectsPage />)
      expect(screen.queryByRole('region', { name: 'Shared with me' })).toBeNull()
      expect(screen.queryByRole('group', { name: 'Show projects' })).toBeNull()
      expect(within(card('Alice audit')).getByText('Shared by Alice (alice@example.test)')).toBeInTheDocument()
      expect(within(card('Alice audit')).queryByTitle('Delete Project')).toBeNull()
      expect(within(card('Bob recon')).getByTitle('Delete Project')).toBeInTheDocument()
      cleanup()
    }
  })
})

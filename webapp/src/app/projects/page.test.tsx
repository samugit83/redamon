/**
 * The projects page: a failed list load is an error with its cause, not "No
 * Projects Yet", and a failed delete is alerted with the server's reason instead
 * of an unhandled rejection that skipped every message.
 *
 * Run: npx vitest run --no-file-parallelism src/app/projects/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  projects: { data: undefined as unknown, isLoading: false, error: null as unknown, refetch: vi.fn() },
  deleteProject: vi.fn(),
  alertError: vi.fn(),
  dangerConfirm: vi.fn(),
  toast: { success: vi.fn(), error: vi.fn() },
  // What the signed-in person holds (hooks/useCan.ts); empty = a member.
  granted: new Set<string>(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }))
vi.mock('next/link', () => ({ default: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjects: () => h.projects,
  useDeleteProject: () => ({ mutateAsync: h.deleteProject }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'u1', name: 'U', email: 'u@example.test' }], isLoading: false }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'u1', setUserId: vi.fn(), setCurrentProject: vi.fn() }),
}))
vi.mock('@/components/projects/ProjectCard', () => ({
  ProjectCard: ({ name, onDelete }: { name: string; onDelete: () => void }) => (
    <button onClick={onDelete}>delete {name}</button>
  ),
}))
vi.mock('./ImportModal', () => ({ ImportModal: () => null }))
vi.mock('./page.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: h.alertError, dangerConfirm: h.dangerConfirm }),
  useToast: () => h.toast,
  WikiInfoButton: () => null,
}))

import ProjectsPage from './page'

const PROJECT = {
  id: 'p1', userId: 'u1', name: 'Alpha', description: null, targetDomain: 'example.test',
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  user: { id: 'u1', name: 'U', email: 'u@example.test' },
}

beforeEach(() => {
  vi.clearAllMocks()
  h.projects = { data: undefined, isLoading: false, error: null, refetch: vi.fn() }
  h.dangerConfirm.mockResolvedValue(true)
  h.granted = new Set()
})
afterEach(cleanup)

describe('the project list', () => {
  test('a failed load shows the cause and a retry, never the empty state', () => {
    h.projects.error = new ApiError({ reason: 'Failed to fetch projects', status: 500, code: 'P1001' })
    render(<ProjectsPage />)
    expect(screen.getByRole('alert')).toHaveTextContent('Failed to fetch projects (P1001 · HTTP 500)')
    expect(screen.queryByText('No Projects Yet')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(h.projects.refetch).toHaveBeenCalled()
  })

  test('an empty account still says so', () => {
    h.projects.data = []
    render(<ProjectsPage />)
    expect(screen.getByText('No Projects Yet')).toBeInTheDocument()
  })
})

describe('deleting a project', () => {
  test('a refused delete alerts the server\'s reason and code, and refreshes the list', async () => {
    h.projects.data = [PROJECT]
    h.deleteProject.mockRejectedValue(new ApiError({
      reason: 'Could not archive this project\'s engagement authorization records, so it was not deleted.',
      status: 500,
      code: 'authorization_archive_failed',
    }))
    render(<ProjectsPage />)
    fireEvent.click(screen.getByRole('button', { name: 'delete Alpha' }))
    await waitFor(() => expect(h.alertError).toHaveBeenCalledWith(
      'Could not archive this project\'s engagement authorization records, so it was not deleted. (authorization_archive_failed · HTTP 500)',
    ))
    expect(h.toast.success).not.toHaveBeenCalled()
    expect(h.projects.refetch).toHaveBeenCalled()
  })

  test('a delete that works still says so', async () => {
    h.projects.data = [PROJECT]
    h.deleteProject.mockResolvedValue(undefined)
    render(<ProjectsPage />)
    fireEvent.click(screen.getByRole('button', { name: 'delete Alpha' }))
    await waitFor(() => expect(h.toast.success).toHaveBeenCalledWith('Project deleted'))
    expect(h.alertError).not.toHaveBeenCalled()
  })
})

/** The user bar is the user directory's (UI-03, step 3.12): each control follows its permission. */
describe('the user bar', () => {
  const ADMIN = ['users:read', 'users:impersonate', 'users:create', 'users:delete']

  test('member sees no user bar on the projects page', () => {
    h.projects.data = []
    render(<ProjectsPage />)
    expect(screen.queryByText('User:')).toBeNull()
    expect(screen.queryByRole('combobox', { name: 'User' })).toBeNull()
    expect(screen.queryByRole('button', { name: /New User/ })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete selected user' })).toBeNull()
    // The project actions stay.
    expect(screen.getByText('New Project')).toBeInTheDocument()
  })

  test('an admin sees the user select, New User and Delete user', () => {
    h.granted = new Set(ADMIN)
    h.projects.data = []
    render(<ProjectsPage />)
    expect(screen.getByRole('combobox', { name: 'User' })).not.toBeDisabled()
    expect(screen.getByRole('button', { name: /New User/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete selected user' })).toBeInTheDocument()
  })

  test('each control follows its own permission: reading the directory alone shows a select that cannot switch', () => {
    h.granted = new Set(['users:read'])
    h.projects.data = []
    render(<ProjectsPage />)
    expect(screen.getByRole('combobox', { name: 'User' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /New User/ })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete selected user' })).toBeNull()
  })
})

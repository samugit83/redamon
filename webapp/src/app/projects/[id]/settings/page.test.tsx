/**
 * The settings page tells a missing project from an outage: under its fixed
 * "Failed to load project settings." it shows the cause (code and status).
 *
 * Run: npx vitest run --no-file-parallelism "src/app/projects/[id]/settings/page.test.tsx"
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({ query: { data: undefined as unknown, isLoading: false, error: null as unknown } }))

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'p1' }),
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}))
vi.mock('@/components/projects', () => ({ ProjectForm: () => <div>form</div> }))
vi.mock('@/hooks/useProjects', () => ({
  useProjectById: () => h.query,
  useUpdateProject: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setCurrentProject: vi.fn() }) }))
vi.mock('./page.module.css', () => ({ default: new Proxy({}, { get: (_t, k) => String(k) }) }))

import ProjectSettingsPage from './page'

afterEach(cleanup)

test('a server failure shows its code and status', () => {
  h.query = { data: undefined, isLoading: false, error: new ApiError({ reason: 'Failed to fetch project', status: 500, code: 'P2024' }) }
  render(<ProjectSettingsPage />)
  expect(screen.getByText('Failed to load project settings.')).toBeInTheDocument()
  expect(screen.getByText('Failed to fetch project (P2024 · HTTP 500)')).toBeInTheDocument()
})

test('a missing project reads differently from an outage', () => {
  h.query = { data: undefined, isLoading: false, error: new ApiError({ reason: 'Not found', status: 404 }) }
  render(<ProjectSettingsPage />)
  expect(screen.getByText('Not found (HTTP 404)')).toBeInTheDocument()
})

// Step 4.13: the Activity link, offered while sharing is in force (/api/auth/me's `sharing`) to the
// people the feed answers: not to a read collaborator, whose feed request is refused.
const auth = vi.hoisted(() => ({ value: null as null | { user: { sharing?: { enabled: boolean } } } }))
vi.mock('@/providers/AuthProvider', () => ({ useOptionalAuth: () => auth.value }))

describe('the Activity link (step 4.13)', () => {
  const project = (myAccess?: { via: string }) => ({ data: { id: 'p1', name: 'P', ...(myAccess ? { myAccess } : {}) }, isLoading: false, error: null })
  afterEach(() => { auth.value = null })

  test('sharing in force: the owner and an overseer get a link to the project activity', () => {
    auth.value = { user: { sharing: { enabled: true } } }
    for (const via of ['owner', 'oversight', 'break_glass']) {
      h.query = project({ via })
      render(<ProjectSettingsPage />)
      expect(screen.getByRole('link', { name: 'Activity' })).toHaveAttribute('href', '/projects/p1/activity')
      cleanup()
    }
  })

  test('a read collaborator gets no link; nor anyone with sharing off, unread, or outside a session', () => {
    auth.value = { user: { sharing: { enabled: true } } }
    h.query = project({ via: 'share' })
    render(<ProjectSettingsPage />)
    expect(screen.queryByRole('link', { name: 'Activity' })).toBeNull()
    cleanup()
    for (const value of [{ user: { sharing: { enabled: false } } }, { user: {} }, null]) {
      auth.value = value
      h.query = project({ via: 'owner' })
      render(<ProjectSettingsPage />)
      expect(screen.queryByRole('link', { name: 'Activity' })).toBeNull()
      cleanup()
    }
  })
})

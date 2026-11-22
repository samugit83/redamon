/**
 * The saved project's read got no answer even after its retries: the header offers Retry beside
 * "No Project", which reloads the page and so reads everything again. A project read the server
 * answered (a 404, a 5xx) leaves no load error and no Retry, as before.
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/GlobalHeader/ProjectSelector/ProjectSelector.unreachable.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { toApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({ projectLoadError: null as unknown }))

vi.mock('next/navigation', () => ({ usePathname: () => '/graph' }))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: vi.fn(), pushUnguarded: vi.fn() }),
  useNavigationGuard: () => null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({
    currentProject: null, setCurrentProject: vi.fn(), userId: 'bob', checkAccessNow: vi.fn(),
    projectLoadError: h.projectLoadError,
  }),
}))
vi.mock('@/providers/AuthProvider', () => ({ useOptionalAuth: () => null }))
vi.mock('@/hooks/useProjects', () => ({ useProjects: () => ({ data: [], refetch: vi.fn() }) }))

import { ProjectSelector } from './ProjectSelector'

const realLocation = window.location
let reload: ReturnType<typeof vi.fn>
beforeEach(() => {
  reload = vi.fn()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, reload } })
})
afterEach(() => {
  cleanup()
  h.projectLoadError = null
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

describe('ProjectSelector when the saved project could not be read', () => {
  test('no answer: a Retry beside "No Project" says why and reloads the page', () => {
    h.projectLoadError = toApiError(new TypeError('Failed to fetch'), 'Could not load the saved project')
    render(<ProjectSelector />)
    expect(screen.getByText('No Project')).toBeInTheDocument()
    const retry = screen.getByRole('button', { name: 'Retry loading the project' })
    expect(retry.getAttribute('title')).toBe('Could not reach the server: Could not load the saved project (network_error). Retry reloads the page.')
    fireEvent.click(retry)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test('no load error: no Retry', () => {
    render(<ProjectSelector />)
    expect(screen.getByText('No Project')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry loading the project' })).toBeNull()
  })
})

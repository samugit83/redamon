/**
 * TrafficMind page on a failure: the list, the filter options, a delete and the
 * detail drawer each say what failed with its code and status. A failed list used
 * to read "No captured traffic yet", which sends the operator to enable a capture
 * that is already on.
 *
 * Run: npx vitest run --no-file-parallelism src/app/traffic/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  list: {} as Record<string, unknown>,
  facets: {} as Record<string, unknown>,
  detail: {} as Record<string, unknown>,
  mutateAsync: vi.fn(),
  toast: { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() },
  // What the signed-in person holds (hooks/useCan.ts); empty = a member.
  granted: new Set<string>(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ projectId: 'p1', userId: 'u1', currentProject: { name: 'P' }, isLoading: false }),
}))
vi.mock('@/components/traffic/TrafficCaptureStatus', () => ({ TrafficCaptureStatus: () => null }))
vi.mock('@/components/traffic/TrafficMindSettingsModal', () => ({
  TrafficMindSettingsModal: ({ isOpen }: { isOpen: boolean }) => <div data-testid="capture-settings" data-open={String(isOpen)} />,
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))
vi.mock('@/components/ui', () => ({
  Drawer: ({ isOpen, children }: { isOpen: boolean; children: ReactNode }) => (isOpen ? <div>{children}</div> : null),
  useToast: () => h.toast,
  useAlertModal: () => ({ dangerConfirm: async () => true }),
  WikiInfoButton: () => null,
}))
vi.mock('./hooks/useTrafficData', async () => {
  const actual = await vi.importActual<typeof import('./hooks/useTrafficData')>('./hooks/useTrafficData')
  return {
    ...actual,
    useTrafficList: () => h.list,
    useTrafficFacets: () => h.facets,
    useTrafficDetail: () => h.detail,
    useDeleteTraffic: () => ({ mutateAsync: h.mutateAsync }),
  }
})

import TrafficPage from './page'

const row = {
  id: 't1', startedAt: '2026-10-29T10:00:00Z', source: 'recon', runId: null, sessionId: null, tool: 'httpx',
  phase: null, method: 'GET', scheme: 'https', host: 'app.example.test', port: 443, path: '/', query: null,
  statusCode: 200, respBodySize: 10, respContentType: null, responseTimeMs: 5, isTls: true, isReplay: false,
  hasSetCookie: false, hadAuth: false, reflectedParams: false, blocked: false, inScope: true,
  iocIncidentId: null, iocIncidentUrl: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.list = { data: { rows: [], total: 0, page: 0, pageSize: 50 }, isLoading: false, isError: false, error: null }
  h.facets = { data: { tools: [], hosts: [], runs: [], sessions: [] }, isError: false, error: null }
  h.detail = { data: undefined, isLoading: false, isError: false, error: null }
  h.granted = new Set()
})
afterEach(cleanup)

describe('TrafficPage failures', () => {
  test('a failed list shows its cause, not the empty-state advice', () => {
    h.list = { data: undefined, isLoading: false, isError: true, error: new ApiError({ reason: 'Failed to list traffic', status: 500, code: 'P2024' }) }
    render(<TrafficPage />)
    expect(screen.getByRole('alert').textContent).toBe('Could not load traffic: Failed to list traffic (P2024 · HTTP 500)')
    expect(screen.queryByText(/No captured traffic yet/)).toBeNull()
  })

  test('an empty, successful list still gives the empty-state advice', () => {
    render(<TrafficPage />)
    expect(screen.getByText(/No captured traffic yet/)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('failed filter options say so inline', () => {
    h.facets = { data: undefined, isError: true, error: new ApiError({ reason: 'Failed to load facets', status: 503, code: 'P1001' }) }
    render(<TrafficPage />)
    expect(screen.getByText('Filter options unavailable: Failed to load facets (P1001 · HTTP 503)')).toBeTruthy()
  })

  test('a failed delete toasts its cause', async () => {
    h.list = { data: { rows: [row], total: 1, page: 0, pageSize: 50 }, isLoading: false, isError: false, error: null }
    h.mutateAsync.mockRejectedValue(new ApiError({ reason: 'Failed to delete traffic', status: 500, code: 'P2024' }))
    render(<TrafficPage />)
    fireEvent.click(screen.getByText('Delete all matching'))
    await waitFor(() => expect(h.toast.error).toHaveBeenCalledWith('Failed to delete traffic (P2024 · HTTP 500)'))
  })

  test('the detail drawer shows a load failure instead of staying blank', () => {
    h.list = { data: { rows: [row], total: 1, page: 0, pageSize: 50 }, isLoading: false, isError: false, error: null }
    h.detail = { data: undefined, isLoading: false, isError: true, error: new ApiError({ reason: 'Failed to load transaction', status: 500, code: 'ENOENT' }) }
    render(<TrafficPage />)
    fireEvent.click(screen.getByLabelText('Open request/response detail'))
    expect(screen.getByText('Could not load this transaction: Failed to load transaction (ENOENT · HTTP 500)')).toBeTruthy()
  })
})

/** The TrafficMind settings are platform:traffic_capture's (step 3.12, UI-03). */
describe('TrafficPage settings', () => {
  test('traffic modal not mounted without the permission, and no Settings button', () => {
    render(<TrafficPage />)
    expect(screen.queryByRole('button', { name: /Settings/ })).toBeNull()
    expect(screen.queryByTestId('capture-settings')).toBeNull()
  })

  test('with platform:traffic_capture: the button opens the mounted modal', () => {
    h.granted = new Set(['platform:traffic_capture'])
    render(<TrafficPage />)
    expect(screen.getByTestId('capture-settings').getAttribute('data-open')).toBe('false')
    fireEvent.click(screen.getByRole('button', { name: /Settings/ }))
    expect(screen.getByTestId('capture-settings').getAttribute('data-open')).toBe('true')
  })
})

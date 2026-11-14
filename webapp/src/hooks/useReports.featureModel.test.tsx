/**
 * Report generation and the user's "Report narratives" model.
 *
 * The gate runs inside the mutation. A cancelled first prompt resolves null
 * (nothing was sent, so there is no error to show); model_required from the
 * route opens the gate again and retries once; every other code becomes the
 * mutation's error, worded by featureModelMessage.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import type { ReactNode } from 'react'
import { renderHook, screen, cleanup, fireEvent, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { useAllReports, useReports, type ReportMeta } from './useReports'

const REPORTS_URL = '/api/projects/p1/reports'
const REPORT = { id: 'r1', projectId: 'p1', title: 'Pentest Report', hasNarratives: true } as ReportMeta

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <FeatureModelGateProvider>{children}</FeatureModelGateProvider>
    </QueryClientProvider>
  )
}

function reportsRoute(post: () => Response) {
  return (url: string, init: RequestInit | undefined) => {
    if (url === REPORTS_URL && init?.method === 'POST') return post()
    return jsonResponse(200, [])
  }
}

describe('useAllReports().generate', () => {
  test('no saved model: the gate opens first, then the report is generated once', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    await pickInGate('Claude Opus 4.6')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.saved).toEqual({ report_narratives: 'claude-opus-4-6' })
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(1)
  })

  test('cancelling the first prompt resolves null and sends nothing', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await expect(generated).resolves.toBeNull()
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(0)
    await waitFor(() => expect(result.current.generateError).toBeNull())
  })

  test('model_required from the route opens the gate and retries exactly once', async () => {
    let n = 0
    const stub = stubGateFetch({ report_narratives: 'claude-haiku-4-5' }, reportsRoute(() => (++n === 1
      ? jsonResponse(409, { error: 'x', code: 'model_required', featureId: 'report_narratives' })
      : jsonResponse(200, REPORT))))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1') })
    await pickInGate('Claude Opus 4.6')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(2)
  })

  test('a non-gate code is the mutation error, in its fixed wording, and never opens the gate', async () => {
    stubGateFetch({ report_narratives: 'claude-haiku-4-5' },
      reportsRoute(() => jsonResponse(502, { error: 'x', code: 'agent_outdated', featureId: 'report_narratives' })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1')).rejects.toThrow('The agent is older than the webapp: rebuild it')
    })
    await waitFor(() => expect(result.current.generateError?.message).toBe('The agent is older than the webapp: rebuild it'))
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('useReports(projectId).generate', () => {
  test('runs through the same gate', async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useReports('p1'), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate() })
    await pickInGate('Claude Haiku 4.5')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.saved).toEqual({ report_narratives: 'claude-haiku-4-5' })
  })
})

// P5-06: on a project the person does not own the route runs the narratives on the OWNER's model
// (or skips them, use_agent_required / owner_model_required); the person's own model is never
// read, asked for, nor offered, so a collaborator with no model of their own still generates.
describe("useAllReports().generate on a project the person does not own (ownerModel)", () => {
  test("no gate and no read of the person's own model: the report is asked once", async () => {
    const skipped = { ...REPORT, hasNarratives: false, narrativesSkipped: 'use_agent_required' }
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(201, skipped)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1', { ownerModel: true })).resolves.toEqual(skipped)
    })
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(1)
    expect(stub.calls(`/api/users/${GATE_USER}/settings`)).toHaveLength(0)
    expect(stub.calls('/api/models')).toHaveLength(0)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test("a gate code about the owner's model is the error, never the person's gate", async () => {
    const stub = stubGateFetch({}, reportsRoute(() =>
      jsonResponse(503, { error: 'x', code: 'model_unavailable', featureId: 'report_narratives', model: 'custom/owner-1' })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1', { ownerModel: true }))
        .rejects.toThrow("The project owner's Report narratives model could not be used")
    })
    expect(stub.calls(REPORTS_URL, 'POST')).toHaveLength(1)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test("the owner's own project (ownerModel false) keeps the gate", async () => {
    const stub = stubGateFetch({}, reportsRoute(() => jsonResponse(200, REPORT)))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    let generated!: Promise<ReportMeta | null>
    act(() => { generated = result.current.generate('p1', { ownerModel: false }) })
    await pickInGate('Claude Opus 4.6')
    await expect(generated).resolves.toEqual(REPORT)
    expect(stub.saved).toEqual({ report_narratives: 'claude-opus-4-6' })
  })
})

describe('what a report failure says (G-12, G-20, G-21, P-29, P-33)', () => {
  test('a proxy 504 names its status instead of a bare "failed"', async () => {
    stubGateFetch({ report_narratives: 'gpt-5' },
      reportsRoute(() => new Response('<html>504 Gateway Time-out</html>', { status: 504 })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1')).rejects.toThrow('Report generation failed (non_json_response · HTTP 504)')
    })
  })

  test('a coded failure keeps its fixed wording and adds the provider class and status', async () => {
    stubGateFetch({ report_narratives: 'gpt-5' }, reportsRoute(() => jsonResponse(503, {
      error: 'x', code: 'agent_outdated', featureId: 'report_narratives',
      errorClass: 'AuthenticationError', providerStatus: 401,
    })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1')).rejects.toThrow(
        'The agent is older than the webapp: rebuild it (AuthenticationError · provider HTTP 401)')
    })
  })

  test('a narratives failure keeps the route text, its status and the provider facts', async () => {
    stubGateFetch({ report_narratives: 'gpt-5' }, reportsRoute(() => jsonResponse(500, {
      error: 'Failed to generate report narratives. The details are in the agent log.',
      error_class: 'RateLimitError', provider_status: 429,
    })))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.generate('p1')).rejects.toThrow(
        'Failed to generate report narratives. The details are in the agent log. (HTTP 500) ' +
        '[RateLimitError · provider HTTP 429]')
    })
  })

  test('a failed list is an error with its code and status, not an empty list', async () => {
    stubGateFetch({}, () => jsonResponse(500, { error: 'Failed to list reports', code: 'P1001' }))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await waitFor(() => expect(result.current.error?.message).toBe('Failed to list reports (P1001 · HTTP 500)'))
  })

  test('a refused delete rejects with its cause instead of resolving', async () => {
    stubGateFetch({}, (url, init) => (init?.method === 'DELETE'
      ? jsonResponse(500, { error: 'Delete failed', code: 'EACCES' })
      : jsonResponse(200, [])))
    const { result } = renderHook(() => useAllReports(), { wrapper })
    await act(async () => {
      await expect(result.current.deleteReportAsync({ projectId: 'p1', reportId: 'r1' }))
        .rejects.toThrow('Delete failed (EACCES · HTTP 500)')
    })
  })
})

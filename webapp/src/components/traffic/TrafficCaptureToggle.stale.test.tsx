/**
 * The traffic capture toggle (step 5.2, SH-40): it saves `captureProxyEnabled` with the row's version
 * (from the settings matrix's list row, or its own read); a stale 409 says "Someone else changed this
 * project" and shows the row's value as it is now; the next save carries that version.
 *
 * Run: npx vitest run --no-file-parallelism src/components/traffic/TrafficCaptureToggle.stale.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))

import { TrafficCaptureToggle } from './TrafficCaptureToggle'

const V1 = '2026-11-13T10:00:00.000Z'
const V2 = '2026-11-13T11:00:00.000Z'
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const h = vi.hoisted(() => ({ calls: [] as Array<{ method: string; body?: Record<string, unknown> }>, stale: false }))

beforeEach(() => {
  h.calls = []
  h.stale = false
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    h.calls.push({ method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (method === 'PUT') {
      return h.stale ? json(409, { error: 'changed', code: 'stale_save' }) : json(200, { id: 'p1', updatedAt: V2 })
    }
    return json(200, { id: 'p1', captureProxyEnabled: true, updatedAt: V2 })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})


describe('the traffic capture toggle and a stale row (step 5.2)', () => {
  test("sends the version of the matrix's list row", async () => {
    render(<TrafficCaptureToggle projectId="p1" initialEnabled={false} initialVersion={V1} />)
    fireEvent.click(screen.getByLabelText(/Toggle traffic capture/))
    await waitFor(() => expect(h.calls.filter(c => c.method === 'PUT')).toHaveLength(1))
    expect(h.calls[0].body).toEqual({ captureProxyEnabled: true, updatedAt: V1 })
  })

  test('auto-save stale -> 409 and reload: the notice, the value as stored now, its version next', async () => {
    h.stale = true
    render(<TrafficCaptureToggle projectId="p1" initialEnabled={false} initialVersion={V1} />)
    fireEvent.click(screen.getByLabelText(/Toggle traffic capture/))
    await waitFor(() => expect(toast.warning).toHaveBeenCalledWith(expect.stringMatching(/Someone else changed this project/)))
    expect(h.calls.map(c => c.method)).toEqual(['PUT', 'GET'])
    expect(toast.error).not.toHaveBeenCalled()
    h.stale = false
    // Stored on now (the reload): the next click turns it off, with the reloaded version.
    await waitFor(() => expect(screen.getByLabelText(/Toggle traffic capture/)).not.toBeDisabled())
    fireEvent.click(screen.getByLabelText(/Toggle traffic capture/))
    await waitFor(() => expect(h.calls.filter(c => c.method === 'PUT')).toHaveLength(2))
    expect(h.calls.filter(c => c.method === 'PUT')[1].body).toEqual({ captureProxyEnabled: false, updatedAt: V2 })
  })
})

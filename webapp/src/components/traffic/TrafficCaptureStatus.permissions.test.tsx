/**
 * The capture status of the /traffic page tells whoever may not change the capture
 * (platform:traffic_capture, step 3.12) to ask an administrator. Whoever may change it gets an
 * Enable / Disable button instead, which writes exactly what that project's switch in the
 * settings matrix (TrafficCaptureToggle) writes: the same PUT, the same body, the same version.
 *
 * Run: npx vitest run --no-file-parallelism src/components/traffic/TrafficCaptureStatus.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import type { ReactElement } from 'react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const V1 = '2026-11-13T10:00:00.000Z'
const V2 = '2026-11-13T11:00:00.000Z'
const h = vi.hoisted(() => ({
  granted: new Set<string>(),
  stored: false,
  puts: [] as Array<{ url: string; body: Record<string, unknown> }>,
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))

import { TrafficCaptureStatus } from './TrafficCaptureStatus'
import { TrafficCaptureToggle } from './TrafficCaptureToggle'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const renderIn = (ui: ReactElement) => render(<ToastProvider>{ui}</ToastProvider>)

beforeEach(() => {
  h.granted = new Set()
  h.stored = false
  h.puts = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'PUT') {
      const body = JSON.parse(String(init.body))
      h.puts.push({ url, body })
      h.stored = body.captureProxyEnabled
      return json(200, { id: 'p1', captureProxyEnabled: h.stored, updatedAt: V2 })
    }
    return json(200, { id: 'p1', captureProxyEnabled: h.stored, updatedAt: V1 })
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('TrafficCaptureStatus and platform:traffic_capture', () => {
  test('capture off, without the permission: ask an administrator, and no button', async () => {
    renderIn(<TrafficCaptureStatus projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Disabled')).toBeTruthy())
    expect(screen.getByText('Ask an administrator to enable it.')).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
  })

  test('capture on, without the permission: the status only', async () => {
    h.stored = true
    renderIn(<TrafficCaptureStatus projectId="p1" projectName="P" />)
    await waitFor(() => expect(screen.getByText('Enabled')).toBeTruthy())
    expect(screen.queryByRole('button')).toBeNull()
  })

  test('capture off, with the permission: no ask-an-admin line; Enable turns it on for this project', async () => {
    h.granted = new Set(['platform:traffic_capture'])
    renderIn(<TrafficCaptureStatus projectId="p1" projectName="P" />)
    const enable = await screen.findByRole('button', { name: 'Enable traffic capture for P' })
    expect(screen.queryByText(/Ask an administrator/)).toBeNull()
    fireEvent.click(enable)
    await waitFor(() => expect(screen.getByText('Enabled')).toBeTruthy())
    expect(h.puts).toEqual([{ url: '/api/projects/p1', body: { captureProxyEnabled: true, updatedAt: V1 } }])
    expect(await screen.findByText('Traffic capture enabled for P')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Disable traffic capture for P' })).toBeTruthy()
  })

  test('capture on, with the permission: Disable turns it off', async () => {
    h.granted = new Set(['platform:traffic_capture'])
    h.stored = true
    renderIn(<TrafficCaptureStatus projectId="p1" projectName="P" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Disable traffic capture for P' }))
    await waitFor(() => expect(screen.getByText('Disabled')).toBeTruthy())
    expect(h.puts).toEqual([{ url: '/api/projects/p1', body: { captureProxyEnabled: false, updatedAt: V1 } }])
  })

  test("the button sends exactly what the settings matrix's switch for the same project sends", async () => {
    h.granted = new Set(['platform:traffic_capture'])
    renderIn(<TrafficCaptureStatus projectId="p1" projectName="P" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Enable traffic capture for P' }))
    await waitFor(() => expect(h.puts).toHaveLength(1))
    const fromButton = h.puts[0]
    cleanup()

    h.stored = false
    h.puts = []
    renderIn(<TrafficCaptureToggle projectId="p1" projectName="P" initialEnabled={false} initialVersion={V1} showName={false} />)
    fireEvent.click(screen.getByRole('switch', { name: 'Toggle traffic capture for P' }))
    await waitFor(() => expect(h.puts).toHaveLength(1))
    expect(h.puts[0]).toEqual(fromButton)
  })
})

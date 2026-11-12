/**
 * The capture status of the /traffic page tells whoever may not change the capture
 * (platform:traffic_capture, step 3.12) to ask an administrator; whoever may change it gets no
 * such line, since the TrafficMind settings are theirs.
 *
 * Run: npx vitest run --no-file-parallelism src/components/traffic/TrafficCaptureStatus.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'

const h = vi.hoisted(() => ({ granted: new Set<string>() }))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))

import { TrafficCaptureStatus } from './TrafficCaptureStatus'

beforeEach(() => {
  h.granted = new Set()
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ captureProxyEnabled: false }), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('TrafficCaptureStatus and platform:traffic_capture', () => {
  test('capture off, without the permission: ask an administrator', async () => {
    render(<TrafficCaptureStatus projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Disabled')).toBeTruthy())
    expect(screen.getByText('Ask an administrator to enable it.')).toBeTruthy()
  })

  test('capture off, with the permission: no such line', async () => {
    h.granted = new Set(['platform:traffic_capture'])
    render(<TrafficCaptureStatus projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Disabled')).toBeTruthy())
    expect(screen.queryByText(/Ask an administrator/)).toBeNull()
  })
})

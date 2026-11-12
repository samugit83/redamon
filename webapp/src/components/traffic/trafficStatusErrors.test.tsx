/**
 * TrafficMind status surfaces on a failure: a failed read is "unavailable" with
 * its status, never "Disabled" or "No projects."; a refused toggle shows the
 * server's own reason.
 *
 * Run: npx vitest run --no-file-parallelism src/components/traffic/trafficStatusErrors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))

vi.mock('@/components/ui', () => ({
  useToast: () => toast,
  Toggle: ({ checked, onChange, disabled, ...rest }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; 'aria-label'?: string }) => (
    <input type="checkbox" checked={checked} disabled={disabled} aria-label={rest['aria-label']} onChange={e => onChange(e.target.checked)} />
  ),
}))

import { TrafficCaptureStatus } from './TrafficCaptureStatus'
import { TrafficMindProjectMatrix } from './TrafficMindProjectMatrix'
import { TrafficCaptureToggle } from './TrafficCaptureToggle'

beforeEach(() => { vi.clearAllMocks() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('TrafficCaptureStatus', () => {
  test('a failed read says unavailable with the status, not Disabled', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>Bad Gateway</html>', { status: 502 })))
    render(<TrafficCaptureStatus projectId="p1" projectName="P" />)
    await waitFor(() => expect(screen.getByText('Capture status unavailable (non_json_response · HTTP 502)')).toBeTruthy())
    expect(screen.queryByText('Disabled')).toBeNull()
    expect(screen.queryByText(/Ask an administrator/)).toBeNull()
  })

  test('a network failure is network_error, not Disabled', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    render(<TrafficCaptureStatus projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Capture status unavailable (network_error)')).toBeTruthy())
    expect(screen.queryByText('Disabled')).toBeNull()
  })

  test('a successful read still shows Disabled when capture is off', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ captureProxyEnabled: false }), { status: 200 })))
    render(<TrafficCaptureStatus projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Disabled')).toBeTruthy())
  })
})

describe('TrafficMindProjectMatrix', () => {
  test('a failed project list shows its cause instead of "No projects."', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'Failed to fetch projects', code: 'P1001' }), { status: 500 })))
    render(<TrafficMindProjectMatrix />)
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Failed to fetch projects (P1001 · HTTP 500)'))
    expect(screen.queryByText('No projects.')).toBeNull()
  })

  test('an empty list is still "No projects."', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('[]', { status: 200 })))
    render(<TrafficMindProjectMatrix />)
    await waitFor(() => expect(screen.getByText('No projects.')).toBeTruthy())
  })
})

describe('TrafficCaptureToggle', () => {
  test('a refused change toasts the server reason and status, and reverts the switch', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'A version activation is in progress for this project.' }), { status: 409 })))
    render(<TrafficCaptureToggle projectId="p1" projectName="P" initialEnabled={false} />)
    const box = screen.getByLabelText('Toggle traffic capture for P') as HTMLInputElement
    fireEvent.click(box)
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('A version activation is in progress for this project. (HTTP 409)'))
    await waitFor(() => expect(box.checked).toBe(false))
  })
})

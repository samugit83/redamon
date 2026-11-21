/**
 * The footer meter says when the stats are missing, instead of vanishing.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SystemMeter } from './SystemMeter'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderMeter() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><SystemMeter /></QueryClientProvider>)
}

describe('SystemMeter', () => {
  test('a failed read shows "unavailable" with the cause on hover', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: 'Failed to connect to backend services', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    }), { status: 503 })))
    renderMeter()
    const chip = await screen.findByRole('status')
    expect(chip.textContent).toBe('RAM/CPU unavailable')
    expect(chip.getAttribute('title')).toBe('Failed to connect to backend services (orchestrator_unreachable · HTTP 503)')
  })

  test('stats that load show the meters', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      mem: {
        host_total: 8 * 1024 ** 3, available: 4 * 1024 ** 3, os_headroom: 0, service_baseline: 0, scan_pool: 0,
        committed: 0, active_scans: 0, remaining_for_new: 2 * 1024 ** 3, pressure: 'ok',
      },
      cpu: { percent: 10, cores: 4 },
      governor_enabled: true,
    }), { status: 200 })))
    renderMeter()
    await waitFor(() => expect(screen.getByText('RAM')).toBeInTheDocument())
    expect(screen.queryByRole('status')).toBeNull()
  })
})

/**
 * Kali sandboxes in the RAM tooltip (group 1, WI-S15-5). Since the governor holds a
 * sandbox class, `committed` counts scans' and sandboxes' bytes together, while
 * `active_scans` counts scans only: each share is shown beside its own count.
 */
describe('SystemMeter reservations', () => {
  const GiB = 1024 ** 3

  async function ramTooltip(mem: Record<string, unknown>) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      mem: {
        host_total: 16 * GiB, available: 8 * GiB, os_headroom: 0, service_baseline: 0, scan_pool: 12 * GiB,
        remaining_for_new: 4 * GiB, pressure: 'ok', ...mem,
      },
      cpu: { percent: 10, cores: 4 },
      governor_enabled: true,
    }), { status: 200 })))
    renderMeter()
    await waitFor(() => expect(screen.getByText('RAM')).toBeInTheDocument())
    // The second line is the governor's: room for a new scan and what is reserved.
    return (screen.getByText('RAM').closest('div')!.getAttribute('title') ?? '').split('\n')[1] ?? ''
  }

  test('scans and sandboxes each with their own share', async () => {
    const title = await ramTooltip({
      committed: 5 * GiB, active_scans: 2, active_sandboxes: 2, sandbox_committed: 2 * GiB, sandbox_envelope: GiB,
    })
    expect(title).toContain('4.0 GB available for a new scan (2 scans reserving 3.0 GB, 2 sandboxes reserving 2.0 GB)')
  })

  test('sandboxes and no scan', async () => {
    const title = await ramTooltip({
      committed: GiB, active_scans: 0, active_sandboxes: 1, sandbox_committed: GiB, sandbox_envelope: GiB,
    })
    expect(title).toContain('(1 sandbox reserving 1.0 GB)')
    expect(title).not.toContain('scan reserving')
  })

  test('scans and no sandbox, as before', async () => {
    const title = await ramTooltip({
      committed: 3 * GiB, active_scans: 1, active_sandboxes: 0, sandbox_committed: 0, sandbox_envelope: GiB,
    })
    expect(title).toContain('(1 scan reserving 3.0 GB)')
    expect(title).not.toContain('sandbox')
  })

  test('an orchestrator without the sandbox fields: the scans line as before', async () => {
    const title = await ramTooltip({ committed: 3 * GiB, active_scans: 2 })
    expect(title).toContain('(2 scans reserving 3.0 GB)')
    expect(title).not.toContain('sandbox')
  })

  test('nothing reserved: no parenthesis', async () => {
    const title = await ramTooltip({ committed: 0, active_scans: 0, active_sandboxes: 0, sandbox_committed: 0 })
    expect(title).toBe('4.0 GB available for a new scan')
  })
})

/**
 * @vitest-environment jsdom
 *
 * Partial recon on an IP-mode project reads the SAVED "Hostnames on target
 * IPs" mode (04_ui_spec.md §5) from GET /api/projects/[id]/ip-hostnames. No
 * typed-hostname box in any IP mode: the orchestrator refuses every typed name
 * there today, and the check that admits a name the policy scans is P6's. In
 * Record hostnames the modal says how many names the last run recorded.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.ipHostnames.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const GRAPH = {
  domain: 'ip-targets.p1', domains: ['ip-targets.p1'], existing_subdomains: [], existing_subdomains_count: 0,
  existing_ips_count: 1, existing_ports_count: 2, existing_baseurls: [], existing_baseurls_count: 0,
  existing_endpoints_count: 0, source: 'graph',
}

function open(preview: { status: number; body: unknown } | null, ipTargets: string[] | null = ['203.0.113.10']) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn((url: string) => {
    calls.push(url)
    if (url.includes('/ip-hostnames')) {
      const p = preview ?? { status: 500, body: { error: 'Failed' } }
      return Promise.resolve(new Response(JSON.stringify(p.body), { status: p.status }))
    }
    return Promise.resolve(new Response(JSON.stringify(url.includes('/graph-inputs/') ? GRAPH : {}), { status: 200 }))
  }))
  render(<PartialReconModal isOpen toolId="Httpx" onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain="" userId="u1" ipTargets={ipTargets} />)
  return calls
}

const answer = (mode: string, recorded = 0) => ({ status: 200, body: { mode, totals: { recorded, found: recorded } } })

describe('no typed-hostname box in any IP mode (until P6 adds the real check)', () => {
  test.each(['ip_only', 'record_only', 'record_filter', 'scan_all'])('%s: no box, and the reason', async (mode) => {
    const calls = open(answer(mode, 3))
    const note = await screen.findByTestId('partial-recon-ip-names-off')
    await waitFor(() => expect(note).toHaveTextContent(/Typed hostnames are not taken in an IP-mode project/))
    expect(screen.queryByText(/Custom hostnames|Custom subdomains/)).toBeNull()
    expect(calls).toContain('/api/projects/p1/ip-hostnames?limit=1')
    // Run stays available: a box whose every line is refused would disable it.
    expect((screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement).disabled).toBe(false)
  })

  test('the note names the saved mode once it is read', async () => {
    open(answer('record_filter'))
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-names-off'))
      .toHaveTextContent('Hostnames on target IPs (Record + scan matching)'))
  })

  test('Record hostnames: how many names were recorded, not scanned', async () => {
    open(answer('record_only', 14))
    expect(await screen.findByTestId('partial-recon-ip-recorded'))
      .toHaveTextContent('14 names recorded, not scanned (Hostnames on target IPs: Record hostnames).')
  })

  test('the mode cannot be read: still no box, and no count', async () => {
    open(null)
    expect(await screen.findByTestId('partial-recon-ip-names-off')).toBeInTheDocument()
    expect(screen.queryByText(/Custom hostnames|Custom subdomains/)).toBeNull()
    expect(screen.queryByTestId('partial-recon-ip-recorded')).toBeNull()
  })
})

describe('a domain project is unchanged', () => {
  test('no hostname-mode read, the subdomain box as before', async () => {
    const calls = open(answer('ip_only'), null)
    await waitFor(() => expect(screen.getByText('Custom subdomains (optional, one per line)')).toBeInTheDocument())
    expect(calls.some(u => u.includes('/ip-hostnames'))).toBe(false)
    expect(screen.queryByTestId('partial-recon-ip-names-off')).toBeNull()
  })
})

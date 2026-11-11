/**
 * @vitest-environment jsdom
 *
 * Typed input on an IP-mode project. The run's root is the `ip-targets.<id>`
 * placeholder, which no typed host sits under, so the modal must apply the
 * orchestrator's IP-mode rule instead (recon_orchestrator/batch_scope.py
 * filter_partial_user_input): a URL host, a typed IP and every host of a typed
 * CIDR must be one of the project's own addresses (CIDR-aware), and typed IPs
 * attach only to a target's label. The name-only tools (SubdomainDiscovery,
 * Urlscan, OriginDiscovery) are refused. The modal is the early answer; the
 * orchestrator and the container are the control.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.ipMode.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/graph-inputs/')
      ? { domain: 'ip-targets.p1', domains: ['ip-targets.p1'], existing_subdomains: [],
          existing_subdomains_count: 0, existing_baseurls: ['http://10.0.0.5'], existing_baseurls_count: 1,
          existing_endpoints_count: 4, source: 'graph' }
      : {}),
  } as Response)))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function typeUrls(urls: string, ipTargets?: string[]) {
  render(<PartialReconModal isOpen toolId="RouteExposure" onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain="" userId="u1" ipTargets={ipTargets} />)
  await waitFor(() => expect(screen.getByText(/1 BaseURLs, 4 Endpoints/)).toBeTruthy())
  // The modal renders in a portal, outside render()'s container.
  fireEvent.change(document.querySelector('textarea')!, { target: { value: urls } })
  return (screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement)
}

describe('PartialReconModal: typed URLs in IP mode', () => {
  test("a URL on one of the project's addresses is accepted", async () => {
    const run = await typeUrls('http://10.0.0.5/admin', ['10.0.0.5', '10.0.0.6'])
    expect(screen.queryByText(/out of scope|not one of this project's target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
  })

  test('a URL on any other address is refused, naming the rule', async () => {
    const run = await typeUrls('http://10.0.0.9/', ['10.0.0.5'])
    expect(screen.getByText(/10\.0\.0\.9 is not one of this project's target IPs/)).toBeTruthy()
    expect(run.disabled).toBe(true)
  })

  test('an IPv6 target matches without its brackets, as the server parses it', async () => {
    const run = await typeUrls('http://[FD00::5]:8080/', ['fd00::5'])
    expect(screen.queryByText(/not one of this project's target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
  })
})

async function open(toolId: string, ipTargets?: string[] | null, graph: Record<string, unknown> = {}) {
  vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/graph-inputs/')
      ? { domain: 'ip-targets.p1', domains: ['ip-targets.p1'], existing_subdomains: [],
          existing_subdomains_count: 0, existing_ips_count: 2, existing_baseurls: [],
          existing_baseurls_count: 0, existing_endpoints_count: 0, source: 'graph', ...graph }
      : {}),
  } as Response)))
  render(<PartialReconModal isOpen toolId={toolId} onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain="" userId="u1" ipTargets={ipTargets} />)
  await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled())
  const run = screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement
  return run
}

function typeIps(ips: string) {
  // Masscan has one textarea, the custom IPs.
  fireEvent.change(document.querySelector('textarea')!, { target: { value: ips } })
}

describe('PartialReconModal: typed IPs in IP mode are CIDR-aware (B-20, B-22)', () => {
  test('a URL on a host of a target CIDR is accepted, its broadcast address is not', async () => {
    const run = await typeUrls('http://10.0.0.2/', ['10.0.0.0/30'])
    expect(screen.queryByText(/not one of this project's target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
    fireEvent.change(document.querySelector('textarea')!, { target: { value: 'http://10.0.0.3/' } })
    expect(screen.getByText(/10\.0\.0\.3 is not one of this project's target IPs/)).toBeTruthy()
    expect(run.disabled).toBe(true)
  })

  test('a typed address outside the targets is refused; a target, or a CIDR inside them, is not', async () => {
    const run = await open('Masscan', ['10.0.0.4/30', '10.0.0.9'])
    await waitFor(() => expect(document.querySelector('textarea')).toBeTruthy())
    typeIps('10.0.0.20')
    expect(screen.getByText(/10\.0\.0\.20 is not one of this project's target IPs/)).toBeTruthy()
    expect(run.disabled).toBe(true)
    typeIps('10.0.0.0/29')
    expect(screen.getByText(/4 of the 6 addresses in 10\.0\.0\.0\/29/)).toBeTruthy()
    typeIps('10.0.0.9\n10.0.0.5\n10.0.0.4/30')
    expect(screen.queryByText(/target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
  })

  test('typed IPs attach only to a target address label, never to a name', async () => {
    await open('Masscan', ['10.0.0.5', '10.0.0.6'],
               { existing_subdomains: ['10-0-0-5', 'www.example.com', '10-0-0-9'], existing_subdomains_count: 3 })
    await waitFor(() => expect(document.querySelector('textarea')).toBeTruthy())
    typeIps('10.0.0.6')
    const select = await waitFor(() => document.querySelector('select') as HTMLSelectElement)
    const options = [...select.options].map(o => o.value)
    expect(options).toEqual(['', '10-0-0-5'])
  })

  test('outside IP mode the attach list keeps every graph subdomain', async () => {
    await open('Masscan', null, { existing_subdomains: ['www.example.com'], existing_subdomains_count: 1 })
    await waitFor(() => expect(document.querySelector('textarea')).toBeTruthy())
    typeIps('192.0.2.10')
    const select = await waitFor(() => document.querySelector('select') as HTMLSelectElement)
    expect([...select.options].map(o => o.value)).toEqual(['', 'www.example.com'])
  })
})

describe('PartialReconModal: the name-only tools in IP mode (B-19, D-11, B-08)', () => {
  test.each(['SubdomainDiscovery', 'Urlscan', 'OriginDiscovery'])('%s is refused with its reason', async tool => {
    const run = await open(tool, ['10.0.0.5'], { discovery_domains: [] })
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-mode-refused')).toBeTruthy())
    expect(screen.getByTestId('partial-recon-ip-mode-refused').textContent).toMatch(/Not available for an IP-mode project/)
    expect(run.disabled).toBe(true)
  })

  test('a domain project is not refused', async () => {
    await open('Urlscan', null, { domain: 'example.com', domains: ['example.com'] })
    expect(screen.queryByTestId('partial-recon-ip-mode-refused')).toBeNull()
  })
})

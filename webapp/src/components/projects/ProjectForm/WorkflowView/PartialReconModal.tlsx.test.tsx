/**
 * @vitest-environment jsdom
 *
 * Strategy row 6 (L2): the Tlsx partial-recon modal must offer IP and Port inputs.
 *
 * SECTION_INPUT_MAP only declares WHICH node types a tool reads. Whether the
 * operator actually gets a control is decided by the hasUserInputs / hasIpInput /
 * hasPortInput chains in this component. A tool missing from those chains renders
 * a modal that looks correctly wired -- title, description, node badges -- with no
 * way to supply a target. No unit test covers those chains, which is exactly why
 * this row exists.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tlsx.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

function mockFetch(ipCount: number, portCount: number) {
  return vi.fn((url: string) => {
    if (url.includes('/graph-inputs/')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          domain: 'acme.test', existing_subdomains: [], existing_subdomains_count: 0,
          existing_ips_count: ipCount, existing_ports_count: portCount, source: 'graph',
        }),
      } as Response)
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
  })
}

function renderModal(toolId: string) {
  return render(
    <PartialReconModal
      isOpen
      toolId={toolId}
      onClose={vi.fn()}
      onConfirm={vi.fn()}
      projectId="p1"
      targetDomain="acme.test"
      userId="u1"
    />,
  )
}

afterEach(cleanup)
beforeEach(() => { vi.stubGlobal('fetch', mockFetch(3, 7)) })

describe('PartialReconModal — Tlsx inputs', () => {
  test('offers the Custom IPs control', async () => {
    renderModal('Tlsx')
    expect((await screen.findAllByText(/Custom IPs/i)).length).toBeGreaterThan(0)
  })

  test('offers the Custom ports control (tlsx grabs certs per open port)', async () => {
    renderModal('Tlsx')
    expect((await screen.findAllByText(/Custom ports/i)).length).toBeGreaterThan(0)
  })

  test('renders a Tlsx-specific description, not the generic fallback', async () => {
    renderModal('Tlsx')
    const generic = /Runs this pipeline phase independently and merges results/i
    expect((await screen.findAllByText(/TLS certificate/i)).length).toBeGreaterThan(0)
    expect(screen.queryAllByText(generic).length).toBe(0)
  })

  test('the run button is reachable when the graph has IPs and ports', async () => {
    renderModal('Tlsx')
    const btn = await screen.findByRole('button', { name: /Run Partial Recon/i })
    expect((btn as HTMLButtonElement).disabled).toBe(false)
  })

  test('control: a tool with no IP input does not show the IPs control', async () => {
    // Proves the assertions above are driven by the Tlsx wiring, not by the
    // control being present for every tool.
    renderModal('Katana')
    expect(await screen.findByRole('button', { name: /Run Partial Recon/i })).toBeDefined()
    expect(screen.queryAllByText(/Custom IPs/i).length).toBe(0)
  })
})

describe('PartialReconModal — Tlsx shares Nmap\'s port-dependent guards', () => {
  test('the input summary reports IP and port counts, like Nmap', async () => {
    // tlsx has Nmap's input shape (IP + Port). Falling through to the generic
    // branch hid the very counts that decide whether the run can do anything.
    renderModal('Tlsx')
    expect((await screen.findAllByText(/3 IPs, 7 ports/i)).length).toBeGreaterThan(0)
  })

  test('an empty-port graph explains that a port scan must run first', async () => {
    vi.stubGlobal('fetch', mockFetch(3, 0))
    renderModal('Tlsx')
    expect((await screen.findAllByText(/No ports found in graph/i)).length).toBeGreaterThan(0)
  })

  test('the port guard names the TLS grab, not Nmap', async () => {
    // The guard already fired for tlsx, but the warning read "Nmap requires
    // ports to scan" while the operator was running the certificate grab.
    vi.stubGlobal('fetch', mockFetch(3, 7))
    renderModal('Tlsx')

    // Unchecking graph targets with no custom ports is the impossible state.
    const label = await screen.findByText(/Include existing graph targets in scan/i)
    const checkbox = label.closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement
    fireEvent.click(checkbox)

    // IPs but no ports is the impossible state: with nothing typed at all the
    // broader "no targets to scan" warning wins instead, which is correct.
    const ipBox = document.querySelector('textarea[placeholder^="192.168.1.1"]') as HTMLTextAreaElement
    fireEvent.change(ipBox, { target: { value: '192.88.98.10' } })

    const warning = await screen.findAllByText(/requires ports to scan/i)
    expect(warning[0].textContent).toMatch(/TLS Certificate Grab requires ports/i)
    expect(warning[0].textContent).not.toMatch(/Nmap requires ports/i)
  })
})

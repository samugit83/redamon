/**
 * @vitest-environment jsdom
 *
 * The partial-recon modal describes every tool it can run, and its Run button
 * looks disabled whenever it is.
 *
 * The button's `disabled`, `cursor` and `opacity` were three copies of one
 * condition, and two of them missed the IP Attribution "no IP" and IP-mode
 * refusals: a refused run rendered as a clickable button.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { PartialReconModal, TOOL_DESCRIPTIONS } from './PartialReconModal'
import { PARTIAL_RECON_SUPPORTED_TOOLS } from '@/lib/recon-types'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

function stubGraph(graph: Record<string, unknown>) {
  vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/graph-inputs/')
      ? { domain: 'acme.test', existing_subdomains: [], existing_subdomains_count: 2, source: 'graph', ...graph }
      : {}),
  } as Response)))
}

async function runButton(toolId: string, ipTargets?: string[]) {
  render(<PartialReconModal isOpen toolId={toolId} onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain={ipTargets ? '' : 'acme.test'} userId="u1"
                            ipTargets={ipTargets} />)
  await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled())
  return await screen.findByRole('button', { name: /Run Partial Recon/i }) as HTMLButtonElement
}

function expectLooksDisabled(btn: HTMLButtonElement) {
  expect(btn.disabled).toBe(true)
  expect(btn.style.cursor).toBe('not-allowed')
  expect(btn.style.opacity).toBe('0.5')
}

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('every partial-recon tool has its own description', () => {
  test('no supported tool falls back to the generic text', () => {
    const missing = [...PARTIAL_RECON_SUPPORTED_TOOLS].filter(id => !TOOL_DESCRIPTIONS[id])
    expect(missing).toEqual([])
  })

  test('Origin Discovery says what it reads and writes', async () => {
    stubGraph({ fronted_count: 1 })
    await runButton('OriginDiscovery')
    expect(screen.getByText(/real origin server behind a CDN or WAF/)).toBeTruthy()
    expect(screen.queryByText(/Runs this pipeline phase independently/)).toBeNull()
  })
})

describe('the Run button looks disabled whenever it is', () => {
  test('IP Attribution with no IP in the graph', async () => {
    stubGraph({ existing_ips_count: 0 })
    const btn = await runButton('IpAttribution')
    // The refusal holds only once the graph counts have loaded.
    await screen.findByText(/0 IPs, 2 subdomains/)
    expectLooksDisabled(btn)
  })

  test('a tool an IP-mode project refuses', async () => {
    stubGraph({ domain: 'ip-targets.p1', domains: ['ip-targets.p1'], fronted_count: 1 })
    expectLooksDisabled(await runButton('OriginDiscovery', ['10.0.0.1']))
  })

  test('an enabled run looks enabled', async () => {
    stubGraph({ existing_ips_count: 3 })
    const btn = await runButton('IpAttribution')
    await waitFor(() => expect(btn.disabled).toBe(false))
    expect(btn.style.cursor).toBe('pointer')
    expect(btn.style.opacity).toBe('1')
  })
})

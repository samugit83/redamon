/**
 * @vitest-environment jsdom
 *
 * Partial recon on an IP-mode project reads the SAVED "Hostnames on target
 * IPs" policy (04_ui_spec.md §5): the mode from GET /api/projects/[id] (else
 * GET /api/projects/[id]/ip-hostnames), the include/exclude entries from the
 * project. In IP only and Record hostnames there is no typed-hostname box and
 * the name-only tools (Gau, ParamSpider, SubdomainTakeover) are off with the
 * reason; in Record + scan matching / Record + scan all the box is back, each
 * line checked with the TS mirror of the rule (typedHostnameRefusal) and
 * labelled "re-checked at run time". In Record hostnames the modal says how
 * many names the last run recorded. The orchestrator and the container are
 * the control; this is the early answer.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.ipHostnames.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
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

interface SavedRow { ipHostnameMode?: string; ipHostnameInclude?: unknown; ipHostnameExclude?: unknown }

function open(preview: { status: number; body: unknown } | null, ipTargets: string[] | null = ['203.0.113.10'],
  { toolId = 'Httpx', project = {} as SavedRow | null } = {}) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn((url: string) => {
    calls.push(url)
    if (url.includes('/ip-hostnames')) {
      const p = preview ?? { status: 500, body: { error: 'Failed' } }
      return Promise.resolve(new Response(JSON.stringify(p.body), { status: p.status }))
    }
    if (url === '/api/projects/p1') {
      return Promise.resolve(project === null
        ? new Response('{}', { status: 500 })
        : new Response(JSON.stringify(project), { status: 200 }))
    }
    return Promise.resolve(new Response(JSON.stringify(url.includes('/graph-inputs/') ? GRAPH : {}), { status: 200 }))
  }))
  render(<PartialReconModal isOpen toolId={toolId} onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain="" userId="u1" ipTargets={ipTargets} />)
  return calls
}

const answer = (mode: string, recorded = 0) => ({ status: 200, body: { mode, totals: { recorded, found: recorded } } })
const runButton = () => screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement
const FILTER = { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'] }

describe('IP only and Record hostnames: no typed-hostname box', () => {
  test.each(['ip_only', 'record_only'])('%s: no box, and the reason', async (mode) => {
    const calls = open(answer(mode, 3))
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-names-off'))
      .toHaveTextContent(/Typed hostnames are not taken with Hostnames on target IPs set to/))
    expect(screen.queryByText(/Custom hostnames|Custom subdomains/)).toBeNull()
    expect(calls).toContain('/api/projects/p1/ip-hostnames?limit=1')
    // Run stays available: a box whose every line is refused would disable it.
    expect(runButton().disabled).toBe(false)
  })

  test('the note names the saved mode once it is read', async () => {
    open(answer('record_only'))
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-names-off'))
      .toHaveTextContent('set to Record hostnames: no hostname is a target'))
  })

  test('the project row wins over the preview for the saved mode', async () => {
    open(answer('record_filter'), undefined, { project: { ipHostnameMode: 'ip_only' } })
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-names-off')).toHaveTextContent('set to IP only'))
  })

  test('Record hostnames: how many names were recorded, not scanned', async () => {
    open(answer('record_only', 14))
    expect(await screen.findByTestId('partial-recon-ip-recorded'))
      .toHaveTextContent('14 names recorded, not scanned (Hostnames on target IPs: Record hostnames).')
  })

  test('the mode cannot be read: still no box, and no count (it reads as IP only)', async () => {
    open(null, undefined, { project: null })
    expect(await screen.findByTestId('partial-recon-ip-names-off')).toBeInTheDocument()
    expect(screen.queryByText(/Custom hostnames|Custom subdomains/)).toBeNull()
    expect(screen.queryByTestId('partial-recon-ip-recorded')).toBeNull()
  })
})

describe('Record + scan matching and Record + scan all: the box with the real check', () => {
  async function typeNames(names: string) {
    const box = await screen.findByText('Custom hostnames (optional, one per line)')
    const textarea = box.parentElement!.querySelector('textarea')!
    fireEvent.change(textarea, { target: { value: names } })
  }

  test('a name the include entries admit passes, labelled as re-checked at run time', async () => {
    open(answer('record_filter'), undefined, { project: FILTER })
    await typeNames('app.example.com')
    expect(screen.getByTestId('partial-recon-ip-names-recheck'))
      .toHaveTextContent('Re-checked at run time: every address the name resolves to must be one of your target IPs')
    expect(screen.queryByTestId('partial-recon-ip-names-off')).toBeNull()
    expect(runButton().disabled).toBe(false)
  })

  test('a name the filter refuses, or an excluded one, is refused with the reason', async () => {
    open(answer('record_filter'), undefined, { project: FILTER })
    await typeNames('shop.example.net\nold.example.com')
    expect(screen.getByText(/Line 1: shop\.example\.net matches no include entry/)).toBeTruthy()
    expect(screen.getByText(/Line 2: old\.example\.com matches an exclude entry/)).toBeTruthy()
    expect(runButton().disabled).toBe(true)
  })

  test('Record + scan all takes any name, never a hard-blocked one', async () => {
    open(answer('scan_all'), undefined, { project: { ipHostnameMode: 'scan_all' } })
    await typeNames('shop.example.net')
    expect(runButton().disabled).toBe(false)
    await typeNames('www.example.gov')
    expect(screen.getByText(/Line 1: .*www\.example\.gov.*blocked/)).toBeTruthy()
    expect(runButton().disabled).toBe(true)
  })

  test('a URL on a name follows the same check', async () => {
    open(answer('record_filter'), undefined, { toolId: 'Katana', project: FILTER })
    const textarea = await waitFor(() => document.querySelector('textarea') as HTMLTextAreaElement)
    fireEvent.change(textarea, { target: { value: 'https://app.example.com/login\nhttps://shop.example.net/' } })
    expect(screen.getByText(/Line 2: shop\.example\.net matches no include entry/)).toBeTruthy()
    expect(screen.queryByText(/Line 1/)).toBeNull()
  })
})

describe('the name-only tools', () => {
  test.each(['Gau', 'ParamSpider', 'SubdomainTakeover'])('%s is off in IP only, with the reason', async (toolId) => {
    open(answer('ip_only'), undefined, { toolId })
    await waitFor(() => expect(screen.getByTestId('partial-recon-ip-mode-refused'))
      .toHaveTextContent(/no hostname is a target/))
    expect(runButton().disabled).toBe(true)
  })

  test.each(['Gau', 'ParamSpider', 'SubdomainTakeover'])('%s runs in Record + scan matching', async (toolId) => {
    open(answer('record_filter'), undefined, { toolId, project: FILTER })
    await screen.findByText('Custom hostnames (optional, one per line)')
    expect(screen.queryByTestId('partial-recon-ip-mode-refused')).toBeNull()
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

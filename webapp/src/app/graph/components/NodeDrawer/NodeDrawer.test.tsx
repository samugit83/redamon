import React from 'react'
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { NodeDrawer } from './NodeDrawer'
import type { GraphData, GraphNode } from '../../types'

const cve: GraphNode = {
  id: '1', type: 'CVE', name: 'CVE-2000-0001',
  properties: { severity: 'MEDIUM', project_id: 'p-secret' },
}
const tech: GraphNode = { id: '2', type: 'Technology', name: 'nginx 1.0', properties: {} }
const graphData: GraphData = {
  projectId: 'p',
  nodes: [cve, tech],
  links: [{ source: '2', target: '1', type: 'HAS_VULNERABILITY' }],
}

function renderDrawer(props: Partial<React.ComponentProps<typeof NodeDrawer>> = {}) {
  return render(
    <AlertProvider>
      <ToastProvider>
        <NodeDrawer node={cve} isOpen onClose={() => {}} graphData={graphData} projectName="Lab" {...props} />
      </ToastProvider>
    </AlertProvider>,
  )
}

let writeText: ReturnType<typeof vi.fn>

beforeEach(() => {
  writeText = vi.fn().mockResolvedValue(undefined)
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('NodeDrawer header actions', () => {
  it('shows copy and ask-agent buttons for a node', () => {
    renderDrawer({ onStartAgentSession: vi.fn() })
    expect(screen.getByLabelText('Copy node context')).toBeInTheDocument()
    expect(screen.getByLabelText('Ask agent about this node')).toBeInTheDocument()
  })

  it('sits on the Basic Info row, left of delete, sharing its button style', () => {
    renderDrawer({ onStartAgentSession: vi.fn(), onDeleteNode: vi.fn() })
    const copy = screen.getByLabelText('Copy node context')
    const ask = screen.getByLabelText('Ask agent about this node')
    const del = screen.getByLabelText('Delete node')

    const row = screen.getByRole('heading', { name: 'Basic Info' }).parentElement!
    const buttons: Element[] = Array.from(row.querySelectorAll('button'))
    expect(buttons.indexOf(copy)).toBeGreaterThanOrEqual(0)
    expect(buttons.indexOf(copy)).toBeLessThan(buttons.indexOf(ask))
    expect(buttons.indexOf(ask)).toBeLessThan(buttons.indexOf(del))

    // Not in the drawer's title bar any more (only its close button lives there).
    const titleBar = screen.getByRole('heading', { name: 'CVE: CVE-2000-0001' }).parentElement!
    expect(titleBar.contains(copy)).toBe(false)
    expect(titleBar.querySelectorAll('button')).toHaveLength(1)

    for (const b of [copy, ask, del]) expect(b.className).toContain('iconBtn')
  })

  it('shows the full name on hover only when the title is clipped', () => {
    renderDrawer()
    const heading = screen.getByRole('heading', { name: 'CVE: CVE-2000-0001' })
    const text = heading.querySelector('span')!
    // jsdom does no layout: fake the <h2> box's widths.
    const setWidths = (scroll: number, client: number) => {
      Object.defineProperty(heading, 'scrollWidth', { value: scroll, configurable: true })
      Object.defineProperty(heading, 'clientWidth', { value: client, configurable: true })
    }

    setWidths(200, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('')

    setWidths(420, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('CVE: CVE-2000-0001')

    setWidths(180, 200)
    fireEvent.mouseEnter(text)
    expect(text.title).toBe('')
  })

  it('hides ask-agent when no session handler is given (past version)', () => {
    renderDrawer()
    expect(screen.getByLabelText('Copy node context')).toBeInTheDocument()
    expect(screen.queryByLabelText('Ask agent about this node')).toBeNull()
  })

  it('shows no node actions on a cluster list', () => {
    // jsdom has no Element.scrollTo; ClusterNodeList resets its scroll on mount.
    Object.defineProperty(Element.prototype, 'scrollTo', { value: () => {}, configurable: true })
    const cluster: GraphNode = {
      id: 'c', type: 'Subdomain', name: 'cluster', properties: {},
      isCluster: true, clusterChildType: 'Subdomain', clusterChildren: [tech],
    }
    renderDrawer({ node: cluster, onStartAgentSession: vi.fn() })
    expect(screen.queryByLabelText('Copy node context')).toBeNull()
    expect(screen.queryByLabelText('Ask agent about this node')).toBeNull()
  })

  it('copies the node context, relationships included, to the clipboard', async () => {
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const text = writeText.mock.calls[0][0] as string
    expect(text).toContain('Project: Lab')
    expect(text).toContain('- Type: CVE')
    expect(text).toContain('- (:Technology)-[:HAS_VULNERABILITY]->(this) x1:')
    expect(text).not.toContain('p-secret')
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('falls back to execCommand when the clipboard API is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
    const execCommand = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith('copy'))
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('falls back to execCommand when the Clipboard API rejects', async () => {
    writeText.mockRejectedValue(new Error('denied'))
    const execCommand = vi.fn().mockReturnValue(true)
    Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    await waitFor(() => expect(execCommand).toHaveBeenCalledWith('copy'))
    expect(await screen.findByText('Node context copied for an external agent')).toBeInTheDocument()
  })

  it('reports a clipboard failure instead of claiming success', async () => {
    writeText.mockRejectedValue(new Error('denied'))
    Object.defineProperty(document, 'execCommand', { value: vi.fn().mockReturnValue(false), configurable: true })
    renderDrawer()
    fireEvent.click(screen.getByLabelText('Copy node context'))
    expect(await screen.findByText('Could not access the clipboard')).toBeInTheDocument()
  })
})

describe('NodeDrawer coverage section (BaseURL)', () => {
  const baseUrl = (properties: Record<string, unknown>, id = 'b1'): GraphNode => ({
    id, type: 'BaseURL', name: 'https://app.example.com', properties: { url: 'https://app.example.com', ...properties },
  })
  const project = (...nodes: GraphNode[]): GraphData => ({ projectId: 'p', nodes, links: [] })
  const coverage = () => screen.getByTestId('coverage-section')

  it('renders one line per module, and the raw stamp keys only there', () => {
    const node = baseUrl({ js_recon_status: 'complete', js_recon_inputs: 12, js_recon_outputs: 0 })
    const other = baseUrl({ nuclei_status: 'complete', nuclei_inputs: 2, nuclei_outputs: 0 }, 'b2')
    renderDrawer({ node, graphData: project(node, other) })
    expect(coverage()).toHaveTextContent('JS analysis')
    expect(coverage()).toHaveTextContent('complete, 12 files, 0 findings')
    expect(coverage()).toHaveTextContent('not scanned by this module')
    expect(screen.queryByText('js_recon_status')).toBeNull()
    expect(screen.queryByText('js_recon_inputs')).toBeNull()
    expect(screen.getByText('url')).toBeInTheDocument()
  })

  it('says "coverage not recorded" where the project carries no stamp at all', () => {
    const node = baseUrl({})
    renderDrawer({ node, graphData: project(node) })
    const lines = within(coverage()).getAllByText('coverage not recorded')
    expect(lines).toHaveLength(2)
    expect(screen.queryByText('not scanned by this module')).toBeNull()
  })

  it('shows a partial stamp with its reason and a failed one with its cause', () => {
    const node = baseUrl({
      js_recon_status: 'partial', js_recon_inputs: 2, js_recon_outputs: 1, js_recon_reason: 'file cap',
      nuclei_status: 'failed', nuclei_inputs: 0, nuclei_outputs: 0, nuclei_reason: 'runtime cap',
    })
    renderDrawer({ node, graphData: project(node) })
    expect(coverage()).toHaveTextContent('partial (file cap), 2 files, 1 finding')
    expect(coverage()).toHaveTextContent('failed (runtime cap)')
  })

  it('reads "coverage not recorded" when there is no graph to compare against (a past version)', () => {
    renderDrawer({ node: baseUrl({}), graphData: null })
    expect(within(coverage()).getAllByText('coverage not recorded')).toHaveLength(2)
  })

  it('is absent on any other node type', () => {
    renderDrawer({ node: { ...tech, properties: { js_recon_status: 'complete' } } })
    expect(screen.queryByTestId('coverage-section')).toBeNull()
  })
})

describe('NodeDrawer ask-agent modal', () => {
  it('starts a session with the typed request, the node context and its label', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))

    const start = screen.getByRole('button', { name: 'Start session' })
    expect(start).toBeDisabled()

    fireEvent.change(screen.getByLabelText('What should the agent do?'), {
      target: { value: '  Is this exploitable?  ' },
    })
    fireEvent.click(start)

    expect(onStart).toHaveBeenCalledTimes(1)
    const [request, context, label] = onStart.mock.calls[0]
    expect(request).toBe('Is this exploitable?')
    expect(context).toContain('- (:Technology)-[:HAS_VULNERABILITY]->(this) x1:')
    expect(label).toBe('CVE: CVE-2000-0001')
    expect(screen.queryByRole('button', { name: 'Start session' })).toBeNull()
  })

  it('submits on Ctrl+Enter and ignores a blank request', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))
    const textarea = screen.getByLabelText('What should the agent do?')

    fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true })
    expect(onStart).not.toHaveBeenCalled()

    fireEvent.change(textarea, { target: { value: 'Summarise' } })
    fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true })
    expect(onStart).toHaveBeenCalledWith('Summarise', expect.any(String), 'CVE: CVE-2000-0001')
  })

  it('cancel closes the modal without starting a session', () => {
    const onStart = vi.fn()
    renderDrawer({ onStartAgentSession: onStart })
    fireEvent.click(screen.getByLabelText('Ask agent about this node'))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onStart).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('What should the agent do?')).toBeNull()
  })
})

describe('NodeDrawer disposition line (plan 10.2b)', () => {
  const finding = (properties: GraphNode['properties']): GraphNode => ({
    id: '7', type: 'Vulnerability', name: 'Exposed panel', properties,
  })

  it('a finding node says whether it can go in a report, and what blocks it', () => {
    renderDrawer({ node: finding({ severity: 'high', triage_tier_rule: 'credible, with impact worth planning for' }) })
    const row = screen.getByTestId('drawer-disposition')
    expect(row).toHaveTextContent('Disposition')
    expect(row).toHaveTextContent('Candidate, blocked by credible, with impact worth planning for')
  })

  it('a finding never triaged says so', () => {
    renderDrawer({ node: finding({ severity: 'high' }) })
    expect(screen.getByTestId('drawer-disposition')).toHaveTextContent('Candidate, not triaged yet')
  })

  it('a node a v3.10 run rescored shows the blocker the run stored (plan 10.5)', () => {
    renderDrawer({ node: finding({ severity: 'high', triage_tier_rule: 'credible, with impact worth planning for',
      triage_disposition: 'candidate', triage_blocker: 'unknown: attributed' }) })
    expect(screen.getByTestId('drawer-disposition')).toHaveTextContent('Candidate, blocked by unknown: attributed')
  })

  it('proof makes it reportable, a person\'s False positive excludes it', () => {
    renderDrawer({ node: finding({ triage_tier_rule: 'proven' }) })
    expect(screen.getByTestId('drawer-disposition')).toHaveTextContent('Reportable')
    cleanup()
    renderDrawer({ node: finding({ triage_status: 'likely_noise', triage_source: 'human' }) })
    expect(screen.getByTestId('drawer-disposition')).toHaveTextContent('Excluded')
  })

  it('a node that is not a finding has no disposition', () => {
    renderDrawer()
    expect(screen.queryByTestId('drawer-disposition')).toBeNull()
  })

  it('a finding whose properties could not be read shows no line, never a default', () => {
    renderDrawer({ node: { id: '8', type: 'Secret', name: 'k', properties: undefined as never } })
    expect(screen.queryByTestId('drawer-disposition')).toBeNull()
  })
})

describe('NodeDrawer ownership line (plan 11.4)', () => {
  const ip = (properties: Record<string, unknown>): GraphNode =>
    ({ id: '9', type: 'IP', name: '198.51.100.20', properties })

  it('an IP says whose it is, and why', () => {
    renderDrawer({ node: ip({
      ownership: 'shared_edge', cdn_name: 'cloudflare',
      ownership_reasons: ['default certificate covers no target domain', 'in a published CDN edge range'],
    }) })
    const row = screen.getByTestId('drawer-ownership')
    expect(row).toHaveTextContent('Ownership')
    expect(row).toHaveTextContent(
      'Shared edge (Cloudflare): default certificate covers no target domain; in a published CDN edge range')
  })

  it('an IP no run attributed yet says not checked yet', () => {
    renderDrawer({ node: ip({ address: '198.51.100.20' }) })
    expect(screen.getByTestId('drawer-ownership')).toHaveTextContent('not checked yet')
  })

  it('the raw keys leave the property list, the other IP properties stay', () => {
    renderDrawer({ node: ip({ ownership: 'dedicated', ownership_reasons: ['default certificate covers example.com'],
      current_dns_names: 2 }) })
    const props = screen.getByRole('heading', { name: 'Properties' }).parentElement!
    expect(within(props).queryByText('ownership')).toBeNull()
    expect(within(props).queryByText('ownership_reasons')).toBeNull()
    expect(within(props).getByText('current_dns_names')).toBeInTheDocument()
  })

  it('a node that is not an IP has no ownership line', () => {
    renderDrawer()
    expect(screen.queryByTestId('drawer-ownership')).toBeNull()
  })
})

describe('NodeDrawer route exposure block', () => {
  const lead: GraphNode = {
    id: '7', type: 'Vulnerability', name: 'unauthenticated_endpoint',
    properties: { source: 'route_exposure', exposure_kind: 'anonymous_access', needs_agent_confirmation: true,
      route_class: 'internal_api', anon_status: 200, auth_expected_by: ['siblings_locked'] },
  }

  it('labels a lead and reads its CONFIRMS edge from the loaded graph', () => {
    renderDrawer({ node: lead, graphData: { projectId: 'p', nodes: [lead], links: [] } })
    const block = screen.getByTestId('route-exposure-section')
    expect(block).toHaveTextContent('Answers without a login')
    expect(block).toHaveTextContent('Internal API')
    expect(block).toHaveTextContent('neighbouring routes need a login')
    expect(block).toHaveTextContent('waiting for the agent')
    cleanup()

    const cf: GraphNode = { id: '9', type: 'ChainFinding', name: 'proof', properties: {} }
    renderDrawer({ node: lead, graphData: { projectId: 'p', nodes: [lead, cf],
      links: [{ source: '9', target: '7', type: 'CONFIRMS' }] } })
    expect(screen.getByTestId('route-exposure-section')).toHaveTextContent('Confirmed by the agent')
  })

  it('an Endpoint the scan measured shows its anonymous answer', () => {
    const ep: GraphNode = { id: '5', type: 'Endpoint', name: '/api/users/me',
      properties: { anon_status: 200, status_code: 401 } }
    renderDrawer({ node: ep })
    expect(screen.getByTestId('route-exposure-section')).toHaveTextContent("200 (recon's probe saw 401)")
  })

  it('another node has no route exposure block', () => {
    renderDrawer()
    expect(screen.queryByTestId('route-exposure-section')).toBeNull()
  })
})

describe('NodeDrawer hostnames on target IPs (04_ui_spec §5)', () => {
  const ipA: GraphNode = { id: 'ip1', type: 'IP', name: '203.0.113.10', properties: { address: '203.0.113.10' } }
  const ipB: GraphNode = { id: 'ip2', type: 'IP', name: '203.0.113.11', properties: { address: '203.0.113.11' } }
  const recorded = (properties: Record<string, unknown>): GraphNode =>
    ({ id: 'ed1', type: 'ExternalDomain', name: 'old.example.com', properties })

  it('a recorded name lists the IPs of its SEEN_ON links, its sources and the reason in words', () => {
    const ed = recorded({
      ip_hostname_reason: 'resolves_outside_targets', sources: ['tlsx_san', 'ptr'], ips_seen: ['198.51.100.99'],
    })
    renderDrawer({ node: ed, graphData: { projectId: 'p', nodes: [ed, ipA, ipB], links: [
      { source: 'ed1', target: 'ip1', type: 'SEEN_ON' },
      { source: 'ed1', target: 'ip2', type: 'SEEN_ON' },
      { source: 'ed1', target: 'ip2', type: 'HAS_EXTERNAL_DOMAIN' },
    ] } })
    const block = screen.getByTestId('ip-hostname-seen-on')
    expect(within(block).getByRole('heading', { name: 'Seen on target IPs' })).toBeInTheDocument()
    expect(block).toHaveTextContent('points outside your IPs')
    expect(block).not.toHaveTextContent('resolves_outside_targets')
    expect(within(block).getAllByRole('listitem').map(li => li.textContent)).toEqual(['203.0.113.10', '203.0.113.11'])
    expect(block).toHaveTextContent('tlsx_san, ptr')
  })

  it('a link whose ends were resolved to node objects counts the same', () => {
    const ed = recorded({ ip_hostname_reason: 'record_only' })
    renderDrawer({ node: ed, graphData: { projectId: 'p', nodes: [ed, ipA], links: [
      { source: ed, target: ipA, type: 'SEEN_ON' },
    ] } })
    const block = screen.getByTestId('ip-hostname-seen-on')
    expect(block).toHaveTextContent('recorded only: this mode scans the IPs, not the names')
    expect(within(block).getByRole('listitem')).toHaveTextContent('203.0.113.10')
  })

  it('without the IP nodes at hand the node\'s own ips_seen is listed', () => {
    const ed = recorded({ ip_hostname_reason: 'filter_no_match', ips_seen: ['203.0.113.12'] })
    renderDrawer({ node: ed, graphData: { projectId: 'p', nodes: [ed], links: [] } })
    expect(within(screen.getByTestId('ip-hostname-seen-on')).getByRole('listitem')).toHaveTextContent('203.0.113.12')
  })

  it('the per-IP SEEN_ON evidence is read from the preview route by the name', async () => {
    const urls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      urls.push(url)
      return new Response(JSON.stringify({ recorded: [{
        name: 'old.example.com', seen: [
          { ip: '203.0.113.10', sources: ['tlsx_san'], first_seen: '2026-01-02T00:00:00Z', last_seen: '2026-10-30',
            resolves_here: false, cert_covers: true },
          { ip: '203.0.113.11', sources: ['otx_passive_dns'], first_seen: null, last_seen: null,
            resolves_here: null, cert_covers: false },
        ],
      }] }), { status: 200 })
    }))
    try {
      const ed = recorded({ ip_hostname_reason: 'resolves_outside_targets', domain: 'old.example.com', project_id: 'p9' })
      renderDrawer({ node: ed, graphData: { projectId: 'p9', nodes: [ed, ipA], links: [
        { source: 'ed1', target: 'ip1', type: 'SEEN_ON' },
      ] } })
      const edges = await screen.findByTestId('ip-hostname-seen-on-edges')
      expect(within(edges).getAllByRole('listitem').map(li => li.textContent)).toEqual([
        '203.0.113.10 · tlsx_san · seen 2026-01-02 to 2026-10-30 · resolves here now: no · certificate covers it: yes',
        '203.0.113.11 · otx_passive_dns · resolves here now: unknown · certificate covers it: no',
      ])
      expect(urls).toEqual(['/api/projects/p9/ip-hostnames?limit=1&name=old.example.com'])
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('when the route cannot answer, the IPs the drawer knows stay listed', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 500 })))
    try {
      const ed = recorded({ ip_hostname_reason: 'record_only', project_id: 'p9' })
      renderDrawer({ node: ed, graphData: { projectId: 'p9', nodes: [ed, ipA], links: [
        { source: 'ed1', target: 'ip1', type: 'SEEN_ON' },
      ] } })
      await waitFor(() => expect(fetch).toHaveBeenCalled())
      expect(screen.queryByTestId('ip-hostname-seen-on-edges')).toBeNull()
      expect(within(screen.getByTestId('ip-hostname-seen-on')).getByRole('listitem')).toHaveTextContent('203.0.113.10')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('an unknown reason code is never shown raw', () => {
    renderDrawer({ node: recorded({ ip_hostname_reason: 'some_future_code' }) })
    const block = screen.getByTestId('ip-hostname-seen-on')
    expect(block).toHaveTextContent('recorded, not scanned')
    expect(screen.queryByText(/some_future_code/)).toBeNull()
  })

  it('the raw codes leave the property list; the other properties stay', () => {
    renderDrawer({ node: recorded({
      ip_hostname_reason: 'filter_excluded', sources: ['ptr'], ips_seen: ['203.0.113.10'], ip_hostname_org: 'example.com',
    }) })
    const props = screen.getByRole('heading', { name: 'Properties' }).parentElement!
    for (const key of ['ip_hostname_reason', 'sources', 'ips_seen']) expect(within(props).queryByText(key)).toBeNull()
    expect(within(props).getByText('ip_hostname_org')).toBeInTheDocument()
  })

  it('an ExternalDomain without a hostname reason (a redirect host) has no block', () => {
    renderDrawer({ node: recorded({ redirect_from_urls: ['https://example.com/'] }) })
    expect(screen.queryByTestId('ip-hostname-seen-on')).toBeNull()
  })

  it('an org Domain says it is on target IPs and counts its scanned hostnames', () => {
    const org: GraphNode = { id: 'd1', type: 'Domain', name: 'example.com', properties: { ip_hostname_org: true } }
    const sub = (id: string, reason: string): GraphNode =>
      ({ id, type: 'Subdomain', name: `${id}.example.com`, properties: { ip_hostname_reason: reason } })
    const [a, b, c] = [sub('app', 'scanned'), sub('shop', 'scanned'), sub('old', 'out_of_policy')]
    renderDrawer({ node: org, graphData: { projectId: 'p', nodes: [org, a, b, c], links: [
      { source: 'd1', target: 'app', type: 'HAS_SUBDOMAIN' },
      { source: 'shop', target: 'd1', type: 'BELONGS_TO' },
      { source: 'd1', target: 'shop', type: 'HAS_SUBDOMAIN' },
      { source: 'd1', target: 'old', type: 'HAS_SUBDOMAIN' },
    ] } })
    expect(screen.getByText('Domain (organisation · on target IPs)')).toBeInTheDocument()
    expect(screen.getByTestId('ip-hostname-org')).toHaveTextContent('2 hostnames scanned on target IPs')
  })

  it('the IP-mode root keeps "Domain", an ordinary org Domain keeps its badge', () => {
    renderDrawer({ node: { id: 'r', type: 'Domain', name: 'ip-targets.p1', properties: { ip_mode: true, is_mock: true } } })
    expect(screen.getByText('Domain')).toBeInTheDocument()
    expect(screen.queryByTestId('ip-hostname-org')).toBeNull()
    cleanup()
    renderDrawer({ node: { id: 'd', type: 'Domain', name: 'example.com', properties: {} } })
    expect(screen.getByText('Domain (organisation)')).toBeInTheDocument()
  })

  it('a scanned Subdomain shows the sources that found it', () => {
    renderDrawer({ node: { id: 's', type: 'Subdomain', name: 'app.example.com', properties: {
      source: 'ip_hostname_selection', ip_hostname_reason: 'scanned', ip_hostname_sources: ['ptr', 'tlsx_san'],
    } } })
    const block = screen.getByTestId('ip-hostname-subdomain')
    expect(block).toHaveTextContent('Found on target IPs by')
    expect(block).toHaveTextContent('ptr, tlsx_san')
    expect(block).not.toHaveTextContent('No longer in the hostname policy')
  })

  it('an out_of_policy Subdomain says since when it left the policy', () => {
    renderDrawer({ node: { id: 's', type: 'Subdomain', name: 'old.example.com', properties: {
      source: 'ip_hostname_selection', ip_hostname_reason: 'out_of_policy',
      ip_hostname_evaluated_at: { year: 2026, month: 11, day: 10, hour: 9, minute: 5, second: 0 },
    } } })
    expect(screen.getByTestId('ip-hostname-subdomain'))
      .toHaveTextContent('No longer in the hostname policy (since 2026-11-10)')
    const props = screen.getByRole('heading', { name: 'Properties' }).parentElement!
    expect(within(props).queryByText('out_of_policy')).toBeNull()
  })

  it('a domain-mode Subdomain has no hostname block', () => {
    renderDrawer({ node: { id: 's', type: 'Subdomain', name: 'www.example.com', properties: {} } })
    expect(screen.queryByTestId('ip-hostname-subdomain')).toBeNull()
  })
})

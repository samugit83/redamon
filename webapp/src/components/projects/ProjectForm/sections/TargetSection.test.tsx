/**
 * Strategy row 6: the Domain batch group preview must agree with what is saved.
 *
 * The preview is the ONLY place the grouping rule (scope groups by registrable
 * domain) is visible to an operator, and it is what they approve before the scan runs. If it disagrees
 * with the persisted grouping, or if the input cannot be typed into, the feature's
 * central promise ("you see exactly what will run, in order") is broken.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TargetSection.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'
import { TargetSection } from './TargetSection'
import { JevSelectionProvider } from '@/hooks/useHasJevProvider'
import { groupHostsByScanRoot } from '@/lib/domainBatch'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

afterEach(() => { cleanup() })

type Data = Record<string, unknown>

const BASE: Data = {
  name: '', description: '', targetDomain: '', subdomainList: [],
  ipMode: false, targetIps: [], domainBatchMode: true, domainBatchHosts: [],
  subdomainDiscoveryEnabled: true, aiInPipeline: false, verifyDomainOwnership: false,
  ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '',
}

/** Renders with live state so a change event feeds the next render, as in the form. */
function renderSection(initial: Partial<Data> = {}) {
  let data: Data = { ...BASE, ...initial }
  const updateField = vi.fn((k: string, v: unknown) => { data[k] = v; rerender() })
  const draw = () => <JevSelectionProvider ownerUserId="u1" selectedProviderId={typeof data.jevProviderId === 'string' ? data.jevProviderId : null}>
    <TargetSection data={{ ...data } as never} updateField={updateField as never} mode="create" />
  </JevSelectionProvider>
  const view = render(draw())
  function rerender() { view.rerender(draw()) }
  return { get data() { return data }, updateField, textarea: () => screen.getByPlaceholderText(/sub1\.domain1\.com/) }
}

describe('the hostname input accepts a multi-line list', () => {
  test('a newline can be typed (the list is editable at all)', () => {
    // Regression: the textarea's value was derived from the PARSED array, so any
    // separator the user typed was stripped on the next render and a second host
    // could never be entered.
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com\n' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com\n')
  })

  test('a second host on a new line survives', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com\nb.other.com' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com\nb.other.com')
    expect(s.data.domainBatchHosts).toEqual(['a.example.com', 'b.other.com'])
  })

  test('a trailing space mid-typing is not swallowed', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com ' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com ')
  })
})

describe('the preview matches the grouping that will be persisted', () => {
  const HOSTS = 'sub1.domain1.com\nsub2.domain2.it\nsub3.domain3.com\nsuba.sub3.domain3.com'

  test('groups render in run order', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })

    const rows = screen.getAllByRole('row').slice(1) // drop the header
    const domains = rows.map(r => within(r).getAllByRole('cell')[1].textContent)
    expect(domains).toEqual(['domain1.com', 'domain2.it', 'domain3.com'])
  })

  test('the rendered groups equal groupHostsByScanRoot, the helper the server uses', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })

    const expected = groupHostsByScanRoot(s.data.domainBatchHosts as string[]).groups
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows.map(r => within(r).getAllByRole('cell')[1].textContent))
      .toEqual(expected.map(g => g.scanRoot))
    expect(rows.map(r => within(r).getAllByRole('cell')[4].textContent))
      .toEqual(expected.map(g => g.entries.join(', ')))
  })

  test('a deep subdomain joins its domain group rather than starting a new one', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(3)
    expect(screen.getByText('sub3.domain3.com, suba.sub3.domain3.com')).toBeTruthy()
  })

  test('an invalid entry is flagged and not silently grouped', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'good.example.com\nlocalhost' } })
    // getByText matches the <strong> label; the offending entry is a sibling list item.
    const label = screen.getByText(/Not accepted/)
    expect(label.parentElement?.textContent).toContain('localhost: not a valid hostname')
  })

  test('a permanently blocked root is called out before submit', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'ok.example.com\nwww.whitehouse.gov' } })
    expect(screen.getByText(/permanently blocked/i)).toBeTruthy()
  })

  test('single-domain banner flags a blocked prefix host, not only the target', () => {
    // org.jm is not blocked, isa.org.jm is: the live banner checked the target
    // alone, so the block only surfaced at submit.
    // A plain render: on mount, single-domain mode syncs Include Root through
    // updateField, before renderSection's live re-render can exist.
    const data = { ...BASE, domainBatchMode: false, targetDomain: 'org.jm', subdomainList: ['isa.'] }
    render(<TargetSection data={data as never} updateField={vi.fn() as never} mode="create" />)
    const banner = screen.getByText(/Target permanently blocked:/)
    expect(banner.textContent).toContain('isa.org.jm')
  })

  test('the banner names the listed host, not the group root it falls under', () => {
    // www.isa.org.jm groups under org.jm, which no rule names: only the host is
    // blocked, so a root-only check showed nothing and a root-named banner lied.
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'ok.example.com\nwww.isa.org.jm' } })
    const banner = screen.getByText(/Target permanently blocked:/)
    expect(banner.textContent).toContain('www.isa.org.jm')
    expect(banner.textContent).not.toMatch(/blocked: org\.jm/)
  })

  test('the counts shown are the real host and group counts', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })
    const hint = screen.getAllByText((_t, el) => /\d+ hostnames?/.test(el?.textContent ?? '')).at(-1)!
    expect(hint.textContent).toMatch(/4 hostnames/)
    expect(hint.textContent).toMatch(/3 scope groups across 3 domains/)
  })
})

describe('the preview columns (scan root, org, mode, hosts)', () => {
  const cells = (row: number) => within(screen.getAllByRole('row')[row]).getAllByRole('cell').map(c => c.textContent)

  test('a wildcard row shows *.root, FULL ENUMERATION and its seeds', () => {
    renderSection({ domainBatchHosts: ['*.example.com', 'v1.example.com', 'www.acme.co.uk'] })
    expect(cells(1).slice(1, 4)).toEqual(['*.example.com', 'example.com', 'FULL ENUMERATION'])
    expect(cells(1)[4]).toContain('v1.example.com seeded')
    expect(cells(2).slice(1, 5)).toEqual(['acme.co.uk', 'acme.co.uk', 'EXACT', 'www.acme.co.uk'])
  })

  test('a collapsed wildcard is noted on the group that covers it', () => {
    renderSection({ domainBatchHosts: ['*.example.com', '*.api.example.com'] })
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(1)
    expect(cells(1)[4]).toContain('*.api.example.com covered by *.example.com')
  })

  test('a second group under the same org is greyed and points at the first', () => {
    renderSection({ domainBatchHosts: ['*.api.example.com', 'www.example.com'] })
    expect(cells(1)[2]).toBe('example.com')
    expect(cells(2)[2]).toBe('example.com (shared with #1)')
    expect(cells(1)[1]).toBe('*.api.example.com')
    // Root on a nested wildcard toggles the scan root's own line, not the org's.
    expect(screen.getByLabelText('Also scan api.example.com itself')).toBeInTheDocument()
  })

  test('each refused entry carries its own reason', () => {
    renderSection({ domainBatchHosts: ['*.co.uk', 'www.example.com'] })
    expect(screen.getByText(/Not accepted/).parentElement?.textContent)
      .toContain('*.co.uk: a wildcard on a public suffix')
  })
})

describe('single domain: the target may be a hostname', () => {
  function renderSingle(targetDomain: string, subdomainList: string[] = []) {
    const data = { ...BASE, domainBatchMode: false, targetDomain, subdomainList }
    render(<TargetSection data={data as never} updateField={vi.fn() as never} mode="create" />)
  }

  test('the field says a hostname is fine', () => {
    renderSingle('')
    expect(screen.getByText('Target domain or hostname')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('example.com or api.example.com')).toBeInTheDocument()
  })

  test('the hint names the graph (registrable) domain and the scan root', () => {
    renderSingle('api.example.com')
    expect(screen.getByText(/Graph domain: example\.com · scan root: api\.example\.com/)).toBeInTheDocument()
  })

  test('Include Root names the actual target', () => {
    renderSingle('api.example.com')
    expect(screen.getByText(/Also scan api\.example\.com itself/)).toBeInTheDocument()
  })

  test('a public-suffix target is refused with its reason; a half-typed one is not', () => {
    renderSingle('co.uk')
    expect(screen.getByText(/co\.uk: a public suffix/)).toBeInTheDocument()
    cleanup()
    renderSingle('exam')
    expect(screen.queryByText(/public suffix/)).toBeNull()
  })

  test('a dotted prefix is accepted; an empty label is refused by name', () => {
    renderSingle('example.com', ['eu.api.'])
    expect(screen.queryByText(/Not accepted/)).toBeNull()
    cleanup()
    renderSingle('example.com', ['a..b.'])
    expect(screen.getByText(/Not accepted/).parentElement?.textContent).toContain('a..b (not a valid subdomain prefix)')
  })
})

describe('mode switching', () => {
  test('choosing Domain batch clears the single-domain target', () => {
    const s = renderSection({ domainBatchMode: false, targetDomain: 'old.example.com' })
    fireEvent.click(screen.getByText('Domain batch'))
    expect(s.data.domainBatchMode).toBe(true)
    expect(s.data.targetDomain).toBe('')
  })

  test('leaving Domain batch clears the host list', () => {
    const s = renderSection({ domainBatchHosts: ['a.example.com'] })
    fireEvent.click(screen.getByText('IP / CIDR'))
    expect(s.data.ipMode).toBe(true)
    expect(s.data.domainBatchMode).toBe(false)
    expect(s.data.domainBatchHosts).toEqual([])
  })
})

describe('the wildcard Root control', () => {
  /** Renders in edit mode, where the batch list is now unlocked. */
  function renderEdit(initial: Partial<Data> = {}) {
    let data: Data = { ...BASE, ...initial }
    const updateField = vi.fn((k: string, v: unknown) => { data[k] = v; rerender() })
    const view = render(<TargetSection data={data as never} updateField={updateField as never} mode="edit" />)
    function rerender() {
      view.rerender(<TargetSection data={{ ...data } as never} updateField={updateField as never} mode="edit" />)
    }
    return { get data() { return data } }
  }

  test('ticking Root adds the bare domain to the host list', () => {
    // Root inclusion is per wildcard domain and is expressed the way a batch
    // already asks for an apex: the bare root appearing in the list. There is no
    // separate field, so this checkbox IS the host list.
    const h = renderSection({ domainBatchMode: true, domainBatchHosts: ['*.domain.com'] })
    fireEvent.click(screen.getByLabelText(/Also scan domain\.com itself/i))
    expect(h.data.domainBatchHosts).toContain('domain.com')
    expect(h.data.domainBatchHosts).toContain('*.domain.com')
  })

  test('unticking Root removes it again', () => {
    const h = renderSection({
      domainBatchMode: true, domainBatchHosts: ['*.domain.com', 'domain.com'],
    })
    fireEvent.click(screen.getByLabelText(/Also scan domain\.com itself/i))
    expect(h.data.domainBatchHosts).not.toContain('domain.com')
    expect(h.data.domainBatchHosts).toContain('*.domain.com')
  })

  test('unticking Root also removes a pasted spelling of the same name', () => {
    const h = renderSection({
      domainBatchMode: true, domainBatchHosts: ['*.domain.com', 'https://Domain.com/'],
    })
    fireEvent.click(screen.getByLabelText(/Also scan domain\.com itself/i))
    expect(h.data.domainBatchHosts).toEqual(['*.domain.com'])
  })

  test('it is offered only on wildcard rows', () => {
    renderSection({ domainBatchMode: true, domainBatchHosts: ['api.literal.com'] })
    expect(screen.queryByLabelText(/Also scan/i)).toBeNull()
  })

  test('one domain\'s Root does not move another\'s', () => {
    const h = renderSection({
      domainBatchMode: true, domainBatchHosts: ['*.a.com', '*.b.com', 'b.com'],
    })
    fireEvent.click(screen.getByLabelText(/Also scan a\.com itself/i))
    expect(h.data.domainBatchHosts).toContain('a.com')
    expect(h.data.domainBatchHosts).toContain('b.com')
  })

  test('the batch list stays editable in edit mode', () => {
    // The list was locked after creation, which made the whole feature
    // unreachable for every project that already existed.
    const h = renderEdit({ domainBatchMode: true, domainBatchHosts: ['*.domain.com'] })
    fireEvent.click(screen.getByLabelText(/Also scan domain\.com itself/i))
    expect(h.data.domainBatchHosts).toContain('domain.com')
  })

  test('a wildcard list warns that the run is unbounded', () => {
    // Nothing caps wildcard count, so this warning and the badge are the only
    // thing standing between a pasted list and a multi-hour scan.
    renderSection({ domainBatchMode: true, domainBatchHosts: ['*.a.com', '*.b.com'] })
    expect(screen.getByText(/2 scope groups will be\s+fully enumerated/i)).toBeInTheDocument()
  })

  test('a literal-only list does not warn', () => {
    renderSection({ domainBatchMode: true, domainBatchHosts: ['api.a.com'] })
    expect(screen.queryByText(/will be\s+fully enumerated/i)).toBeNull()
  })
})

describe('the AI in Pipeline panel', () => {
  const HOOKS = ['ffufAiExtensions', 'nucleiAiTags', 'wafAiClassifier', 'nucleiAiResponseFilter', 'takeoverAiClassifier']
  const JEV_ONLY = ['httpxJevPageType', 'ffufJevBasePaths', 'hakrawlerJevSeedOrder', 'resourceEnumJevToolHealth',
    'serializedScanJevRank', 'routeExposureJevRank', 'routeExposureJevWallCheck', 'routeExposureJevAssess']
  const AI_ON: Data = {
    domainBatchMode: false, aiInPipeline: true, jevProviderId: 'j',
    ffufAiExtensions: true, nucleiAiTags: false, wafAiClassifier: true, nucleiAiResponseFilter: true,
    takeoverAiClassifier: true,
    ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: true, takeoverAiUseJev: false,
    ffufJevBasePaths: false, httpxJevPageType: true, resourceEnumJevToolHealth: false, hakrawlerJevSeedOrder: false,
    serializedScanJevRank: false, routeExposureJevRank: false, routeExposureJevWallCheck: false,
    routeExposureJevAssess: false,
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => ({
      ok: true, status: 200,
      json: async () => url.includes('llm-providers') ? [{ id: 'j', name: 'Synthetic Jev', providerType: 'jev', apiKey: '••••c0de', modelIdentifier: 'jev-1.13.0' }] : {},
    })))
  })
  afterEach(() => vi.unstubAllGlobals())

  test('the model picker and the Jev token sit side by side', async () => {
    renderSection(AI_ON)
    const panel = await screen.findByTestId('jev-token-panel')
    const row = screen.getByText('AI Model').closest('div')!.parentElement!
    expect(row).toContainElement(panel)
  })

  test('selecting and clearing a provider writes the project field and changes all hook gates immediately', async () => {
    const s = renderSection({ ...AI_ON, jevProviderId: null })
    const picker = await screen.findByRole('combobox', { name: 'Jev provider' })
    const ffuf = within(screen.getByTestId('ai-hook-ffufAiExtensions')).getByRole('button', { name: 'Jev' })
    const hakrawler = within(screen.getByTestId('ai-hook-hakrawlerJevSeedOrder')).getByRole('button', { name: 'Jev' })
    expect(ffuf).toBeDisabled()
    expect(hakrawler).toBeDisabled()
    fireEvent.change(picker, { target: { value: 'j' } })
    expect(s.updateField).toHaveBeenLastCalledWith('jevProviderId', 'j')
    expect(ffuf).toBeEnabled()
    expect(hakrawler).toBeEnabled()
    fireEvent.change(picker, { target: { value: '' } })
    expect(s.updateField).toHaveBeenLastCalledWith('jevProviderId', null)
    expect(ffuf).toBeDisabled()
    expect(hakrawler).toBeDisabled()
    expect(s.data.wafAiUseJev).toBe(true)
    expect(s.data.httpxJevPageType).toBe(true)
  })

  test('each hook is ONE card holding its label, summary, toggle and engine', () => {
    renderSection(AI_ON)
    for (const field of HOOKS) {
      const card = screen.getByTestId(`ai-hook-${field}`)
      expect(within(card).getByRole('switch')).toBeInTheDocument()
      expect(within(card).getByText('Engine')).toBeInTheDocument()
    }
    expect(screen.getByTestId('ai-hook-list').children).toHaveLength(HOOKS.length + JEV_ONLY.length)
  })

  test('a Jev-only hook is one card with an Off | Jev control and no hook toggle', () => {
    renderSection(AI_ON)
    for (const field of JEV_ONLY) {
      const card = screen.getByTestId(`ai-hook-${field}`)
      expect(within(card).queryByRole('switch')).not.toBeInTheDocument()
      expect(within(card).getByText('Jev only')).toBeInTheDocument()
      expect(within(card).getByRole('button', { name: 'Off' })).toBeInTheDocument()
    }
  })

  test('no Jev-only hook card carries a shadow chip', () => {
    renderSection(AI_ON)
    for (const field of JEV_ONLY) {
      expect(within(screen.getByTestId(`ai-hook-${field}`)).queryByText('Shadow')).not.toBeInTheDocument()
    }
  })

  test('a Jev-only card writes its own field, and the stored value is shown', async () => {
    const s = renderSection(AI_ON)
    const card = screen.getByTestId('ai-hook-hakrawlerJevSeedOrder')
    const jev = within(card).getByRole('button', { name: 'Jev' })
    await waitFor(() => expect(jev).toBeEnabled())
    fireEvent.click(jev)
    expect(s.updateField).toHaveBeenCalledWith('hakrawlerJevSeedOrder', true)
    const pageType = screen.getByTestId('ai-hook-httpxJevPageType')
    expect(within(pageType).getByRole('button', { name: 'Jev' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(within(pageType).getByRole('button', { name: 'Off' }))
    expect(s.updateField).toHaveBeenCalledWith('httpxJevPageType', false)
  })

  test('the master switch never sets or resets a Jev-only flag', () => {
    const s = renderSection({ ...AI_ON, aiInPipeline: false })
    // The nearest ancestor of the master label that holds a switch is its row.
    let row: HTMLElement | null = screen.getByText('Enable AI in Pipeline').parentElement
    while (row && within(row).queryAllByRole('switch').length === 0) row = row.parentElement
    fireEvent.click(within(row!).getAllByRole('switch')[0])
    const written = s.updateField.mock.calls.map((c: unknown[]) => c[0])
    expect(written).toContain('aiInPipeline')
    for (const field of JEV_ONLY) expect(written).not.toContain(field)
  })

  test('the false-positive filter offers no Jev engine, and says why', () => {
    renderSection(AI_ON)
    const card = screen.getByTestId('ai-hook-nucleiAiResponseFilter')
    expect(within(card).queryByRole('button', { name: 'Jev' })).not.toBeInTheDocument()
    expect(within(card).getByText('LLM only')).toHaveAttribute('title', expect.stringMatching(/drop a finding/))
  })

  test('a hook that is off keeps its engine visible but disabled, with a reason that fits', () => {
    renderSection(AI_ON)
    const card = screen.getByTestId('ai-hook-nucleiAiTags')
    const jev = within(card).getByRole('button', { name: 'Jev' })
    expect(jev).toBeDisabled()
    expect(jev).toHaveAttribute('title', 'Turn this hook on to choose its engine.')
  })

  test('picking an engine in a card writes that hook\'s own field, and the stored choice is shown', async () => {
    const s = renderSection(AI_ON)
    const ffuf = screen.getByTestId('ai-hook-ffufAiExtensions')
    const jev = within(ffuf).getByRole('button', { name: 'Jev' })
    await waitFor(() => expect(jev).toBeEnabled())          // once the token lookup says yes
    fireEvent.click(jev)
    expect(s.updateField).toHaveBeenCalledWith('ffufAiUseJev', true)
    expect(within(screen.getByTestId('ai-hook-wafAiClassifier')).getByRole('button', { name: 'Jev' }))
      .toHaveAttribute('aria-pressed', 'true')
  })
})

// IP mode once hid the whole panel behind the Domain Verification gate, so an IP
// project had no way to turn AI or Jev on even though the backend runs the same
// hooked tools for every mode.
describe('target modes: AI in Pipeline everywhere, Domain Verification never on a bare IP', () => {
  // [mode, the fields that select it, whether Domain Verification applies]
  const MODES: Array<[string, Partial<Data>, boolean]> = [
    ['domain', { ipMode: false, domainBatchMode: false }, true],
    ['ip', { ipMode: true, domainBatchMode: false, targetIps: ['172.25.0.92'] }, false],
    ['batch', { ipMode: false, domainBatchMode: true }, true],
  ]
  const CASCADED = ['ffufAiExtensions', 'nucleiAiTags', 'wafAiClassifier', 'nucleiAiResponseFilter', 'takeoverAiClassifier']

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => ({
      ok: true, status: 200,
      json: async () => url.includes('llm-providers') ? [{ id: 'j', name: 'Synthetic Jev', providerType: 'jev', apiKey: '••••c0de', modelIdentifier: 'jev-1.13.0' }] : {},
    })))
  })
  afterEach(() => vi.unstubAllGlobals())

  test.each(MODES)('%s: the master switch and, once on, every hook card render', (_mode, modeData) => {
    renderSection({ ...modeData, aiInPipeline: true })
    expect(screen.getByText('Enable AI in Pipeline')).toBeInTheDocument()
    for (const field of [...CASCADED, 'httpxJevPageType', 'ffufJevBasePaths', 'hakrawlerJevSeedOrder', 'resourceEnumJevToolHealth',
      'serializedScanJevRank', 'routeExposureJevRank', 'routeExposureJevWallCheck', 'routeExposureJevAssess']) {
      expect(screen.getByTestId(`ai-hook-${field}`)).toBeInTheDocument()
    }
  })

  test.each(MODES)('%s: flipping the master switch cascades to every per-tool AI flag', (_mode, modeData) => {
    const s = renderSection({ ...modeData, aiInPipeline: false })
    let row: HTMLElement | null = screen.getByText('Enable AI in Pipeline').parentElement
    while (row && within(row).queryAllByRole('switch').length === 0) row = row.parentElement
    fireEvent.click(within(row!).getAllByRole('switch')[0])
    expect(s.data.aiInPipeline).toBe(true)
    for (const field of CASCADED) expect(s.data[field]).toBe(true)
  })

  test.each(MODES)('%s: Domain Verification shown = %s', (_mode, modeData, applies) => {
    renderSection(modeData)
    expect(screen.queryByText('Domain Verification') !== null).toBe(applies)
  })

  test('ip: a hook\'s Jev engine can be picked once the hook is on', async () => {
    const s = renderSection({
      ipMode: true, domainBatchMode: false, targetIps: ['172.25.0.92'],
      aiInPipeline: true, ffufAiExtensions: true, ffufAiUseJev: false, jevProviderId: 'j',
    })
    const jev = within(screen.getByTestId('ai-hook-ffufAiExtensions')).getByRole('button', { name: 'Jev' })
    await waitFor(() => expect(jev).toBeEnabled())
    fireEvent.click(jev)
    expect(s.updateField).toHaveBeenCalledWith('ffufAiUseJev', true)
  })
})

describe('ownership: the record names recon accepts (§4.8)', () => {
  test('the preview names both records per scan root when verification is on', () => {
    renderSection({ verifyDomainOwnership: true, ownershipTxtPrefix: '_rv',
      domainBatchHosts: ['*.api.example.com', 'www.example.com'] })
    const table = screen.getByRole('table')
    expect(within(table).getByText('Ownership TXT')).toBeInTheDocument()
    expect(within(table).getByText('_rv.api.example.com')).toBeInTheDocument()
    expect(within(table).getAllByText('_rv.example.com')).toHaveLength(2)
  })

  test('no ownership column while verification is off', () => {
    renderSection({ domainBatchHosts: ['www.example.com'] })
    expect(screen.queryByText('Ownership TXT')).not.toBeInTheDocument()
  })

  test('a single domain below its org names both records, with the default prefix', () => {
    renderSection({ domainBatchMode: false, targetDomain: 'api.example.com', verifyDomainOwnership: true })
    expect(screen.getByText('_redamon-verify.api.example.com')).toBeInTheDocument()
    expect(screen.getByText('_redamon-verify.example.com')).toBeInTheDocument()
  })
})

describe('ownership: the token (L-16)', () => {
  const renderEdit = (ownershipToken: unknown) => render(
    <TargetSection data={{ ...BASE, domainBatchMode: false, targetDomain: 'example.com',
      verifyDomainOwnership: true, ownershipToken } as never} updateField={vi.fn() as never} mode="edit" />)

  test('a new project shows no token and says one is generated on save', () => {
    // /defaults no longer serves one, so the form starts without the column.
    renderSection({ domainBatchMode: false, targetDomain: 'example.com',
      verifyDomainOwnership: true, ownershipToken: undefined })
    const input = screen.getByLabelText('Ownership Token') as HTMLInputElement
    expect(input.value).toBe('')
    expect(input.placeholder).toBe('Generated when the project is created')
    expect(screen.getByText(/gets its own random token on save/)).toBeInTheDocument()
  })

  test('a token typed at creation is what the form saves', () => {
    const s = renderSection({ domainBatchMode: false, targetDomain: 'example.com', verifyDomainOwnership: true })
    fireEvent.change(screen.getByLabelText('Ownership Token'), { target: { value: 'k7-mine' } })
    expect(s.data.ownershipToken).toBe('k7-mine')
  })

  test('a saved project still on the shipped placeholder is warned about', () => {
    renderEdit('your-secret-token-here')
    expect(screen.getByRole('status')).toHaveTextContent(/placeholder every RedAmon install shipped/)
  })

  test('a saved project with no token is warned about', () => {
    renderEdit('')
    expect(screen.getByRole('status')).toHaveTextContent(/has no token/)
  })

  test('a project with its own token shows it and no warning', () => {
    renderEdit('0b8f6c1e-3d2a-4c55-9a77-1f0e2d3c4b5a')
    expect((screen.getByLabelText('Ownership Token') as HTMLInputElement).value)
      .toBe('0b8f6c1e-3d2a-4c55-9a77-1f0e2d3c4b5a')
    expect(screen.queryByText(/placeholder every RedAmon install shipped|has no token/)).not.toBeInTheDocument()
  })
})

describe('a widening save warns about enabled schedules (WEB-35, D-21)', () => {
  const realFetch = globalThis.fetch
  afterEach(() => { globalThis.fetch = realFetch })

  function renderEdit(hosts: string[], schedules: { enabled: boolean }[]) {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ schedules }), { status: 200 })) as never
    const saved = { ...BASE, domainBatchHosts: ['*.example.com'] }
    const data = { ...saved, domainBatchHosts: hosts }
    render(<TargetSection data={data as never} updateField={vi.fn() as never} mode="edit"
      savedScope={saved as never} projectId="p1" />)
  }

  test('a new scan root warns, naming how many schedules will run it', async () => {
    renderEdit(['*.example.com', '*.other.test'], [{ enabled: true }, { enabled: true }, { enabled: false }])
    expect(await screen.findByText(/2 scheduled scans will run the wider scope/)).toBeInTheDocument()
  })

  test('a narrowing does not warn', async () => {
    renderEdit(['*.api.example.com'], [{ enabled: true }])
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    expect(screen.queryByText(/will run the wider scope/)).not.toBeInTheDocument()
  })

  test('no enabled schedule, no warning', async () => {
    renderEdit(['*.example.com', '*.other.test'], [{ enabled: false }])
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    expect(screen.queryByText(/will run the wider scope/)).not.toBeInTheDocument()
  })
})

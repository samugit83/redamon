/**
 * The minimal "Hostnames on target IPs" controls of an IP-mode project, and the
 * scheduled-scope warning a policy widening shows in the form (D-24: the form
 * warns, it never pauses a schedule; update_project_scope does).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TargetSection.ipHostnames.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { TargetSection } from './TargetSection'
import { IP_HOSTNAME_DEFAULTS } from '@/lib/scopeGroups'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

afterEach(() => { cleanup() })

type Data = Record<string, unknown>

const IP: Data = {
  name: '', description: '', targetDomain: '', subdomainList: [],
  ipMode: true, targetIps: ['203.0.113.10'], domainBatchMode: false, domainBatchHosts: [],
  subdomainDiscoveryEnabled: true, aiInPipeline: false, verifyDomainOwnership: false,
  ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '', engagementKind: 'internal',
  ipHostnameMode: 'ip_only', ipHostnameInclude: [], ipHostnameExclude: [], ipHostnamePassiveExpand: true,
  ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100, ipHostnamePassiveMaxNames: 500,
}

function renderLive(initial: Partial<Data> = {}, mode: 'create' | 'edit' = 'create') {
  const data: Data = { ...IP, ...initial }
  const updateField = vi.fn((k: string, v: unknown) => { data[k] = v; view.rerender(draw()) })
  const draw = () => <TargetSection data={{ ...data } as never} updateField={updateField as never} mode={mode} />
  const view = render(draw())
  return { data, updateField }
}

const modeSelect = () => screen.getByLabelText('Hostnames on target IPs') as HTMLSelectElement

describe('the minimal controls', () => {
  test('a native select over the four modes, ip_only by default', () => {
    renderLive()
    expect([...modeSelect().options].map(o => o.value)).toEqual(['ip_only', 'record_only', 'record_filter', 'scan_all'])
    expect(modeSelect().value).toBe('ip_only')
    expect(screen.queryByLabelText(/Scan names matching/)).not.toBeInTheDocument()
  })

  test('a row without the column reads as ip_only', () => {
    renderLive({ ipHostnameMode: undefined })
    expect(modeSelect().value).toBe('ip_only')
  })

  test('record_filter shows the filters, the passive search and both caps', () => {
    const { updateField, data } = renderLive()
    fireEvent.change(modeSelect(), { target: { value: 'record_filter' } })
    expect(data.ipHostnameMode).toBe('record_filter')
    fireEvent.change(screen.getByLabelText(/Scan names matching/), { target: { value: '*.example.com\napp.example.org' } })
    expect(data.ipHostnameInclude).toEqual(['*.example.com', 'app.example.org'])
    fireEvent.change(screen.getByLabelText(/Never scan/), { target: { value: '' } })
    expect(data.ipHostnameExclude).toEqual([])
    fireEvent.click(screen.getByLabelText(/Also search subdomains/))
    expect(data.ipHostnamePassiveExpand).toBe(false)
    fireEvent.change(screen.getByLabelText(/Most hostnames scanned per run/), { target: { value: '250' } })
    expect(data.ipHostnameMaxScanned).toBe(250)
    fireEvent.change(screen.getByLabelText(/Passive search: most names/), { target: { value: '' } })
    expect(data.ipHostnamePassiveMaxNames).toBe(500)
    expect(updateField).toHaveBeenCalledWith('ipHostnameScanAllConfirmed', false)
  })

  test('the caps carry the registry bounds', () => {
    renderLive({ ipHostnameMode: 'record_filter' })
    const max = screen.getByLabelText(/Most hostnames scanned per run/) as HTMLInputElement
    const passive = screen.getByLabelText(/Passive search: most names/) as HTMLInputElement
    expect([max.min, max.max, passive.min, passive.max]).toEqual(['1', '2000', '1', '10000'])
  })

  test('scan_all asks for its confirmation; leaving it resets the confirmation', () => {
    const { data } = renderLive({ ipHostnameMode: 'scan_all' })
    fireEvent.click(screen.getByLabelText(/I confirm every hostname/))
    expect(data.ipHostnameScanAllConfirmed).toBe(true)
    fireEvent.change(modeSelect(), { target: { value: 'record_only' } })
    expect(data.ipHostnameScanAllConfirmed).toBe(false)
    expect(screen.queryByLabelText(/I confirm every hostname/)).not.toBeInTheDocument()
  })

  test('scan_all cannot be picked on a third-party engagement (D-03)', () => {
    renderLive({ engagementKind: 'third_party' })
    const option = [...modeSelect().options].find(o => o.value === 'scan_all')!
    expect(option.disabled).toBe(true)
  })

  test('the policy stays editable after creation (a rescope, unlike the IP list)', () => {
    renderLive({}, 'edit')
    expect(modeSelect().disabled).toBe(false)
  })

  test.each(['Single Domain', 'Domain batch'])('switching from IP to %s puts the seven fields back at their defaults', (card) => {
    const { data } = renderLive({
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'],
      ipHostnamePassiveExpand: false, ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: 7,
      ipHostnamePassiveMaxNames: 9,
    })
    fireEvent.click(screen.getByText(card))
    expect(data.ipMode).toBe(false)
    expect({
      ipHostnameMode: data.ipHostnameMode, ipHostnameInclude: data.ipHostnameInclude,
      ipHostnameExclude: data.ipHostnameExclude, ipHostnamePassiveExpand: data.ipHostnamePassiveExpand,
      ipHostnameScanAllConfirmed: data.ipHostnameScanAllConfirmed, ipHostnameMaxScanned: data.ipHostnameMaxScanned,
      ipHostnamePassiveMaxNames: data.ipHostnamePassiveMaxNames,
    }).toEqual(IP_HOSTNAME_DEFAULTS)
  })

  test('staying in IP mode keeps the policy', () => {
    const { data } = renderLive({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] })
    fireEvent.click(screen.getByText('IP / CIDR'))
    expect(data.ipHostnameMode).toBe('record_filter')
    expect(data.ipHostnameInclude).toEqual(['*.example.com'])
  })

  test('a domain project shows none of it', () => {
    renderLive({ ipMode: false, targetDomain: 'example.com', targetIps: [] })
    expect(screen.queryByLabelText('Hostnames on target IPs')).not.toBeInTheDocument()
  })
})

describe('a hostname-policy widening warns about enabled schedules, never pauses them', () => {
  const realFetch = globalThis.fetch
  afterEach(() => { globalThis.fetch = realFetch })

  function renderEdit(saved: Partial<Data>, next: Partial<Data>, schedules: { enabled: boolean }[]) {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ schedules }), { status: 200 })) as never
    render(<TargetSection data={{ ...IP, ...next } as never} updateField={vi.fn() as never} mode="edit"
      savedScope={{ ...IP, ...saved } as never} projectId="p1" />)
  }

  test('record_only -> record_filter warns, naming the widening', async () => {
    renderEdit({ ipHostnameMode: 'record_only' },
      { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }, [{ enabled: true }])
    expect(await screen.findByText(/1 scheduled scan will run the wider scope/)).toBeInTheDocument()
    expect(screen.getByText(/hostname mode record_only -> record_filter/)).toBeInTheDocument()
    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
  })

  test('ip_only -> record_only does not warn: no new target traffic', async () => {
    renderEdit({}, { ipHostnameMode: 'record_only' }, [{ enabled: true }])
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    expect(screen.queryByText(/will run the wider scope/)).not.toBeInTheDocument()
  })

  test('a narrowing does not warn', async () => {
    renderEdit({ ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.example.org'] },
      { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }, [{ enabled: true }])
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalled())
    expect(screen.queryByText(/will run the wider scope/)).not.toBeInTheDocument()
  })
})

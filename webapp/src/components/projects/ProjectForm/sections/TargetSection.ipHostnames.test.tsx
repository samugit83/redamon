/**
 * The "Hostnames on target IPs" block of an IP-mode project (04_ui_spec.md §1,
 * §2, §7): the four mode cards, the filter editor and its preview, the M1
 * confirmation, the per-run limits; and the scheduled-scope warning a policy
 * widening shows in the form (D-24: the form warns, it never pauses a schedule;
 * update_project_scope does).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TargetSection.ipHostnames.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
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

const group = () => screen.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
const radio = (label: RegExp | string) => within(group()).getByRole('radio', { name: label }) as HTMLInputElement
const checkedMode = () => (within(group()).getAllByRole('radio') as HTMLInputElement[]).find(r => r.checked)?.value

describe('the mode cards in the form', () => {
  test('four radios in reach order, ip_only by default', () => {
    renderLive()
    expect((within(group()).getAllByRole('radio') as HTMLInputElement[]).map(r => r.value))
      .toEqual(['ip_only', 'record_only', 'record_filter', 'scan_all'])
    expect(checkedMode()).toBe('ip_only')
    expect(screen.queryByLabelText(/^Include/)).not.toBeInTheDocument()
  })

  test('a row without the column reads as ip_only', () => {
    renderLive({ ipHostnameMode: undefined })
    expect(checkedMode()).toBe('ip_only')
  })

  test('record_filter shows the filters, the passive search, the preview and both caps', () => {
    const { updateField, data } = renderLive()
    fireEvent.click(radio(/Record \+ scan matching/))
    expect(data.ipHostnameMode).toBe('record_filter')
    fireEvent.change(screen.getByLabelText(/^Include/), { target: { value: '*.example.com\napp.example.org' } })
    expect(data.ipHostnameInclude).toEqual(['*.example.com', 'app.example.org'])
    fireEvent.change(screen.getByLabelText(/^Exclude/), { target: { value: '' } })
    expect(data.ipHostnameExclude).toEqual([])
    fireEvent.click(screen.getByLabelText(/Also search subdomains/))
    expect(data.ipHostnamePassiveExpand).toBe(false)
    fireEvent.change(screen.getByLabelText(/Most hostnames scanned per run/), { target: { value: '250' } })
    expect(data.ipHostnameMaxScanned).toBe(250)
    fireEvent.change(screen.getByLabelText(/Passive search: most names/), { target: { value: '' } })
    expect(data.ipHostnamePassiveMaxNames).toBe(500)
    expect(updateField).toHaveBeenCalledWith('ipHostnameScanAllConfirmed', false)
    // Create mode: nothing has run yet.
    expect(screen.getByText('Available after the first scan in a recording mode.')).toBeInTheDocument()
  })

  test('the caps carry the registry bounds and sit in an Advanced disclosure', () => {
    renderLive({ ipHostnameMode: 'record_filter' })
    const max = screen.getByLabelText(/Most hostnames scanned per run/) as HTMLInputElement
    const passive = screen.getByLabelText(/Passive search: most names/) as HTMLInputElement
    expect([max.min, max.max, passive.min, passive.max]).toEqual(['1', '2000', '1', '10000'])
    expect(max.closest('details')).not.toBeNull()
  })

  test('scan_all asks for its confirmation, says it is required; leaving it resets the confirmation', () => {
    const { data } = renderLive({ ipHostnameMode: 'scan_all' })
    expect(screen.getByText(/Every hostname found on your IPs will be scanned/)).toBeInTheDocument()
    expect(screen.getByText(/Required to save/)).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText(/I confirm every site hosted on these IPs is in scope/))
    expect(data.ipHostnameScanAllConfirmed).toBe(true)
    expect(screen.queryByText(/Required to save/)).not.toBeInTheDocument()
    fireEvent.click(radio(/Record hostnames/))
    expect(data.ipHostnameScanAllConfirmed).toBe(false)
    expect(screen.queryByLabelText(/I confirm every site/)).not.toBeInTheDocument()
  })

  test('scan_all cannot be picked on a third-party engagement (D-03), and says why', () => {
    renderLive({ engagementKind: 'third_party' })
    expect(radio(/Record \+ scan all/).disabled).toBe(true)
    expect(within(group()).getByText(/Not available for third-party engagements/)).toBeInTheDocument()
  })

  test('the policy stays editable after creation (a rescope, unlike the IP list)', () => {
    renderLive({}, 'edit')
    expect((within(group()).getAllByRole('radio') as HTMLInputElement[]).every(r => !r.disabled)).toBe(true)
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
    expect(screen.queryByRole('radiogroup', { name: 'Hostnames on target IPs' })).not.toBeInTheDocument()
  })

  test('the IP-mode description no longer claims reverse DNS always runs (B-29)', () => {
    renderLive()
    expect(screen.queryByText(/runs reverse DNS to recover hostnames/)).not.toBeInTheDocument()
    expect(screen.getByText(/by default none is looked up/)).toBeInTheDocument()
  })

  test('the save payload carries the seven fields as the controls set them', () => {
    const { data } = renderLive()
    fireEvent.click(radio(/Record \+ scan matching/))
    fireEvent.change(screen.getByLabelText(/^Include/), { target: { value: '*.example.com' } })
    fireEvent.change(screen.getByLabelText(/^Exclude/), { target: { value: 'old.example.com' } })
    const fields = Object.keys(IP_HOSTNAME_DEFAULTS)
    expect(Object.fromEntries(fields.map(k => [k, data[k]]))).toEqual({
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: ['old.example.com'],
      ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: false, ipHostnameMaxScanned: 100,
      ipHostnamePassiveMaxNames: 500,
    })
  })
})

describe('a hostname-policy widening warns about enabled schedules, never pauses them', () => {
  const realFetch = globalThis.fetch
  afterEach(() => { globalThis.fetch = realFetch })

  function renderEdit(saved: Partial<Data>, next: Partial<Data>, schedules: { enabled: boolean }[]) {
    globalThis.fetch = vi.fn(async (url: string) => (String(url).includes('/schedules')
      ? new Response(JSON.stringify({ schedules }), { status: 200 })
      : new Response(JSON.stringify({ error: 'Not found' }), { status: 404 }))) as never
    render(<TargetSection data={{ ...IP, ...next } as never} updateField={vi.fn() as never} mode="edit"
      savedScope={{ ...IP, ...saved } as never} projectId="p1" />)
  }

  test('record_only -> record_filter warns, naming the widening', async () => {
    renderEdit({ ipHostnameMode: 'record_only' },
      { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }, [{ enabled: true }])
    expect(await screen.findByText(/1 scheduled scan will run the wider scope/)).toBeInTheDocument()
    expect(screen.getByText(/hostname mode record_only -> record_filter/)).toBeInTheDocument()
    const calls = vi.mocked(globalThis.fetch).mock.calls.map(c => String(c[0]))
    expect(calls.filter(u => u.includes('/schedules'))).toHaveLength(1)
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

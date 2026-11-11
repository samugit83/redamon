/**
 * The four "Hostnames on target IPs" cards (04_ui_spec.md §2, §7, §8): a native
 * radio group in reach order, an info button beside (never inside) each card's
 * label, scan_all disabled with its reason on a third-party engagement.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/IpHostnameModeCards.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { useState } from 'react'
import { IpHostnameModeCards, SCAN_ALL_THIRD_PARTY_REASON } from './IpHostnameModeCards'
import type { IpHostnameMode } from './ipHostnameModes'
import { TargetSection } from './sections/TargetSection'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

afterEach(() => { cleanup() })

function Harness({ initial = 'ip_only', onChange = () => {}, thirdParty = false, disabled = false }: {
  initial?: IpHostnameMode; onChange?: (m: IpHostnameMode) => void; thirdParty?: boolean; disabled?: boolean
}) {
  const [mode, setMode] = useState<IpHostnameMode>(initial)
  return (
    <>
      <span id="lbl">Hostnames on target IPs</span>
      <IpHostnameModeCards
        value={mode}
        labelledBy="lbl"
        thirdParty={thirdParty}
        disabled={disabled}
        onModeChange={m => { setMode(m); onChange(m) }}
      />
    </>
  )
}

const group = () => screen.getByRole('radiogroup', { name: 'Hostnames on target IPs' })
const radios = () => within(group()).getAllByRole('radio') as HTMLInputElement[]
const checked = () => radios().find(r => r.checked)?.value

describe('the radio group', () => {
  test('four radios in reach order, labelled by the section label; ip_only is checked by default', () => {
    render(<Harness />)
    expect(radios().map(r => r.value)).toEqual(['ip_only', 'record_only', 'record_filter', 'scan_all'])
    expect(radios().map(r => r.labels?.[0]?.textContent)).toEqual([
      expect.stringContaining('IP only'),
      expect.stringContaining('Record hostnames'),
      expect.stringContaining('Record + scan matching'),
      expect.stringContaining('Record + scan all'),
    ])
    expect(checked()).toBe('ip_only')
    expect(within(group()).getByText('DEFAULT')).toBeInTheDocument()
    expect(within(group()).getByText('NEEDS CONFIRM')).toBeInTheDocument()
  })

  test('one native group: every radio shares the name, so arrow keys move the selection', () => {
    render(<Harness />)
    expect(new Set(radios().map(r => r.name))).toEqual(new Set(['ipHostnameMode']))
    // jsdom does not run the browser's arrow-key behaviour; what makes it work is
    // one shared name on native radios, pinned above. The change a key press
    // produces arrives as a change event:
    fireEvent.click(radios()[1])
    expect(checked()).toBe('record_only')
  })

  test('each summary describes its radio for a screen reader', () => {
    render(<Harness />)
    const r = radios()[2]
    const described = document.getElementById(r.getAttribute('aria-describedby')!)
    expect(described?.textContent).toMatch(/names that match your filters/)
  })

  test('picking a card reports the mode', () => {
    const onChange = vi.fn()
    render(<Harness onChange={onChange} />)
    fireEvent.click(radios()[2])
    expect(onChange).toHaveBeenCalledWith('record_filter')
  })
})

describe('the info buttons', () => {
  test('sit beside the label, open the right modal and do not change the mode', () => {
    const onChange = vi.fn()
    render(<Harness onChange={onChange} />)
    const button = screen.getByRole('button', { name: "How 'Record hostnames' works" })
    expect(button.getAttribute('aria-haspopup')).toBe('dialog')
    expect(button.closest('label')).toBeNull()
    fireEvent.click(button)
    expect(screen.getByRole('dialog', { name: "How 'Record hostnames' works" })).toBeInTheDocument()
    expect(onChange).not.toHaveBeenCalled()
    expect(checked()).toBe('ip_only')
  })

  test('"Use this mode" in the modal selects it', () => {
    const onChange = vi.fn()
    render(<Harness onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: "How 'Record + scan matching' works" }))
    fireEvent.click(screen.getByRole('button', { name: 'Use this mode' }))
    expect(onChange).toHaveBeenCalledWith('record_filter')
    expect(checked()).toBe('record_filter')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})

describe('third-party engagements and read-only forms', () => {
  test('scan_all is disabled with its reason (D-03); the others stay available', () => {
    render(<Harness thirdParty />)
    const byValue = Object.fromEntries(radios().map(r => [r.value, r.disabled]))
    expect(byValue).toEqual({ ip_only: false, record_only: false, record_filter: false, scan_all: true })
    expect(within(group()).getByText(SCAN_ALL_THIRD_PARTY_REASON.trim(), { exact: false })).toBeInTheDocument()
  })

  test('its modal cannot pick it either, and says why', () => {
    render(<Harness thirdParty />)
    fireEvent.click(screen.getByRole('button', { name: "How 'Record + scan all' works" }))
    expect((screen.getByRole('button', { name: 'Use this mode' }) as HTMLButtonElement).disabled).toBe(true)
    expect(within(screen.getByRole('dialog')).getAllByText(/Not available for third-party engagements/).length)
      .toBeGreaterThan(0)
  })

  test('a disabled form disables every radio and hides "Use this mode"', () => {
    render(<Harness disabled />)
    expect(radios().every(r => r.disabled)).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: "How 'IP only' works" }))
    expect(screen.queryByRole('button', { name: 'Use this mode' })).toBeNull()
  })
})

describe('in the Target section', () => {
  const IP = {
    name: '', description: '', targetDomain: '', subdomainList: [], ipMode: true, targetIps: ['203.0.113.10'],
    domainBatchMode: false, domainBatchHosts: [], subdomainDiscoveryEnabled: true, aiInPipeline: false,
    verifyDomainOwnership: false, ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '',
    engagementKind: 'internal', ipHostnameMode: 'scan_all', ipHostnameInclude: [], ipHostnameExclude: [],
    ipHostnamePassiveExpand: true, ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: 100,
    ipHostnamePassiveMaxNames: 500,
  }

  function renderSection(mode: 'create' | 'edit', over: Record<string, unknown> = {}) {
    const data: Record<string, unknown> = { ...IP, ...over }
    const updateField = vi.fn((k: string, v: unknown) => { data[k] = v; view.rerender(draw()) })
    const draw = () => <TargetSection data={{ ...data } as never} updateField={updateField as never} mode={mode} />
    const view = render(draw())
    return data
  }

  test('leaving scan_all clears the confirmation', () => {
    const data = renderSection('create')
    fireEvent.click(radios()[1])
    expect(data.ipHostnameMode).toBe('record_only')
    expect(data.ipHostnameScanAllConfirmed).toBe(false)
  })

  test('the cards stay editable in edit mode, unlike the target-mode cards', () => {
    renderSection('edit')
    expect(radios().every(r => !r.disabled)).toBe(true)
    expect((screen.getByText('IP / CIDR').closest('button') as HTMLButtonElement).disabled).toBe(true)
  })
})

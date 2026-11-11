/**
 * "How '<mode>' works" (04_ui_spec.md §3, §7, §8): every section in order for
 * each mode, the diagram as an image with the mode's own label, the comparison
 * table, "Use this mode", Escape and focus return, the full-screen modal on a
 * phone.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/IpHostnameModeInfoModal.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { useState } from 'react'
import { IpHostnameModeInfoModal } from './IpHostnameModeInfoModal'
import { IP_HOSTNAME_MODES, type IpHostnameMode, ipHostnameModeInfo } from './ipHostnameModes'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const SECTIONS = [
  'In one sentence', 'Diagram', 'What RedAmon does', 'What you will see in the graph', 'Traffic',
  'When to use', 'When not to use', 'Example',
]

function Opener({ mode, onSelect, disabledReasons }: {
  mode: IpHostnameMode; onSelect?: (m: IpHostnameMode) => void; disabledReasons?: Partial<Record<IpHostnameMode, string>>
}) {
  const [open, setOpen] = useState<IpHostnameMode | null>(null)
  return (
    <>
      <button type="button" onClick={() => setOpen(mode)}>info</button>
      <IpHostnameModeInfoModal mode={open} onClose={() => setOpen(null)} onSelect={onSelect}
                               disabledReasons={disabledReasons} currentMode="ip_only" />
    </>
  )
}

const dialog = () => screen.getByRole('dialog')

describe.each(IP_HOSTNAME_MODES.map(m => [m.mode, m] as const))('%s', (mode, info) => {
  test('every section, in order, under the "How \'<label>\' works" title', () => {
    render(<IpHostnameModeInfoModal mode={mode} onClose={() => {}} />)
    expect(screen.getByRole('dialog', { name: `How '${info.label}' works` })).toBeInTheDocument()
    expect(within(dialog()).getAllByRole('heading', { level: 3 }).map(h => h.textContent)).toEqual(SECTIONS)
    expect(within(dialog()).getByText(info.sentence)).toBeInTheDocument()
    for (const step of info.steps) expect(within(dialog()).getAllByText(step).length).toBeGreaterThan(0)
    for (const line of [...info.graph, ...info.whenToUse, ...info.whenNotToUse, info.example.setup]) {
      expect(within(dialog()).getByText(line)).toBeInTheDocument()
    }
    expect(within(dialog()).getByText(info.traffic.targets)).toBeInTheDocument()
  })

  test("the diagram is an image carrying the mode's own label, and the steps are a visible list", () => {
    render(<IpHostnameModeInfoModal mode={mode} onClose={() => {}} />)
    const img = within(dialog()).getByRole('img')
    expect(img.getAttribute('aria-label')).toBe(info.diagram.ariaLabel)
    const steps = within(dialog()).getByRole('heading', { name: 'What RedAmon does' }).parentElement!
    expect(within(steps).getAllByRole('listitem').map(li => li.textContent)).toEqual(info.steps)
  })
})

describe('specific content', () => {
  test('Record hostnames says the unseen-rows badge will be large after a run', () => {
    render(<IpHostnameModeInfoModal mode="record_only" onClose={() => {}} />)
    expect(within(dialog()).getByText(/"unseen" badges.*a large badge on shared hosting is expected/)).toBeInTheDocument()
  })

  test('Record + scan all shows its confirmation guarantee in red', () => {
    render(<IpHostnameModeInfoModal mode="scan_all" onClose={() => {}} />)
    const warning = within(dialog()).getByText('You must confirm that every site hosted on these IPs is in scope.')
    expect(warning.className).toMatch(/danger/)
  })

  test('IP only: VHost/SNI tries only the custom wordlist (D-09); credentials stay on the IPs (D-22)', () => {
    render(<IpHostnameModeInfoModal mode="ip_only" onClose={() => {}} />)
    expect(within(dialog()).getByText(/VHost\/SNI tries only the names of your own custom wordlist/)).toBeInTheDocument()
    expect(within(dialog()).getByText(/credentials from an auth profile go to the target IPs only/)).toBeInTheDocument()
  })
})

describe('the footer', () => {
  test('"Compare all four modes" toggles the comparison table', () => {
    render(<IpHostnameModeInfoModal mode="record_filter" onClose={() => {}} />)
    const toggle = screen.getByRole('button', { name: 'Compare all four modes' })
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(within(dialog()).queryByRole('table')).toBeNull()
    fireEvent.click(toggle)
    const table = within(dialog()).getByRole('table')
    expect(within(table).getAllByRole('columnheader').map(c => c.textContent))
      .toEqual(['IP only', 'Record hostnames', 'Record + scan matching', 'Record + scan all'])
    expect(within(table).getByRole('rowheader', { name: 'Third-party engagements' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Hide the comparison' }).getAttribute('aria-expanded')).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: 'Hide the comparison' }))
    expect(within(dialog()).queryByRole('table')).toBeNull()
  })

  test('"Use this mode" selects it and closes', () => {
    const onSelect = vi.fn()
    render(<Opener mode="record_filter" onSelect={onSelect} />)
    fireEvent.click(screen.getByText('info'))
    fireEvent.click(screen.getByRole('button', { name: 'Use this mode' }))
    expect(onSelect).toHaveBeenCalledWith('record_filter')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('the current mode reads "In use", and a refused one is disabled with its reason', () => {
    const { unmount } = render(<IpHostnameModeInfoModal mode="ip_only" currentMode="ip_only" onClose={() => {}} onSelect={() => {}} />)
    expect((screen.getByRole('button', { name: 'In use' }) as HTMLButtonElement).disabled).toBe(true)
    unmount()
    render(<IpHostnameModeInfoModal mode="scan_all" onClose={() => {}} onSelect={() => {}}
                                    disabledReasons={{ scan_all: 'Not available for third-party engagements.' }} />)
    const use = screen.getByRole('button', { name: 'Use this mode' }) as HTMLButtonElement
    expect(use.disabled).toBe(true)
    expect(use.title).toBe('Not available for third-party engagements.')
  })

  test('Escape closes, and focus returns to the button that opened it', () => {
    render(<Opener mode="record_only" />)
    const opener = screen.getByText('info')
    opener.focus()
    fireEvent.click(opener)
    fireEvent.keyDown(dialog(), { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  test('a reopened modal starts on the explanation, not on a table left open', () => {
    render(<Opener mode="record_only" />)
    fireEvent.click(screen.getByText('info'))
    fireEvent.click(screen.getByRole('button', { name: 'Compare all four modes' }))
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    fireEvent.click(screen.getByText('info'))
    expect(within(dialog()).queryByRole('table')).toBeNull()
  })
})

describe('on a phone (< 640 px)', () => {
  test('the modal takes the whole screen', () => {
    vi.stubGlobal('matchMedia', (q: string) => ({
      matches: q === '(max-width: 639px)', addEventListener: () => {}, removeEventListener: () => {},
    }))
    render(<IpHostnameModeInfoModal mode="record_filter" onClose={() => {}} />)
    expect(dialog().className).toMatch(/modalFull/)
  })

  test('otherwise it is the large modal', () => {
    render(<IpHostnameModeInfoModal mode="record_filter" onClose={() => {}} />)
    expect(dialog().className).toMatch(/modalLarge/)
    expect(ipHostnameModeInfo('record_filter').label).toBe('Record + scan matching')
  })
})

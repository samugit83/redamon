/**
 * Settings an IP-mode project's hostname mode forces (D-20, 04_ui_spec.md §5).
 *
 * recon's apply_ip_hostname_overrides ignores the stored value of tlsx's
 * reverse-PTR SNI (every IP-mode project), Shodan's reverse DNS and vhost/SNI
 * graph candidates (IP only). The form must not offer a switch the run ignores:
 * the toggle shows the forced value, is disabled, and says why. Nothing changes
 * outside IP mode or when the mode does not force the column.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/ipHostnameOverrideNotes.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ShodanSection } from './ShodanSection'
import { TlsxSection } from './TlsxSection'
import { VhostSniSection } from './VhostSniSection'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ shodanApiKey: 'set' }), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

type Data = Record<string, unknown>

const BASE: Data = {
  ipMode: true, targetIps: ['203.0.113.10'], ipHostnameMode: 'ip_only',
  shodanEnabled: true, shodanHostLookup: true, shodanReverseDns: true, shodanDomainDns: false,
  shodanPassiveCves: true, shodanWorkers: 5,
  tlsxEnabled: true, tlsxCipherEnum: false, tlsxRevPtrSni: true,
  vhostSniEnabled: true, vhostSniUseGraphCandidates: true, vhostSniUseDefaultWordlist: false,
  vhostSniCustomWordlist: '', vhostSniTestL7: true, vhostSniTestL4: false,
}

const CASES = [
  { name: 'Shodan reverse DNS', Section: ShodanSection, column: 'shodanReverseDns', toggle: 'Reverse DNS',
    forcedIn: ['ip_only'] },
  { name: 'tlsx reverse-PTR SNI', Section: TlsxSection, column: 'tlsxRevPtrSni', toggle: 'Reverse-PTR SNI for bare IPs',
    forcedIn: ['ip_only', 'record_only', 'record_filter', 'scan_all'] },
  { name: 'vhost/SNI graph candidates', Section: VhostSniSection, column: 'vhostSniUseGraphCandidates',
    toggle: 'Use graph candidates', forcedIn: ['ip_only'] },
] as const

const LABEL: Record<string, string> = {
  ip_only: 'IP only', record_only: 'Record hostnames', record_filter: 'Record + scan matching', scan_all: 'Record + scan all',
}
const MODES = Object.keys(LABEL)

function renderSection(c: (typeof CASES)[number], patch: Data) {
  const updateField = vi.fn()
  const data = { ...BASE, ...patch }
  render(<c.Section data={data as never} updateField={updateField as never} />)
  return { updateField, toggle: screen.getByRole('switch', { name: c.toggle }) }
}

describe.each(CASES)('$name', (c) => {
  test.each(MODES.filter(m => (c.forcedIn as readonly string[]).includes(m)))(
    'forced in %s: disabled, shown off, with the note naming the mode', (mode) => {
      const { toggle, updateField } = renderSection(c, { ipHostnameMode: mode, [c.column]: true })
      expect(toggle).toBeDisabled()
      // The value the run uses, not the stored one.
      expect(toggle).toHaveAttribute('aria-checked', 'false')
      expect(screen.getByText(`Off: forced by Hostnames on target IPs (${LABEL[mode]}).`, { exact: false }))
        .toBeInTheDocument()
      fireEvent.click(toggle)
      expect(updateField).not.toHaveBeenCalled()
    },
  )

  test.each(MODES.filter(m => !(c.forcedIn as readonly string[]).includes(m)))(
    'not forced in %s: enabled, stored value, no note', (mode) => {
      const { toggle, updateField } = renderSection(c, { ipHostnameMode: mode, [c.column]: true })
      expect(toggle).toBeEnabled()
      expect(toggle).toHaveAttribute('aria-checked', 'true')
      expect(screen.queryByText(/forced by Hostnames on target IPs/)).not.toBeInTheDocument()
      fireEvent.click(toggle)
      expect(updateField).toHaveBeenCalledWith(c.column, false)
    },
  )

  test('a domain project is unchanged, whatever its (default) hostname mode says', () => {
    const { toggle, updateField } = renderSection(c, { ipMode: false, targetIps: [], ipHostnameMode: 'ip_only', [c.column]: true })
    expect(toggle).toBeEnabled()
    expect(toggle).toHaveAttribute('aria-checked', 'true')
    expect(screen.queryByText(/forced by Hostnames on target IPs/)).not.toBeInTheDocument()
    fireEvent.click(toggle)
    expect(updateField).toHaveBeenCalledWith(c.column, false)
  })

  test('a row without the mode column is ip_only, the strictest, as in recon', () => {
    const { toggle } = renderSection(c, { ipHostnameMode: undefined, [c.column]: true })
    expect(toggle).toBeDisabled()
    expect(screen.getByText(/Off: forced by Hostnames on target IPs \(IP only\)\./)).toBeInTheDocument()
  })
})

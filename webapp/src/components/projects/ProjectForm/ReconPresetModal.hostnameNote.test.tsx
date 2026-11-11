/**
 * D-17 in the preset drawer: a preset never sets "Hostnames on target IPs", so
 * a built-in IP preset designed around the names found on the target IPs gets a
 * one-line note on an IP-only form, on its card and in its detail. The form
 * passes its own values, so a project being created is judged too.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/ReconPresetModal.hostnameNote.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: vi.fn(), error: vi.fn() }),
  useAlertModal: () => ({ dangerConfirm: vi.fn() }),
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/Modal/Modal', () => ({
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) =>
    (isOpen ? <div role="dialog">{children}</div> : null),
}))

import { ReconPresetModal, presetHostnameNote } from './ReconPresetModal'
import { IP_PRESETS_RELYING_ON_HOSTNAMES } from '@/lib/recon-presets/targeting'
import { getPresetById } from '@/lib/recon-presets'

afterEach(() => { cleanup() })

function drawer(hostnamePolicy?: { ipMode?: boolean; ipHostnameMode?: string }) {
  render(<ReconPresetModal isOpen onClose={vi.fn()} onSelect={vi.fn() as never} onLoadUserPreset={vi.fn() as never}
                           userId="u1" hostnamePolicy={hostnamePolicy} />)
}

const card = (name: string) => screen.getByRole('heading', { name, level: 3 }).closest('div[class*="card"]')!.parentElement!

describe('presetHostnameNote', () => {
  test('only an IP-mode, IP-only project, and only the presets that rely on names', () => {
    expect(presetHostnameNote('internal-network', { ipMode: true, ipHostnameMode: 'ip_only' })).toMatch(/IP only/)
    expect(presetHostnameNote('internal-network', { ipMode: true, ipHostnameMode: 'record_only' })).toBeNull()
    expect(presetHostnameNote('internal-network', { ipMode: false, ipHostnameMode: 'ip_only' })).toBeNull()
    expect(presetHostnameNote('internal-network', undefined)).toBeNull()
    for (const id of IP_PRESETS_RELYING_ON_HOSTNAMES) {
      expect(getPresetById(id), id).toBeDefined()
      expect(presetHostnameNote(id, { ipMode: true, ipHostnameMode: 'ip_only' }), id).not.toBeNull()
    }
  })
})

describe('the drawer', () => {
  const internal = () => getPresetById('internal-network')!.name

  test('an IP-only form: the note is on the preset\'s card and in its detail', () => {
    drawer({ ipMode: true, ipHostnameMode: 'ip_only' })
    const notes = screen.getAllByTestId('preset-hostname-note')
    expect(notes).toHaveLength(IP_PRESETS_RELYING_ON_HOSTNAMES.size)
    const own = within(card(internal())).getByTestId('preset-hostname-note')
    expect(own.textContent).toMatch(/A preset never changes that mode: set it on the Target tab/)
    fireEvent.click(within(card(internal())).getByRole('button', { name: /show more/i }))
    expect(within(screen.getByRole('dialog')).getByTestId('preset-hostname-note')).toBeInTheDocument()
  })

  test('a recording mode, a domain form, or no policy passed: no note anywhere', () => {
    for (const policy of [{ ipMode: true, ipHostnameMode: 'record_only' }, { ipMode: false, ipHostnameMode: 'ip_only' }, undefined]) {
      drawer(policy)
      expect(screen.queryAllByTestId('preset-hostname-note')).toHaveLength(0)
      cleanup()
    }
  })
})

/**
 * Scan Timeline — second-run modal (Section 3.2).
 *
 * The choice is only offered when there is a graph to lose, it defaults to the
 * non-destructive option, and the chosen mode is what reaches the caller.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { ReconConfirmModal } from './ReconConfirmModal'
import { resolveScopeGroups } from '@/lib/scopeGroups'

const baseProps = {
  isOpen: true,
  onClose: vi.fn(),
  onConfirm: vi.fn(),
  projectName: 'Acme',
  targetDomain: 'acme.tld',
  isLoading: false,
}

const withData = { totalNodes: 120, nodesByType: { IP: 40, Port: 80 } }

beforeEach(() => vi.clearAllMocks())
// The suite has no `globals: true`, so RTL's auto-cleanup does not run and the
// modal's portal would otherwise stack across tests.
afterEach(cleanup)

describe('ReconConfirmModal — scan mode choice', () => {
  test('no existing data → no choice, confirms with the default mode', () => {
    render(<ReconConfirmModal {...baseProps} stats={null} />)
    expect(screen.queryByRole('radiogroup')).toBeNull()
    fireEvent.click(screen.getByText('Start Recon'))
    expect(baseProps.onConfirm).toHaveBeenCalledWith('new')
  })

  test('existing data → both options offered, "new version" preselected', () => {
    render(<ReconConfirmModal {...baseProps} stats={withData} />)
    const radios = screen.getAllByRole('radio') as HTMLInputElement[]
    expect(radios).toHaveLength(2)
    expect(radios[0].value).toBe('new')
    expect(radios[0].checked).toBe(true)
    expect(radios[1].value).toBe('overwrite')
    expect(radios[1].checked).toBe(false)
    expect(screen.getByText('Save Version & Start')).toBeTruthy()
  })

  test('choosing overwrite confirms with overwrite and relabels the action', () => {
    render(<ReconConfirmModal {...baseProps} stats={withData} />)
    fireEvent.click(screen.getAllByRole('radio')[1])
    expect(screen.getByText('Discard & Start')).toBeTruthy()
    fireEvent.click(screen.getByText('Discard & Start'))
    expect(baseProps.onConfirm).toHaveBeenCalledWith('overwrite')
  })

  test('shows the label the current graph would be saved as', () => {
    render(<ReconConfirmModal {...baseProps} stats={withData} currentVersionLabel="Scan 2 - 2026-07-01 10:00 UTC" />)
    expect(screen.getByText(/Scan 2 - 2026-07-01 10:00 UTC/)).toBeTruthy()
  })

  test('reopening resets a previously chosen overwrite back to the safe default', () => {
    const { rerender } = render(<ReconConfirmModal {...baseProps} stats={withData} />)
    fireEvent.click(screen.getAllByRole('radio')[1])
    expect((screen.getAllByRole('radio')[1] as HTMLInputElement).checked).toBe(true)
    rerender(<ReconConfirmModal {...baseProps} isOpen={false} stats={withData} />)
    rerender(<ReconConfirmModal {...baseProps} isOpen stats={withData} />)
    expect((screen.getAllByRole('radio')[0] as HTMLInputElement).checked).toBe(true)
  })

  test('while starting, the options are disabled', () => {
    render(<ReconConfirmModal {...baseProps} stats={withData} isLoading />)
    for (const r of screen.getAllByRole('radio') as HTMLInputElement[]) {
      expect(r.disabled).toBe(true)
    }
  })
})

describe('ReconConfirmModal — a Domain batch names its scope groups', () => {
  const groups = resolveScopeGroups({
    domainBatchMode: true, domainBatchHosts: ['*.acme.co.uk', 'www.beta.test', 'api.beta.test'],
  }).groups

  test('one label per group and the enumerated count, never a blank target', () => {
    render(<ReconConfirmModal {...baseProps} targetDomain="" batchGroups={groups} stats={null} />)
    const text = document.body.textContent ?? ''
    expect(text).toContain('2 scope groups: ')
    expect(text).toContain('*.acme.co.uk (enumerated)')
    expect(text).toContain('beta.test: www, api (listed)')
    expect(text).toContain('1 enumerated group (may take hours)')
    expect(text).not.toContain('fully enumerated')
  })

  test('a listed-only batch carries no enumeration warning', () => {
    const listed = groups.filter(g => g.mode === 'exact')
    render(<ReconConfirmModal {...baseProps} targetDomain="" batchGroups={listed} stats={null} />)
    expect(document.body.textContent).toContain('1 scope group: beta.test')
    expect(document.body.textContent).not.toContain('may take hours')
  })
})

describe('ReconConfirmModal — Hostnames on target IPs (04_ui_spec.md §5)', () => {
  const ip = { ...baseProps, targetDomain: '', ipMode: true, targetIps: ['203.0.113.10'], stats: null }

  test('one line naming the mode', () => {
    render(<ReconConfirmModal {...ip} hostnamePolicy={{ ipHostnameMode: 'record_only' }} />)
    expect(screen.getByTestId('recon-confirm-hostname-mode').textContent)
      .toBe('Hostnames on target IPs: Record hostnames')
    expect(screen.queryByTestId('recon-confirm-scan-all')).toBeNull()
  })

  test('Record + scan matching lists its include and exclude counts', () => {
    render(<ReconConfirmModal {...ip} hostnamePolicy={{
      ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com', '*.example.de'],
      ipHostnameExclude: ['old.example.com'],
    }} />)
    expect(screen.getByTestId('recon-confirm-hostname-mode').textContent)
      .toBe('Hostnames on target IPs: Record + scan matching (include 2, exclude 1)')
  })

  test('Record + scan all repeats the red warning', () => {
    render(<ReconConfirmModal {...ip} hostnamePolicy={{ ipHostnameMode: 'scan_all' }} />)
    expect(screen.getByTestId('recon-confirm-scan-all').textContent)
      .toMatch(/Every hostname found on these IPs will be scanned.*CDN edge addresses are always skipped/)
  })

  test('a domain project, or a read without the mode, shows no line', () => {
    render(<ReconConfirmModal {...baseProps} stats={null} hostnamePolicy={{ ipHostnameMode: 'scan_all' }} />)
    expect(screen.queryByTestId('recon-confirm-hostname-mode')).toBeNull()
    cleanup()
    render(<ReconConfirmModal {...ip} />)
    expect(screen.queryByTestId('recon-confirm-hostname-mode')).toBeNull()
  })
})

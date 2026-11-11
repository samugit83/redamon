/**
 * The graph page opens the start dialog without passing the hostname policy:
 * the dialog reads it from the current project's summary, which the project
 * provider builds from the full project read (toProjectSummary).
 *
 * Run: npx vitest run src/app/graph/components/ReconConfirmModal/ReconConfirmModal.hostnameContext.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { toProjectSummary } from '@/lib/projectSummary'

const ctx = vi.hoisted(() => ({ current: null as null | { currentProject: unknown } }))
vi.mock('@/providers/ProjectProvider', () => ({ useOptionalProject: () => ctx.current }))

import { ReconConfirmModal } from './ReconConfirmModal'

afterEach(() => { cleanup(); ctx.current = null })

const props = {
  isOpen: true, onClose: vi.fn(), onConfirm: vi.fn(), projectName: 'Lab', targetDomain: '', ipMode: true,
  targetIps: ['203.0.113.10'], stats: null, isLoading: false,
}

describe('the policy from the current project', () => {
  test('a full project read carries the mode and the filters', () => {
    ctx.current = {
      currentProject: toProjectSummary({
        id: 'p1', name: 'Lab', targetDomain: '', ipMode: true, targetIps: ['203.0.113.10'],
        ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'], ipHostnameExclude: [],
      }),
    }
    render(<ReconConfirmModal {...props} />)
    expect(screen.getByTestId('recon-confirm-hostname-mode').textContent)
      .toBe('Hostnames on target IPs: Record + scan matching (include 1, exclude 0)')
  })

  test('a passed policy wins over the context', () => {
    ctx.current = { currentProject: { ipHostnameMode: 'record_only' } }
    render(<ReconConfirmModal {...props} hostnamePolicy={{ ipHostnameMode: 'ip_only' }} />)
    expect(screen.getByTestId('recon-confirm-hostname-mode').textContent).toBe('Hostnames on target IPs: IP only')
  })
})

/**
 * The project form's Save gate for "Record + scan all" (04_ui_spec.md §8, M1
 * confirmation): unchecked, Save is disabled with the reason under the button.
 * The save routes and MCP refuse the same row (crossField), so this is the
 * early answer, not the control.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/ProjectForm.ipHostnameGate.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
vi.mock('next/dynamic', () => ({ default: () => () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'alice' }) }))
vi.mock('@/hooks/useReconStatus', () => ({ default: () => ({ state: null }) }))
vi.mock('@/hooks/useScanControls', () => ({
  useScanControls: () => ({ otherScansOpen: false, gvm: {}, githubHunt: {}, trufflehog: { runs: [] }, supplyChain: {} }),
}))
vi.mock('@/components/scans/ScanActions', () => ({ ScanActions: () => null }))
vi.mock('@/app/graph/components/OtherScansModal/OtherScansModal', () => ({ OtherScansModal: () => null }))
vi.mock('@/hooks/useMultiPartialReconStatus', () => ({ useMultiPartialReconStatus: () => ({ runs: [], activeRuns: [], refetch: vi.fn() }) }))
vi.mock('@/hooks/useScanStartFailure', () => ({ useScanStartFailure: () => ({ handleStartFailure: vi.fn() }) }))
vi.mock('@/hooks/useDrawerOffsets', () => ({ useDrawerOffsets: () => {} }))
vi.mock('@/hooks/useMultiPartialReconSSE', () => ({ useMultiPartialReconSSE: () => ({ logsMap: {}, phaseMap: {}, clearLogsForRun: vi.fn() }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => '' }))
vi.mock('./UserPresetDrawer', () => ({
  UserPresetDrawer: ({ onLoad }: { onLoad: (p: { id: string; name: string }) => void }) => (
    <button type="button" onClick={() => onLoad({ id: 'up1', name: 'Fast' })}>load-user-preset</button>
  ),
}))

import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'
import { ipHostnamePolicyProblem } from '@/lib/scopeGroups'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

type Route = (url: string, init?: RequestInit) => Response | null
let route: Route = () => null

beforeEach(() => {
  route = () => null
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const answer = route(String(url), init)
    if (answer) return answer
    if (url === '/api/projects/defaults') return json(200, {})
    if (url.endsWith('/llm-providers')) return json(200, [{ id: 'pr1', providerType: 'openai' }])
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider><AlertProvider>{children}</AlertProvider></ToastProvider>
    </QueryClientProvider>
  )
}

function drawIpProject(over: Record<string, unknown> = {}) {
  const initialData = {
    ...MINIMAL_DEFAULTS, id: 'p1', name: 'Lab IPs', targetDomain: '', ipMode: true, targetIps: ['203.0.113.10'],
    engagementKind: 'internal', ...over,
  } as never
  render(
    <ProjectForm mode="edit" initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()}
      projectIdFromRoute="p1" />,
    { wrapper: providers },
  )
}

describe('Record + scan all cannot be saved unconfirmed (04_ui_spec.md §8)', () => {
  const save = () => screen.getByRole('button', { name: /Update Settings/ }) as HTMLButtonElement
  const cards = () => screen.getByRole('radiogroup', { name: 'Hostnames on target IPs' })

  test('picking it disables Save with the reason under it; confirming enables Save again', async () => {
    drawIpProject()
    fireEvent.click(await screen.findByTitle('Tab view'))
    fireEvent.click(within(cards()).getByRole('radio', { name: /Record \+ scan all/ }))
    expect(save().disabled).toBe(true)
    const reason = document.getElementById(save().getAttribute('aria-describedby')!)!
    // The same sentence the save routes and MCP refuse with (§8).
    const apiSentence = ipHostnamePolicyProblem({ ipMode: true, ipHostnameMode: 'scan_all', engagementKind: 'internal' })
    expect(apiSentence).toMatch(/scan_all needs ipHostnameScanAllConfirmed: true/)
    expect(reason.textContent).toBe(apiSentence)
    expect(save().title).toBe(apiSentence)
    fireEvent.click(screen.getByLabelText(/I confirm every site hosted on these IPs is in scope/))
    expect(save().disabled).toBe(false)
    expect(save().getAttribute('aria-describedby')).toBeNull()
  })

  test('any other mode saves as before', async () => {
    drawIpProject()
    fireEvent.click(await screen.findByTitle('Tab view'))
    fireEvent.click(within(cards()).getByRole('radio', { name: /Record hostnames/ }))
    expect(save().disabled).toBe(false)
    expect(screen.queryByText(/needs ipHostnameScanAllConfirmed/)).toBeNull()
  })
})

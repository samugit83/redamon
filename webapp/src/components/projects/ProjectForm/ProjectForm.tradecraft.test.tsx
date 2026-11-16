/**
 * The project form and Tradecraft (§3.4, T4.7): the tab is "Agent Skills & Tradecraft" when the
 * owner has 2.0 on; the switches travel in the form's own save (one save, one version, R-064) and a
 * save that changed them tells the chat's counter badge. The heavy hooks and sections are stubbed.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
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
const posted = vi.hoisted(() => [] as unknown[])
vi.mock('@/lib/tradecraft/channels', () => ({ postTradecraftCountsChanged: (c: unknown) => posted.push(c) }))
vi.mock('./sections/AttackSkillsSection', () => ({
  AttackSkillsSection: ({ data, updateField }: { data: { tradecraftOff?: string[] }; updateField: (k: string, v: unknown) => void }) => (
    <div>
      <pre data-testid="off">{JSON.stringify(data.tradecraftOff ?? null)}</pre>
      <button type="button" onClick={() => updateField('tradecraftOff', ['r1', 'r2'])}>turn-off</button>
    </div>
  ),
}))

import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

const h = vi.hoisted(() => ({ v2: true }))
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  window.history.replaceState({}, '', '/projects/p1/settings?tab=attack')
  h.v2 = true
  posted.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/projects/p1/tradecraft') return json(200, { v2: h.v2, viewerIsOwner: true, resources: [], counts: null })
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

function draw() {
  const onSubmit = vi.fn(async (data: Record<string, unknown>) => ({ ...data, updatedAt: '2026-11-16T12:00:00.000Z' }))
  const initialData = {
    ...MINIMAL_DEFAULTS, id: 'p1', name: 'ACME lab', targetDomain: 'acme-lab.test', tradecraftOff: ['r2'], updatedAt: '2026-11-16T10:00:00.000Z',
  } as never
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <AlertProvider>
          <ProjectForm mode="edit" initialData={initialData} onSubmit={onSubmit as never} onCancel={vi.fn()} projectIdFromRoute="p1" />
        </AlertProvider>
      </ToastProvider>
    </QueryClientProvider>,
  )
  return { onSubmit }
}

describe('ProjectForm and Tradecraft', () => {
  test('renders_in_tab: the tab is "Agent Skills & Tradecraft" while the owner has 2.0 on', async () => {
    draw()
    expect(await screen.findByRole('button', { name: 'Agent Skills & Tradecraft' })).toBeInTheDocument()
  })

  test('label_unchanged_when_v2_off: "Agent Skills"', async () => {
    h.v2 = false
    draw()
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(c => c[0] === '/api/projects/p1/tradecraft')).toBe(true))
    expect(screen.getByRole('button', { name: 'Agent Skills' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Agent Skills & Tradecraft' })).toBeNull()
  })

  test('saved_with_project_save: the switches go with Save, with the version; the badge is told', async () => {
    const { onSubmit } = draw()
    expect(JSON.parse(screen.getByTestId('off').textContent!)).toEqual(['r2'])
    fireEvent.click(screen.getByText('turn-off'))
    const update = screen.getByRole('button', { name: /Update Settings/ })
    await waitFor(() => expect(update).toBeEnabled())
    fireEvent.click(update)
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const sent = onSubmit.mock.calls[0][0] as Record<string, unknown>
    expect(sent.tradecraftOff).toEqual(['r1', 'r2'])
    expect(sent.updatedAt).toBe('2026-11-16T10:00:00.000Z')
    expect(posted).toEqual([{ projectId: 'p1' }])
  })
})

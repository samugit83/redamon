/**
 * The settings form's single-field auto-save and a collaborator's saves (step 5.2; SH-40, SH-28):
 *   - a workflow toggle's auto-save sends the row's `updatedAt` as the form last saw it; a stale save
 *     (409 `stale_save`) says "Someone else changed this project", reloads the row and takes it into
 *     the form (the refused field shows the server's value), and the next save carries its version;
 *   - a collaborator's form leaves the owner's secret columns (`share: secret`, which their read never
 *     carried) out of a preset save, so the save never reads as a change of the owner's secrets; the
 *     owner's save sends them as before.
 *
 * The real form; fetch, the dynamic views (a stub that exposes the workflow's auto-save) and the
 * project context are doubles.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
// Every dynamic view renders nothing, except the workflow view, which offers its auto-save.
vi.mock('next/dynamic', () => ({
  default: () => (props: { onAutoSaveField?: (field: string, value: unknown) => void }) =>
    props.onAutoSaveField
      ? <button type="button" onClick={() => props.onAutoSaveField!('naabuRateLimit', 25)}>auto-save-field</button>
      : null,
}))
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
import type { MyAccess } from '@/lib/authz/projectAccess'

const V1 = '2026-10-12T10:00:00.000Z'
const V2 = '2026-10-12T11:00:00.000Z'
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const h = vi.hoisted(() => ({
  calls: [] as Array<{ url: string; method: string; body?: Record<string, unknown> }>,
  stale: false,
}))

beforeEach(() => {
  window.history.replaceState({}, '', '/projects/p1/settings')
  h.calls = []
  h.stale = false
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    h.calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (url === '/api/presets/up1') return json(200, { settings: { naabuRateLimit: 50, httpxCustomHeaders: ['X-Preset: rbac-fake'] } })
    if (url === '/api/projects/defaults') return json(200, {})
    if (url === '/api/projects/p1' && method === 'PUT') {
      return h.stale
        ? json(409, { error: 'This project changed since you opened it.', code: 'stale_save' })
        : json(200, { id: 'p1', naabuRateLimit: 25, updatedAt: V2 })
    }
    if (url === '/api/projects/p1') return json(200, { id: 'p1', naabuRateLimit: 99, updatedAt: V2 })
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

function draw(myAccess?: MyAccess) {
  const initialData = {
    ...MINIMAL_DEFAULTS, id: 'p1', name: 'ACME lab', targetDomain: 'acme-lab.test', naabuRateLimit: 10, updatedAt: V1,
    ...(myAccess ? { myAccess } : {}),
  } as never
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <AlertProvider>
          <ProjectForm mode="edit" initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()} projectIdFromRoute="p1" />
        </AlertProvider>
      </ToastProvider>
    </QueryClientProvider>,
  )
}
const puts = () => h.calls.filter(c => c.method === 'PUT' && c.url === '/api/projects/p1')

describe('the auto-save of one field (step 5.2)', () => {
  test('sends the version the form loaded', async () => {
    draw()
    fireEvent.click(screen.getByText('auto-save-field'))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(puts()[0].body).toEqual({ naabuRateLimit: 25, updatedAt: V1 })
  })

  test('auto-save stale -> 409 and reload: the notice, the row read again, its version on the next save', async () => {
    h.stale = true
    draw()
    fireEvent.click(screen.getByText('auto-save-field'))
    expect(await screen.findByText(/Someone else changed this project/)).toBeInTheDocument()
    await waitFor(() => expect(h.calls.some(c => c.method === 'GET' && c.url === '/api/projects/p1')).toBe(true))
    h.stale = false
    fireEvent.click(screen.getByText('auto-save-field'))
    await waitFor(() => expect(puts()).toHaveLength(2))
    expect(puts()[1].body?.updatedAt).toBe(V2)
  })
})

describe("a collaborator's form leaves the owner's secrets out of its saves (step 5.2)", () => {
  const EDITOR: MyAccess = {
    level: 'write', via: 'share', owner: { name: 'Alice', email: 'alice@e2e.local' },
    toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false },
  }

  test.each([
    ['a collaborator', EDITOR, false],
    ['the owner', undefined, true],
  ] as Array<[string, MyAccess | undefined, boolean]>)('%s: the preset save sends the header list: %s', async (_who, access, sent) => {
    draw(access)
    fireEvent.click(screen.getByText('load-user-preset'))
    fireEvent.click(await screen.findByRole('button', { name: 'Replace and save' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    const body = puts()[0].body!
    expect(body.naabuRateLimit).toBe(50)
    expect('httpxCustomHeaders' in body).toBe(sent)
  })
})

/**
 * The new-project provider gate with instance LLM providers (step 6.11, GV-15): an account with no
 * provider of its own whose model list holds an instance provider's model (`instance/<id>/<model>`,
 * offered by an administrator through a set it holds) is not sent to "Configure an LLM provider
 * first"; without one the gate stays as before.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/ProjectForm.instanceProviders.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
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

function draw(mode: 'create' | 'edit') {
  const initialData = mode === 'edit'
    ? { ...MINIMAL_DEFAULTS, id: 'p1', name: 'ACME lab', targetDomain: 'acme-lab.test' } as never
    : undefined
  render(
    <ProjectForm mode={mode} initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()}
      projectIdFromRoute={mode === 'edit' ? 'p1' : undefined} />,
    { wrapper: providers },
  )
}

describe('create mode, no provider of its own', () => {
  test('an instance provider in the model list: no gate, the form opens', async () => {
    route = url => (url.endsWith('/llm-providers')
      ? json(200, [])
      : url === '/api/models' ? json(200, { 'Instance: Shared': [{ id: 'instance/inst-1/gpt-5', name: 'GPT-5' }] }) : null)
    draw('create')
    expect(await screen.findByText('Create New Project')).toBeTruthy()
    expect(screen.queryByText('Configure an LLM provider first')).toBeNull()
  })

  test('no instance provider either: the gate, as before', async () => {
    route = url => (url.endsWith('/llm-providers')
      ? json(200, [])
      : url === '/api/models' ? json(200, { 'Agent in the Loop': [{ id: 'loop/mcp', name: 'Agent in the Loop' }] }) : null)
    draw('create')
    expect(await screen.findByText('Configure an LLM provider first')).toBeTruthy()
  })

  test('a model list that cannot be read is no instance provider: the gate', async () => {
    route = url => (url.endsWith('/llm-providers') ? json(200, []) : url === '/api/models' ? json(503, { error: 'down' }) : null)
    draw('create')
    expect(await screen.findByText('Configure an LLM provider first')).toBeTruthy()
  })
})

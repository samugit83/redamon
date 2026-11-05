import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { useJevProvider } from '@/hooks/useHasJevProvider'
import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
vi.mock('next/dynamic', () => ({ default: () => WorkflowProbe }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'actor' }) }))
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

function WorkflowProbe({ formData, updateField }: {
  formData: Record<string, unknown>; updateField: (key: string, value: unknown) => void
}) {
  const { status, ownerUserId, selectedProviderId, lookupStatus } = useJevProvider()
  return <>
    <output data-testid="scope">{JSON.stringify({ status, ownerUserId, selectedProviderId, lookupStatus,
      formSelection: formData.jevProviderId, storedHook: formData.ffufAiUseJev })}</output>
    <button type="button" onClick={() => updateField('jevProviderId', 'direct')}>Select project Jev</button>
    <button type="button" onClick={() => updateField('jevProviderId', null)}>Clear project Jev</button>
  </>
}

const fetchMock = vi.fn()
const onSubmit = vi.fn().mockResolvedValue({})
const json = (value: unknown) => new Response(JSON.stringify(value))

beforeEach(() => {
  window.history.replaceState({}, '', '/')
  onSubmit.mockClear()
  fetchMock.mockReset().mockImplementation(async (url: string) => {
    if (url.endsWith('/llm-providers')) return json([
      { id: 'chat', providerType: 'openai', name: 'Synthetic chat', apiKey: 'masked', modelIdentifier: 'gpt-4o' },
      { id: 'direct', providerType: 'jev', name: 'Synthetic direct', apiKey: 'masked', modelIdentifier: 'jev-1.13.0' },
    ])
    if (url === '/api/projects/defaults') return json({ jevProviderId: 'must-not-inherit' })
    if (url.endsWith('/settings')) return json({})
    return json([])
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function draw(mode: 'create' | 'edit', overrides: Record<string, unknown> = {}) {
  render(<QueryClientProvider client={new QueryClient()}><ToastProvider><AlertProvider>
    <ProjectForm mode={mode} initialData={{ ...MINIMAL_DEFAULTS, id: 'project-1', name: 'Synthetic project',
      targetDomain: 'synthetic-project.test', agentOpenaiModel: 'claude-sonnet-4-5', aiPipelineModel: 'claude-sonnet-4-5',
      ffufAiUseJev: true, ...overrides } as never}
      onSubmit={onSubmit as never} onCancel={vi.fn()} projectIdFromRoute={mode === 'edit' ? 'project-1' : undefined} />
  </AlertProvider></ToastProvider></QueryClientProvider>)
}

function scope() { return JSON.parse(screen.getByTestId('scope').textContent!) }

describe('whole-project Jev form scope', () => {
  test('new/copied projects clear inherited provider IDs from initial data and server defaults', async () => {
    draw('create', { userId: 'old-owner', jevProviderId: 'copied-account-id' })
    await waitFor(() => expect(scope().status).toBe('no'))
    expect(scope()).toMatchObject({ ownerUserId: 'actor', selectedProviderId: null, formSelection: null, storedHook: true })
    fireEvent.click(screen.getByRole('button', { name: 'Select project Jev' }))
    expect(scope()).toMatchObject({ selectedProviderId: 'direct', formSelection: 'direct', status: 'yes' })
  })

  test('legacy null projects retain hook flags and can start scans; unsaved selection reaches workflow consumers', async () => {
    draw('edit', { userId: 'project-owner' })
    await waitFor(() => expect(scope().status).toBe('no'))
    expect(scope()).toMatchObject({ ownerUserId: 'project-owner', formSelection: null, storedHook: true })
    expect(screen.getByRole('button', { name: 'Start Recon Pipeline' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Select project Jev' }))
    expect(scope()).toMatchObject({ status: 'yes', formSelection: 'direct', selectedProviderId: 'direct', storedHook: true })
    fireEvent.click(screen.getByRole('button', { name: 'Clear project Jev' }))
    expect(scope()).toMatchObject({ status: 'no', formSelection: null, storedHook: true })
    expect(onSubmit).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledWith('/api/users/project-owner/llm-providers')
    expect(fetchMock).not.toHaveBeenCalledWith('/api/users/actor/llm-providers')
  })

  test('editing preserves explicit saved selection and submits a user-cleared null', async () => {
    draw('edit', { userId: 'project-owner', jevProviderId: 'direct' })
    await waitFor(() => expect(scope().status).toBe('yes'))
    fireEvent.click(screen.getByRole('button', { name: 'Clear project Jev' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Settings' }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalled())
    expect(onSubmit.mock.calls[0][0]).toMatchObject({ jevProviderId: null, ffufAiUseJev: true })
  })

  test('a shared legacy row with unknown owner stays limited rather than offering actor configs', () => {
    draw('edit', { jevProviderId: 'direct' })
    expect(scope()).toMatchObject({ status: 'error', lookupStatus: 'limited', ownerUserId: null, selectedProviderId: 'direct' })
    expect(fetchMock).not.toHaveBeenCalledWith('/api/users/actor/llm-providers')
    expect(screen.getByRole('button', { name: 'Start Recon Pipeline' })).toBeEnabled()
  })
})

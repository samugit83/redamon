/**
 * The Activity button in the settings header (step 4.13): the page hands the form the feed's address
 * only for whom the feed answers (page.test.tsx); the form shows the button in its header row, next to
 * Export, and leaves through the unsaved-changes guard like every other header exit, so a dirty form
 * asks before the edits are dropped.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/ProjectForm.activity.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'

const nav = vi.hoisted(() => ({ push: vi.fn() }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: nav.push, replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
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

import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

const FEED = '/projects/p1/activity'
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  nav.push.mockReset()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/llm-providers')) return json(200, [{ id: 'pr1', providerType: 'openai' }])
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider><AlertProvider>{children}</AlertProvider></ToastProvider>
    </QueryClientProvider>
  )
}

function draw(activityHref?: string) {
  const initialData = { ...MINIMAL_DEFAULTS, id: 'p1', userId: 'alice', name: 'ACME lab', targetDomain: 'acme-lab.test' } as never
  render(
    <ProjectForm mode="edit" initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()} projectIdFromRoute="p1" activityHref={activityHref} />,
    { wrapper: providers },
  )
}

const activityButton = () => screen.queryByRole('button', { name: 'Activity' })

describe('the Activity button', () => {
  test('sits in the header row beside Export, not in a bar of its own', () => {
    draw(FEED)
    const button = activityButton()
    expect(button).not.toBeNull()
    expect(button!.parentElement).toBe(screen.getByRole('button', { name: /Export/ }).parentElement)
  })

  test('is absent when the page gives the form no feed address', () => {
    draw(undefined)
    expect(activityButton()).toBeNull()
  })

  test('with nothing unsaved, opens the project activity', async () => {
    draw(FEED)
    fireEvent.click(activityButton()!)
    await waitFor(() => expect(nav.push).toHaveBeenCalledWith(FEED))
  })

  test('with unsaved edits, asks first: Cancel stays on the form, Confirm leaves', async () => {
    draw(FEED)
    fireEvent.click(screen.getByTitle('Tab view'))
    fireEvent.change(screen.getByPlaceholderText('My Security Project'), { target: { value: 'ACME lab renamed' } })

    fireEvent.click(activityButton()!)
    expect(await screen.findByText('Discard changes?')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByText('Discard changes?')).toBeNull())
    expect(nav.push).not.toHaveBeenCalled()

    fireEvent.click(activityButton()!)
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(nav.push).toHaveBeenCalledWith(FEED))
  })
})

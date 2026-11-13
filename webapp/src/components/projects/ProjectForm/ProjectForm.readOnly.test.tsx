/**
 * Project settings opened by a read collaborator (step 4.11, UI-05, P4-03; secrets are withheld by
 * the project GET, step 4.1): every setting is shown and none can be changed. The sections sit in a
 * disabled fieldset (every input, select and toggle in them), Update Settings, Load Preset, the Recon
 * Preset tab and Export are disabled with "Read access, shared by <owner>", and a notice says so. The
 * view switches stay usable. The owner's form, and the form with RBAC_SHARING_ENABLED off (the read
 * carries no `myAccess`), are unchanged.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/ProjectForm.readOnly.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'
import type { MyAccess } from '@/lib/authz/projectAccess'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
vi.mock('next/dynamic', () => ({ default: () => () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'bob' }) }))
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

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  fetchMock = vi.fn(async (url: string) => {
    if (url.endsWith('/llm-providers')) return json(200, [{ id: 'pr1', providerType: 'openai' }])
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  })
  vi.stubGlobal('fetch', fetchMock)
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

const onSubmit = vi.fn()

function draw(myAccess: MyAccess | undefined) {
  const initialData = {
    ...MINIMAL_DEFAULTS, id: 'p1', userId: 'alice', name: 'ACME lab', targetDomain: 'acme-lab.test',
    ...(myAccess ? { myAccess } : {}),
  } as never
  render(
    <ProjectForm mode="edit" initialData={initialData} onSubmit={onSubmit as never} onCancel={vi.fn()} projectIdFromRoute="p1" />,
    { wrapper: providers },
  )
  // The tab view renders the sections (the Workflow view is a lazily loaded canvas).
  fireEvent.click(screen.getByTitle('Tab view'))
}

const button = (label: string) => screen.getAllByRole('button').find(b => b.textContent?.trim() === label) as HTMLButtonElement

describe('ProjectForm at read', () => {
  test('controls disabled with the reason at read: saves, presets, export and every section control', () => {
    draw(READ)
    expect(screen.getByRole('status')).toHaveTextContent(`${NOTICE}.`)
    for (const label of ['Update Settings', 'Load Preset', 'Export']) {
      expect(button(label).disabled).toBe(true)
      expect(button(label).title).toBe(NOTICE)
    }
    const presetTab = button('Recon Preset')
    expect(presetTab.disabled).toBe(true)
    // The sections: every form control under the disabled fieldset.
    const fieldset = document.querySelector('fieldset[disabled]') as HTMLFieldSetElement
    expect(fieldset).not.toBeNull()
    const controls = fieldset.querySelectorAll('input, select, textarea, button')
    expect(controls.length).toBeGreaterThan(0)
    for (const c of Array.from(controls)) expect(c).toBeDisabled()
    // Reading stays: the view switches and the tabs.
    expect(screen.getByTitle('Workflow view')).not.toBeDisabled()
    expect(button('Port Scanning')).not.toBeDisabled()
    // Save as Preset copies the settings into the person's own presets: a read.
    expect(button('Save as Preset').disabled).toBe(false)
    fireEvent.submit(document.querySelector('form') as HTMLFormElement)
    expect(onSubmit).not.toHaveBeenCalled()
  })

  test('owner unchanged, and switch off (no myAccess) unchanged', () => {
    for (const access of [OWNS, undefined]) {
      draw(access)
      expect(screen.queryByRole('status')).toBeNull()
      expect(document.querySelector('fieldset[disabled]')).toBeNull()
      expect(button('Load Preset').disabled).toBe(false)
      expect(button('Export').disabled).toBe(false)
      expect(button('Recon Preset').disabled).toBe(false)
      cleanup()
    }
  })
})

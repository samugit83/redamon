/**
 * TrafficMind on a project shared with Raw data & files (step 4.11, UI-05): the collaborator reads and
 * exports the owner's traffic and deletes none (traffic:delete is `W`): both delete buttons are
 * disabled with "Read access, shared by <owner>". The owner's page is unchanged, and with
 * RBAC_SHARING_ENABLED off (no `myAccess`) nothing is refused here.
 *
 * Phase 6 step 6.7 adds a link to the Instance page beside the Settings button of this header
 * (app/traffic/page.tsx, after the delete buttons this test covers).
 *
 * Run: npx vitest run --no-file-parallelism src/app/traffic/page.readOnly.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'

const h = vi.hoisted(() => ({
  mutateAsync: vi.fn(),
  dangerConfirm: vi.fn(async () => true),
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ projectId: 'p1', userId: 'bob', currentProject: { name: 'P' }, isLoading: false }),
}))
vi.mock('@/components/traffic/TrafficCaptureStatus', () => ({ TrafficCaptureStatus: () => null }))
vi.mock('@/components/traffic/TrafficMindSettingsModal', () => ({ TrafficMindSettingsModal: () => null }))
vi.mock('@/components/ui', () => ({
  Drawer: ({ isOpen, children }: { isOpen: boolean; children: ReactNode }) => (isOpen ? <div>{children}</div> : null),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }),
  useAlertModal: () => ({ dangerConfirm: h.dangerConfirm }),
  WikiInfoButton: () => null,
}))
vi.mock('./hooks/useTrafficData', async () => {
  const actual = await vi.importActual<typeof import('./hooks/useTrafficData')>('./hooks/useTrafficData')
  const row = {
    id: 't1', startedAt: '2026-10-29T10:00:00Z', source: 'recon', runId: null, sessionId: null, tool: 'httpx',
    phase: null, method: 'GET', scheme: 'https', host: 'app.example.test', port: 443, path: '/', query: null,
    statusCode: 200, respBodySize: 10, respContentType: null, responseTimeMs: 5, isTls: true, isReplay: false,
    hasSetCookie: false, hadAuth: false, reflectedParams: false, blocked: false, inScope: true,
    iocIncidentId: null, iocIncidentUrl: null,
  }
  return {
    ...actual,
    useTrafficList: () => ({ data: { rows: [row], total: 1, page: 0, pageSize: 50 }, isLoading: false, isError: false, error: null }),
    useTrafficFacets: () => ({ data: { tools: [], hosts: [], runs: [], sessions: [] }, isError: false, error: null }),
    useTrafficDetail: () => ({ data: undefined, isLoading: false, isError: false, error: null }),
    useDeleteTraffic: () => ({ mutateAsync: h.mutateAsync }),
  }
})

import TrafficPage from './page'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ_RAW: MyAccess = { level: 'read', toggles: { rawData: true }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

beforeEach(() => vi.clearAllMocks())
afterEach(cleanup)

function page(access: MyAccess | null) {
  return render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <TrafficPage />
    </ProjectAccessContext.Provider>,
  )
}

const deleteAll = () => screen.getByText('Delete all matching') as HTMLButtonElement

describe('TrafficMind at read with Raw data & files', () => {
  test('controls disabled with the reason at read: delete all and delete selected, exports kept', () => {
    page(READ_RAW)
    expect(deleteAll().disabled).toBe(true)
    expect(deleteAll().title).toBe(NOTICE)
    fireEvent.click(document.querySelector('thead input[type="checkbox"]') as HTMLInputElement)
    const selected = screen.getByText('Delete selected (1)') as HTMLButtonElement
    expect(selected.disabled).toBe(true)
    expect(selected.title).toBe(NOTICE)
    fireEvent.click(deleteAll())
    expect(h.dangerConfirm).not.toHaveBeenCalled()
    expect(screen.getByText('Export CSV')).toBeTruthy()
  })

  test('owner unchanged, and switch off (no myAccess) unchanged', () => {
    page(OWNS)
    expect(deleteAll().disabled).toBe(false)
    expect(deleteAll().title).toBe('')
    cleanup()
    page(null)
    expect(deleteAll().disabled).toBe(false)
  })
})

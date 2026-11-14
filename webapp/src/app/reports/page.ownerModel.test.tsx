/**
 * Generating a report of a project the person does not own (P5-06, step 5.6): the route runs its
 * narratives on the project OWNER's "Report narratives" model, or skips them, so the page neither
 * asks for nor shows the person's own model there; it says the model is the owner's. The rule is
 * the one the project form and the graph page read the owner's catalog by (`readsOwnerCatalog`),
 * from the list row's `myAccess`. The owner's own project and the page with RBAC_SHARING_ENABLED
 * off (rows without `myAccess`) keep the person's own model line and gate, and nothing here asks
 * for the owner's catalog (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/reports/page.ownerModel.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, act } from '@testing-library/react'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const h = vi.hoisted(() => ({
  reports: {} as Record<string, unknown>,
  projects: [] as Array<Record<string, unknown>>,
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))

vi.mock('@/hooks/useReports', () => ({ useAllReports: () => h.reports }))
vi.mock('@/hooks/useProjects', () => ({ useProjects: () => ({ data: h.projects }) }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'bob' }) }))
vi.mock('@/components/ui', () => ({ useToast: () => h.toast, WikiInfoButton: () => null }))
vi.mock('@/components/shared/FeatureModelGate', () => ({
  FeatureModelLine: ({ featureId }: { featureId: string }) => <span data-testid="own-model-line">{featureId}</span>,
}))

import ReportsPage from './page'

const WRITE_TOGGLES = { rawData: false, runScans: false, useAgent: false, exploit: false, manage: false }
const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('{}', { status: 200 }))

beforeEach(() => {
  h.reports = {
    reports: [], isLoading: false, error: null,
    generate: vi.fn().mockResolvedValue({ id: 'r1', projectId: 'x', narrativesSkipped: 'use_agent_required' }),
    isGenerating: false, generateError: null,
    deleteReport: vi.fn(), deleteReportAsync: vi.fn(), isDeleting: false,
  }
  h.projects = [
    { id: 'p-own', name: 'Mine', myAccess: { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: 'bob@e2e.local' } } },
    { id: 'p-write', name: 'Shared', myAccess: { level: 'write', toggles: WRITE_TOGGLES, via: 'share', owner: OWNER } },
    { id: 'p-off', name: 'Before sharing' },
  ]
  fetchMock.mockClear()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function pick(projectId: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: projectId } })
}

async function generate() {
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Generate Report/ })) })
}

const ownerCatalogAsked = () => fetchMock.mock.calls.some(([url]) => String(url).includes('/owner-catalog'))

describe("reports page: the narratives model of a project the person does not own (P5-06)", () => {
  test("a Read + Write share: generated on the owner's model, the person's own model neither asked nor shown", async () => {
    render(<ReportsPage />)
    pick('p-write')
    expect(screen.queryByTestId('own-model-line')).toBeNull()
    expect(screen.getByText("Narratives model: the project owner's")).toBeTruthy()
    await generate()
    expect(h.reports.generate).toHaveBeenCalledWith('p-write', { ownerModel: true })
    expect(h.toast.warning).toHaveBeenCalledWith(expect.stringContaining('(use_agent_required)'))
  })

  test("the owner's own project is unchanged: the person's own model line and gate, no owner catalog asked (DV-30)", async () => {
    render(<ReportsPage />)
    pick('p-own')
    expect(screen.getByTestId('own-model-line')).toHaveTextContent('report_narratives')
    expect(screen.queryByText("Narratives model: the project owner's")).toBeNull()
    await generate()
    expect(h.reports.generate).toHaveBeenCalledWith('p-own', { ownerModel: false })
    expect(ownerCatalogAsked()).toBe(false)
  })

  test('switch off (a row without myAccess): the person\'s own model, as before', async () => {
    render(<ReportsPage />)
    pick('p-off')
    expect(screen.getByTestId('own-model-line')).toBeTruthy()
    await generate()
    expect(h.reports.generate).toHaveBeenCalledWith('p-off', { ownerModel: false })
    expect(ownerCatalogAsked()).toBe(false)
  })
})

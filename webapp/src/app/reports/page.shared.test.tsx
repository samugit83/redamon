/**
 * Reports of a project shared at Read (step 4.11, UI-05): the list spans projects, so each action
 * reads its own project's `myAccess` from GET /api/projects. A read collaborator downloads and opens
 * the owner's reports and neither generates nor deletes them ("Read access, shared by <owner>"); the
 * owner's rows are unchanged, and with RBAC_SHARING_ENABLED off (rows without `myAccess`) nothing
 * is refused here.
 *
 * Run: npx vitest run --no-file-parallelism src/app/reports/page.shared.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

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
vi.mock('@/components/shared/FeatureModelGate', () => ({ FeatureModelLine: () => null }))

import ReportsPage from './page'

const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'
const report = (id: string, projectId: string) => ({ id, projectId, title: `Report ${id}`, filename: 'r.html', fileSize: 10,
  format: 'html', metrics: {}, hasNarratives: false, createdAt: '2026-10-01T00:00:00Z' })

beforeEach(() => {
  h.reports = {
    reports: [report('r-own', 'p-own'), report('r-shared', 'p-shared')], isLoading: false, error: null,
    generate: vi.fn(), isGenerating: false, generateError: null,
    deleteReport: vi.fn(), deleteReportAsync: vi.fn().mockResolvedValue(undefined), isDeleting: false,
  }
  h.projects = [
    { id: 'p-own', name: 'Mine', myAccess: { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: 'bob@e2e.local' } } },
    { id: 'p-shared', name: 'Shared', myAccess: { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER } },
  ]
})
afterEach(() => cleanup())

const deleteButtons = () => screen.getAllByRole('button', { name: 'Delete report' }) as HTMLButtonElement[]

function pick(projectId: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: projectId } })
}

describe('reports page with a project shared at Read', () => {
  test('controls disabled with the reason at read: no Generate and no Delete on the shared project', () => {
    render(<ReportsPage />)
    const [own, shared] = deleteButtons()
    expect(shared.disabled).toBe(true)
    expect(shared.title).toBe(NOTICE)
    expect(own.disabled).toBe(false)
    pick('p-shared')
    const generate = screen.getByRole('button', { name: /Generate Report/ }) as HTMLButtonElement
    expect(generate.disabled).toBe(true)
    expect(generate.title).toBe(NOTICE)
    expect(screen.getByRole('note')).toHaveTextContent(`${NOTICE}: you can download and open this project's reports, not generate them.`)
    fireEvent.click(generate)
    expect(h.reports.generate).not.toHaveBeenCalled()
    // Downloading and opening stay.
    expect((screen.getAllByTitle('Download report')[1] as HTMLButtonElement).disabled).toBe(false)
  })

  test('owner unchanged: Generate and Delete on the owned project', () => {
    render(<ReportsPage />)
    pick('p-own')
    const generate = screen.getByRole('button', { name: /Generate Report/ }) as HTMLButtonElement
    expect(generate.disabled).toBe(false)
    expect(screen.queryByRole('note')).toBeNull()
    fireEvent.click(deleteButtons()[0])
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy()
  })

  test('switch off (rows without myAccess): nothing refused', () => {
    h.projects = [{ id: 'p-own', name: 'Mine' }, { id: 'p-shared', name: 'Shared' }]
    render(<ReportsPage />)
    expect(deleteButtons().every(b => !b.disabled)).toBe(true)
    pick('p-shared')
    expect((screen.getByRole('button', { name: /Generate Report/ }) as HTMLButtonElement).disabled).toBe(false)
  })
})

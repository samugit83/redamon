/**
 * The Priority Board on a project shared at Read (step 4.11, UI-05; step 4.8 opened the reads): the
 * collaborator reads the ranked findings, the decisions and the evidence, and changes nothing: the
 * row verdicts, Mute and the detail panel's decision are disabled with "Read access, shared by
 * <owner>", and no verdict or mute is posted. The owner's board is unchanged.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/Triage/TriageTable.readOnly.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: vi.fn(async () => true) }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), addToast: vi.fn() }),
  WikiInfoButton: () => null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'bob' }),
  useOptionalProject: () => ({ userId: 'bob' }),
}))
vi.mock('@/hooks/useCypherFixTriageWS', () => ({
  useCypherFixTriageWS: () => ({
    status: 'idle', currentPhase: null, progress: null, findings: [],
    error: null, thinking: '', startTriage: vi.fn(), stopTriage: vi.fn(), disconnect: vi.fn(),
  }),
}))
vi.mock('@/components/triage/TriageRunButton', () => ({ TriageRunButton: () => null, default: () => null }))
vi.mock('../CypherFixTab/TriageProgress/TriageProgress', () => ({ TriageProgress: () => null, PHASE_LABELS: {} }))

import { TriageTable } from './TriageTable'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

const ranked = {
  id: 'f1', label: 'Vulnerability', name: 'Missing header', severity: 'low',
  source: 'nuclei', section: 0, triage_state: 'open',
  triage_status: 'unreviewed', triage_confidence: null, triage_reason: null,
  triage_priority_score: 34.4, triage_tier: 'T3', triage_factors: null, triage_signals: [],
  triage_source: null, triage_ai_verdict: null, triage_run_id: 'run-1', triaged_at: '2026-09-12T00:00:00Z',
}

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn(async (url: string) => {
    const body = url.includes('/api/triage/finding?')
      ? { row: ranked, detector: null }
      : url.includes('/api/triage/evidence') ? { evidence: '', matches_last_run: true } : { findings: [ranked], total: 1 }
    return { ok: true, status: 200, json: async () => body }
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function board(access: MyAccess | null) {
  return render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <TriageTable projectId="p1" />
    </ProjectAccessContext.Provider>,
  )
}

const posted = () => fetchMock.mock.calls.some(([u, o]) => (o as RequestInit | undefined)?.method === 'POST' && String(u).includes('/api/triage/'))

describe('Priority Board at read', () => {
  test('controls disabled with the reason at read: Real, False, Mute; nothing posted', async () => {
    board(READ)
    await screen.findByText('Missing header')
    const real = screen.getAllByRole('button').find(b => b.textContent?.includes('Real')) as HTMLButtonElement
    const fp = screen.getAllByRole('button').find(b => b.textContent?.includes('False')) as HTMLButtonElement
    for (const b of [real, fp]) {
      expect(b.disabled).toBe(true)
      expect(b.title).toBe(NOTICE)
    }
    const mute = screen.getAllByTitle(NOTICE).find(b => b.textContent?.includes('Mute')) as HTMLButtonElement
    expect(mute.disabled).toBe(true)
    fireEvent.click(real)
    fireEvent.click(mute)
    expect(posted()).toBe(false)
  })

  test('the detail panel reads the decision and offers none', async () => {
    board(READ)
    fireEvent.click(await screen.findByText('Missing header'))
    const note = await screen.findByRole('note')
    expect(note).toHaveTextContent(`${NOTICE}.`)
    expect((screen.getByLabelText(/Reason \(optional\)/) as HTMLTextAreaElement).disabled).toBe(true)
  })

  test('owner unchanged', async () => {
    board(OWNS)
    await screen.findByText('Missing header')
    const real = screen.getAllByRole('button').find(b => b.textContent?.includes('Real')) as HTMLButtonElement
    expect(real.disabled).toBe(false)
    expect(real.title).toBe('Mark this real. It counts as 100% real and no run changes it.')
  })
})

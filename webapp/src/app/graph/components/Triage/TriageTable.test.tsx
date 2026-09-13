/**
 * Component test for the Priority Board's factor line (strategy row 10).
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/Triage/TriageTable.test.tsx
 *
 * One claim: the evidence behind each factor is reachable from the row. The
 * "real" factor now carries what the operator's own Real / False positive
 * clicks taught it, and a number that moved with no visible reason is one
 * nobody can disagree with.
 */

import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: vi.fn() }),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn() }),
  WikiInfoButton: () => null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'u1' }),
}))
vi.mock('@/hooks/useCypherFixTriageWS', () => ({
  useCypherFixTriageWS: () => ({
    status: 'idle', currentPhase: null, progress: null, findings: [],
    error: null, thinking: '', startTriage: vi.fn(), stopTriage: vi.fn(),
    disconnect: vi.fn(),
  }),
}))
vi.mock('@/components/triage/TriageRunButton', () => ({
  TriageRunButton: () => null,
  default: () => null,
}))
vi.mock('../CypherFixTab/TriageProgress/TriageProgress', () => ({
  TriageProgress: () => null,
  PHASE_LABELS: {},
}))

import { TriageTable } from './TriageTable'

const factors = {
  C: { value: 0.34, evidence: 'detected by nuclei; you judged 2 of 10 of these real' },
  L: { value: 0.5, evidence: 'the misconfiguration class prior' },
  I: { value: 0.45, evidence: 'severity medium' },
  R: { value: 0.8, evidence: 'no reachability evidence either way' },
}

const ranked = {
  id: 'f1', label: 'Vulnerability', name: 'Missing header', severity: 'low',
  source: 'nuclei', section: 0, triage_state: 'open',
  triage_status: 'unreviewed', triage_confidence: null, triage_reason: null,
  triage_priority_score: 34.4, triage_tier: 'T3',
  triage_factors: JSON.stringify(factors), triage_signals: [],
  triage_source: null, triage_ai_verdict: null, triage_run_id: 'run-1',
  triaged_at: '2026-09-12T00:00:00Z',
}

function ok(body: unknown) {
  return Promise.resolve({ ok: true, json: () => Promise.resolve(body) })
}

describe('TriageTable factor line', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) =>
      url.includes('/api/triage/muted')
        ? ok({ findings: [] })
        : ok({ findings: [ranked], total: 1 })))
  })
  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  test('the hover carries the reason the real factor moved', async () => {
    render(<TriageTable projectId="p1" />)
    const line = await screen.findByText(/real 34%/)
    expect(line.getAttribute('title')).toContain('you judged 2 of 10')
    // Every factor's evidence is there, not just C's.
    expect(line.getAttribute('title')).toContain('reach: no reachability evidence')
  })

  test('a row from an older run with no factors says so instead of inventing them', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string) =>
      url.includes('/api/triage/muted')
        ? ok({ findings: [] })
        : ok({ findings: [{ ...ranked, triage_factors: null }], total: 1 })))
    render(<TriageTable projectId="p1" />)
    expect(await screen.findByText('math only')).toBeInTheDocument()
  })
})

/**
 * Starting CodeFix asks for the user's CodeFix model first.
 *
 * CodeFix runs on the user's own model; without one the agent refuses the run
 * after the socket is up. So the gate runs BEFORE startFix, a cancelled gate
 * starts nothing, and an agent that still answers model_required (the model
 * was cleared elsewhere after the check) offers the picker again.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const gateSpies = vi.hoisted(() => ({ ensureFeatureModel: vi.fn() }))
const codefix = vi.hoisted(() => ({
  state: {} as Record<string, unknown>,
  startFix: vi.fn(),
}))

vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => gateSpies,
}))
vi.mock('@/hooks/useCypherFixCodeFixWS', () => ({
  useCypherFixCodeFixWS: () => codefix.state,
}))
vi.mock('./ActivityLog', () => ({ ActivityLog: () => null }))

import { DiffViewer } from './DiffViewer'
import type { Remediation } from '@/lib/cypherfix-types'

const REMEDIATION = { id: 'rem-1', title: 'Upgrade openssl' } as Remediation

function renderViewer() {
  return render(
    <DiffViewer remediation={REMEDIATION} projectId="p1" userId="u1" onBack={vi.fn()} onRefresh={vi.fn()} />,
  )
}

beforeEach(() => {
  gateSpies.ensureFeatureModel.mockReset()
  codefix.startFix.mockReset()
  codefix.state = {
    status: 'connected',
    diffBlocks: [],
    activityLog: [],
    error: null,
    errorCode: null,
    startFix: codefix.startFix,
    sendBlockDecision: vi.fn(),
    stopFix: vi.fn(),
  }
})

afterEach(cleanup)

describe('Start CodeFix', () => {
  test('the gate runs before startFix', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-opus-4-6')
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Start CodeFix' }))
    await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix')
    expect(gateSpies.ensureFeatureModel.mock.invocationCallOrder[0])
      .toBeLessThan(codefix.startFix.mock.invocationCallOrder[0])
  })

  test('cancelling the gate starts nothing', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Start CodeFix' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalled())
    await Promise.resolve()
    expect(codefix.startFix).not.toHaveBeenCalled()
  })

  test('Restart after a run goes through the gate too', async () => {
    codefix.state = { ...codefix.state, activityLog: [{ id: 1, type: 'complete', completionStatus: 'completed' }] }
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Restart CodeFix' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix'))
    expect(codefix.startFix).not.toHaveBeenCalled()
  })
})

describe('the agent answers model_required', () => {
  beforeEach(() => {
    codefix.state = {
      ...codefix.state,
      status: 'error',
      error: 'No CodeFix model is set',
      errorCode: 'model_required',
      activityLog: [{ id: 1, type: 'error', message: 'No CodeFix model is set' }],
    }
  })

  test('it offers the picker, forced open, then starts again', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue('claude-opus-4-6')
    renderViewer()
    expect(screen.getByText(/Choose a model for this feature first/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Choose a model and start' }))
    await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
    expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix', { force: true })
  })

  test('cancelling that picker starts nothing', async () => {
    gateSpies.ensureFeatureModel.mockResolvedValue(null)
    renderViewer()
    fireEvent.click(screen.getByRole('button', { name: 'Choose a model and start' }))
    await waitFor(() => expect(gateSpies.ensureFeatureModel).toHaveBeenCalled())
    await Promise.resolve()
    expect(codefix.startFix).not.toHaveBeenCalled()
  })

  test('any other agent error does not offer it', () => {
    codefix.state = { ...codefix.state, errorCode: null, error: 'boom' }
    renderViewer()
    expect(screen.queryByRole('button', { name: 'Choose a model and start' })).toBeNull()
  })
})

describe('a failure before the first event is shown (G-4)', () => {
  test('a refused ticket is rendered with Try again instead of a blank panel', async () => {
    codefix.state = {
      ...codefix.state, status: 'error', errorCode: null,
      error: 'CodeFix authentication failed (could not obtain a ticket): Not found (HTTP 404)',
    }
    gateSpies.ensureFeatureModel.mockResolvedValue('m')
    renderViewer()
    expect(screen.getByRole('alert')).toHaveTextContent('Not found (HTTP 404)')
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
  })

  test('an agent error already in the log is not shown twice', () => {
    const message = 'The repository could not be cloned. (clone_failed)'
    codefix.state = {
      ...codefix.state, status: 'error', errorCode: 'clone_failed', error: message,
      activityLog: [{ id: 'log-1', type: 'error', message, ts: 0 }],
    }
    renderViewer()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
  })

  test('model_required keeps its own picker, not the generic block', () => {
    codefix.state = { ...codefix.state, status: 'error', errorCode: 'model_required', error: 'x' }
    renderViewer()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Choose a model and start' })).toBeInTheDocument()
  })
})

describe('a push the agent refused (step 5.4 review)', () => {
  const unavailable = 'Nothing was pushed: RedAmon could not check that you may push to this project\'s repository. '
    + 'The changes are saved on the remediation; start the fix again in a moment. (decision_check_unavailable)'

  for (const status of ['error', 'completed'] as const) {
    test(`a check that did not answer offers to start the fix again (status ${status})`, async () => {
      codefix.state = {
        ...codefix.state, status, errorCode: 'decision_check_unavailable', error: unavailable,
        activityLog: [
          { id: 'log-1', type: 'error', message: unavailable, ts: 0 },
          ...(status === 'completed' ? [{ id: 'log-2', type: 'complete', completionStatus: 'error', ts: 0 }] : []),
        ],
      }
      gateSpies.ensureFeatureModel.mockResolvedValue('m')
      renderViewer()
      expect(screen.getByRole('alert')).toHaveTextContent(/could not confirm your permission to push this fix/)
      fireEvent.click(screen.getByRole('button', { name: 'Start the fix again' }))
      await waitFor(() => expect(codefix.startFix).toHaveBeenCalledWith('rem-1'))
      expect(gateSpies.ensureFeatureModel).toHaveBeenCalledWith('codefix')
    })
  }

  test('a refusal for the permission keeps the notice in the log and offers no retry', () => {
    const notice = 'Nothing was pushed: pushing the fix with the project\'s GitHub token needs Manage on this project.'
    codefix.state = {
      ...codefix.state, status: 'completed', errorCode: 'permission_required', error: notice,
      activityLog: [{ id: 'log-1', type: 'error', message: notice, ts: 0 },
        { id: 'log-2', type: 'complete', completionStatus: 'error', ts: 0 }],
    }
    renderViewer()
    expect(screen.queryByRole('button', { name: 'Start the fix again' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
  })

  test('a push the check admitted shows nothing extra (DV-30)', () => {
    codefix.state = {
      ...codefix.state, status: 'completed', errorCode: null, error: null,
      activityLog: [{ id: 'log-1', type: 'complete', completionStatus: 'pr_created', ts: 0 }],
    }
    renderViewer()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Start the fix again' })).toBeNull()
  })
})

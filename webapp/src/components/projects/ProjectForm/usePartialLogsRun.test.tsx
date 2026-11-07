/**
 * The Project Settings partial-recon logs drawer shows the orchestrator's run,
 * and closes when the orchestrator drops it 60 s after it ends. The start reply
 * (status `running`) used to stay as the fallback, so once the finished run was
 * dropped the drawer went back to "Scanning: …" and never closed.
 */
import { describe, test, expect, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import type { PartialReconState, PartialReconStatus } from '@/lib/recon-types'
import { usePartialLogsRun } from './usePartialLogsRun'

afterEach(cleanup)

const run = (status: PartialReconStatus, run_id = 'r1'): PartialReconState =>
  ({ project_id: 'p1', run_id, tool_id: 'Httpx', status } as PartialReconState)

function setup() {
  return renderHook(({ runs }) => usePartialLogsRun(runs), {
    initialProps: { runs: [] as PartialReconState[] },
  })
}

describe('usePartialLogsRun', () => {
  test('a run just started shows its start reply until a poll lists it', () => {
    const { result } = setup()
    act(() => result.current.showStarted(run('running')))
    expect(result.current.runId).toBe('r1')
    expect(result.current.run?.status).toBe('running')
  })

  test('the listed run wins over the start reply', () => {
    const { result, rerender } = setup()
    act(() => result.current.showStarted(run('running')))
    rerender({ runs: [run('completed')] })
    expect(result.current.run?.status).toBe('completed')
  })

  test('a finished run the orchestrator dropped closes the drawer', () => {
    const { result, rerender } = setup()
    act(() => result.current.showStarted(run('running')))
    rerender({ runs: [run('running')] })
    rerender({ runs: [run('completed')] })
    expect(result.current.run?.status).toBe('completed')
    rerender({ runs: [] })
    expect(result.current.run).toBeNull()
  })

  test('a run opened from its badge closes once dropped', () => {
    const { result, rerender } = setup()
    rerender({ runs: [run('error', 'r2')] })
    act(() => result.current.setRunId('r2'))
    expect(result.current.run?.status).toBe('error')
    rerender({ runs: [] })
    expect(result.current.run).toBeNull()
  })

  test("another run's start reply never stands in for the open one", () => {
    const { result, rerender } = setup()
    act(() => result.current.showStarted(run('running', 'r1')))
    rerender({ runs: [run('running', 'r2')] })
    act(() => result.current.setRunId('r2'))
    rerender({ runs: [] })
    expect(result.current.run).toBeNull()
  })
})

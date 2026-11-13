/**
 * Scan Timeline — Scan Scheduler table (Section 7.1).
 *
 * Beyond rendering: a failing load must not turn into a request storm. The
 * component loads inside an effect, and the alert helpers it used to depend on
 * change identity every time an alert opens — so reporting a load failure through
 * one of them re-triggered the load, which failed again, forever.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const alertError = vi.fn()
const dangerConfirm = vi.fn()
const toastInfo = vi.fn()

// The REAL AlertProvider rebuilds `alert*` with useCallback([current]), so their
// identity changes every time an alert opens or closes. Reproduce that worst case
// here (fresh function identities on every render) so a component that feeds an
// alert helper back into an effect's dependency list shows up as a request storm.
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({
    alertError: (...a: unknown[]) => alertError(...a),
    dangerConfirm: (...a: unknown[]) => dangerConfirm(...a),
  }),
  useToast: () => ({ info: (...a: unknown[]) => toastInfo(...a) }),
  WikiInfoButton: ({ target, title }: { target: string; title?: string }) =>
    <a href={`#${target}`} aria-label={title}>wiki</a>,
}))

import { ScanScheduleTable } from './ScanScheduleTable'

const SCHEDULE = {
  id: 's1', label: 'nightly', mode: 'cron' as const, runAt: null, intervalMinutes: null,
  cronExpr: '0 3 * * *', scanMode: 'new' as const, enabled: true,
  nextRunAt: '2026-08-01T03:00:00.000Z', lastRunAt: null,
}
const JOB = {
  id: 'j1', kind: 'full_recon', trigger: 'scheduled' as const, mode: 'new' as const, status: 'deferred_ram',
  startedAt: null, finishedAt: null, createdAt: '2026-07-30T03:00:00.000Z',
  nodeCount: null, ramReason: 'graph busy: a version activation is in progress',
}

let fetchMock: ReturnType<typeof vi.fn>
const ok = (body: unknown) => ({ ok: true, json: async () => body })
const fail = (status: number, body: unknown) => ({ ok: false, status, json: async () => body })

/** GETs of the schedules endpoint only: the embedded Scan queue panel polls
 *  /api/system/jobs on its own, and that is not this component's load. */
const scheduleGets = () => fetchMock.mock.calls.filter(
  c => String(c[1]?.method ?? 'GET') === 'GET' && String(c[0]).includes('/schedules')
)

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn().mockResolvedValue(ok({ schedules: [SCHEDULE], jobs: [JOB] }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ScanScheduleTable', () => {
  test('lists schedules and run history, including why a run did not happen', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    expect(screen.getByText(/cron 0 3 \* \* \* \(UTC\)/)).toBeTruthy()
    expect(screen.getByText('deferred_ram')).toBeTruthy()
    expect(screen.getByText(/graph busy/)).toBeTruthy()
  })

  // On a shared project the reader is not always who set a schedule up or started a run (SH-24).
  test('names who created each schedule and who started each run, where the row records it', async () => {
    fetchMock.mockResolvedValue(ok({
      schedules: [{ ...SCHEDULE, createdBy: { name: 'Alice Owner', email: 'alice@e2e.local' } }],
      jobs: [
        { ...JOB, startedBy: { name: '', email: 'carol@e2e.local' } },
        { ...JOB, id: 'j2', startedBy: null },
      ],
    }))
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Alice Owner')).toBeTruthy())
    expect(screen.getByRole('columnheader', { name: 'Created by' })).toBeTruthy()
    expect(screen.getByRole('columnheader', { name: 'Started by' })).toBeTruthy()
    expect(screen.getByText('Alice Owner').getAttribute('title')).toBe('alice@e2e.local')
    expect(screen.getByText('carol@e2e.local')).toBeTruthy()
  })

  // Run history now mixes ScanJobs (every kind) with finished queue jobs, so the
  // row has to say which kind it was.
  test('run history names the scan type of each row', async () => {
    fetchMock.mockResolvedValue(ok({
      schedules: [],
      jobs: [JOB, { ...JOB, id: 'q1', kind: 'trufflehog', status: 'failed' }],
    }))
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Secret Multiscanner')).toBeTruthy())
    expect(screen.getByText('Full recon')).toBeTruthy()
  })

  // Order on the page: what will run, what is running, what already ran.
  test('sections read Scheduled scans, then Scan queue, then Run history', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    // The mocked WikiInfoButton renders inside the first heading, so match a prefix.
    const headings = Array.from(document.querySelectorAll('h3')).map(h => h.textContent?.trim())
    expect(headings).toHaveLength(3)
    expect(headings[0]).toMatch(/^Scheduled scans/)
    expect(headings[1]).toBe('Scan queue')
    expect(headings[2]).toBe('Run history')
  })

  test('a failing load is reported ONCE, not retried in a loop', async () => {
    fetchMock.mockResolvedValue(fail(500, { error: 'schedules exploded' }))
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    // Give a runaway effect plenty of turns to pile requests up.
    for (let i = 0; i < 10; i++) await new Promise(r => setTimeout(r, 5))
    expect(scheduleGets()).toHaveLength(1)
    // The embedded queue panel gets the same failing answer, so the text shows twice.
    await waitFor(() => expect(screen.getAllByText('schedules exploded (HTTP 500)').length).toBeGreaterThan(0))
  })

  test('only one load happens per project on mount', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    for (let i = 0; i < 5; i++) await new Promise(r => setTimeout(r, 5))
    expect(scheduleGets()).toHaveLength(1)
  })

  test('toggling enabled PATCHes the schedule and reloads', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fireEvent.click(screen.getByTitle('Disable'))
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(c => c[1]?.method === 'PATCH')
      expect(patch).toBeTruthy()
      expect(String(patch![0])).toBe('/api/projects/p1/schedules/s1')
      expect(JSON.parse(patch![1].body)).toEqual({ enabled: false })
    })
  })

  // WEB-31: the paused-for-scope badge is computed live from the project's
  // saved scope, not from run history.
  describe('a saved scope the rules now refuse', () => {
    const route = (project: Record<string, unknown>, schedule = SCHEDULE) =>
      fetchMock.mockImplementation(async (url: string) =>
        String(url) === '/api/projects/p1' ? ok(project) : ok({ schedules: [schedule], jobs: [] }))
    const INVALID = {
      id: 'p1', ipMode: false, domainBatchMode: true, targetDomain: '', subdomainList: [],
      domainBatchHosts: ['*.com.vn', 'www.example.com'],
    }

    test('a paused schedule says why, names the entry, and cannot be re-enabled', async () => {
      route(INVALID, { ...SCHEDULE, enabled: false })
      render(<ScanScheduleTable projectId="p1" />)
      await waitFor(() => expect(screen.getByText(/paused: the saved scope is no longer valid/)).toBeTruthy())
      expect(screen.getByText(/\(\*\.com\.vn\)/)).toBeTruthy()
      expect(screen.getByText(/edit the target list and re-enable/)).toBeTruthy()
      const enable = screen.getByTitle('Fix the target list before enabling') as HTMLButtonElement
      expect(enable.disabled).toBe(true)
    })

    test('an enabled schedule warns that its next run will be refused', async () => {
      route(INVALID)
      render(<ScanScheduleTable projectId="p1" />)
      await waitFor(() => expect(screen.getByText(/next run will be refused/)).toBeTruthy())
    })

    test('a valid scope shows no badge', async () => {
      route({ ...INVALID, domainBatchHosts: ['www.example.com'] }, { ...SCHEDULE, enabled: false })
      render(<ScanScheduleTable projectId="p1" />)
      await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
      for (let i = 0; i < 3; i++) await new Promise(r => setTimeout(r, 5))
      expect(screen.queryByText(/no longer valid/)).toBeNull()
      expect((screen.getByTitle('Enable') as HTMLButtonElement).disabled).toBe(false)
    })
  })

  test('a rejected create surfaces the server reason (e.g. the RAM overlap check)', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fetchMock.mockResolvedValueOnce(fail(409, { error: 'not enough RAM in that window' }))
    fireEvent.click(screen.getByText('Add schedule'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'not enough RAM in that window (HTTP 409)', 'Schedule not created'
    ))
  })

  test('a create the network dropped is reported, not swallowed', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    fireEvent.click(screen.getByText('Add schedule'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Could not create the schedule (network_error)', 'Schedule not created'
    ))
  })

  test('a toggle answered by an empty 500 shows the status instead of nothing', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fetchMock.mockResolvedValueOnce({ ok: false, status: 500, text: async () => '' })
    fireEvent.click(screen.getByTitle('Disable'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Could not update the schedule (empty_response · HTTP 500)', 'Schedule'
    ))
  })

  test('a delete refused by the route shows its code', async () => {
    dangerConfirm.mockResolvedValue(true)
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fetchMock.mockResolvedValueOnce(fail(500, { error: 'Failed to delete the schedule', code: 'P2034' }))
    fireEvent.click(screen.getByTitle('Delete schedule'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Failed to delete the schedule (P2034 · HTTP 500)', 'Schedule'
    ))
  })

  test('deleting asks for a destructive confirm first', async () => {
    dangerConfirm.mockResolvedValue(false)
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('nightly')).toBeTruthy())
    fireEvent.click(screen.getByTitle('Delete schedule'))
    await waitFor(() => expect(dangerConfirm).toHaveBeenCalled())
    expect(fetchMock.mock.calls.find(c => c[1]?.method === 'DELETE')).toBeUndefined()
  })

  test('no "Delete selected" button until a run is checked', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('deferred_ram')).toBeTruthy())
    expect(screen.queryByText(/Delete selected/)).toBeNull()
  })

  test('select-all checks every run and reveals the delete button', async () => {
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('deferred_ram')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Select all runs'))
    expect(screen.getByText(/Delete selected \(1\)/)).toBeTruthy()
  })

  test('deleting selected runs posts the ids to the history endpoint', async () => {
    dangerConfirm.mockResolvedValue(true)
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('deferred_ram')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Select run j1'))
    fetchMock.mockResolvedValueOnce(ok({ ok: true, deleted: 1 }))
    fireEvent.click(screen.getByText(/Delete selected \(1\)/))
    await waitFor(() => {
      const del = fetchMock.mock.calls.find(c => c[1]?.method === 'DELETE')
      expect(del).toBeTruthy()
      expect(String(del![0])).toBe('/api/projects/p1/schedules/history')
      expect(JSON.parse(del![1].body as string).ids).toEqual(['j1'])
    })
    expect(toastInfo).toHaveBeenCalledWith('Deleted 1 run record')
  })

  test('a checked run is NOT deleted if the confirm is declined', async () => {
    dangerConfirm.mockResolvedValue(false)
    render(<ScanScheduleTable projectId="p1" />)
    await waitFor(() => expect(screen.getByText('deferred_ram')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Select run j1'))
    fireEvent.click(screen.getByText(/Delete selected \(1\)/))
    await waitFor(() => expect(dangerConfirm).toHaveBeenCalled())
    expect(fetchMock.mock.calls.find(c => c[1]?.method === 'DELETE')).toBeUndefined()
  })
})

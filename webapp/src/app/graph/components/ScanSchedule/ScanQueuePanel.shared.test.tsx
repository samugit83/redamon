/**
 * The scan queue on a project shared at Read, and the projects shared with the operator (step 4.11,
 * after 4.5's lists): a read collaborator sees the owner's queued jobs and can neither cancel nor
 * re-confirm them (the route asks recon:schedule, which a read share never reaches), and the jobs of
 * projects shared with the operator are counted apart from "Your other projects". With sharing off
 * the answer names no shared project and nothing changes (the owner's tests in ScanQueuePanel.test.tsx).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ScanSchedule/ScanQueuePanel.shared.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import { AlertProvider } from '@/components/ui'
import { ScanQueuePanel } from './ScanQueuePanel'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

const job = (over: Record<string, unknown>) => ({
  id: 'j1', projectId: 'p1', projectName: 'Proj One', kind: 'partial_recon', status: 'queued',
  blockedReason: '', error: '', enqueuedAt: '2026-08-09T21:00:00.000Z', startedAt: null, source: 'queue',
  ...over,
})

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mount(access: MyAccess | null, body: unknown) {
  fetchMock.mockResolvedValue({ ok: true, json: async () => body })
  render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <AlertProvider><ScanQueuePanel projectId="p1" /></AlertProvider>
    </ProjectAccessContext.Provider>,
  )
}

const activity = (over: Record<string, unknown> = {}) => ({
  mine: {
    running: [], recent: [],
    queued: [job({ id: 'q1' })],
    needsReview: [job({ id: 'q2', status: 'needs_review' })],
  },
  others: { queued: 0, running: 0, needsReview: 0 },
  ...over,
})

describe('ScanQueuePanel with sharing', () => {
  test('controls disabled with the reason at read: no Cancel, no Re-confirm, and nothing posted', async () => {
    mount(READ, activity({ sharedProjectIds: ['p1'] }))
    const cancel = await screen.findAllByRole('button', { name: 'Cancel' }) as HTMLButtonElement[]
    const reconfirm = screen.getByRole('button', { name: 'Re-confirm' }) as HTMLButtonElement
    for (const b of [...cancel, reconfirm]) {
      expect(b.disabled).toBe(true)
      expect(b.title).toBe(NOTICE)
    }
    fireEvent.click(cancel[0])
    fireEvent.click(reconfirm)
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('/api/job-queue/'))).toBe(false)
  })

  test('owner unchanged: Cancel works', async () => {
    mount(OWNS, activity())
    const cancel = (await screen.findAllByRole('button', { name: 'Cancel' }))[0] as HTMLButtonElement
    expect(cancel.disabled).toBe(false)
    expect(cancel.title).toBe('Cancel this queued job')
    fireEvent.click(cancel)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/job-queue/q2/cancel', { method: 'POST' }))
  })

  test('jobs of projects shared with the operator are counted apart from "Your other projects"', async () => {
    mount(OWNS, activity({
      mine: {
        running: [job({ id: 'r-own', projectId: 'p2', status: 'running', source: 'scan' }),
          job({ id: 'r-sh', projectId: 'p3', status: 'running', source: 'scan' })],
        queued: [job({ id: 'q-sh', projectId: 'p3' }), job({ id: 'q-sh2', projectId: 'p4' })],
        needsReview: [], recent: [],
      },
      sharedProjectIds: ['p3', 'p4'],
    }))
    expect(await screen.findByText(/Your other projects: 1 running, 0 queued\./)).toBeTruthy()
    expect(screen.getByText(/Projects shared with you: 1 running, 2 queued\./)).toBeTruthy()
  })

  test('switch off: no sharedProjectIds key, every other project is the operator\'s, as before', async () => {
    mount(null, activity({
      mine: { running: [], queued: [job({ id: 'q-other', projectId: 'p2' })], needsReview: [], recent: [] },
    }))
    expect(await screen.findByText(/Your other projects: 0 running, 1 queued\./)).toBeTruthy()
    expect(screen.queryByText(/shared with you/)).toBeNull()
  })
})

/**
 * The "<person> is running <kind> on this project" strip (step 5.11, SH-40): from GET
 * /api/projects/[id]/writers, while the open project's access is the owner's or a write share's.
 * With sharing off there is no `myAccess` and nothing is fetched (DV-30); a Read share starts
 * nothing and asks nothing; a failed read shows nothing; the list refreshes on the poll.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectWriters/ProjectWriters.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, act } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import type { OtherWritersView } from '@/lib/authz/projectWriters'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import { ProjectWriters, WRITERS_POLL_MS } from './ProjectWriters'

const OWNER = { name: 'Alice', email: 'alice@example.test' }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const WRITE: MyAccess = {
  level: 'write', toggles: { rawData: true, runScans: true, useAgent: true, exploit: false, manage: false }, via: 'share', owner: OWNER,
}
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }

const BOB_SCAN: OtherWritersView = {
  writers: [{ kind: 'partial_recon', phrase: 'a partial recon', person: { name: 'Bob', email: 'bob@example.test', accountType: 'member', deleted: false } }],
  unverified: false,
  startsRefused: true,
}

const fetchMock = vi.fn()
const answer = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: async () => body }) as unknown as Response

function within(access: MyAccess | null, projectId: string | null = 'p1') {
  return render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <ProjectWriters projectId={projectId} />
    </ProjectAccessContext.Provider>,
  )
}

async function flush() {
  await act(async () => { await Promise.resolve(); await Promise.resolve() })
}

beforeEach(() => {
  fetchMock.mockReset()
  fetchMock.mockResolvedValue(answer(BOB_SCAN))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ProjectWriters', () => {
  test('notice shown with the other writer: their identity, what they run, and that starts wait', async () => {
    within(OWNS)
    await flush()
    const strip = screen.getByTestId('project-writers')
    expect(strip.getAttribute('role')).toBe('status')
    expect(strip.textContent).toContain('is running a partial recon on this project.')
    expect(screen.getByTestId('identity-label').getAttribute('aria-label')).toBe('Bob, bob@example.test, Member')
    expect(strip.textContent).toContain('You can start a scan or an agent run here once they finish.')
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/p1/writers', { cache: 'no-store' })
  })

  test('a write share sees it too; the notice policy says they write alongside', async () => {
    fetchMock.mockResolvedValue(answer({ ...BOB_SCAN, startsRefused: false, unverified: true }))
    within(WRITE)
    await flush()
    const text = screen.getByTestId('project-writers').textContent
    expect(text).toContain('Your scans and agent runs write the same graph alongside theirs.')
    expect(text).toContain('Some writers could not be checked just now.')
  })

  test('a deleted account is named as one', async () => {
    fetchMock.mockResolvedValue(answer({
      ...BOB_SCAN,
      writers: [{ kind: 'agent', phrase: 'an agent session', person: { name: '', email: null, accountType: null, deleted: true } }],
    }))
    within(OWNS)
    await flush()
    expect(screen.getByTestId('project-writers').textContent).toContain('a deleted account is running an agent session on this project.')
  })

  test('sharing off (no myAccess) and a Read share: nothing fetched, nothing shown', async () => {
    within(null)
    within(READ)
    await flush()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.queryByTestId('project-writers')).toBeNull()
  })

  test('nobody else writing, a failed read, a refused one: nothing shown', async () => {
    for (const res of [answer({ writers: [], unverified: false, startsRefused: true }), answer({ error: 'x' }, false)]) {
      fetchMock.mockResolvedValueOnce(res)
      const view = within(OWNS)
      await flush()
      expect(screen.queryByTestId('project-writers')).toBeNull()
      view.unmount()
    }
    fetchMock.mockRejectedValueOnce(new TypeError('network'))
    within(OWNS)
    await flush()
    expect(screen.queryByTestId('project-writers')).toBeNull()
  })

  test('the poll picks up a writer that started, and drops one that ended', async () => {
    vi.useFakeTimers()
    fetchMock.mockResolvedValueOnce(answer({ writers: [], unverified: false, startsRefused: true }))
    within(OWNS)
    await flush()
    expect(screen.queryByTestId('project-writers')).toBeNull()
    fetchMock.mockResolvedValueOnce(answer(BOB_SCAN))
    await act(async () => { vi.advanceTimersByTime(WRITERS_POLL_MS) })
    await flush()
    expect(screen.getByTestId('project-writers')).toBeTruthy()
    fetchMock.mockResolvedValueOnce(answer({ writers: [], unverified: false, startsRefused: true }))
    await act(async () => { vi.advanceTimersByTime(WRITERS_POLL_MS) })
    await flush()
    expect(screen.queryByTestId('project-writers')).toBeNull()
  })

  test('another project than the open one: nothing asked', async () => {
    within(OWNS, 'p2')
    await flush()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

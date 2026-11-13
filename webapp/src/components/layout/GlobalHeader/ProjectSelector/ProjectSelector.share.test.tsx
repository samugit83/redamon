/**
 * The header's project picker offers the open project's share control (step 4.12; UI-07, SH-10):
 * Share on the person's own project (the dialog is ShareDialog.test.tsx's), Leave on a project shared
 * with them, which then asks the open project's access at once so the provider leads out; an owner
 * whose set lacks `project:share` sees Share refused up front. With sharing not in force neither
 * appears (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/GlobalHeader/ProjectSelector/ProjectSelector.share.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import type { MyAccess } from '@/lib/authz/projectAccess'

const h = vi.hoisted(() => ({
  sharing: undefined as undefined | null | { enabled: boolean; maxLevel: 'read' | 'write' },
  currentProject: null as null | { id: string; name: string; targetDomain: string; myAccess?: unknown },
  checkAccessNow: vi.fn(async () => {}),
  refetch: vi.fn(),
  dangerConfirm: vi.fn(async () => true),
}))

vi.mock('next/navigation', () => ({ usePathname: () => '/graph' }))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: vi.fn(), pushUnguarded: vi.fn() }),
  useNavigationGuard: () => null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ currentProject: h.currentProject, setCurrentProject: vi.fn(), userId: 'bob', checkAccessNow: h.checkAccessNow }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useOptionalAuth: () => ({ user: { id: 'bob', name: 'Bob', email: 'bob@example.test', role: 'standard', sharing: h.sharing } }),
}))
vi.mock('@/hooks/useProjects', () => ({ useProjects: () => ({ data: [], refetch: h.refetch }) }))
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError: vi.fn(), dangerConfirm: h.dangerConfirm }),
  useToast: () => ({ success: vi.fn() }),
}))
vi.mock('@/components/sharing/ShareDialog', () => ({
  ShareDialog: ({ project }: { project: { name: string } }) => <div role="dialog" aria-label={`Share "${project.name}"`} />,
}))

import { ProjectSelector } from './ProjectSelector'

const OWNER: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: { name: 'Bob', email: 'bob@example.test' } }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: 'alice@example.test' } }

function renderPicker(myAccess: MyAccess | undefined, capabilities: string[] = ['project:share']) {
  h.currentProject = { id: 'P1', name: 'Alpha recon', targetDomain: 'alpha.example.test', ...(myAccess ? { myAccess } : {}) }
  const auth = {
    user: null, isLoading: false, capabilities: new Set(capabilities), sessionError: null,
    flags: { identity: true, permissions: true, sharing: true, sharingWrite: false, governance: false },
  } as never
  render(
    <AuthContext.Provider value={auth}>
      <ProjectAccessContext.Provider value={{ projectId: 'P1', myAccess: myAccess ?? null }}>
        <ProjectSelector />
      </ProjectAccessContext.Provider>
    </AuthContext.Provider>,
  )
}

const fetchMock = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  h.sharing = { enabled: true, maxLevel: 'read' }
  h.dangerConfirm.mockResolvedValue(true)
  fetchMock.mockReset().mockResolvedValue(new Response(JSON.stringify({ left: { projectId: 'P1' }, socketsClosed: true }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('sharing in force', () => {
  test('the open project is mine: Share opens the dialog; no Leave', () => {
    renderPicker(OWNER)
    expect(screen.queryByRole('button', { name: 'Leave Alpha recon' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Share Alpha recon' }))
    expect(screen.getByRole('dialog', { name: 'Share "Alpha recon"' })).toBeInTheDocument()
  })

  test('leave: the open project is shared with me; after leaving its access is asked at once', async () => {
    renderPicker(READ)
    expect(screen.queryByRole('button', { name: 'Share Alpha recon' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Leave Alpha recon' }))
    await waitFor(() => expect(h.checkAccessNow).toHaveBeenCalledTimes(1))
    expect(h.dangerConfirm).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/P1/leave', expect.objectContaining({ method: 'POST' }))
    expect(h.refetch).toHaveBeenCalled()
  })

  test('an owner whose set lacks project:share: Share refused up front, the dialog never opens', () => {
    renderPicker(OWNER, [])
    const share = screen.getByRole('button', { name: 'Share Alpha recon' })
    expect(share).toHaveAttribute('aria-disabled', 'true')
    expect(share.getAttribute('title')).toMatch(/project:share/)
    fireEvent.click(share)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('a project read by oversight offers neither', () => {
    renderPicker({ ...READ, via: 'oversight' })
    expect(screen.queryByRole('button', { name: /^(Share|Leave) / })).toBeNull()
  })
})

describe('sharing not in force: neither (DV-30)', () => {
  test.each([
    ['the switch off (no myAccess on the project)', undefined, undefined],
    ['the policy disabled', { enabled: false, maxLevel: 'read' as const }, OWNER],
    ['the state unread', null, READ],
  ])('%s', (_what, sharing, access) => {
    h.sharing = sharing
    renderPicker(access)
    expect(screen.queryByRole('button', { name: /^(Share|Leave) / })).toBeNull()
    expect(screen.getByTitle('Project Settings')).toBeInTheDocument()
  })
})

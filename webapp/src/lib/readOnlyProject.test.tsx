/**
 * The read-only project mode and the stale-access poll (step 4.11; UI-02, UI-05, SH-11, PE-21).
 *
 * A read collaborator sees the owner's project with every control its route would refuse disabled,
 * titled "Read access, shared by <owner>"; a control refused by a missing permission keeps the
 * permission notice. The owner's screens are unchanged. ProjectProvider asks GET
 * /api/projects/[id]/my-access every 30 s while the open project's read carried `myAccess`: access
 * gone sends the person back to /projects with a notice, access narrowed re-renders read-only, a
 * failed answer backs off. With RBAC_SHARING_ENABLED off no read carries `myAccess`: nothing is asked
 * and nothing is refused by level (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/readOnlyProject.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { AuthContext } from '@/providers/authContext'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { PermissionId } from '@/lib/authz/permissions'
import { levelRefusalText, myAccessMeets, readAccessNotice, sameMyAccess } from './readOnlyProject'

const nav = vi.hoisted(() => ({
  search: new URLSearchParams('project=P1'),
  pathname: '/graph',
  replace: vi.fn(),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'bob' }, isLoading: false, refresh: async () => {} }),
}))
vi.mock('next/navigation', () => ({
  useSearchParams: () => nav.search,
  useRouter: () => ({ replace: nav.replace, push: vi.fn() }),
  usePathname: () => nav.pathname,
}))

import { ProjectProvider, useProject, ACCESS_POLL_MS } from '@/providers/ProjectProvider'
import { useCan } from '@/hooks/useCan'
import { useRefusal } from '@/hooks/useRefusal'
import { GraphToolbar } from '@/app/graph/components/GraphToolbar/GraphToolbar'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
const READ_RAW: MyAccess = { level: 'read', toggles: { rawData: true }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  nav.replace.mockClear()
  nav.pathname = '/graph'
  localStorage.clear()
})

describe('the level table and the words (lib/readOnlyProject)', () => {
  test('owner reaches every level; read reaches R, and R* only with Raw data & files', () => {
    for (const level of ['R', 'R*', 'W', 'W+S', 'W+A', 'W+X', 'M', 'O'] as const) {
      expect(myAccessMeets(OWNS, level)).toBe(true)
    }
    expect(myAccessMeets(READ, 'R')).toBe(true)
    expect(myAccessMeets(READ, 'R*')).toBe(false)
    expect(myAccessMeets(READ_RAW, 'R*')).toBe(true)
    for (const level of ['W', 'W+S', 'W+A', 'W+X', 'M', 'O'] as const) expect(myAccessMeets(READ_RAW, level)).toBe(false)
  })

  test('no myAccess (switch off) and an instance permission refuse nothing', () => {
    expect(myAccessMeets(null, 'O')).toBe(true)
    expect(myAccessMeets(undefined, 'W')).toBe(true)
    expect(levelRefusalText(null, 'recon:scan')).toBeNull()
    expect(levelRefusalText(READ, 'users:read')).toBeNull()
  })

  test('an unknown access kind fails closed', () => {
    expect(myAccessMeets({ ...READ, level: 'write' as never }, 'R')).toBe(false)
  })

  test('"Read access, shared by <owner>", naming raw data when the control needs it', () => {
    expect(levelRefusalText(READ, 'recon:scan')).toBe(NOTICE)
    expect(levelRefusalText(READ, 'traffic:read')).toBe('Read access without Raw data & files, shared by Alice (alice@e2e.local)')
    expect(levelRefusalText(READ_RAW, 'traffic:read')).toBeNull()
    expect(levelRefusalText(READ_RAW, 'traffic:delete')).toBe(NOTICE)
    expect(readAccessNotice({ ...READ, via: 'oversight' })).toBe('Read access through oversight; the project belongs to Alice (alice@e2e.local)')
    expect(readAccessNotice({ ...READ, owner: { name: null, email: 'a@x' } })).toBe('Read access, shared by a@x')
  })

  test('sameMyAccess compares what a screen shows', () => {
    expect(sameMyAccess(READ, { ...READ, owner: { ...OWNER } })).toBe(true)
    expect(sameMyAccess(READ, READ_RAW)).toBe(false)
    expect(sameMyAccess(READ, OWNS)).toBe(false)
    expect(sameMyAccess(null, undefined)).toBe(false)
    expect(sameMyAccess(null, null)).toBe(true)
  })
})

function Probe({ permission, projectId }: { permission: PermissionId; projectId?: string }) {
  const refusal = useRefusal(permission, projectId)
  const can = useCan(permission, projectId)
  return <span data-testid="probe">{`${refusal?.kind ?? 'none'}|${refusal?.text ?? ''}|${can}`}</span>
}

function probe(access: MyAccess | null, permission: PermissionId, opts: { held?: PermissionId[]; projectId?: string; scopeId?: string } = {}) {
  render(
    <AuthContext.Provider value={fakeAuth(FLAGS_ON, opts.held ?? [permission])}>
      <ProjectAccessContext.Provider value={{ projectId: opts.scopeId ?? 'P1', myAccess: access }}>
        <Probe permission={permission} projectId={opts.projectId} />
      </ProjectAccessContext.Provider>
    </AuthContext.Provider>,
  )
  const text = screen.getByTestId('probe').textContent ?? ''
  cleanup()
  return text
}

describe('useRefusal and useCan combine the level with the permission', () => {
  test('controls disabled with the reason at read: the level words, before the permission ones', () => {
    // A control on the open project (no id given) is refused by its level.
    expect(probe(READ, 'recon:scan').startsWith(`level|${NOTICE}|`)).toBe(true)
    expect(probe(READ, 'recon:scan', { projectId: 'P1' })).toBe(`level|${NOTICE}|false`)
    expect(probe(READ, 'recon:scan', { projectId: 'P1', held: [] })).toBe(`level|${NOTICE}|false`)
    expect(probe(READ, 'graph:read', { projectId: 'P1' })).toBe('none||true')
  })

  test('owner unchanged: only a missing permission refuses', () => {
    expect(probe(OWNS, 'recon:scan', { projectId: 'P1' })).toBe('none||true')
    expect(probe(OWNS, 'recon:scan', { projectId: 'P1', held: [] })).toBe(`permission|${forbiddenNoticeText('recon:scan')}|false`)
  })

  test('another project than the open one: no level is known, the route decides', () => {
    expect(probe(READ, 'recon:scan', { projectId: 'P2' })).toBe('none||true')
  })

  test('switch off (no myAccess): nothing refused by level', () => {
    expect(probe(null, 'recon:scan', { projectId: 'P1' })).toBe('none||true')
  })

  test('useCan without a project answers for the set alone (the shell sessions list spans projects)', () => {
    expect(probe(READ, 'agent:sessions').endsWith('|true')).toBe(true)
  })
})

describe('the graph toolbar at read', () => {
  function toolbar(access: MyAccess | null, recon: 'idle' | 'running' = 'idle') {
    return render(
      <AuthContext.Provider value={fakeAuth(FLAGS_ON, ['recon:scan', 'scan:gvm', 'recon:read'])}>
        <ProjectAccessContext.Provider value={{ projectId: 'P1', myAccess: access }}>
          <GraphToolbar
            projectId="P1" is3D={false} showLabels onToggle3D={() => {}} onToggleLabels={() => {}}
            hasReconData gvmAvailable reconStatus={recon} gvmStatus="idle"
            onStartRecon={vi.fn()} onStopRecon={vi.fn()} onPauseRecon={vi.fn()} onStartGvm={vi.fn()} onToggleAI={vi.fn()}
          />
        </ProjectAccessContext.Provider>
      </AuthContext.Provider>,
    )
  }
  const button = (label: string) => screen.getAllByRole('button').find(b => b.textContent?.includes(label)) as HTMLButtonElement

  test('controls disabled with the reason at read: start, and the owner\'s running scan\'s pause and stop', () => {
    toolbar(READ)
    expect(button('Start Recon Pipeline').disabled).toBe(true)
    expect(button('Start Recon Pipeline').title).toBe(NOTICE)
    expect(button('GVM Scan').title).toBe(NOTICE)
    cleanup()
    toolbar(READ, 'running')
    // Start (running), pause and stop of recon, and the GVM start: each disabled with the notice.
    const refused = screen.getAllByTitle(NOTICE).filter(b => b.tagName === 'BUTTON') as HTMLButtonElement[]
    expect(refused.length).toBe(4)
    expect(refused.every(b => b.disabled)).toBe(true)
    expect(screen.queryByTitle('Pause Recon')).toBeNull()
    expect(screen.queryByTitle('Stop Recon')).toBeNull()
    // The AI Agent button stays: its drawer says why.
    expect((screen.getByLabelText('Toggle AI Agent') as HTMLButtonElement).disabled).toBe(false)
  })

  test('owner unchanged', () => {
    toolbar(OWNS, 'running')
    expect(screen.getByTitle('Pause Recon')).toBeTruthy()
    expect((screen.getByTitle('Stop Recon') as HTMLButtonElement).disabled).toBe(false)
  })
})

// ---------------------------------------------------------------------------------------------
// The stale-access poll
// ---------------------------------------------------------------------------------------------

interface Server {
  /** What the project GET carries as myAccess; undefined = none (switch off); 'gone' = 404. */
  project: MyAccess | undefined | 'gone'
  /** /my-access: an access, or a status. */
  myAccess: MyAccess | number
  calls: string[]
}

function serve(server: Server) {
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    const u = String(url)
    server.calls.push(u)
    const json = (status: number, body: unknown) => ({
      ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body),
      headers: new Headers({ 'content-type': 'application/json' }), clone() { return this },
    }) as unknown as Response
    if (u === '/api/projects/P1/my-access') {
      return typeof server.myAccess === 'number' ? json(server.myAccess, { error: 'x' }) : json(200, { myAccess: server.myAccess })
    }
    if (u === '/api/projects/P1') {
      if (server.project === 'gone') return json(404, { error: 'Not found' })
      return json(200, { id: 'P1', name: 'Shared project', targetDomain: 'example.test',
        ...(server.project ? { myAccess: server.project } : {}) })
    }
    return json(404, { error: 'Not found' })
  }))
}

function PollProbe() {
  const { currentProject, accessNotice } = useProject()
  const refusal = useRefusal('traffic:read')
  return (
    <div>
      <span data-testid="project">{currentProject?.id ?? 'none'}</span>
      <span data-testid="raw">{String(currentProject?.myAccess?.toggles.rawData ?? 'absent')}</span>
      <span data-testid="traffic">{refusal?.text ?? 'allowed'}</span>
      <span data-testid="notice">{accessNotice ? `${accessNotice.kind}:${accessNotice.projectName}` : ''}</span>
    </div>
  )
}

async function flush(ms = 0) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms) })
}

async function mountProvider(server: Server) {
  serve(server)
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
  render(<ProjectProvider><PollProbe /></ProjectProvider>)
  for (let i = 0; i < 5; i++) await flush(0)
}

const myAccessCalls = (server: Server) => server.calls.filter(u => u.endsWith('/my-access')).length
const text = (id: string) => screen.getByTestId(id).textContent

describe('the stale-access poll', () => {
  beforeEach(() => localStorage.clear())

  test('poll kicks out on revoke (fake timers): back to /projects with a notice, the selection forgotten', async () => {
    const server: Server = { project: READ, myAccess: READ, calls: [] }
    await mountProvider(server)
    expect(text('project')).toBe('P1')
    expect(localStorage.getItem('redamon-current-project')).toBe('P1')
    expect(myAccessCalls(server)).toBe(0)

    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(1)
    expect(text('project')).toBe('P1')

    // Revoked: /my-access 404, and the project read confirms it.
    server.myAccess = 404
    server.project = 'gone'
    await flush(ACCESS_POLL_MS)
    expect(text('project')).toBe('none')
    expect(text('notice')).toBe('ended:Shared project')
    expect(nav.replace).toHaveBeenCalledWith('/projects')
    expect(localStorage.getItem('redamon-current-project')).toBeNull()

    // Nothing more is asked once the project is closed.
    const asked = myAccessCalls(server)
    await flush(ACCESS_POLL_MS * 4)
    expect(myAccessCalls(server)).toBe(asked)
  })

  test('already on /projects: the project closes and the page stays', async () => {
    nav.pathname = '/projects'
    const server: Server = { project: READ, myAccess: 404, calls: [] }
    await mountProvider(server)
    server.project = 'gone'
    await flush(ACCESS_POLL_MS)
    expect(text('project')).toBe('none')
    expect(nav.replace).not.toHaveBeenCalled()
  })

  test('poll downgrades to read-only: Raw data & files taken away re-renders the controls', async () => {
    const server: Server = { project: READ_RAW, myAccess: READ_RAW, calls: [] }
    await mountProvider(server)
    expect(text('traffic')).toBe('allowed')
    server.myAccess = READ
    await flush(ACCESS_POLL_MS)
    expect(text('raw')).toBe('false')
    expect(text('traffic')).toBe('Read access without Raw data & files, shared by Alice (alice@e2e.local)')
    expect(text('notice')).toBe('changed:Shared project')
    expect(nav.replace).not.toHaveBeenCalled()
  })

  test('switch off: no poll, owner unchanged', async () => {
    const server: Server = { project: undefined, myAccess: 404, calls: [] }
    await mountProvider(server)
    expect(text('project')).toBe('P1')
    expect(text('raw')).toBe('absent')
    expect(text('traffic')).toBe('allowed')
    await flush(ACCESS_POLL_MS * 10)
    expect(myAccessCalls(server)).toBe(0)
    expect(text('project')).toBe('P1')
    expect(nav.replace).not.toHaveBeenCalled()
  })

  test('a 404 while the project still reads without myAccess (the switch turned off) keeps the owner on the page', async () => {
    const server: Server = { project: OWNS, myAccess: OWNS, calls: [] }
    await mountProvider(server)
    server.myAccess = 404
    server.project = undefined
    await flush(ACCESS_POLL_MS)
    expect(text('project')).toBe('P1')
    expect(text('raw')).toBe('absent')
    expect(text('notice')).toBe('')
    expect(nav.replace).not.toHaveBeenCalled()
    const asked = myAccessCalls(server)
    await flush(ACCESS_POLL_MS * 4)
    expect(myAccessCalls(server)).toBe(asked)
  })

  test('a failed answer backs off (30 s, then 60 s, then 120 s) and an answer resets the wait', async () => {
    const server: Server = { project: READ, myAccess: 503, calls: [] }
    await mountProvider(server)
    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(1)
    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(1)
    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(2)
    await flush(ACCESS_POLL_MS * 3)
    expect(myAccessCalls(server)).toBe(2)
    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(3)
    // Nothing kicked out on a failure.
    expect(text('project')).toBe('P1')
    server.myAccess = READ
    await flush(ACCESS_POLL_MS * 8)
    expect(myAccessCalls(server)).toBe(4)
    await flush(ACCESS_POLL_MS)
    expect(myAccessCalls(server)).toBe(5)
  })

  test('a hidden tab asks nothing until it is shown again', async () => {
    const server: Server = { project: READ, myAccess: READ, calls: [] }
    await mountProvider(server)
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    await flush(ACCESS_POLL_MS * 3)
    expect(myAccessCalls(server)).toBe(0)
    visibility.mockReturnValue('visible')
    await act(async () => { fireEvent(document, new Event('visibilitychange')) })
    await flush(0)
    expect(myAccessCalls(server)).toBe(1)
    visibility.mockRestore()
  })
})

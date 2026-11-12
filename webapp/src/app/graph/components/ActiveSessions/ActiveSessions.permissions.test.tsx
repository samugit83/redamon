/**
 * The Active Sessions panel tells someone without agent:sessions why it is empty (UI-12), with the
 * standard ForbiddenNotice instead of the list or a 403 read as "Could not load sessions" (step 3.9:
 * the sessions API asks agent:sessions). With the permissions switch off, the panel is unchanged
 * whatever the set holds (DV-30); which sessions the list holds stays the server's rule (1.13).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ActiveSessions/ActiveSessions.permissions.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { RbacFlags } from '@/lib/authz/flags'
import type { PermissionId } from '@/lib/authz/permissions'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))
vi.mock('./SessionTerminal', async (orig) => ({
  ...(await orig<typeof import('./SessionTerminal')>()),
  SessionTerminal: () => null,
}))

import { ActiveSessions } from './ActiveSessions'

const FLAGS_OFF: RbacFlags = { sharedToolsCompat: false, identity: false, permissions: false, sharing: false, sharingWrite: false, governance: false }
const FLAGS_ON: RbacFlags = { ...FLAGS_OFF, identity: true, permissions: true }

function auth(flags: RbacFlags, held: PermissionId[]): AuthContextValue {
  return {
    user: { id: 'm1', name: 'Member', email: 'member@e2e.local', role: 'standard', flags },
    isLoading: false,
    capabilities: new Set(held),
    flags,
    sessionError: null,
    login: async () => ({}),
    logout: async () => {},
    refresh: async () => {},
  }
}

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const base = {
  jobs: [], nonMsfSessions: [], agentBusy: false, isLoading: false, projectId: 'p1',
  onInteract: vi.fn(), onKillSession: vi.fn(async () => {}), onKillJob: vi.fn(async () => {}),
}
const session = { id: 7, type: 'shell', info: '', tunnel_peer: '10.0.0.1:4444', target_host: '', via_exploit: '', chat_session_id: null } as never

function panel(value: AuthContextValue, props: Partial<Parameters<typeof ActiveSessions>[0]> = {}) {
  return render(
    <AuthContext.Provider value={value}>
      <ActiveSessions {...base} sessions={[]} {...props} />
    </AuthContext.Provider>,
  )
}

describe('Active Sessions panel and agent:sessions', () => {
  test('switch on, without agent:sessions: the ForbiddenNotice names it, no list and no empty state', () => {
    panel(auth(FLAGS_ON, ['agent:chat']))
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('You do not have the permission this needs.')
    expect(notice).toHaveTextContent('agent:sessions')
    expect(notice).toHaveTextContent('Ask an administrator')
    expect(screen.queryByText('No Reverse Shells')).toBeNull()
    expect(screen.queryByText('Could not load sessions')).toBeNull()
  })

  test('switch on, without agent:sessions: rows or an error from an earlier read are not shown either', () => {
    panel(auth(FLAGS_ON, []), { sessions: [session], error: 'Forbidden (forbidden · HTTP 403)' })
    expect(screen.getByRole('alert')).toHaveTextContent('agent:sessions')
    expect(screen.queryByText('Sessions')).toBeNull()
    expect(screen.queryByText(/Not refreshed/)).toBeNull()
  })

  test('switch on, with agent:sessions: the panel is as before', () => {
    panel(auth(FLAGS_ON, ['agent:sessions']))
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('switch off: the panel is as before whatever the set holds (DV-30)', () => {
    panel(auth(FLAGS_OFF, []), { error: 'Failed to fetch sessions (agent_unreachable · HTTP 503)' })
    expect(screen.getByText('Could not load sessions')).toBeInTheDocument()
    expect(screen.queryByText(/You do not have the permission/)).toBeNull()
  })
})

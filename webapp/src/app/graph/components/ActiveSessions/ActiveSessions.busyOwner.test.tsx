/**
 * Per-sandbox console busy flag and the every-session viewer's labels (gaps G-15, G-33).
 *
 * - Each sandbox runs its own console: the terminal warns that the agent is executing a command only
 *   when the selected row's own sandbox is in the answer's `busy` list, never for another sandbox.
 * - A holder of every session sees whose sandbox and which project a row is (the route adds
 *   `person_label` / `project_label` for them only); an owner's rows carry none and show none.
 *
 * Run: npx vitest run src/app/graph/components/ActiveSessions/ActiveSessions.busyOwner.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))
vi.mock('./SessionTerminal', async (orig) => ({
  ...(await orig<typeof import('./SessionTerminal')>()),
  SessionTerminal: (props: { sessionKey?: string | null; agentBusy: boolean; owner?: string | null }) => (
    <div data-testid="terminal">{`${props.sessionKey ?? 'none'} busy=${props.agentBusy} owner=${props.owner ?? '-'}`}</div>
  ),
}))

import { ActiveSessions, rowOwnerText } from './ActiveSessions'

const row = (sandbox: string, info: string, extra: Record<string, unknown> = {}) =>
  ({ id: 1, sandbox, type: 'shell', info, connection: '', target_ip: '', chat_session_id: null, ...extra })

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 404 })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function panel(over: Record<string, unknown> = {}) {
  return (
    <ActiveSessions
      sessions={[row('aaaaa1', 'box A'), row('bbbbb1', 'box B')] as never} jobs={[]} nonMsfSessions={[]}
      busyInstances={['bbbbb1']} isLoading={false} projectId="p1"
      onInteract={vi.fn() as never} onKillSession={vi.fn() as never} onKillJob={vi.fn() as never}
      {...over}
    />
  )
}

describe('the busy banner follows the selected row\'s own sandbox (G-15)', () => {
  test('busy only for the sandbox the answer names', () => {
    render(panel())
    fireEvent.click(screen.getByText('box A'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('aaaaa1:1 busy=false')
    fireEvent.click(screen.getByText('box B'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('bbbbb1:1 busy=true')
  })

  test('no row selected: never busy', () => {
    render(panel())
    expect(screen.getByTestId('terminal')).toHaveTextContent('none busy=false')
  })
})

describe('whose row it is, for a holder of every session (G-33)', () => {
  test('the card and the terminal header name the person and the project', () => {
    render(panel({
      sessions: [row('aaaaa1', 'box A', { person_label: 'Alice', project_label: 'Lab project' })],
      jobs: [{ id: 0, sandbox: 'aaaaa1', name: 'handler A', payload: '', port: 0, person_label: 'Alice (act-as)' }],
    }))
    const card = screen.getByText('box A').closest('[data-session-key]') as HTMLElement
    expect(within(card).getByTestId('row-person')).toHaveTextContent('Alice')
    expect(within(card).getByTestId('row-project')).toHaveTextContent('Lab project')
    const job = screen.getByText('handler A').closest('[data-session-key]') as HTMLElement
    expect(within(job).getByTestId('row-person')).toHaveTextContent('Alice (act-as)')
    fireEvent.click(screen.getByText('box A'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('owner=Alice · Lab project')
  })

  test('rows without labels (an owner\'s own) show none', () => {
    render(panel())
    expect(screen.queryByTestId('row-person')).toBeNull()
    expect(screen.queryByTestId('row-project')).toBeNull()
    fireEvent.click(screen.getByText('box A'))
    expect(screen.getByTestId('terminal')).toHaveTextContent('owner=-')
  })

  test('the header text joins what is known', () => {
    expect(rowOwnerText({ person_label: 'Alice', project_label: 'P' })).toBe('Alice · P')
    expect(rowOwnerText({ person_label: 'Alice' })).toBe('Alice')
    expect(rowOwnerText({})).toBeNull()
    expect(rowOwnerText(undefined)).toBeNull()
  })
})

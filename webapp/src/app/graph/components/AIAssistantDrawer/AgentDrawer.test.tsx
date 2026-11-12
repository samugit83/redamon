/**
 * E2E-P3-01's "agent drawer refused" (step 3.16b, PE-29, UI-12): the agent socket's ticket asks
 * `agent:chat` (ws-ticket route), so someone without it gets the drawer holding only the
 * ForbiddenNotice, and none of the chat is mounted: no ticket, conversation, key or model read is
 * asked. With the permissions switch off, while the session loads, or with no AuthProvider, the
 * chat is mounted as before (DV-30).
 *
 * The chat itself needs a page of providers; it is replaced here by a stub that records its props.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/AIAssistantDrawer/AgentDrawer.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AIAssistantDrawerProps } from './types'

const chat = vi.hoisted(() => ({ props: [] as unknown[] }))
vi.mock('./AIAssistantDrawer', () => ({
  AIAssistantDrawer: (props: unknown) => {
    chat.props.push(props)
    return <div data-testid="agent-chat" />
  },
}))

import { AgentDrawer } from './AgentDrawer'

afterEach(() => {
  cleanup()
  chat.props = []
  vi.clearAllMocks()
})

const onClose = vi.fn()
const props = { isOpen: true, onClose, userId: 'm1', projectId: 'p1', sessionId: 's1' } as AIAssistantDrawerProps

function drawer(value: AuthContextValue | null, over: Partial<AIAssistantDrawerProps> = {}) {
  return render(
    <AuthContext.Provider value={value}>
      <AgentDrawer {...props} {...over} />
    </AuthContext.Provider>,
  )
}

describe('AgentDrawer and agent:chat', () => {
  test('switch on, Read-only analyst: the drawer shows the notice and mounts no chat', () => {
    drawer(fakeAuth(FLAGS_ON, ['recon:read', 'graph:read', 'agent:assistants']))
    expect(screen.queryByTestId('agent-chat')).toBeNull()
    expect(chat.props).toHaveLength(0)
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('You do not have the permission this needs.')
    expect(notice).toHaveTextContent('agent:chat')
    expect(notice).toHaveTextContent('Ask an administrator to grant it to you.')
    expect(screen.getByRole('heading', { name: 'AI Agent' })).toBeTruthy()
  })

  test('the refused drawer closes like the chat, and is hidden while closed', () => {
    const { container, rerender } = drawer(fakeAuth(FLAGS_ON, []))
    fireEvent.click(screen.getByRole('button', { name: 'Close assistant' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    rerender(
      <AuthContext.Provider value={fakeAuth(FLAGS_ON, [])}>
        <AgentDrawer {...props} isOpen={false} />
      </AuthContext.Provider>,
    )
    expect((container.firstElementChild as HTMLElement).getAttribute('aria-hidden')).toBe('true')
  })

  test('switch on, with agent:chat: the chat is mounted with every prop, no notice', () => {
    drawer(fakeAuth(FLAGS_ON, ['agent:chat']), { modelName: 'm' })
    expect(screen.getByTestId('agent-chat')).toBeTruthy()
    expect(chat.props.at(-1)).toEqual({ ...props, modelName: 'm' })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('switch off, an empty set: the chat is mounted as before (DV-30)', () => {
    drawer(fakeAuth(FLAGS_OFF, []))
    expect(screen.getByTestId('agent-chat')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('while the session loads and with no provider: the chat is mounted as before', () => {
    drawer(fakeAuth(FLAGS_ON, [], { isLoading: true }))
    expect(screen.getByTestId('agent-chat')).toBeTruthy()
    cleanup()
    drawer(null)
    expect(screen.getByTestId('agent-chat')).toBeTruthy()
  })

  test('a set that loses agent:chat (an act-as switch) unmounts the chat', () => {
    const { rerender } = drawer(fakeAuth(FLAGS_ON, ['agent:chat']))
    expect(screen.getByTestId('agent-chat')).toBeTruthy()
    rerender(
      <AuthContext.Provider value={fakeAuth(FLAGS_ON, ['recon:read'])}>
        <AgentDrawer {...props} />
      </AuthContext.Provider>,
    )
    expect(screen.queryByTestId('agent-chat')).toBeNull()
    expect(screen.getByRole('alert')).toHaveTextContent('agent:chat')
  })
})

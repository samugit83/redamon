/**
 * The chat drawer during an Agent in the Loop run: the status word override,
 * the first-use notice with its two links, the chip, and the answered-via line.
 */
import React, { createRef } from 'react'
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ChatArea } from './ChatArea'
import { AgentStatusChips } from './AgentStatusChips'
import { ThinkingCard } from './ThinkingCard'
import { LOOP_FIRST_USE, LOOP_SETTINGS_URL, LOOP_WIKI_URL, loopDisplay } from './hooks/loopStatus'
import type { ThinkingItem } from './AgentTimeline'

afterEach(cleanup)

function renderChat(props: Partial<React.ComponentProps<typeof ChatArea>>) {
  return render(
    <ChatArea
      messagesContainerRef={createRef<HTMLDivElement>()}
      messagesEndRef={createRef<HTMLDivElement>()}
      checkIfAtBottom={() => true}
      chatItems={[]}
      groupedChatItems={[]}
      isLoading
      todoList={[]}
      statusWord="Pondering"
      isConnected
      setInputValue={() => {}}
      missingApiKeys={new Set()}
      openApiKeyModal={() => {}}
      handleTimelineToolConfirmation={() => {}}
      {...props}
    />,
  )
}

const waiting = (connected: boolean) => loopDisplay({
  state: 'thinking', detail: {}, openSteps: 1, sinceSeconds: 2,
  driver: { connected, lastSeenSeconds: connected ? 1 : null },
  step: { stepId: 'a'.repeat(32), state: 'open', purpose: 'think', iteration: 1 },
})

describe('ChatArea in a loop run', () => {
  test('the loop word replaces the rotating word', () => {
    renderChat({ loop: waiting(true) })
    expect(screen.getByText('Waiting for your agent…')).toBeInTheDocument()
    expect(screen.queryByText('Pondering')).toBeNull()
    expect(screen.queryByText(LOOP_FIRST_USE)).toBeNull()
  })

  test('no agent connected: the first-use notice links the guide and the settings', () => {
    renderChat({ loop: waiting(false) })
    expect(screen.getByText(LOOP_FIRST_USE)).toBeInTheDocument()
    const guide = screen.getByRole('link', { name: 'Set up Agent in the Loop' })
    expect(guide).toHaveAttribute('href', LOOP_WIKI_URL)
    expect(guide).toHaveAttribute('target', '_blank')
    expect(screen.getByRole('link', { name: 'Global Settings → MCP Server' }))
      .toHaveAttribute('href', LOOP_SETTINGS_URL)
  })

  test('a provider run keeps the rotating word', () => {
    renderChat({})
    expect(screen.getByText('Pondering')).toBeInTheDocument()
  })
})

describe('the chip and the attribution', () => {
  test('the Agent in the Loop chip appears only for a loop run', () => {
    const { rerender } = render(<AgentStatusChips latsActive={false} loopActive />)
    const chip = screen.getByText('Agent in the Loop')
    expect(chip.parentElement).toHaveAttribute('title', expect.stringMatching(/dangerous tools always ask you/))
    rerender(<AgentStatusChips latsActive={false} />)
    expect(screen.queryByText('Agent in the Loop')).toBeNull()
  })

  test('a thinking card says which token answered', () => {
    const item: ThinkingItem = {
      type: 'thinking', id: 't1', timestamp: new Date(), thought: 'scan ports', reasoning: 'r',
      action: 'thinking', updated_todo_list: [],
      answeredBy: { token_prefix: 'rdmn_mcp_ab12cd34', token_name: 'laptop' },
    }
    render(<ThinkingCard item={item} isExpanded onToggleExpand={() => {}} />)
    expect(screen.getByText('answered via laptop (rdmn_mcp_ab12cd34…)')).toBeInTheDocument()
  })
})

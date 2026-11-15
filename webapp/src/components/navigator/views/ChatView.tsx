'use client'

import { useEffect, useRef } from 'react'
import { MessageBubble } from '../MessageBubble'
import type { ChatMessage } from '../useNavigatorChat'
import styles from '../Navigator.module.css'

/**
 * The conversation. Only a finished answer is announced to screen readers (aria-live on the last
 * completed one), never each token.
 */
export function ChatView({ messages, onRetry, onOpenAgent, agentAllowed, empty }: {
  messages: readonly ChatMessage[]
  onRetry: (text: string) => void
  onOpenAgent: () => void
  agentAllowed: boolean
  empty: React.ReactNode
}) {
  const end = useRef<HTMLDivElement>(null)
  const last = messages.at(-1)
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: 'end' })
  }, [messages.length, last?.content.length])
  if (!messages.length) return <div className={styles.chat}>{empty}</div>
  const lastUser = [...messages].reverse().find((m) => m.role === 'user')
  return (
    <div className={styles.chat} data-testid="navigator-chat">
      {messages.map((m, i) => {
        const isLast = i === messages.length - 1
        const unanswered = m.role === 'user' && isLast && m.status === 'complete' && !m.id.startsWith('local-')
        return (
          <div key={m.id} aria-live={isLast && m.role === 'assistant' && m.status !== 'streaming' ? 'polite' : undefined}>
            <MessageBubble
              message={m}
              last={isLast}
              agentAllowed={agentAllowed}
              onOpenAgent={onOpenAgent}
              onRetry={lastUser ? () => onRetry(lastUser.content) : undefined}
            />
            {unanswered && (
              <p className={styles.muted}>
                No answer was saved.{' '}
                <button type="button" className={styles.linkButton} onClick={() => onRetry(m.content)}>Retry</button>
              </p>
            )}
          </div>
        )
      })}
      <div ref={end} />
    </div>
  )
}

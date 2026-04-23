'use client'

import { useCallback, useRef } from 'react'

export function useChatPersistence(conversationId: string | null) {
  const batchRef = useRef<Array<{ type: string; data: any }>>([])
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const flush = useCallback(async () => {
    if (!conversationId || batchRef.current.length === 0) return

    const messages = [...batchRef.current]
    batchRef.current = []

    try {
      await fetch(`/api/conversations/${conversationId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages }),
      })
    } catch (err) {
      // Non-critical — agent backend also persists
      console.warn('Chat persistence flush failed:', err)
    }
  }, [conversationId])

  const saveMessage = useCallback((type: string, data: any) => {
    if (!conversationId) return

    batchRef.current.push({ type, data })

    // Flush immediately for important messages, debounce for streaming items
    const immediate = ['user_message', 'assistant_message', 'error', 'approval_request', 'question_request', 'task_complete']
    if (immediate.includes(type)) {
      if (flushTimerRef.current) {
        clearTimeout(flushTimerRef.current)
        flushTimerRef.current = null
      }
      flush()
    } else {
      // Debounce streaming items (thinking, tool_start, tool_complete, plan_start, plan_complete, plan_analysis, deep_think) in 500ms windows
      if (!flushTimerRef.current) {
        flushTimerRef.current = setTimeout(() => {
          flushTimerRef.current = null
          flush()
        }, 500)
      }
    }
  }, [conversationId, flush])

  const updateConversation = useCallback(async (updates: Record<string, any>) => {
    if (!conversationId) return
    try {
      await fetch(`/api/conversations/${conversationId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
    } catch (err) {
      console.warn('Conversation update failed:', err)
    }
  }, [conversationId])

  return { saveMessage, updateConversation, flush }
}

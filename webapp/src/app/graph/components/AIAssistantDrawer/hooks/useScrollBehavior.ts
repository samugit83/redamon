import { useRef, useCallback, useEffect } from 'react'
import type { ChatItem } from '../types'

export function useScrollBehavior(chatItems: ChatItem[]) {
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const shouldAutoScroll = useRef(true)

  const scrollToBottom = useCallback((force = false) => {
    if (force || shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  const checkIfAtBottom = useCallback(() => {
    const container = messagesContainerRef.current
    if (!container) return true
    const threshold = 50
    const isAtBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < threshold
    shouldAutoScroll.current = isAtBottom
    return isAtBottom
  }, [])

  // Auto-scroll when chatItems change (only if user is at bottom)
  useEffect(() => {
    scrollToBottom()
  }, [chatItems, scrollToBottom])

  function resetScrollState() {
    shouldAutoScroll.current = true
  }

  return { messagesEndRef, messagesContainerRef, shouldAutoScroll, scrollToBottom, checkIfAtBottom, resetScrollState }
}

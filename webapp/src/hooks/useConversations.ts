'use client'

import { useState, useCallback, useRef } from 'react'

export interface Conversation {
  id: string
  sessionId: string
  title: string
  status: string
  agentRunning: boolean
  currentPhase: string
  iterationCount: number
  activeSkillId: string
  createdAt: string
  updatedAt: string
  _count?: { messages: number }
}

export interface ConversationWithMessages extends Conversation {
  messages: Array<{
    id: string
    sequenceNum: number
    type: string
    data: any
    createdAt: string
  }>
}

export function useConversations(projectId: string, userId: string) {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  const fetchConversations = useCallback(async () => {
    if (!projectId || !userId) return

    // Abort any in-flight request
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      setLoading(true)
      setError(null)
      const res = await fetch(
        `/api/conversations?projectId=${projectId}&userId=${userId}`,
        { signal: controller.signal }
      )
      if (!res.ok) throw new Error('Failed to fetch conversations')
      const data = await res.json()
      setConversations(data)
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }, [projectId, userId])

  const createConversation = useCallback(async (sessionId: string): Promise<Conversation | null> => {
    if (!projectId || !userId) return null

    try {
      const res = await fetch('/api/conversations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, userId, sessionId }),
      })
      if (!res.ok) throw new Error('Failed to create conversation')
      const conversation = await res.json()
      // Prepend to list
      setConversations(prev => [{ ...conversation, _count: { messages: 0 } }, ...prev])
      return conversation
    } catch (err: any) {
      setError(err.message)
      return null
    }
  }, [projectId, userId])

  const deleteConversation = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/conversations/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete conversation')
      setConversations(prev => prev.filter(c => c.id !== id))
    } catch (err: any) {
      setError(err.message)
    }
  }, [])

  const loadConversation = useCallback(async (id: string): Promise<ConversationWithMessages | null> => {
    try {
      const res = await fetch(`/api/conversations/${id}`)
      if (!res.ok) throw new Error('Failed to load conversation')
      return await res.json()
    } catch (err: any) {
      setError(err.message)
      return null
    }
  }, [])

  const updateConversation = useCallback(async (id: string, updates: Partial<Conversation>) => {
    try {
      const res = await fetch(`/api/conversations/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
      if (!res.ok) throw new Error('Failed to update conversation')
      const updated = await res.json()
      setConversations(prev => prev.map(c => c.id === id ? { ...c, ...updated } : c))
    } catch (err: any) {
      setError(err.message)
    }
  }, [])

  return {
    conversations,
    loading,
    error,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
    updateConversation,
  }
}

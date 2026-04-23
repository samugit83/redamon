/**
 * useAgentWebSocket Hook
 *
 * Custom React hook for managing WebSocket connection to the RedAmon agent backend.
 * Provides automatic reconnection, message handling, and type-safe communication.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import {
  MessageType,
  ConnectionStatus,
  type ServerMessage,
  type ClientMessage,
  type InitPayload,
  type QueryPayload,
  type ApprovalPayload,
  type AnswerPayload,
  isServerMessage,
} from '@/lib/websocket-types'

// =============================================================================
// HOOK CONFIGURATION
// =============================================================================

interface UseAgentWebSocketConfig {
  userId: string
  projectId: string
  sessionId: string
  graphViewCypher?: string
  enabled?: boolean
  onMessage?: (message: ServerMessage) => void
  onError?: (error: Error) => void
  onConnect?: () => void
  onDisconnect?: () => void
  maxReconnectAttempts?: number
  reconnectInterval?: number
}

interface UseAgentWebSocketReturn {
  status: ConnectionStatus
  isConnected: boolean
  reconnectAttempt: number
  error: Error | null
  sendQuery: (question: string) => void
  sendApproval: (decision: 'approve' | 'modify' | 'abort', modification?: string) => void
  sendToolConfirmation: (decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => void
  sendFireteamMemberConfirmation: (wave_id: string, member_id: string, decision: 'approve' | 'reject', modifications?: Record<string, any>) => void
  sendAnswer: (answer: string) => void
  sendGuidance: (message: string) => void
  sendSkillInject: (payload: { skill_id: string; skill_name: string; content: string }) => void
  sendStop: () => void
  sendResume: () => void
  sendToolStop: (tool_name: string, wave_id?: string, step_index?: number) => void
  disconnect: () => void
  reconnect: () => void
}

// =============================================================================
// WEBSOCKET HOOK
// =============================================================================

export function useAgentWebSocket({
  userId,
  projectId,
  sessionId,
  graphViewCypher,
  enabled = true,
  onMessage,
  onError,
  onConnect,
  onDisconnect,
  maxReconnectAttempts = 5,
  reconnectInterval = 3000,
}: UseAgentWebSocketConfig): UseAgentWebSocketReturn {
  const [status, setStatus] = useState<ConnectionStatus>(ConnectionStatus.DISCONNECTED)
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [error, setError] = useState<Error | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const isIntentionalDisconnect = useRef(false)
  const isAuthenticatedRef = useRef(false)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // Get WebSocket URL - auto-detect from browser location so it works on any machine
  const getWebSocketUrl = useCallback(() => {
    // 1. Explicit build-time env var (if set during next build)
    if (process.env.NEXT_PUBLIC_AGENT_WS_URL) {
      return process.env.NEXT_PUBLIC_AGENT_WS_URL
    }
    // 2. Auto-detect from current browser location
    // Agent runs on the same host as the webapp, mapped to port 8090
    if (typeof window !== 'undefined') {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.hostname
      return `${protocol}//${host}:8090/ws/agent`
    }
    // 3. Fallback for SSR
    return 'ws://localhost:8090/ws/agent'
  }, [])

  // Send a message to the server
  const sendMessage = useCallback(<T = any>(type: MessageType, payload: T) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      return
    }

    const message: ClientMessage<T> = { type, payload }
    const messageStr = JSON.stringify(message)

    wsRef.current.send(messageStr)
  }, [])

  // Send initialization message
  const sendInit = useCallback(() => {
    if (!wsRef.current || isAuthenticatedRef.current) return

    const initPayload: InitPayload = {
      user_id: userId,
      project_id: projectId,
      session_id: sessionId,
      ...(graphViewCypher && { graph_view_cypher: graphViewCypher }),
    }

    sendMessage(MessageType.INIT, initPayload)
  }, [userId, projectId, sessionId, graphViewCypher, sendMessage])

  // Public API: Send query
  const sendQuery = useCallback((question: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const queryPayload: QueryPayload = { question }
    sendMessage(MessageType.QUERY, queryPayload)
  }, [sendMessage])

  // Public API: Send approval
  const sendApproval = useCallback((decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const approvalPayload: ApprovalPayload = { decision, modification }
    sendMessage(MessageType.APPROVAL, approvalPayload)
  }, [sendMessage])

  // Public API: Send tool confirmation
  const sendToolConfirmation = useCallback((decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const payload: any = { decision }
    if (modifications) payload.modifications = modifications
    sendMessage(MessageType.TOOL_CONFIRMATION, payload)
  }, [sendMessage])

  // Public API: Send a single fireteam member's dangerous-tool decision.
  // Unlike sendToolConfirmation, this does NOT pause the parent graph —
  // other members keep running while this one resumes on approve/reject.
  const sendFireteamMemberConfirmation = useCallback((
    wave_id: string,
    member_id: string,
    decision: 'approve' | 'reject',
    modifications?: Record<string, any>,
  ) => {
    if (!isAuthenticatedRef.current) return
    const payload: any = { wave_id, member_id, decision }
    if (modifications) payload.modifications = modifications
    sendMessage(MessageType.FIRETEAM_MEMBER_CONFIRMATION, payload)
  }, [sendMessage])

  // Public API: Send answer
  const sendAnswer = useCallback((answer: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const answerPayload: AnswerPayload = { answer }
    sendMessage(MessageType.ANSWER, answerPayload)
  }, [sendMessage])

  // Public API: Send guidance (steer agent while it's working)
  const sendGuidance = useCallback((message: string) => {
    if (!isAuthenticatedRef.current) return
    sendMessage(MessageType.GUIDANCE, { message })
  }, [sendMessage])

  // Public API: Send skill injection (push Chat Skill content into guidance queue)
  const sendSkillInject = useCallback((payload: { skill_id: string; skill_name: string; content: string }) => {
    if (!isAuthenticatedRef.current) return
    sendMessage(MessageType.SKILL_INJECT, payload)
  }, [sendMessage])

  // Public API: Stop agent execution
  const sendStop = useCallback(() => {
    if (!isAuthenticatedRef.current) return
    sendMessage(MessageType.STOP, {})
  }, [sendMessage])

  // Public API: Resume agent execution from checkpoint
  const sendResume = useCallback(() => {
    if (!isAuthenticatedRef.current) return
    sendMessage(MessageType.RESUME, {})
  }, [sendMessage])

  // Public API: Stop a single tool (same semantics as the global Stop button
  // but scoped to one tool_execution card). Backend cancels just that tool
  // task; the tool completes with success=false and the agent flow proceeds.
  const sendToolStop = useCallback((tool_name: string, wave_id?: string, step_index?: number) => {
    if (!isAuthenticatedRef.current) return
    const payload: { tool_name: string; wave_id?: string; step_index?: number } = { tool_name }
    if (wave_id) payload.wave_id = wave_id
    if (step_index !== undefined && step_index !== null) payload.step_index = step_index
    sendMessage(MessageType.TOOL_STOP, payload)
  }, [sendMessage])

  // Start ping interval for keep-alive
  const startPingInterval = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
    }

    pingIntervalRef.current = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        sendMessage(MessageType.PING, {})
      }
    }, 30000) // Ping every 30 seconds
  }, [sendMessage])

  // Stop ping interval
  const stopPingInterval = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
  }, [])

  // Handle incoming messages
  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data)

      if (!isServerMessage(data)) {
        return
      }

      const message = data as ServerMessage


      // Handle CONNECTED message
      if (message.type === MessageType.CONNECTED) {
        isAuthenticatedRef.current = true
        setStatus(ConnectionStatus.CONNECTED)
        setReconnectAttempt(0)
        setError(null)
        startPingInterval()
        onConnect?.()
      }

      // Handle PONG message
      if (message.type === MessageType.PONG) {
        return // Don't forward pong to message handler
      }

      // Forward message to handler
      onMessage?.(message)

    } catch (err) {
    }
  }, [onMessage, onConnect, startPingInterval])

  // Handle WebSocket errors
  const handleError = useCallback((event: Event) => {
    const error = new Error('WebSocket error occurred')
    setError(error)
    onError?.(error)
  }, [onError])

  // Handle WebSocket close
  const handleClose = useCallback((event: CloseEvent) => {

    isAuthenticatedRef.current = false
    stopPingInterval()
    wsRef.current = null
    setStatus(ConnectionStatus.DISCONNECTED)
    onDisconnect?.()

    // Auto-reconnect if not intentional and enabled
    if (!isIntentionalDisconnect.current && enabled && reconnectAttempt < maxReconnectAttempts) {
      setStatus(ConnectionStatus.RECONNECTING)
      setReconnectAttempt(prev => prev + 1)

      reconnectTimeoutRef.current = setTimeout(() => {
        connect()
      }, reconnectInterval)
    } else if (reconnectAttempt >= maxReconnectAttempts) {
      setStatus(ConnectionStatus.FAILED)
      const maxRetriesError = new Error('Max reconnection attempts reached')
      setError(maxRetriesError)
      onError?.(maxRetriesError)
    }
  }, [enabled, reconnectAttempt, maxReconnectAttempts, reconnectInterval, stopPingInterval, onDisconnect, onError])

  // Connect to WebSocket
  const connect = useCallback(() => {
    // Close existing connection — detach handlers first to prevent
    // the old close event from clobbering the new connection
    if (wsRef.current) {
      wsRef.current.onopen = null
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }

    // Clear reconnect timeout
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    // Reset authentication state for new connection
    isAuthenticatedRef.current = false

    try {
      const wsUrl = getWebSocketUrl()

      setStatus(ConnectionStatus.CONNECTING)
      setError(null)

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        sendInit()
      }

      ws.onmessage = handleMessage
      ws.onerror = handleError
      ws.onclose = handleClose

    } catch (err) {
      const connectionError = err instanceof Error ? err : new Error('Failed to create WebSocket')
      setError(connectionError)
      setStatus(ConnectionStatus.FAILED)
      onError?.(connectionError)
    }
  }, [getWebSocketUrl, sendInit, handleMessage, handleError, handleClose, onError])

  // Public API: Disconnect
  const disconnect = useCallback(() => {
    isIntentionalDisconnect.current = true
    stopPingInterval()

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.onopen = null
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }

    isAuthenticatedRef.current = false
    setStatus(ConnectionStatus.DISCONNECTED)
    setReconnectAttempt(0)
  }, [stopPingInterval])

  // Public API: Reconnect
  const reconnect = useCallback(() => {
    isIntentionalDisconnect.current = false
    setReconnectAttempt(0)
    connect()
  }, [connect])

  // Connect when enabled
  useEffect(() => {
    if (enabled) {
      isIntentionalDisconnect.current = false
      connect()
    } else {
      disconnect()
    }

    // Cleanup on unmount
    return () => {
      isIntentionalDisconnect.current = true
      stopPingInterval()

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }

      if (wsRef.current) {
        wsRef.current.onopen = null
        wsRef.current.onmessage = null
        wsRef.current.onerror = null
        wsRef.current.onclose = null
        wsRef.current.close()
      }
    }
  }, [enabled, userId, projectId, sessionId, graphViewCypher]) // Reconnect if session or graph view changes

  return {
    status,
    isConnected: status === ConnectionStatus.CONNECTED,
    reconnectAttempt,
    error,
    sendQuery,
    sendApproval,
    sendToolConfirmation,
    sendFireteamMemberConfirmation,
    sendAnswer,
    sendGuidance,
    sendSkillInject,
    sendStop,
    sendResume,
    sendToolStop,
    disconnect,
    reconnect,
  }
}

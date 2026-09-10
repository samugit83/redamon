/**
 * useCypherFixTriageWS Hook
 *
 * WebSocket hook for the CypherFix triage agent.
 * Follows the same patterns as useAgentWebSocket.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { buildAgentWsUrl } from './agentWsUrl'
import {
  CypherFixTriageMessageType,
  type TriagePhase,
  type TriagePhasePayload,
  type TriageFindingPayload,
  type TriageCompletePayload,
} from '@/lib/cypherfix-types'

// =============================================================================
// TYPES
// =============================================================================

type TriageStatus = 'disconnected' | 'connecting' | 'connected' | 'running' | 'completed' | 'error'

interface TriageMessage {
  type: string
  payload?: Record<string, unknown>
}

interface UseCypherFixTriageWSConfig {
  userId: string
  projectId: string
  enabled?: boolean
  /**
   * Open the socket on mount instead of waiting for `startTriage`.
   *
   * A triage run outlives the tab that started it, but the server can only
   * re-attach a tab that actually connects. Without this the hook connected
   * ONLY from startTriage, so returning to the page after leaving mid-run
   * showed an idle screen over a run that was still going.
   *
   * Off by default so the CypherFix page keeps connecting lazily.
   */
  autoConnect?: boolean
  onPhase?: (payload: TriagePhasePayload) => void
  onFinding?: (payload: TriageFindingPayload) => void
  onComplete?: (payload: TriageCompletePayload) => void
  onError?: (message: string) => void
}

export interface UseCypherFixTriageWSReturn {
  status: TriageStatus
  currentPhase: TriagePhase | null
  progress: number
  findings: TriageFindingPayload[]
  thinking: string
  error: string | null
  startTriage: () => void
  stopTriage: () => void
  disconnect: () => void
}

// =============================================================================
// HOOK
// =============================================================================

export function useCypherFixTriageWS({
  userId,
  projectId,
  enabled = true,
  autoConnect = false,
  onPhase,
  onFinding,
  onComplete,
  onError,
}: UseCypherFixTriageWSConfig): UseCypherFixTriageWSReturn {
  const [status, setStatus] = useState<TriageStatus>('disconnected')
  const [currentPhase, setCurrentPhase] = useState<TriagePhase | null>(null)
  const [progress, setProgress] = useState(0)
  const [findings, setFindings] = useState<TriageFindingPayload[]>([])
  const [thinking, setThinking] = useState('')
  const [error, setError] = useState<string | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const isAuthenticatedRef = useRef(false)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const pendingStartRef = useRef(false)
  //: `${userId}:${projectId}` the live socket is bound to, so a project switch
  // can tell "already connected here" from "connected to a different project".
  const connectedIdRef = useRef<string | null>(null)
  // S4: connect() became async (it awaits a ws-ticket fetch) which opened a
  // double-fire window before wsRef is set. This synchronous sentinel prevents a
  // second concurrent connect() from opening an orphan socket whose later onclose
  // would null the live socket's ref and kill its keepalive.
  const connectingRef = useRef(false)

  // STRIDE S4: the agent handler requires a ws-ticket (query param); buildAgentWsUrl
  // appends it. Single-origin deploys reuse the agent WS origin and swap the path.
  const getWebSocketUrl = useCallback(
    (ticket?: string) => buildAgentWsUrl('/ws/cypherfix-triage', ticket),
    [],
  )

  const sendMessage = useCallback((type: string, payload: Record<string, unknown> = {}) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return
    wsRef.current.send(JSON.stringify({ type, payload }))
  }, [])

  const connect = useCallback(async () => {
    if (wsRef.current || connectingRef.current) return
    if (!enabled || !userId || !projectId) return
    connectingRef.current = true

    setStatus('connecting')
    setError(null)

    // STRIDE S4: mint a ws-ticket (effective user + project) before dialing;
    // the agent handler now fails closed without one.
    const sessionId = `triage-${Date.now()}`
    let ticket: string | null = null
    try {
      const resp = await fetch('/api/agent/ws-ticket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, sessionId }),
      })
      if (resp.ok) ticket = (await resp.json())?.ticket ?? null
    } catch {
      ticket = null
    }
    if (!ticket) {
      connectingRef.current = false
      wsRef.current = null
      setStatus('error')
      setError('Triage authentication failed (could not obtain a ticket)')
      return
    }

    const url = getWebSocketUrl(ticket)
    const ws = new WebSocket(url)
    wsRef.current = ws
    connectingRef.current = false

    ws.onopen = () => {
      sendMessage(CypherFixTriageMessageType.INIT, {
        user_id: userId,
        project_id: projectId,
        session_id: sessionId,
      })
    }

    ws.onmessage = (event) => {
      let msg: TriageMessage
      try {
        msg = JSON.parse(event.data)
      } catch {
        return
      }

      const payload = msg.payload || {}

      switch (msg.type) {
        case CypherFixTriageMessageType.CONNECTED:
          isAuthenticatedRef.current = true
          setStatus('connected')
          // Clear any existing ping interval before creating a new one
          if (pingIntervalRef.current) clearInterval(pingIntervalRef.current)
          pingIntervalRef.current = setInterval(() => {
            sendMessage(CypherFixTriageMessageType.PING)
          }, 30000)
          // If we had a pending start, trigger it now
          if (pendingStartRef.current) {
            sendMessage(CypherFixTriageMessageType.START_TRIAGE)
            pendingStartRef.current = false
          }
          break

        case CypherFixTriageMessageType.TRIAGE_PHASE: {
          const phase = payload as unknown as TriagePhasePayload
          setCurrentPhase(phase.phase)
          setProgress(phase.progress)
          setStatus('running')
          onPhase?.(phase)
          break
        }

        case CypherFixTriageMessageType.TRIAGE_FINDING: {
          const finding = payload as unknown as TriageFindingPayload
          setFindings(prev => [...prev, finding])
          onFinding?.(finding)
          break
        }

        case CypherFixTriageMessageType.THINKING:
          setThinking((payload as { thought?: string }).thought || '')
          break

        case CypherFixTriageMessageType.THINKING_CHUNK:
          setThinking(prev => prev + ((payload as { chunk?: string }).chunk || ''))
          break

        case CypherFixTriageMessageType.TRIAGE_COMPLETE: {
          const complete = payload as unknown as TriageCompletePayload
          setStatus('completed')
          setProgress(100)
          onComplete?.(complete)
          break
        }

        case CypherFixTriageMessageType.ERROR: {
          const errMsg = (payload as { message?: string }).message || 'Unknown error'
          setError(errMsg)
          setStatus('error')
          onError?.(errMsg)
          break
        }

        case CypherFixTriageMessageType.STOPPED:
          setStatus('connected')
          break

        case CypherFixTriageMessageType.PONG:
          break
      }
    }

    ws.onerror = () => {
      setError('WebSocket connection error')
      setStatus('error')
    }

    ws.onclose = () => {
      wsRef.current = null
      isAuthenticatedRef.current = false
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current)
        pingIntervalRef.current = null
      }
      if (status !== 'completed' && status !== 'error') {
        setStatus('disconnected')
      }
    }
  }, [enabled, userId, projectId, getWebSocketUrl, sendMessage, onPhase, onFinding, onComplete, onError, status])

  const resetState = useCallback(() => {
    setStatus('disconnected')
    setCurrentPhase(null)
    setProgress(0)
    setFindings([])
    setThinking('')
    setError(null)
    isAuthenticatedRef.current = false
    pendingStartRef.current = false
  }, [])

  const teardownSocket = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
    const stale = wsRef.current
    wsRef.current = null
    connectingRef.current = false
    if (stale) {
      // Sever the handlers BEFORE closing: a closing socket's onclose nulls the
      // shared wsRef, which would otherwise orphan the next socket we open for
      // the project just switched to.
      stale.onopen = null
      stale.onmessage = null
      stale.onerror = null
      stale.onclose = null
      try { stale.close() } catch { /* already closing */ }
    }
  }, [])

  const startTriage = useCallback(() => {
    // Reset state
    setFindings([])
    setThinking('')
    setCurrentPhase(null)
    setProgress(0)
    setError(null)

    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      // Defer start until CONNECTED event fires
      pendingStartRef.current = true
      connect()
    } else {
      sendMessage(CypherFixTriageMessageType.START_TRIAGE)
    }
  }, [connect, sendMessage])

  const stopTriage = useCallback(() => {
    sendMessage(CypherFixTriageMessageType.STOP)
  }, [sendMessage])

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
  }, [])

  // Bind the socket to the CURRENT identity, and rebind when the project (or
  // user) changes. Without this, switching project left project A's socket open
  // (connect() no-ops while one exists), so its "running" phase kept this hook
  // in status:'running' and the "Priority Board running" banner bled onto every
  // other project. On an identity change we drop the old socket and its streamed
  // state, then reconnect so the server can re-attach us to THIS project's run
  // (or none). `connect` is deliberately excluded from the deps: it is memoised
  // on `status`, so including it would tear the socket down on every phase event.
  useEffect(() => {
    if (!enabled || !userId || !projectId) {
      if (wsRef.current) {
        teardownSocket()
        resetState()
      }
      connectedIdRef.current = null
      return
    }
    const id = `${userId}:${projectId}`
    if (connectedIdRef.current !== null && connectedIdRef.current !== id) {
      teardownSocket()
      resetState()
    }
    connectedIdRef.current = id
    if (autoConnect) void connect()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoConnect, enabled, userId, projectId, teardownSocket, resetState])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  return {
    status,
    currentPhase,
    progress,
    findings,
    thinking,
    error,
    startTriage,
    stopTriage,
    disconnect,
  }
}

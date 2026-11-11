/**
 * useCypherFixTriageWS Hook
 *
 * WebSocket hook for the CypherFix triage agent.
 * Follows the same patterns as useAgentWebSocket.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { buildAgentWsUrl } from './agentWsUrl'
import { mintWsTicket } from '@/lib/wsTicket'
import { closeEventText, isAbnormalClose, reviewNoticeText, socketErrorText } from '@/lib/triage/socketErrors'
import {
  CypherFixTriageMessageType,
  PUBLISHING_STOP_REFUSAL,
  type TriagePhase,
  type TriagePhasePayload,
  type TriageFindingPayload,
  type TriageCompletePayload,
} from '@/lib/cypherfix-types'

// =============================================================================
// TYPES
// =============================================================================

export type TriageStatus =
  | 'disconnected' | 'connecting' | 'connected' | 'running' | 'completed' | 'stopped' | 'error'

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
   * Off by default; both the Priority Board and the CypherFix page turn it on.
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
  /** Something the operator should read that is not a failure, such as a Stop
   *  the agent refused because the run is publishing. The run goes on. */
  notice: string | null
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
  const [notice, setNotice] = useState<string | null>(null)

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
    const minted = await mintWsTicket(projectId, sessionId, 'cypherfix-triage')
    if (!minted.ok) {
      connectingRef.current = false
      wsRef.current = null
      setStatus('error')
      setError(`Triage authentication failed (could not obtain a ticket): ${minted.error.message}`)
      return
    }

    // A null ticket is a deployment without ticket signing, not a failure.
    const url = getWebSocketUrl(minted.ticket ?? undefined)
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
          setNotice(reviewNoticeText(payload))
          setStatus('completed')
          setProgress(100)
          onComplete?.(complete)
          break
        }

        case CypherFixTriageMessageType.ERROR: {
          const { message, code } = payload as { message?: string; code?: string }
          // A refused Stop is not a failed run: the run is still going and
          // will finish, so the status must stay where it is.
          if (code === 'publishing') {
            setNotice(message || PUBLISHING_STOP_REFUSAL)
            break
          }
          const errMsg = socketErrorText(payload)
          setError(errMsg)
          setStatus('error')
          onError?.(errMsg)
          break
        }

        // Its own status, not `connected`: a stopped run is a terminal state
        // the board reloads on and the progress panel offers to close (U4).
        case CypherFixTriageMessageType.STOPPED:
          setStatus('stopped')
          setNotice(null)
          break

        case CypherFixTriageMessageType.PONG:
          break
      }
    }

    ws.onerror = () => {
      setError('WebSocket connection error')
      setStatus('error')
    }

    ws.onclose = (event) => {
      wsRef.current = null
      isAuthenticatedRef.current = false
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current)
        pingIntervalRef.current = null
      }
      if (status !== 'completed' && status !== 'error' && status !== 'stopped') {
        setStatus('disconnected')
      }
      // onerror carries nothing; the close code and the agent's reason (an
      // expired ticket, a restart) are the only account of what happened.
      if (event && isAbnormalClose(event)) {
        setError(closeEventText('The connection to the triage agent closed', event))
        setStatus(s => (s === 'completed' || s === 'stopped') ? s : 'error')
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
    setNotice(null)
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
    setNotice(null)

    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      // Defer start until CONNECTED event fires
      pendingStartRef.current = true
      connect()
    } else {
      // Leave the previous run's terminal state, or the panel shows "stopped"
      // over the new run until its first phase arrives.
      setStatus(s => (s === 'completed' || s === 'stopped' || s === 'error') ? 'connected' : s)
      sendMessage(CypherFixTriageMessageType.START_TRIAGE)
    }
  }, [connect, sendMessage])

  const stopTriage = useCallback(() => {
    // sendMessage drops a frame on a closed socket, so a Stop pressed while
    // disconnected looked sent while the run went on.
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      setNotice('Stop was not sent: this page is not connected to the agent. Reload the page to reconnect, then stop the run.')
      return
    }
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
    notice,
    startTriage,
    stopTriage,
    disconnect,
  }
}

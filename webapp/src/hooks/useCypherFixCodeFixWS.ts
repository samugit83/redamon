/**
 * useCypherFixCodeFixWS Hook
 *
 * WebSocket hook for the CypherFix CodeFix agent.
 * Handles diff block streaming, block decisions, and PR creation.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { buildAgentWsUrl } from './agentWsUrl'
import { mintWsTicket } from '@/lib/wsTicket'
import { closeEventText, isAbnormalClose, socketErrorText } from '@/lib/triage/socketErrors'
import {
  CypherFixCodeFixMessageType,
  type ActivityEntry,
  type CodeFixPhase,
  type DiffBlockPayload,
  type FixPlanPayload,
  type PRCreatedPayload,
} from '@/lib/cypherfix-types'

// =============================================================================
// TYPES
// =============================================================================

type CodeFixStatus = 'disconnected' | 'connecting' | 'connected' | 'running' | 'awaiting_approval' | 'stopping' | 'completed' | 'error'

interface CodeFixMessage {
  type: string
  payload?: Record<string, unknown>
}

interface UseCypherFixCodeFixWSConfig {
  userId: string
  projectId: string
  enabled?: boolean
  onDiffBlock?: (block: DiffBlockPayload) => void
  onPRCreated?: (payload: PRCreatedPayload) => void
  onComplete?: (remediationId: string, status: string, prUrl?: string) => void
  onError?: (message: string) => void
}

interface UseCypherFixCodeFixWSReturn {
  status: CodeFixStatus
  currentPhase: CodeFixPhase | null
  thinking: string
  diffBlocks: DiffBlockPayload[]
  fixPlan: FixPlanPayload | null
  prData: PRCreatedPayload | null
  error: string | null
  /** The agent's machine-readable reason for `error`, e.g. 'model_required'. */
  errorCode: string | null
  currentTool: { name: string; args: Record<string, unknown> } | null
  activityLog: ActivityEntry[]
  startFix: (remediationId: string) => void
  sendBlockDecision: (blockId: string, decision: 'accept' | 'reject', reason?: string) => void
  sendGuidance: (message: string) => void
  stopFix: () => void
  disconnect: () => void
}

// =============================================================================
// HOOK
// =============================================================================

export function useCypherFixCodeFixWS({
  userId,
  projectId,
  enabled = true,
  onDiffBlock,
  onPRCreated,
  onComplete,
  onError,
}: UseCypherFixCodeFixWSConfig): UseCypherFixCodeFixWSReturn {
  const [status, setStatus] = useState<CodeFixStatus>('disconnected')
  const [currentPhase, setCurrentPhase] = useState<CodeFixPhase | null>(null)
  const [thinking, setThinking] = useState('')
  const [diffBlocks, setDiffBlocks] = useState<DiffBlockPayload[]>([])
  const [fixPlan, setFixPlan] = useState<FixPlanPayload | null>(null)
  const [prData, setPrData] = useState<PRCreatedPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [errorCode, setErrorCode] = useState<string | null>(null)
  const [currentTool, setCurrentTool] = useState<{ name: string; args: Record<string, unknown> } | null>(null)
  const [activityLog, setActivityLog] = useState<ActivityEntry[]>([])

  const wsRef = useRef<WebSocket | null>(null)
  const isAuthenticatedRef = useRef(false)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const pendingRemediationRef = useRef<string | null>(null)
  const logIdRef = useRef(0)
  // S4: guard the async connect() double-fire window (see triage hook).
  const connectingRef = useRef(false)

  // Distributive Omit so TS preserves the discriminated union variants
  type LogInput = ActivityEntry extends infer T ? T extends ActivityEntry ? Omit<T, 'id' | 'ts'> : never : never

  const pushLog = useCallback((entry: LogInput) => {
    const id = `log-${++logIdRef.current}`
    setActivityLog((prev: ActivityEntry[]) => [...prev, { ...entry, id, ts: Date.now() } as ActivityEntry])
    return id
  }, [])

  // STRIDE S4: the agent handler requires a ws-ticket (query param); buildAgentWsUrl
  // appends it. Single-origin deploys reuse the agent WS origin and swap the path.
  const getWebSocketUrl = useCallback((ticket?: string) => {
    return buildAgentWsUrl('/ws/cypherfix-codefix', ticket)
  }, [])

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

    // STRIDE S4: mint a ws-ticket before dialing; the agent fails closed now.
    const sessionId = `codefix-${Date.now()}`
    const minted = await mintWsTicket(projectId, sessionId, 'cypherfix-codefix')
    if (!minted.ok) {
      connectingRef.current = false
      wsRef.current = null
      setStatus('error')
      setError(`CodeFix authentication failed (could not obtain a ticket): ${minted.error.message}`)
      return
    }

    // A null ticket is a deployment without ticket signing, not a failure.
    const url = getWebSocketUrl(minted.ticket ?? undefined)
    const ws = new WebSocket(url)
    wsRef.current = ws
    connectingRef.current = false

    ws.onopen = () => {
      sendMessage(CypherFixCodeFixMessageType.INIT, {
        user_id: userId,
        project_id: projectId,
        session_id: sessionId,
      })
    }

    ws.onmessage = (event) => {
      let msg: CodeFixMessage
      try {
        msg = JSON.parse(event.data)
      } catch {
        return
      }

      const payload = msg.payload || {}

      switch (msg.type) {
        case CypherFixCodeFixMessageType.CONNECTED:
          isAuthenticatedRef.current = true
          setStatus('connected')
          // Clear any existing ping interval before creating a new one
          if (pingIntervalRef.current) clearInterval(pingIntervalRef.current)
          pingIntervalRef.current = setInterval(() => {
            sendMessage(CypherFixCodeFixMessageType.PING)
          }, 30000)
          // If we had a pending remediation, start the fix now
          if (pendingRemediationRef.current) {
            sendMessage(CypherFixCodeFixMessageType.START_FIX, {
              remediation_id: pendingRemediationRef.current,
            })
            pendingRemediationRef.current = null
          }
          break

        case CypherFixCodeFixMessageType.CODEFIX_PHASE: {
          const phase = (payload as { phase?: CodeFixPhase }).phase || null
          const desc = (payload as { description?: string }).description || ''
          setCurrentPhase(phase)
          if (phase === 'awaiting_approval') {
            setStatus('awaiting_approval')
          } else {
            setStatus('running')
          }
          if (phase) {
            pushLog({ type: 'phase', phase, description: desc })
          }
          break
        }

        case CypherFixCodeFixMessageType.THINKING: {
          const thought = (payload as { thought?: string }).thought || ''
          setThinking(thought)
          pushLog({ type: 'thinking', text: thought })
          break
        }

        case CypherFixCodeFixMessageType.THINKING_CHUNK: {
          const chunk = (payload as { chunk?: string }).chunk || ''
          setThinking(prev => prev + chunk)
          // Append chunk to the last thinking entry
          setActivityLog((prev: ActivityEntry[]) => {
            const lastIdx = prev.length - 1
            if (lastIdx >= 0 && prev[lastIdx].type === 'thinking') {
              const last = prev[lastIdx] as ActivityEntry & { type: 'thinking' }
              return [...prev.slice(0, lastIdx), { ...last, text: last.text + chunk }]
            }
            // No existing thinking entry - create one
            return [...prev, { id: `log-${++logIdRef.current}`, type: 'thinking' as const, ts: Date.now(), text: chunk }]
          })
          break
        }

        case CypherFixCodeFixMessageType.TOOL_START: {
          const toolName = (payload as { tool_name?: string }).tool_name || ''
          const toolArgs = (payload as { tool_args?: Record<string, unknown> }).tool_args || {}
          setCurrentTool({ name: toolName, args: toolArgs })
          pushLog({ type: 'tool', name: toolName, args: toolArgs, status: 'running' })
          break
        }

        case CypherFixCodeFixMessageType.TOOL_COMPLETE: {
          const completedName = (payload as { tool_name?: string }).tool_name || ''
          const success = (payload as { success?: boolean }).success !== false
          const outputSummary = (payload as { output_summary?: string }).output_summary || ''
          setCurrentTool(null)
          // Update the last matching running tool entry
          setActivityLog((prev: ActivityEntry[]) => {
            for (let i = prev.length - 1; i >= 0; i--) {
              const e = prev[i]
              if (e.type === 'tool' && e.name === completedName && e.status === 'running') {
                const newStatus: 'done' | 'error' = success ? 'done' : 'error'
                const updated = { ...e, status: newStatus, success, output: outputSummary }
                return [...prev.slice(0, i), updated, ...prev.slice(i + 1)]
              }
            }
            return prev
          })
          break
        }

        case CypherFixCodeFixMessageType.FIX_PLAN: {
          const plan = payload as unknown as FixPlanPayload
          setFixPlan(plan)
          pushLog({ type: 'fix_plan', plan })
          break
        }

        case CypherFixCodeFixMessageType.DIFF_BLOCK: {
          const block = (payload as { block?: DiffBlockPayload }).block ||
                        payload as unknown as DiffBlockPayload
          setDiffBlocks(prev => [...prev, block])
          setStatus('awaiting_approval')
          onDiffBlock?.(block)
          pushLog({ type: 'diff_block', block })
          break
        }

        case CypherFixCodeFixMessageType.BLOCK_STATUS: {
          const blockId = (payload as { block_id?: string }).block_id
          const blockStatus = (payload as { status?: string }).status
          if (blockId && blockStatus) {
            setDiffBlocks(prev =>
              prev.map(b =>
                b.block_id === blockId
                  ? { ...b, status: blockStatus as DiffBlockPayload['status'] }
                  : b
              )
            )
          }
          setStatus('running')
          break
        }

        case CypherFixCodeFixMessageType.PR_CREATED: {
          const pr = payload as unknown as PRCreatedPayload
          setPrData(pr)
          onPRCreated?.(pr)
          pushLog({ type: 'pr_created', pr })
          break
        }

        case CypherFixCodeFixMessageType.CODEFIX_COMPLETE: {
          setStatus('completed')
          const remId = (payload as { remediation_id?: string }).remediation_id || ''
          const completionStatus = (payload as { status?: string }).status || 'completed'
          const prUrl = (payload as { pr_url?: string }).pr_url
          onComplete?.(remId, completionStatus, prUrl)
          pushLog({ type: 'complete', completionStatus })
          break
        }

        case CypherFixCodeFixMessageType.ERROR: {
          const errMsg = socketErrorText(payload)
          const errCode = (payload as { code?: unknown }).code
          setError(errMsg)
          setErrorCode(typeof errCode === 'string' ? errCode : null)
          setStatus('error')
          onError?.(errMsg)
          pushLog({ type: 'error', message: errMsg })
          break
        }

        case CypherFixCodeFixMessageType.STOPPED:
          setStatus('connected')
          break

        case CypherFixCodeFixMessageType.PONG:
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
      if (status !== 'completed' && status !== 'error') {
        setStatus('disconnected')
      }
      // onerror carries nothing; the close code and the agent's reason (an
      // expired ticket, a restart) are the only account of what happened.
      if (event && isAbnormalClose(event)) {
        setError(closeEventText('The connection to the CodeFix agent closed', event))
        setStatus(s => (s === 'completed' ? s : 'error'))
      }
    }
  }, [enabled, userId, projectId, getWebSocketUrl, sendMessage, pushLog, onDiffBlock, onPRCreated, onComplete, onError, status])

  const startFix = useCallback((remediationId: string) => {
    // Reset state
    setDiffBlocks([])
    setFixPlan(null)
    setPrData(null)
    setThinking('')
    setCurrentPhase(null)
    setCurrentTool(null)
    setError(null)
    setErrorCode(null)
    setActivityLog([])
    logIdRef.current = 0

    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      pendingRemediationRef.current = remediationId
      connect()
    } else {
      sendMessage(CypherFixCodeFixMessageType.START_FIX, {
        remediation_id: remediationId,
      })
    }
  }, [connect, sendMessage])

  const sendBlockDecision = useCallback((blockId: string, decision: 'accept' | 'reject', reason?: string) => {
    sendMessage(CypherFixCodeFixMessageType.BLOCK_DECISION, {
      block_id: blockId,
      decision,
      reason,
    })
  }, [sendMessage])

  const sendGuidance = useCallback((message: string) => {
    sendMessage(CypherFixCodeFixMessageType.GUIDANCE, { message })
  }, [sendMessage])

  const stopFix = useCallback(() => {
    setStatus('stopping')
    sendMessage(CypherFixCodeFixMessageType.STOP)
  }, [sendMessage])

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
  }, [])

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
    thinking,
    diffBlocks,
    fixPlan,
    prData,
    error,
    errorCode,
    currentTool,
    activityLog,
    startFix,
    sendBlockDecision,
    sendGuidance,
    stopFix,
    disconnect,
  }
}

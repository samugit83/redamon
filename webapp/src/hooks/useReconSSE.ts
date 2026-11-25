'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconLogEvent } from '@/lib/recon-types'
import { LOG_STREAM_EVENT_ERROR, LOG_STREAM_LOST, describeLogStreamLoss } from './logStreamError'

export const STREAM_EVENT_ERROR = LOG_STREAM_EVENT_ERROR

export function describeStreamFailure(url: string): Promise<string> {
  return describeLogStreamLoss(url, LOG_STREAM_LOST)
}

const RECONNECTING = 'Log stream disconnected; reconnecting'

/** Shown while a dropped stream is retried, so the drawer does not look live. */
export function reconnectingText(attempt: number, max: number): string {
  return `${RECONNECTING} (attempt ${attempt} of ${max})`
}

/** True for the retry notice: a caller that toasts errors skips it. */
export function isStreamReconnecting(error: string | null | undefined): boolean {
  return !!error && error.startsWith(RECONNECTING)
}

interface UseReconSSEOptions {
  projectId: string | null
  enabled: boolean
  onLog?: (event: ReconLogEvent) => void
  onPhaseChange?: (phase: string, phaseNumber: number) => void
  onComplete?: (status: string, error?: string) => void
  onError?: (error: string) => void
}

interface UseReconSSEReturn {
  logs: ReconLogEvent[]
  isConnected: boolean
  error: string | null
  clearLogs: () => void
  currentPhase: string | null
  currentPhaseNumber: number | null
  /** Domain batch outer progress; null for every other kind of run. */
  currentGroup: string | null
  groupNumber: number | null
  totalGroups: number | null
}

export function useReconSSE({
  projectId,
  enabled,
  onLog,
  onPhaseChange,
  onComplete,
  onError,
}: UseReconSSEOptions): UseReconSSEReturn {
  const [logs, setLogs] = useState<ReconLogEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [currentPhase, setCurrentPhase] = useState<string | null>(null)
  const [currentPhaseNumber, setCurrentPhaseNumber] = useState<number | null>(null)
  // Domain batch: the OUTER progress. Phases restart at 1 for every group, so
  // without this the drawer cannot tell group 2 starting from group 1 looping.
  const [currentGroup, setCurrentGroup] = useState<string | null>(null)
  const [groupNumber, setGroupNumber] = useState<number | null>(null)
  const [totalGroups, setTotalGroups] = useState<number | null>(null)

  const eventSourceRef = useRef<EventSource | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  const clearLogs = useCallback(() => {
    setLogs([])
    setCurrentPhase(null)
    setCurrentPhaseNumber(null)
    setCurrentGroup(null)
    setGroupNumber(null)
    setTotalGroups(null)
  }, [])

  const connect = useCallback(() => {
    // Named, so a retry reopens the stream with the props this callback was made with.
    function open() {
      if (!projectId || !enabled) return

      // Clean up existing connection
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
      }

      const url = `/api/recon/${projectId}/logs`
      const eventSource = new EventSource(url)
      eventSourceRef.current = eventSource

      eventSource.onopen = () => {
        setIsConnected(true)
        setError(null)
        reconnectAttempts.current = 0
      }

      // Handle named 'log' events
      eventSource.addEventListener('log', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          const data = JSON.parse(eventData)

          const logEvent: ReconLogEvent = {
            log: data.log,
            timestamp: data.timestamp,
            phase: data.phase,
            phaseNumber: data.phaseNumber,
            isPhaseStart: data.isPhaseStart,
            level: data.level || 'info',
          }

          setLogs(prev => [...prev, logEvent])
          onLog?.(logEvent)

          // Update phase tracking
          if (logEvent.isPhaseStart && logEvent.phase && logEvent.phaseNumber) {
            setCurrentPhase(logEvent.phase)
            setCurrentPhaseNumber(logEvent.phaseNumber)
            onPhaseChange?.(logEvent.phase, logEvent.phaseNumber)
          }

          // Domain batch: a new group resets the phase counter, so track it too.
          if (data.isGroupStart && data.groupNumber) {
            setCurrentGroup(data.currentGroup ?? null)
            setGroupNumber(data.groupNumber)
            setTotalGroups(data.totalGroups ?? null)
          }
        } catch (err) {
          console.error('Error parsing SSE log event:', err)
        }
      })

      // Handle named 'error' events (from server, not connection errors)
      eventSource.addEventListener('error', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          // Connection errors don't have data - ignore them (handled by onerror)
          if (!eventData) return

          const data = JSON.parse(eventData)
          if (data.error) {
            console.error('Recon log stream error event:', data.error)
            setError(STREAM_EVENT_ERROR)
            onError?.(STREAM_EVENT_ERROR)
          }
        } catch (err) {
          console.error('Error parsing SSE error event:', err)
        }
      })

      // Handle named 'complete' events
      eventSource.addEventListener('complete', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          const data = JSON.parse(eventData)
          onComplete?.(data.status, data.error)
          // Close connection after completion
          eventSource.close()
          setIsConnected(false)
        } catch (err) {
          console.error('Error parsing SSE complete event:', err)
        }
      })

      // Handle generic messages (fallback)
      eventSource.onmessage = (event) => {
        try {
          if (!event.data) return
          const data = JSON.parse(event.data)

          // Handle error events
          if (data.error) {
            console.error('Recon log stream error event:', data.error)
            setError(STREAM_EVENT_ERROR)
            onError?.(STREAM_EVENT_ERROR)
            return
          }

          // Handle completion events
          if (data.status) {
            onComplete?.(data.status, data.error)
            return
          }

          // Handle log events (fallback for unnamed events)
          if (data.log) {
            const logEvent: ReconLogEvent = {
              log: data.log,
              timestamp: data.timestamp,
              phase: data.phase,
              phaseNumber: data.phaseNumber,
              isPhaseStart: data.isPhaseStart,
              level: data.level || 'info',
            }

            setLogs(prev => [...prev, logEvent])
            onLog?.(logEvent)

            if (logEvent.isPhaseStart && logEvent.phase && logEvent.phaseNumber) {
              setCurrentPhase(logEvent.phase)
              setCurrentPhaseNumber(logEvent.phaseNumber)
              onPhaseChange?.(logEvent.phase, logEvent.phaseNumber)
            }
          }
        } catch (err) {
          console.error('Error parsing SSE message:', err)
        }
      }

      eventSource.onerror = () => {
        setIsConnected(false)
        eventSource.close()

        // Attempt reconnection with exponential backoff
        if (reconnectAttempts.current < maxReconnectAttempts) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 10000)
          reconnectAttempts.current++
          setError(reconnectingText(reconnectAttempts.current, maxReconnectAttempts))

          reconnectTimeoutRef.current = setTimeout(() => {
            open()
          }, delay)
        } else {
          setError(LOG_STREAM_LOST)
          void describeStreamFailure(url).then(message => {
            // A newer connection (or an unmount) replaced this one meanwhile.
            if (eventSourceRef.current !== eventSource) return
            setError(message)
            onError?.(message)
          })
        }
      }
    }
    open()
  }, [projectId, enabled, onLog, onPhaseChange, onComplete, onError])

  // Clear logs only when switching to a different project
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- SSE subscription: the reset runs in the commit that reconnects, so a late event from the old stream is cleared too
    setLogs([])
    setCurrentPhase(null)
    setCurrentPhaseNumber(null)
    setCurrentGroup(null)
    setGroupNumber(null)
    setTotalGroups(null)
    reconnectAttempts.current = 0
  }, [projectId])

  // Connect/disconnect when enabled or project changes
  useEffect(() => {
    if (enabled && projectId) {
      connect()
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
    }
  }, [enabled, projectId, connect])

  return {
    logs,
    isConnected,
    error,
    clearLogs,
    currentPhase,
    currentPhaseNumber,
    currentGroup,
    groupNumber,
    totalGroups,
  }
}

export default useReconSSE

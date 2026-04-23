'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconLogEvent } from '@/lib/recon-types'

interface UseMultiPartialReconSSEOptions {
  projectId: string | null
  /** The run_id of the currently visible logs drawer (only this run gets an SSE connection) */
  activeRunId: string | null
  /** Fires on every incoming log event (even when this run is not the drawer-active one). */
  onLog?: (runId: string, event: ReconLogEvent) => void
  /** Fires when a run emits a terminal 'complete' event. */
  onComplete?: (runId: string) => void
}

interface UseMultiPartialReconSSEReturn {
  /** Logs keyed by run_id. Persists across drawer switches. */
  logsMap: Record<string, ReconLogEvent[]>
  /** Phase info for each run */
  phaseMap: Record<string, { phase: string | null; phaseNumber: number | null }>
  isConnected: boolean
  error: string | null
  clearLogsForRun: (runId: string) => void
}

export function useMultiPartialReconSSE({
  projectId,
  activeRunId,
  onLog,
  onComplete,
}: UseMultiPartialReconSSEOptions): UseMultiPartialReconSSEReturn {
  const [logsMap, setLogsMap] = useState<Record<string, ReconLogEvent[]>>({})
  const [phaseMap, setPhaseMap] = useState<Record<string, { phase: string | null; phaseNumber: number | null }>>({})
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const eventSourceRef = useRef<EventSource | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempts = useRef(0)
  const activeRunIdRef = useRef(activeRunId)
  const onLogRef = useRef(onLog)
  const onCompleteRef = useRef(onComplete)
  const maxReconnectAttempts = 5

  // Keep ref in sync
  useEffect(() => {
    activeRunIdRef.current = activeRunId
  }, [activeRunId])

  useEffect(() => {
    onLogRef.current = onLog
    onCompleteRef.current = onComplete
  }, [onLog, onComplete])

  const clearLogsForRun = useCallback((runId: string) => {
    setLogsMap(prev => {
      const next = { ...prev }
      delete next[runId]
      return next
    })
    setPhaseMap(prev => {
      const next = { ...prev }
      delete next[runId]
      return next
    })
  }, [])

  // Connect/disconnect SSE based on activeRunId
  useEffect(() => {
    // Cleanup previous connection
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
      setIsConnected(false)
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    reconnectAttempts.current = 0

    if (!projectId || !activeRunId) return

    const runId = activeRunId

    function connect() {
      if (!projectId || !runId) return

      const eventSource = new EventSource(`/api/recon/${projectId}/partial/${runId}/logs`)
      eventSourceRef.current = eventSource

      eventSource.onopen = () => {
        setIsConnected(true)
        setError(null)
        reconnectAttempts.current = 0
      }

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

          // Always notify upstream (used to drive graph refetches). Independent
          // of whether this run's drawer is open.
          onLogRef.current?.(runId, logEvent)

          // Only append if this is still the active run
          if (activeRunIdRef.current === runId) {
            setLogsMap(prev => ({
              ...prev,
              [runId]: [...(prev[runId] || []), logEvent],
            }))

            if (logEvent.isPhaseStart && logEvent.phase && logEvent.phaseNumber) {
              setPhaseMap(prev => ({
                ...prev,
                [runId]: { phase: logEvent.phase!, phaseNumber: logEvent.phaseNumber! },
              }))
            }
          }
        } catch (err) {
          console.error('Error parsing partial recon SSE log event:', err)
        }
      })

      eventSource.addEventListener('error', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          const data = JSON.parse(eventData)
          if (data.error) {
            setError(data.error)
          }
        } catch {
          // Connection-level error, not a named error event
        }
      })

      eventSource.addEventListener('complete', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          onCompleteRef.current?.(runId)
          // Just close the connection; the status hook handles state
          eventSource.close()
          setIsConnected(false)
        } catch (err) {
          console.error('Error parsing partial recon SSE complete event:', err)
        }
      })

      eventSource.onerror = () => {
        setIsConnected(false)
        eventSource.close()

        if (reconnectAttempts.current < maxReconnectAttempts && activeRunIdRef.current === runId) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 10000)
          reconnectAttempts.current++
          reconnectTimeoutRef.current = setTimeout(connect, delay)
        } else if (reconnectAttempts.current >= maxReconnectAttempts) {
          setError('Connection lost. Max reconnection attempts reached.')
        }
      }
    }

    connect()

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
      setIsConnected(false)
    }
  }, [projectId, activeRunId])

  return {
    logsMap,
    phaseMap,
    isConnected,
    error,
    clearLogsForRun,
  }
}

export default useMultiPartialReconSSE

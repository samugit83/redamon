'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconLogEvent } from '@/lib/recon-types'
import { LOG_STREAM_EVENT_ERROR, LOG_STREAM_LOST, describeLogStreamLoss } from './logStreamError'

interface UseSupplyChainSSEOptions {
  projectId: string | null
  enabled: boolean
  onLog?: (event: ReconLogEvent) => void
  onPhaseChange?: (phase: string, phaseNumber: number) => void
  onComplete?: (status: string, error?: string) => void
  onError?: (error: string) => void
}

interface UseSupplyChainSSEReturn {
  logs: ReconLogEvent[]
  isConnected: boolean
  error: string | null
  clearLogs: () => void
  currentPhase: string | null
  currentPhaseNumber: number | null
}

export function useSupplyChainSSE({
  projectId,
  enabled,
  onLog,
  onPhaseChange,
  onComplete,
  onError,
}: UseSupplyChainSSEOptions): UseSupplyChainSSEReturn {
  const [logs, setLogs] = useState<ReconLogEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [currentPhase, setCurrentPhase] = useState<string | null>(null)
  const [currentPhaseNumber, setCurrentPhaseNumber] = useState<number | null>(null)

  const eventSourceRef = useRef<EventSource | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  const clearLogs = useCallback(() => {
    setLogs([])
    setCurrentPhase(null)
    setCurrentPhaseNumber(null)
  }, [])

  const connect = useCallback(() => {
    // Named, so a retry reopens the stream with the props this callback was made with.
    function open() {
      if (!projectId || !enabled) return

      if (eventSourceRef.current) {
        eventSourceRef.current.close()
      }

      const streamUrl = `/api/supply-chain/${projectId}/logs`
      const eventSource = new EventSource(streamUrl)
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

          setLogs(prev => [...prev, logEvent])
          onLog?.(logEvent)

          if (logEvent.isPhaseStart && logEvent.phase && logEvent.phaseNumber) {
            setCurrentPhase(logEvent.phase)
            setCurrentPhaseNumber(logEvent.phaseNumber)
            onPhaseChange?.(logEvent.phase, logEvent.phaseNumber)
          }
        } catch (err) {
          console.error('Error parsing supply-chain SSE log event:', err)
        }
      })

      eventSource.addEventListener('error', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          const data = JSON.parse(eventData)
          if (data.error) {
            console.error('supply-chain log stream error:', data.error)
            setError(LOG_STREAM_EVENT_ERROR)
            onError?.(LOG_STREAM_EVENT_ERROR)
          }
        } catch (err) {
          console.error('Error parsing supply-chain SSE error event:', err)
        }
      })

      eventSource.addEventListener('complete', (event) => {
        try {
          const eventData = (event as MessageEvent).data
          if (!eventData) return

          const data = JSON.parse(eventData)
          onComplete?.(data.status, data.error)
          eventSource.close()
          setIsConnected(false)
        } catch (err) {
          console.error('Error parsing supply-chain SSE complete event:', err)
        }
      })

      eventSource.onmessage = (event) => {
        try {
          if (!event.data) return
          const data = JSON.parse(event.data)

          if (data.error) {
            console.error('supply-chain log stream error:', data.error)
            setError(LOG_STREAM_EVENT_ERROR)
            onError?.(LOG_STREAM_EVENT_ERROR)
            return
          }

          if (data.status) {
            onComplete?.(data.status, data.error)
            return
          }

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
          console.error('Error parsing supply-chain SSE message:', err)
        }
      }

      eventSource.onerror = () => {
        setIsConnected(false)
        eventSource.close()

        if (reconnectAttempts.current < maxReconnectAttempts) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 10000)
          reconnectAttempts.current++

          reconnectTimeoutRef.current = setTimeout(() => {
            open()
          }, delay)
        } else {
          setError(LOG_STREAM_LOST)
          onError?.(LOG_STREAM_LOST)
          void describeLogStreamLoss(streamUrl, 'Failed to connect to Supply-Chain log stream').then(reason => {
            if (eventSourceRef.current === eventSource) setError(reason)
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
    setError(null)
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
  }
}

export default useSupplyChainSSE

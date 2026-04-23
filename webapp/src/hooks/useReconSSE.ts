'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconLogEvent } from '@/lib/recon-types'

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
    if (!projectId || !enabled) return

    // Clean up existing connection
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const eventSource = new EventSource(`/api/recon/${projectId}/logs`)
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
          setError(data.error)
          onError?.(data.error)
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
          setError(data.error)
          onError?.(data.error)
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

        reconnectTimeoutRef.current = setTimeout(() => {
          connect()
        }, delay)
      } else {
        setError('Connection lost. Max reconnection attempts reached.')
        onError?.('Connection lost. Max reconnection attempts reached.')
      }
    }

  }, [projectId, enabled, onLog, onPhaseChange, onComplete, onError])

  // Clear logs only when switching to a different project
  useEffect(() => {
    setLogs([])
    setCurrentPhase(null)
    setCurrentPhaseNumber(null)
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

export default useReconSSE

'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconLogEvent } from '@/lib/recon-types'

interface UseGvmSSEOptions {
  projectId: string | null
  enabled: boolean
  onLog?: (event: ReconLogEvent) => void
  onPhaseChange?: (phase: string, phaseNumber: number) => void
  onComplete?: (status: string, error?: string) => void
  onError?: (error: string) => void
}

interface UseGvmSSEReturn {
  logs: ReconLogEvent[]
  isConnected: boolean
  error: string | null
  clearLogs: () => void
  currentPhase: string | null
  currentPhaseNumber: number | null
}

export function useGvmSSE({
  projectId,
  enabled,
  onLog,
  onPhaseChange,
  onComplete,
  onError,
}: UseGvmSSEOptions): UseGvmSSEReturn {
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

    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const eventSource = new EventSource(`/api/gvm/${projectId}/logs`)
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
        console.error('Error parsing GVM SSE log event:', err)
      }
    })

    eventSource.addEventListener('error', (event) => {
      try {
        const eventData = (event as MessageEvent).data
        if (!eventData) return

        const data = JSON.parse(eventData)
        if (data.error) {
          setError(data.error)
          onError?.(data.error)
        }
      } catch (err) {
        console.error('Error parsing GVM SSE error event:', err)
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
        console.error('Error parsing GVM SSE complete event:', err)
      }
    })

    eventSource.onmessage = (event) => {
      try {
        if (!event.data) return
        const data = JSON.parse(event.data)

        if (data.error) {
          setError(data.error)
          onError?.(data.error)
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
        console.error('Error parsing GVM SSE message:', err)
      }
    }

    eventSource.onerror = () => {
      setIsConnected(false)
      eventSource.close()

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

export default useGvmSSE

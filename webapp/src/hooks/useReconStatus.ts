'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconState, ReconStatus } from '@/lib/recon-types'

interface UseReconStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number // in milliseconds
  onStatusChange?: (status: ReconStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

// Memory governor (Part 5): structured limit info from a rejected start.
export interface ReconStartLimit {
  limitType?: 'hard' | 'ram'
  settingName?: string | null
  detail?: string
  current?: number
  ceiling?: number
}
export interface ReconStartError {
  message: string
  limit?: ReconStartLimit
}

export interface StartReconOptions {
  deleteGraph?: boolean
}

interface UseReconStatusReturn {
  state: ReconState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startRecon: (options?: StartReconOptions) => Promise<ReconState | null>
  stopRecon: () => Promise<ReconState | null>
  pauseRecon: () => Promise<ReconState | null>
  resumeRecon: () => Promise<ReconState | null>
  // Synchronously-readable detail of the most recent failed startRecon(), for a
  // tailored limit modal (read right after startRecon() resolves to null).
  getLastStartError: () => ReconStartError | null
}

const DEFAULT_POLLING_INTERVAL = 5000 // 5 seconds when running
const IDLE_POLLING_INTERVAL = 30000 // 30 seconds when idle (just to catch external changes)

export function useReconStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseReconStatusOptions): UseReconStatusReturn {
  const [state, setState] = useState<ReconState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<ReconStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  const lastStartErrorRef = useRef<ReconStartError | null>(null)

  // Store callbacks in refs to avoid recreating fetchStatus
  const onStatusChangeRef = useRef(onStatusChange)
  const onCompleteRef = useRef(onComplete)
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange
    onCompleteRef.current = onComplete
    onErrorRef.current = onError
  }, [onStatusChange, onComplete, onError])

  const fetchStatus = useCallback(async () => {
    if (!projectId) return

    try {
      const response = await fetch(`/api/recon/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch status')
      }

      const data: ReconState = await response.json()
      setState(data)
      setError(null)

      // Check for status changes
      if (previousStatusRef.current !== data.status) {
        onStatusChangeRef.current?.(data.status)

        if (data.status === 'completed') {
          onCompleteRef.current?.()
        } else if (data.status === 'error' && data.error) {
          onErrorRef.current?.(data.error)
        }

        previousStatusRef.current = data.status
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
    }
  }, [projectId]) // Only depends on projectId now

  const startRecon = useCallback(async (options: StartReconOptions = {}): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)
    lastStartErrorRef.current = null

    try {
      const response = await fetch(`/api/recon/${projectId}/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          deleteGraph: options.deleteGraph ?? false,
        }),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        // Capture structured limit info (Part 5) before throwing, so the caller
        // can show a tailored modal.
        lastStartErrorRef.current = { message: data.error || 'Failed to start recon', limit: data.limit }
        throw new Error(data.error || 'Failed to start recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      if (!lastStartErrorRef.current) lastStartErrorRef.current = { message: errorMessage }
      setError(errorMessage)
      onErrorRef.current?.(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const getLastStartError = useCallback(() => lastStartErrorRef.current, [])

  const stopRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setState(prev => prev ? { ...prev, status: 'stopping' as ReconState['status'] } : prev)

    try {
      const response = await fetch(`/api/recon/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const pauseRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/recon/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const resumeRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)

    try {
      const response = await fetch(`/api/recon/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setState(null)
      return
    }

    // Initial fetch only
    fetchStatus()
  }, [projectId, enabled, fetchStatus])

  // Smart polling - only poll frequently when recon is running
  useEffect(() => {
    if (!projectId || !enabled) return

    // Clear any existing polling
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const isRunning = state?.status === 'running' || state?.status === 'starting' || state?.status === 'paused'

    // Use shorter interval when running, longer when idle
    const interval = isRunning ? pollingInterval : IDLE_POLLING_INTERVAL

    pollingRef.current = setInterval(fetchStatus, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchStatus, state?.status])

  return {
    state,
    isLoading,
    error,
    refetch: fetchStatus,
    startRecon,
    stopRecon,
    pauseRecon,
    resumeRecon,
    getLastStartError,
  }
}

export default useReconStatus

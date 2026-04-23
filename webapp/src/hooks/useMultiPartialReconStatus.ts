'use client'

import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import type { PartialReconState, PartialReconStatus, PartialReconParams } from '@/lib/recon-types'

interface UseMultiPartialReconStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onRunComplete?: (runId: string) => void
  onRunError?: (runId: string, error: string) => void
}

interface UseMultiPartialReconStatusReturn {
  runs: PartialReconState[]
  activeRuns: PartialReconState[]
  isAnyRunning: boolean
  isLoading: boolean
  error: string | null
  startPartialRecon: (params: PartialReconParams) => Promise<PartialReconState | null>
  stopPartialRecon: (runId: string) => Promise<PartialReconState | null>
  refetch: () => Promise<void>
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useMultiPartialReconStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onRunComplete,
  onRunError,
}: UseMultiPartialReconStatusOptions): UseMultiPartialReconStatusReturn {
  const [runs, setRuns] = useState<PartialReconState[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  const previousStatusesRef = useRef<Record<string, PartialReconStatus>>({})
  const onRunCompleteRef = useRef(onRunComplete)
  const onRunErrorRef = useRef(onRunError)

  useEffect(() => {
    onRunCompleteRef.current = onRunComplete
    onRunErrorRef.current = onRunError
  }, [onRunComplete, onRunError])

  const fetchAllStatuses = useCallback(async () => {
    if (!projectId) return

    try {
      const response = await fetch(`/api/recon/${projectId}/partial/all`)
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to fetch partial recon statuses')
      }

      const data = await response.json()
      const newRuns: PartialReconState[] = data.runs || []
      setRuns(newRuns)
      setError(null)

      // Detect status transitions for callbacks
      for (const run of newRuns) {
        const prevStatus = previousStatusesRef.current[run.run_id]
        if (prevStatus && prevStatus !== run.status) {
          if (run.status === 'completed') {
            onRunCompleteRef.current?.(run.run_id)
          } else if (run.status === 'error' && run.error) {
            onRunErrorRef.current?.(run.run_id, run.error)
          }
        }
      }

      // Update previous statuses
      const newStatuses: Record<string, PartialReconStatus> = {}
      for (const run of newRuns) {
        newStatuses[run.run_id] = run.status
      }
      previousStatusesRef.current = newStatuses

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
    }
  }, [projectId])

  const startPartialRecon = useCallback(async (params: PartialReconParams): Promise<PartialReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(`/api/recon/${projectId}/partial`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to start partial recon')
      }

      const data: PartialReconState = await response.json()
      // Add the new run to the list immediately
      setRuns(prev => [...prev, data])
      previousStatusesRef.current[data.run_id] = data.status
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      onRunErrorRef.current?.('', errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const stopPartialRecon = useCallback(async (runId: string): Promise<PartialReconState | null> => {
    if (!projectId) return null

    // Optimistic update
    setRuns(prev => prev.map(r =>
      r.run_id === runId ? { ...r, status: 'stopping' as PartialReconStatus } : r
    ))

    try {
      const response = await fetch(`/api/recon/${projectId}/partial/${runId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to stop partial recon')
      }

      const data: PartialReconState = await response.json()
      // Remove from list since backend deletes it on stop
      setRuns(prev => prev.filter(r => r.run_id !== runId))
      delete previousStatusesRef.current[runId]
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      // Revert optimistic update
      await fetchAllStatuses()
      return null
    }
  }, [projectId, fetchAllStatuses])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setRuns([])
      previousStatusesRef.current = {}
      return
    }

    fetchAllStatuses()
  }, [projectId, enabled, fetchAllStatuses])

  // Smart polling
  const activeRuns = useMemo(
    () => runs.filter(r => r.status === 'running' || r.status === 'starting' || r.status === 'stopping'),
    [runs]
  )

  const isAnyRunning = useMemo(
    () => runs.some(r => r.status === 'running' || r.status === 'starting'),
    [runs]
  )

  useEffect(() => {
    if (!projectId || !enabled) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const interval = isAnyRunning ? pollingInterval : IDLE_POLLING_INTERVAL
    pollingRef.current = setInterval(fetchAllStatuses, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchAllStatuses, isAnyRunning])

  return {
    runs,
    activeRuns,
    isAnyRunning,
    isLoading,
    error,
    startPartialRecon,
    stopPartialRecon,
    refetch: fetchAllStatuses,
  }
}

export default useMultiPartialReconStatus

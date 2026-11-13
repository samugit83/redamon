'use client'

import { useCallback, useEffect, useState } from 'react'
import { fetchJson } from '@/lib/apiError'
import type { ProjectListItem } from '@/hooks/useProjects'

export interface OversightProjects {
  data: ProjectListItem[] | undefined
  error: unknown
  isLoading: boolean
  refetch: () => void
}

/**
 * Every project of the instance for a holder of `projects:oversee` (GET /api/projects/oversight,
 * step 4.14), read only while `enabled` (the projects page's "All projects (oversight)" filter is
 * chosen), so nobody else ever asks for it.
 */
export function useOversightProjects(enabled: boolean): OversightProjects {
  const [data, setData] = useState<ProjectListItem[] | undefined>(undefined)
  const [error, setError] = useState<unknown>(null)
  const [isLoading, setLoading] = useState(false)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (!enabled) return
    let live = true
    setLoading(true)
    setError(null)
    fetchJson<ProjectListItem[]>('/api/projects/oversight', { cache: 'no-store' }, 'Could not list every project').then(
      (rows) => {
        if (!live) return
        setData(rows)
        setLoading(false)
      },
      (err) => {
        if (!live) return
        setError(err)
        setLoading(false)
      },
    )
    return () => {
      live = false
    }
  }, [enabled, tick])

  const refetch = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, isLoading, refetch }
}

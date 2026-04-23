'use client'

import { useCallback, useEffect, useState } from 'react'
import type { RedZoneTableResponse, RedZoneTableSlug } from './types'

export function useRedZoneTable<T>(slug: RedZoneTableSlug, projectId: string | null) {
  const [data, setData] = useState<RedZoneTableResponse<T> | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    if (!projectId) {
      setData(null)
      return
    }
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/${slug}?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        throw new Error(body.error || `HTTP ${res.status}`)
      }
      const json = (await res.json()) as RedZoneTableResponse<T>
      setData(json)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setIsLoading(false)
    }
  }, [slug, projectId])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return { data, isLoading, error, refetch: fetchData }
}

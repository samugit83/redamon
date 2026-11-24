'use client'

/**
 * Start an apply and follow it until it ends.
 *
 * The run is polled every two seconds while it is `running`; the server sweeps
 * a run whose agent died to `failed`, and a run that is gone stops the polling,
 * so it always ends.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { readApiError } from '@/lib/apiError'
import type { NodeFilterRunSummary } from './useNodeFilters'

export type ApplyTarget = 'current' | 'scans' | 'both'

export const POLL_MS = 2000

export function useApplyRun(projectId: string | null, initialRunId: string | null,
                            onFinished: (run: NodeFilterRunSummary) => void) {
  const [runId, setRunId] = useState<string | null>(initialRunId)
  const [run, setRun] = useState<NodeFilterRunSummary | null>(null)
  const onFinishedRef = useRef(onFinished)
  useLayoutEffect(() => { onFinishedRef.current = onFinished })

  const [seenInitialRunId, setSeenInitialRunId] = useState(initialRunId)
  if (seenInitialRunId !== initialRunId) {
    setSeenInitialRunId(initialRunId)
    setRunId(initialRunId)
  }

  useEffect(() => {
    if (!projectId || !runId) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    const poll = async () => {
      try {
        const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/runs/${encodeURIComponent(runId)}`)
        if (cancelled) return
        if (res.ok) {
          const body: NodeFilterRunSummary = await res.json()
          setRun(body)
          if (body.status !== 'running') {
            setRunId(null)
            onFinishedRef.current(body)
            return
          }
        } else if (res.status === 404 || res.status === 401 || res.status === 403) {
          // Gone for good (a deleted project, or no longer ours to see). Only
          // a 5xx or a network error is worth another poll.
          setRun(null)
          setRunId(null)
          return
        }
      } catch {
        // A blip; the next poll tries again.
      }
      if (!cancelled) timer = setTimeout(poll, POLL_MS)
    }
    void poll()
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [projectId, runId])

  const apply = useCallback(async (target: ApplyTarget, revision: number, versionId: string | null) => {
    if (!projectId) throw new Error('No project')
    const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, revision, versionId }),
    })
    if (!res.ok) throw await readApiError(res, 'Apply failed')
    const body = await res.json().catch(() => ({}))
    if (body.runId) {
      setRun(null)
      setRunId(body.runId)
    }
    return body as { runId: string | null; armed: boolean }
  }, [projectId])

  return { runId, run, running: !!runId, apply }
}

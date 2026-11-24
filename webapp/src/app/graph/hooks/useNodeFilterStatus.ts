'use client'

/**
 * The Mute Rules tab's armed badge, and the page's watch on a running apply.
 *
 * Fetched on load and when the project changes, and refreshed by the page after
 * a save, an apply or a disarm. While an apply runs it is polled, because the
 * Mute Rules view that started the apply unmounts when the operator switches
 * tab, and something must still notice the end and refetch the graph.
 * A failed fetch shows no badge rather than a stale one.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { NodeFilterStatus } from '../components/ViewTabs/ViewTabs'

const POLL_MS = 5000

export function useNodeFilterStatus(projectId: string | null, onApplyFinished?: () => void) {
  // Kept with the project it describes, so the render right after a project
  // switch never shows, or acts on, the previous project's status.
  const [entry, setEntry] = useState<{ projectId: string; status: NodeFilterStatus | null } | null>(null)
  const status = entry && entry.projectId === projectId ? entry.status : null
  const seq = useRef(0)
  const runningFor = useRef<string | null>(null)
  const finished = useRef(onApplyFinished)
  useLayoutEffect(() => { finished.current = onApplyFinished })

  const refresh = useCallback(async () => {
    const mine = ++seq.current
    if (!projectId) {
      setEntry(null)
      return
    }
    let next: NodeFilterStatus | null = null
    try {
      const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/status`)
      next = res.ok ? await res.json() : null
    } catch {
      next = null
    }
    // A later refresh, or another project, has been asked for since.
    if (mine === seq.current) setEntry({ projectId, status: next })
  }, [projectId])

  useEffect(() => {
    runningFor.current = null
    // eslint-disable-next-line react-hooks/set-state-in-effect -- the status fetch on load and on a project change; refresh() is also what the page calls after a save
    void refresh()
  }, [refresh])

  const running = !!status?.runningApply
  useEffect(() => {
    if (running) {
      runningFor.current = projectId
      const timer = setInterval(() => { void refresh() }, POLL_MS)
      return () => clearInterval(timer)
    }
    if (runningFor.current !== null && runningFor.current === projectId) {
      runningFor.current = null
      finished.current?.()
    }
  }, [running, projectId, refresh])

  return { status, refresh }
}

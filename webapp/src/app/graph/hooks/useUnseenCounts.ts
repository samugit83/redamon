'use client'

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useUserPreferences } from '@/hooks/useUserPreferences'
import { BADGED_TABS, type UnseenResponse } from '../unseen/registry'

/** Per-user preference key: `{ [projectId]: { [tabId]: isoInstant } }`. */
const SEEN_AT_KEY = 'unseenSeenAt'

/**
 * How often the badges refresh.
 *
 * A poll fans out to every tab's own query server-side, which is what makes the
 * numbers match the tables - and what makes it worth doing rarely. A scan writes
 * for minutes at a time, so a faster cadence buys nothing a user would notice
 * while multiplying that fan-out by every open browser tab.
 */
const POLL_MS = 60_000

type ProjectMarks = Record<string, string>
type SeenAtPrefs = Record<string, ProjectMarks>

function sameCounts(a: Record<string, number>, b: Record<string, number>): boolean {
  const keys = Object.keys(b)
  if (keys.length !== Object.keys(a).length) return false
  return keys.every(k => a[k] === b[k])
}

/**
 * Unseen-row badges for the graph table tabs.
 *
 * A tab's badge counts the ROWS THAT TAB WOULD SHOW which were written after
 * the instant that user last had it open - the route works that out per tab, so
 * a badge and an empty table can never disagree. Three rules make it behave:
 *
 *  1. **Seeding.** A tab with no stored watermark is not "everything is new" -
 *     it is a user who has never had badges before. The first response seeds
 *     every unseen tab from the server clock, so the feature ships showing zero
 *     rather than twenty four-digit badges.
 *  2. **Server time only.** Watermarks are stamped from the graph's clock
 *     (corrected for browser skew between polls). A client running fast would
 *     otherwise write a watermark into the future and permanently hide the next
 *     scan's findings.
 *  3. **Open means seen.** The active tab is re-marked on every poll, so a tab
 *     the user is actually looking at never accumulates a badge.
 */
export function useUnseenCounts(projectId: string | null, activeTab: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const [counts, setCounts] = useState<Record<string, number>>({})
  // Not derived from `counts`: Node Inspector and All Nodes each cover the whole
  // graph, so adding the badges up reports every new node two or three times.
  // The route sends the reconciled figure - see `barTotal`.
  const [total, setTotal] = useState(0)

  const marks = useMemo<ProjectMarks>(() => {
    if (!projectId) return {}
    return ((prefs[SEEN_AT_KEY] ?? {}) as SeenAtPrefs)[projectId] ?? {}
  }, [prefs, projectId])

  // The poll runs on an interval and must not re-subscribe every time a
  // watermark moves, so it reads these through refs rather than closing over
  // them. Same reason `activeTab` is a ref: switching tabs must not restart the
  // interval or the badges would refetch on every click.
  const marksRef = useRef(marks)
  useLayoutEffect(() => { marksRef.current = marks }, [marks])
  const activeTabRef = useRef(activeTab)
  useLayoutEffect(() => { activeTabRef.current = activeTab }, [activeTab])

  /** serverNow - clientNow, from the last response. */
  const skewRef = useRef(0)
  /** Whether the graph's clock has been read at least once this mount. */
  const syncedRef = useRef(false)

  const stamp = useCallback(() => new Date(Date.now() + skewRef.current).toISOString(), [])

  const writeMarks = useCallback(
    (patch: ProjectMarks) => {
      if (!projectId || Object.keys(patch).length === 0) return
      updatePref(SEEN_AT_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as SeenAtPrefs
        return { ...prevObj, [projectId]: { ...prevObj[projectId], ...patch } }
      })
    },
    [projectId, updatePref]
  )

  /** Mark a tab as seen now, and clear its badge without waiting for a poll. */
  const markSeen = useCallback(
    (tab: string | null) => {
      if (!tab || !BADGED_TABS.includes(tab as (typeof BADGED_TABS)[number])) return
      // Before the first response there is no skew to correct with, and a
      // browser running fast would write a watermark into the future - hiding
      // the next scan for good. The first poll marks the open tab anyway, so
      // this costs at most one round trip of delay.
      if (!syncedRef.current) return
      writeMarks({ [tab]: stamp() })
      setCounts(prev => {
        const cleared = prev[tab] ?? 0
        if (!cleared) return prev
        // The rows this tab was showing were part of the bar's total; the next
        // poll replaces this estimate with the exact figure either way.
        setTotal(t => Math.max(0, t - cleared))
        return { ...prev, [tab]: 0 }
      })
    },
    [stamp, writeMarks]
  )

  // Switching project must not leave the previous project's numbers on screen
  // until the next poll answers - they would be read as this project's.
  const [countsFor, setCountsFor] = useState(projectId)
  if (countsFor !== projectId) {
    setCountsFor(projectId)
    setCounts({})
    setTotal(0)
  }
  useEffect(() => {
    syncedRef.current = false
  }, [projectId])

  useEffect(() => {
    // Waiting for the preferences blob is not an optimisation: firing early
    // would send an empty watermark map, and the seeding branch would then
    // overwrite every real watermark the user has with `now`.
    if (!projectId || isLoading) return

    let cancelled = false

    const poll = async () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      try {
        const res = await fetch('/api/analytics/unseen', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectId, marks: marksRef.current }),
        })
        if (!res.ok || cancelled) return
        const data = (await res.json()) as UnseenResponse
        if (cancelled || !data?.now) return

        const serverMs = Date.parse(data.now)
        if (!Number.isNaN(serverMs)) {
          skewRef.current = serverMs - Date.now()
          syncedRef.current = true
        }

        const written: ProjectMarks = {}
        // Tabs this user has never had a watermark for. The route could not
        // count them, so they start at the server clock and at zero.
        const seeded: string[] = []
        for (const tab of BADGED_TABS) {
          if (marksRef.current[tab]) continue
          written[tab] = data.now
          seeded.push(tab)
        }
        // The tab on screen is being read right now, so its watermark advances
        // with the poll instead of only when it was opened.
        const active = activeTabRef.current
        if (active && BADGED_TABS.includes(active as (typeof BADGED_TABS)[number])) {
          written[active] = stamp()
        }
        writeMarks(written)

        const next = { ...(data.counts as Record<string, number>) }
        for (const tab of seeded) next[tab] = 0
        if (active) next[active] = 0
        // Bail on an unchanged poll. Without this every tick hands the graph
        // page a fresh object and re-renders the canvas, which on a large graph
        // is a visible hitch on every tick to say "nothing changed".
        setCounts(prev => (sameCounts(prev, next) ? prev : next))
        // The bar keeps the route's figure even when the open tab was just
        // zeroed: those nodes are genuinely still unseen by the other tabs.
        setTotal(data.total ?? 0)
      } catch {
        // A failed badge poll is cosmetic. Keep the last numbers and retry on
        // the next tick rather than blanking every badge on a blip.
      }
    }

    poll()
    const timer = setInterval(poll, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [projectId, isLoading, stamp, writeMarks])

  return { counts, total, markSeen }
}

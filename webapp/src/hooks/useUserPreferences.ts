'use client'

import { useCallback, useEffect, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'

export type UiPreferences = Record<string, unknown>

const QUERY_KEY = ['user-preferences'] as const
const DEBOUNCE_MS = 400

async function fetchPrefs(): Promise<UiPreferences> {
  const res = await fetch('/api/user/preferences')
  if (!res.ok) throw new Error(`Failed to load preferences (${res.status})`)
  const data = await res.json()
  return (data ?? {}) as UiPreferences
}

async function patchPref(featureKey: string, value: unknown): Promise<UiPreferences> {
  const res = await fetch('/api/user/preferences', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ featureKey, value }),
  })
  if (!res.ok) throw new Error(`Failed to update preference (${res.status})`)
  return (await res.json()) as UiPreferences
}

export function useUserPreferences() {
  const queryClient = useQueryClient()
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())
  const pendingValuesRef = useRef<Map<string, unknown>>(new Map())

  const query = useQuery({
    queryKey: QUERY_KEY,
    queryFn: fetchPrefs,
    staleTime: 60_000,
    notifyOnChangeProps: ['data', 'error', 'isLoading'],
  })

  const prefs: UiPreferences = (query.data ?? {}) as UiPreferences

  const updatePref = useCallback(
    (featureKey: string, valueOrUpdater: unknown | ((prev: unknown) => unknown)) => {
      const current = (queryClient.getQueryData(QUERY_KEY) ?? {}) as UiPreferences
      const prevValue = current[featureKey]
      const nextValue =
        typeof valueOrUpdater === 'function'
          ? (valueOrUpdater as (prev: unknown) => unknown)(prevValue)
          : valueOrUpdater

      // Optimistic local update
      queryClient.setQueryData(QUERY_KEY, { ...current, [featureKey]: nextValue })
      pendingValuesRef.current.set(featureKey, nextValue)

      // Debounced PATCH per featureKey
      const existingTimer = timersRef.current.get(featureKey)
      if (existingTimer) clearTimeout(existingTimer)

      const timer = setTimeout(async () => {
        const valueToSend = pendingValuesRef.current.get(featureKey)
        pendingValuesRef.current.delete(featureKey)
        timersRef.current.delete(featureKey)
        try {
          const updated = await patchPref(featureKey, valueToSend)
          // Take the server's value for THIS key only, rather than adopting its
          // whole blob. The response is stale for every key still sitting in a
          // debounce somewhere on the page - the server has never seen those
          // values - and this page holds several independent writers (column
          // visibility, filters, theme). Overwriting wholesale is not just a
          // flicker: `updatePref`'s updater form reads the cache, so the next
          // edit to a clobbered key computes from a blob missing its current
          // value and silently discards filters saved for other tables.
          const serverValue = (updated as UiPreferences)[featureKey]
          queryClient.setQueryData(QUERY_KEY, (prev: UiPreferences | undefined) => ({
            ...(prev ?? {}),
            // A response that does not echo the key back is malformed, not a
            // deletion - the route always returns the merged blob. Keeping what
            // was sent beats blanking a setting the user just made.
            [featureKey]: serverValue === undefined ? valueToSend : serverValue,
          }))
        } catch (error) {
          console.error(`Failed to persist preference "${featureKey}":`, error)
          // Rollback only if no newer write is queued for this featureKey.
          // (A subsequent updatePref call would have repopulated pendingValuesRef.)
          if (pendingValuesRef.current.has(featureKey)) return
          const stillCurrent = (queryClient.getQueryData(QUERY_KEY) ?? {}) as UiPreferences
          queryClient.setQueryData(QUERY_KEY, { ...stillCurrent, [featureKey]: prevValue })
        }
      }, DEBOUNCE_MS)
      timersRef.current.set(featureKey, timer)
    },
    [queryClient]
  )

  /**
   * Send whatever the debounce is still holding, rather than dropping it.
   *
   * Two ways a queued write is lost without this, both of which land inside the
   * 400ms window routinely: unmounting (switching table view, closing a
   * drawer), and leaving the page entirely (reload, navigation). The second is
   * not an unmount at all - React never runs cleanup - so it needs `pagehide`.
   *
   * `keepalive` is what lets the request outlive the document; the response is
   * irrelevant, since the value being sent is already the optimistic state.
   */
  const flushPending = useCallback(() => {
    const timers = timersRef.current
    const pending = pendingValuesRef.current
    timers.forEach(t => clearTimeout(t))
    timers.clear()
    for (const [featureKey, value] of pending) {
      try {
        fetch('/api/user/preferences', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ featureKey, value }),
          keepalive: true,
        }).catch(() => {})
      } catch {
        // A failed last-gasp write is not worth breaking teardown over.
      }
    }
    pending.clear()
  }, [])

  useEffect(() => {
    // `pagehide` rather than `beforeunload`: it fires for the bfcache path too,
    // which `beforeunload` misses on mobile Safari.
    window.addEventListener('pagehide', flushPending)
    return () => {
      window.removeEventListener('pagehide', flushPending)
      flushPending()
    }
  }, [flushPending])

  return { prefs, isLoading: query.isLoading, error: query.error, updatePref }
}

// ---- Feature-specific helpers ---------------------------------------------

const NODE_DETAILS_KEY = 'nodeDetailsTable'

interface NodeDetailsTablePrefs {
  [nodeType: string]: { hiddenColumns?: string[] }
}

export function useNodeDetailsPrefs(nodeType: string | null) {
  const { prefs, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[NODE_DETAILS_KEY] ?? {}) as NodeDetailsTablePrefs
  const hiddenColumns = nodeType ? featurePrefs[nodeType]?.hiddenColumns ?? [] : []

  const setHiddenColumns = useCallback(
    (next: string[]) => {
      if (!nodeType) return
      updatePref(NODE_DETAILS_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as NodeDetailsTablePrefs
        return { ...prevObj, [nodeType]: { ...prevObj[nodeType], hiddenColumns: next } }
      })
    },
    [nodeType, updatePref]
  )

  return { hiddenColumns, setHiddenColumns }
}

// ---- Per-column table filters - per-user, per-project, per-table ---------

const TABLE_FILTERS_KEY = 'tableFilters'

/**
 * `{ [projectId]: { [scope]: { [columnId]: filter } } }`.
 *
 * One featureKey for EVERY filterable table (the Node Inspector's per-node-type
 * views and every Red Zone sheet) rather than one per table: the blob is a
 * single JSON column read on every page load, and a key per table would make
 * the debounced PATCH from one table race the in-flight PATCH from another
 * whenever a user switches views mid-write.
 *
 * `scope` is the caller's identifier for "which table am I" - see
 * `tableFilterScope()`. The value is deliberately opaque here: validating a
 * filter's shape belongs with the code that defines it, and this hook must not
 * drop fields it does not recognise from a newer build.
 */
type TableFilterPrefs = Record<string, Record<string, Record<string, unknown>>>

/** The scope key for one filterable table. Keep call sites from inventing their own. */
export function tableFilterScope(surface: string, view: string | null): string {
  return view ? `${surface}:${view}` : surface
}

export function useTableFilterPrefs(projectId: string | null, scope: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[TABLE_FILTERS_KEY] ?? {}) as TableFilterPrefs
  const storedFilters =
    projectId && scope ? featurePrefs[projectId]?.[scope] ?? null : null

  const setStoredFilters = useCallback(
    (next: Record<string, unknown>) => {
      if (!projectId || !scope) return
      updatePref(TABLE_FILTERS_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as TableFilterPrefs
        const project = { ...(prevObj[projectId] ?? {}) }
        // An empty filter set is REMOVED, not stored as `{}`. Otherwise every
        // table a user ever opened accumulates a dead key in a row that is
        // fetched on every page load.
        if (Object.keys(next).length === 0) delete project[scope]
        else project[scope] = next as Record<string, unknown>

        const nextObj = { ...prevObj }
        if (Object.keys(project).length === 0) delete nextObj[projectId]
        else nextObj[projectId] = project
        return nextObj
      })
    },
    [projectId, scope, updatePref]
  )

  return { storedFilters, setStoredFilters, isLoading }
}

// ---- Graph node-type filter (bottom-bar chips) ---------------------------

const GRAPH_TYPE_FILTER_KEY = 'graphTypeFilter'

interface GraphTypeFilterPrefs {
  [projectId: string]: { hiddenTypes?: string[] }
}

/**
 * Per-project persistent set of node types the user has hidden via the
 * bottom-bar filter chips. Stored as HIDDEN (not visible) so newly discovered
 * types default to visible without any DB write.
 *
 * Returns isLoading so callers can defer first-render hydration of derived
 * state (e.g., activeNodeTypes) until prefs have loaded - otherwise the user's
 * saved selection is briefly overwritten by "all visible".
 */
export function useGraphTypeFilterPrefs(projectId: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[GRAPH_TYPE_FILTER_KEY] ?? {}) as GraphTypeFilterPrefs
  const hiddenTypes = projectId ? featurePrefs[projectId]?.hiddenTypes ?? [] : []

  const setHiddenTypes = useCallback(
    (next: string[]) => {
      if (!projectId) return
      updatePref(GRAPH_TYPE_FILTER_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as GraphTypeFilterPrefs
        return { ...prevObj, [projectId]: { ...prevObj[projectId], hiddenTypes: next } }
      })
    },
    [projectId, updatePref]
  )

  return { hiddenTypes, setHiddenTypes, isLoading }
}

// ---- Graph view toggles (2D/3D, labels, render) - per-project per-user ----

const GRAPH_VIEW_KEY = 'graphView'

interface GraphViewPrefs {
  [projectId: string]: { is3D?: boolean; showLabels?: boolean; renderEnabled?: boolean }
}

export const GRAPH_VIEW_DEFAULTS = { is3D: true, showLabels: true, renderEnabled: true } as const

/**
 * Per-project persistent values for the 2D/3D mode, label visibility and
 * graph-rendering toggles. Defaults to everything on when not yet set.
 *
 * `renderEnabled` is the escape hatch for projects whose graph has grown big
 * enough to make the tab sluggish: while it is off the page must not fetch
 * /api/graph at all, so callers have to wait for `isLoading` before deciding -
 * treating "not loaded yet" as on would fire exactly the expensive query the
 * user turned off.
 */
export function useGraphViewPrefs(projectId: string | null) {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const featurePrefs = (prefs[GRAPH_VIEW_KEY] ?? {}) as GraphViewPrefs
  const projectPrefs = projectId ? featurePrefs[projectId] : undefined
  const is3D = projectPrefs?.is3D ?? GRAPH_VIEW_DEFAULTS.is3D
  const showLabels = projectPrefs?.showLabels ?? GRAPH_VIEW_DEFAULTS.showLabels
  const renderEnabled = projectPrefs?.renderEnabled ?? GRAPH_VIEW_DEFAULTS.renderEnabled

  const writeProjectPref = useCallback(
    (patch: { is3D?: boolean; showLabels?: boolean; renderEnabled?: boolean }) => {
      if (!projectId) return
      updatePref(GRAPH_VIEW_KEY, (prev: unknown) => {
        const prevObj = (prev ?? {}) as GraphViewPrefs
        return { ...prevObj, [projectId]: { ...prevObj[projectId], ...patch } }
      })
    },
    [projectId, updatePref]
  )

  const setIs3D = useCallback((v: boolean) => writeProjectPref({ is3D: v }), [writeProjectPref])
  const setShowLabels = useCallback(
    (v: boolean) => writeProjectPref({ showLabels: v }),
    [writeProjectPref]
  )
  const setRenderEnabled = useCallback(
    (v: boolean) => writeProjectPref({ renderEnabled: v }),
    [writeProjectPref]
  )

  return { is3D, showLabels, renderEnabled, setIs3D, setShowLabels, setRenderEnabled, isLoading }
}

// ---- Theme - per-user only (no project scope) ----------------------------

const THEME_KEY = 'theme'

export type PersistedTheme = 'light' | 'dark' | 'system'

/**
 * Reads/writes the theme from user prefs. Used by the theme DB bridge to keep
 * localStorage (fast cache, prevents FOUC) and the DB (cross-device source of
 * truth) in sync. The actual application of the theme to the DOM stays in
 * `useTheme` - this hook is purely persistence.
 */
export function useThemePref() {
  const { prefs, isLoading, updatePref } = useUserPreferences()
  const stored = prefs[THEME_KEY]
  const theme: PersistedTheme | null =
    stored === 'light' || stored === 'dark' || stored === 'system' ? stored : null

  const setTheme = useCallback(
    (next: PersistedTheme) => {
      updatePref(THEME_KEY, next)
    },
    [updatePref]
  )

  return { theme, setTheme, isLoading }
}

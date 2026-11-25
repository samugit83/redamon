'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useTableFilterPrefs } from '@/hooks/useUserPreferences'
import { parseStoredFilters, toStoredFilters, type ColumnFilter } from '../utils/columnFilters'

/**
 * The live filter set for one table, restored from and saved to the user's
 * preferences.
 *
 * Every filterable table shares this because the failure modes are not about
 * filtering at all - they are about the restore racing the user:
 *
 *  - `hydratedScope` stops the restore from repeating. Each save writes the
 *    react-query cache optimistically, so without it every keystroke would
 *    re-run the effect and overwrite the state being typed.
 *  - a commit claims the scope as hydrated immediately. The preferences fetch
 *    can resolve at ANY point, including between two keystrokes, and a restore
 *    landing after an edit silently discards it - a filter that erases itself
 *    while you set it.
 *  - a scope change clears first and restores second. Carrying one view's
 *    filters into another for even one frame shows rows filtered by columns the
 *    new view does not have.
 *
 * @param scope identifies the table - build it with `tableFilterScope`.
 */
export function useColumnFilterState(projectId: string | null, scope: string | null) {
  const [filters, setFilters] = useState<Record<string, ColumnFilter>>({})
  const { storedFilters, setStoredFilters, isLoading } = useTableFilterPrefs(projectId, scope)

  const scopeKey = `${projectId ?? ''}|${scope ?? ''}`
  const hydratedScope = useRef<string | null>(null)
  const activeScope = useRef<string>(scopeKey)

  useEffect(() => {
    if (activeScope.current !== scopeKey) {
      activeScope.current = scopeKey
      hydratedScope.current = null
      // eslint-disable-next-line react-hooks/set-state-in-effect -- restores the editable filters from the preferences cache once per scope, racing the user's edits as the comment above describes
      setFilters({})
    }
    if (isLoading || hydratedScope.current === scopeKey) return
    hydratedScope.current = scopeKey
    setFilters(parseStoredFilters(storedFilters))
  }, [scopeKey, isLoading, storedFilters])

  const commitFilters = useCallback(
    (next: Record<string, ColumnFilter>) => {
      hydratedScope.current = scopeKey
      setFilters(next)
      setStoredFilters(toStoredFilters(next))
    },
    [scopeKey, setStoredFilters]
  )

  const setColumnFilter = useCallback(
    (columnId: string, next: ColumnFilter) => {
      commitFilters({ ...filters, [columnId]: next })
    },
    [filters, commitFilters]
  )

  const clearColumnFilter = useCallback(
    (columnId: string) => {
      const next = { ...filters }
      delete next[columnId]
      commitFilters(next)
    },
    [filters, commitFilters]
  )

  const clearAllFilters = useCallback(() => commitFilters({}), [commitFilters])

  /**
   * Drop filters for columns that no longer exist.
   *
   * A refetch can remove a column from every row (a scan that stops emitting a
   * property, a sheet that changes shape). A filter for an unknown column is
   * never evaluated, so without this the table would show every row while the
   * chip still announced "status is live" - the filter bar and the rows
   * disagreeing, which is the one state a filter UI must never be in.
   *
   * Local only: the stored copy is left alone so a transient empty fetch does
   * not permanently delete what the user saved.
   */
  const pruneUnknown = useCallback((knownColumnIds: readonly string[]) => {
    const known = new Set(knownColumnIds)
    setFilters(prev => {
      const kept = Object.entries(prev).filter(([id]) => known.has(id))
      if (kept.length === Object.keys(prev).length) return prev
      return Object.fromEntries(kept)
    })
  }, [])

  return {
    filters,
    setFilters: commitFilters,
    setColumnFilter,
    clearColumnFilter,
    clearAllFilters,
    pruneUnknown,
    isLoading,
  }
}

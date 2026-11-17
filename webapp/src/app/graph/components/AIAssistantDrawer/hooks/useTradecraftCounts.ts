import { useEffect, useState } from 'react'
import { fetchJson } from '@/lib/apiError'
import { useTradecraftCountsChanged } from '@/lib/tradecraft/channels'
import type { ActiveCounts } from '@/lib/tradecraft/activeCounts'
import type { ProjectTradecraftView } from '@/lib/tradecraft/projectView'
import { librarianWarning } from '@/components/projects/ProjectForm/sections/TradecraftResourcesAccordion'

export interface TradecraftCountsState {
  /** The project owner's Tradecraft 2.0 switch; false hides the badge and keeps the menu's old name. */
  v2: boolean
  counts: ActiveCounts | null
  /** The badge tooltip's librarian warning (Q10), '' when there is none. */
  librarianWarning?: string
}

/**
 * The counts of the chat's top-bar badge (§3.4): what the next message will use, for the person
 * chatting, from the accordion route (which counts by the agent's rules). Read again when a window
 * saves the project's switches (TRADECRAFT_COUNTS_CHANNEL) and whenever `reloadKey` changes (the
 * drawer read the project again). A failed read keeps the last numbers.
 */
export function useTradecraftCounts(projectId: string | null | undefined, reloadKey?: unknown): TradecraftCountsState {
  const [state, setState] = useState<TradecraftCountsState>({ v2: false, counts: null })
  const [token, setToken] = useState(0)
  useTradecraftCountsChanged(projectId ?? null, () => setToken(t => t + 1))
  useEffect(() => {
    if (!projectId) return
    let live = true
    fetchJson<ProjectTradecraftView>(`/api/projects/${encodeURIComponent(projectId)}/tradecraft`, undefined, "Couldn't read the project's counts")
      .then(view => { if (live) setState({ v2: view.v2, counts: view.v2 ? view.counts : null, librarianWarning: view.v2 ? librarianWarning(view) : '' }) })
      .catch(() => { /* the badge keeps its last numbers */ })
    return () => { live = false }
  }, [projectId, token, reloadKey])
  return state
}

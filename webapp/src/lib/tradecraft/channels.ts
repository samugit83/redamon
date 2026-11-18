import { useEffect, useRef } from 'react'

/**
 * A browser-wide notice that a project's tradecraft choices or skill switches were saved, so the
 * chat's counter badge reads its numbers again (§3.4 "The badge updates as soon as a switch
 * changes"). The project form and the drawer's Agent Skills & Tradecraft window post it after a
 * save; the badge listens.
 *
 * A BroadcastChannel delivers a post to every OTHER channel object of the same name, this tab's
 * included (never to the one that posted), so each listener hears a post once. Where there is no
 * BroadcastChannel, a listener set in this module stands in, for this tab only.
 */
export const TRADECRAFT_COUNTS_CHANNEL = 'redamon:tradecraft-counts'

export interface TradecraftCountsChange {
  projectId: string
}

type Listener = (change: TradecraftCountsChange) => void
const local = new Set<Listener>()
const hasChannel = () => typeof BroadcastChannel !== 'undefined'

export function postTradecraftCountsChanged(change: TradecraftCountsChange): void {
  if (!hasChannel()) {
    for (const l of [...local]) l(change)
    return
  }
  try {
    const ch = new BroadcastChannel(TRADECRAFT_COUNTS_CHANNEL)
    ch.postMessage(change)
    ch.close()
  } catch {
    for (const l of [...local]) l(change)
  }
}

function isChange(v: unknown): v is TradecraftCountsChange {
  return !!v && typeof v === 'object' && typeof (v as { projectId?: unknown }).projectId === 'string'
}

/** Calls `onChange` for every notice about `projectId` (any project when it is null). */
export function useTradecraftCountsChanged(projectId: string | null, onChange: Listener): void {
  const ref = useRef(onChange)
  ref.current = onChange
  useEffect(() => {
    const listener: Listener = (c) => { if (!projectId || c.projectId === projectId) ref.current(c) }
    let ch: BroadcastChannel | null = null
    if (hasChannel()) {
      try {
        ch = new BroadcastChannel(TRADECRAFT_COUNTS_CHANNEL)
        ch.onmessage = (e: MessageEvent) => { if (isChange(e.data)) listener(e.data) }
      } catch {
        ch = null
      }
    }
    if (!ch) local.add(listener)
    return () => {
      local.delete(listener)
      ch?.close()
    }
  }, [projectId])
}

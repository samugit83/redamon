/**
 * The panel's size, set by dragging its free edges (the ones away from the launcher) and saved per
 * account in localStorage like the launcher's place (every read and write guarded: storage can be
 * off). The saved size is what the person last saw; a smaller window shrinks the drawn panel without
 * overwriting it.
 */
'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

export interface PanelSize { width: number; height: number }
/** n/s/e/w move one edge; a corner (nw, ne, sw, se) moves both of its edges. */
export type ResizeHandle = 'n' | 's' | 'e' | 'w' | 'nw' | 'ne' | 'sw' | 'se'

export const DEFAULT_PANEL_SIZE: PanelSize = { width: 380, height: 560 }
export const MIN_PANEL_SIZE: PanelSize = { width: 300, height: 320 }
/** Caps a hand-edited or corrupt value; the drawn size is capped again by the window. */
const MAX_SIDE = 4000

export function panelSizeKey(userId: string | null): string {
  return `redamon.navigator.panel.v1.${userId ?? 'anon'}`
}

function clampSide(v: number, min: number): number {
  return Math.min(Math.max(min, Math.round(v)), MAX_SIDE)
}

export function readPanelSize(userId: string | null): PanelSize {
  try {
    const raw = window.localStorage.getItem(panelSizeKey(userId))
    if (!raw) return DEFAULT_PANEL_SIZE
    const s = JSON.parse(raw) as Partial<PanelSize>
    if (typeof s.width === 'number' && typeof s.height === 'number' && Number.isFinite(s.width) && Number.isFinite(s.height)) {
      return { width: clampSide(s.width, MIN_PANEL_SIZE.width), height: clampSide(s.height, MIN_PANEL_SIZE.height) }
    }
  } catch {
    // storage unavailable or corrupt: the default
  }
  return DEFAULT_PANEL_SIZE
}

function writePanelSize(userId: string | null, s: PanelSize) {
  try {
    window.localStorage.setItem(panelSizeKey(userId), JSON.stringify(s))
  } catch {
    // storage unavailable: the size lasts for this page only
  }
}

/**
 * The size nearest `to` on the way from `from` that `fits` accepts, width first and then height, so
 * an edge that meets a margin or a drawer stops against it while the other edge keeps following the
 * pointer. A fast pointer can jump past the limit in one move, hence the bisection. `from` is the
 * drawn size, which fits.
 */
export function constrainSize(from: PanelSize, to: PanelSize, fits: (s: PanelSize) => boolean): PanelSize {
  const along = (axis: keyof PanelSize, base: PanelSize): PanelSize => {
    const at = (v: number) => ({ ...base, [axis]: v })
    if (to[axis] === base[axis] || fits(at(to[axis]))) return at(to[axis])
    let ok = base[axis]
    let bad = to[axis]
    while (Math.abs(bad - ok) > 1) {
      const mid = Math.round((ok + bad) / 2)
      if (fits(at(mid))) ok = mid
      else bad = mid
    }
    return at(ok)
  }
  return along('height', along('width', from))
}

/** The size a drag of `handle` by (dx, dy) asks for, never below the minimum (or `from`, if smaller). */
export function resizedSize(from: PanelSize, handle: ResizeHandle, dx: number, dy: number): PanelSize {
  const w = handle.includes('w') ? from.width - dx : handle.includes('e') ? from.width + dx : from.width
  const h = handle.includes('n') ? from.height - dy : handle.includes('s') ? from.height + dy : from.height
  return {
    width: Math.round(Math.max(w, Math.min(MIN_PANEL_SIZE.width, from.width))),
    height: Math.round(Math.max(h, Math.min(MIN_PANEL_SIZE.height, from.height))),
  }
}

const CURSOR: Record<ResizeHandle, string> = {
  n: 'ns-resize', s: 'ns-resize', e: 'ew-resize', w: 'ew-resize',
  nw: 'nwse-resize', se: 'nwse-resize', ne: 'nesw-resize', sw: 'nesw-resize',
}

export function usePanelSize(userId: string | null) {
  const [size, setSize] = useState<PanelSize>(DEFAULT_PANEL_SIZE)
  const endDrag = useRef<(() => void) | null>(null)

  useEffect(() => {
    setSize(readPanelSize(userId))
  }, [userId])
  useEffect(() => () => endDrag.current?.(), [])

  const save = useCallback((s: PanelSize) => {
    setSize(s)
    writePanelSize(userId, s)
  }, [userId])

  const reset = useCallback(() => save(DEFAULT_PANEL_SIZE), [save])

  /**
   * Starts a drag of `handle` from the drawn size `from`. Each move goes to `preview`, which sizes the
   * panel element directly: a state update per pointer move would re-render every message of the
   * conversation. The size becomes state, and is saved, on release. Moves are read on the window, so
   * the pointer may leave the thin handle.
   */
  const startResize = useCallback((e: React.PointerEvent<HTMLElement>, handle: ResizeHandle, from: PanelSize,
    fits: (s: PanelSize) => boolean, preview: (s: PanelSize) => void) => {
    if (e.button !== 0) return
    e.preventDefault()
    e.stopPropagation()
    endDrag.current?.()
    const x = e.clientX
    const y = e.clientY
    const id = e.pointerId
    let last = from
    const body = document.body.style
    const prev = { cursor: body.cursor, userSelect: body.userSelect }
    body.cursor = CURSOR[handle]
    body.userSelect = 'none'

    const onMove = (ev: PointerEvent) => {
      if (ev.pointerId !== id) return
      const next = constrainSize(last, resizedSize(from, handle, ev.clientX - x, ev.clientY - y), fits)
      if (next.width === last.width && next.height === last.height) return
      last = next
      preview(last)
    }
    const finish = (ev: PointerEvent) => {
      if (ev.pointerId !== id) return
      onMove(ev)
      stop()
      save(last)
    }
    const stop = () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', finish)
      window.removeEventListener('pointercancel', finish)
      body.cursor = prev.cursor
      body.userSelect = prev.userSelect
      endDrag.current = null
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', finish)
    window.addEventListener('pointercancel', finish)
    endDrag.current = stop
  }, [save])

  return { size, startResize, reset }
}

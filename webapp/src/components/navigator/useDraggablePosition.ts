/**
 * The launcher's place (plan §9.3): distances from the right and bottom edges, so it stays put when
 * the window widens; clamped to an 8 px margin; saved per account in localStorage (every read and
 * write guarded: storage can be off). A move of more than 4 px is a drag, which never toggles.
 */
'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

export interface Position { right: number; bottom: number }

export const DEFAULT_POSITION: Position = { right: 24, bottom: 96 }
export const MARGIN = 8
export const SIZE = 48
const DRAG_THRESHOLD = 4

export function storageKey(userId: string | null): string {
  return `redamon.navigator.launcher.v1.${userId ?? 'anon'}`
}

export function clampPosition(p: Position, vw: number, vh: number): Position {
  const maxRight = Math.max(MARGIN, vw - SIZE - MARGIN)
  const maxBottom = Math.max(MARGIN, vh - SIZE - MARGIN)
  return {
    right: Math.min(Math.max(MARGIN, Math.round(p.right)), maxRight),
    bottom: Math.min(Math.max(MARGIN, Math.round(p.bottom)), maxBottom),
  }
}

export function readPosition(userId: string | null): Position {
  try {
    const raw = window.localStorage.getItem(storageKey(userId))
    if (!raw) return DEFAULT_POSITION
    const p = JSON.parse(raw) as Partial<Position>
    if (typeof p.right === 'number' && typeof p.bottom === 'number' && Number.isFinite(p.right) && Number.isFinite(p.bottom)) {
      return { right: p.right, bottom: p.bottom }
    }
  } catch {
    // storage unavailable or corrupt: the default
  }
  return DEFAULT_POSITION
}

function writePosition(userId: string | null, p: Position) {
  try {
    window.localStorage.setItem(storageKey(userId), JSON.stringify(p))
  } catch {
    // storage unavailable: the place lasts for this page only
  }
}

export function useDraggablePosition(userId: string | null, onClick: () => void) {
  const [position, setPosition] = useState<Position>(DEFAULT_POSITION)
  const drag = useRef<{ x: number; y: number; start: Position; moved: boolean; id: number } | null>(null)

  useEffect(() => {
    setPosition(clampPosition(readPosition(userId), window.innerWidth, window.innerHeight))
  }, [userId])

  useEffect(() => {
    const onResize = () => setPosition((p) => clampPosition(p, window.innerWidth, window.innerHeight))
    window.addEventListener('resize', onResize)
    window.addEventListener('orientationchange', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      window.removeEventListener('orientationchange', onResize)
    }
  }, [])

  const save = useCallback((p: Position) => {
    const clamped = clampPosition(p, window.innerWidth, window.innerHeight)
    setPosition(clamped)
    writePosition(userId, clamped)
  }, [userId])

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLElement>) => {
    if (e.button !== 0) return
    drag.current = { x: e.clientX, y: e.clientY, start: position, moved: false, id: e.pointerId }
    try {
      e.currentTarget.setPointerCapture(e.pointerId)
    } catch {
      // jsdom and some browsers refuse capture on synthetic events
    }
  }, [position])

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLElement>) => {
    const d = drag.current
    if (!d || d.id !== e.pointerId) return
    const dx = e.clientX - d.x
    const dy = e.clientY - d.y
    if (!d.moved && Math.hypot(dx, dy) <= DRAG_THRESHOLD) return
    d.moved = true
    setPosition(clampPosition({ right: d.start.right - dx, bottom: d.start.bottom - dy }, window.innerWidth, window.innerHeight))
  }, [])

  const onPointerUp = useCallback((e: React.PointerEvent<HTMLElement>) => {
    const d = drag.current
    drag.current = null
    if (!d || d.id !== e.pointerId) return
    if (d.moved) {
      save({ right: d.start.right - (e.clientX - d.x), bottom: d.start.bottom - (e.clientY - d.y) })
    } else {
      onClick()
    }
  }, [onClick, save])

  const nudge = useCallback((dx: number, dy: number) => {
    save({ right: position.right - dx, bottom: position.bottom - dy })
  }, [position, save])

  const reset = useCallback(() => save(DEFAULT_POSITION), [save])

  return { position, onPointerDown, onPointerMove, onPointerUp, nudge, reset }
}

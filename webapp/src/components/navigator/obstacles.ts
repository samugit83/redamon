/**
 * Elements the AI Navigator must never cover (plan §9.3): the drawers fixed to a screen edge (the AI
 * Agent drawer, the recon logs, the Kali terminal, the overlay Drawer). Each registers its element
 * while open; the launcher steps aside while one overlaps it and the panel is placed outside them.
 * Same idea as useDrawerOffsets.
 */
'use client'

import { useEffect, useSyncExternalStore, type RefObject } from 'react'

type Listener = () => void

const elements = new Set<HTMLElement>()
const listeners = new Set<Listener>()
let version = 0

function emit() {
  version += 1
  listeners.forEach((l) => l())
}

/**
 * A drawer registers as it opens, usually mid slide-in (still off-screen), so its place is measured
 * again when its transition ends, when it is resized, and once shortly after, whichever comes.
 */
export function registerObstacle(el: HTMLElement): () => void {
  elements.add(el)
  emit()
  const remeasure = () => emit()
  el.addEventListener('transitionend', remeasure)
  const observer = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(remeasure) : null
  observer?.observe(el)
  const late = setTimeout(remeasure, 450)
  return () => {
    clearTimeout(late)
    observer?.disconnect()
    el.removeEventListener('transitionend', remeasure)
    elements.delete(el)
    emit()
  }
}

export function obstacleRects(): DOMRect[] {
  return [...elements].filter((el) => el.isConnected).map((el) => el.getBoundingClientRect())
    .filter((r) => r.width > 0 && r.height > 0)
}

function subscribe(l: Listener) {
  listeners.add(l)
  return () => listeners.delete(l)
}

/** Re-renders when an obstacle opens or closes. */
export function useObstaclesVersion(): number {
  return useSyncExternalStore(subscribe, () => version, () => 0)
}

/** Registers `ref`'s element as an obstacle while `active`. */
export function useNavigatorObstacle(ref: RefObject<HTMLElement | null>, active = true): void {
  useEffect(() => {
    const el = ref.current
    if (!active || !el) return
    return registerObstacle(el)
  }, [ref, active])
}

export interface Box { left: number; top: number; width: number; height: number }

export function overlaps(a: Box, b: DOMRect | Box): boolean {
  const bl = 'left' in b ? b.left : 0
  const bt = 'top' in b ? b.top : 0
  return a.left < bl + b.width && a.left + a.width > bl && a.top < bt + b.height && a.top + a.height > bt
}

/** Test seam. */
export function clearObstaclesForTests() {
  elements.clear()
  emit()
}

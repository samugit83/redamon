'use client'

import { Compass } from 'lucide-react'
import styles from './Navigator.module.css'

/** The round button (plan §9.3). Drag it anywhere; a click (no drag) opens the panel. */
export function NavigatorLauncher({ style, open, badge, panelId, handlers, onKeyMove, onKeyReset, onToggle }: {
  style: React.CSSProperties
  open: boolean
  badge: boolean
  panelId: string
  handlers: {
    onPointerDown: (e: React.PointerEvent<HTMLElement>) => void
    onPointerMove: (e: React.PointerEvent<HTMLElement>) => void
    onPointerUp: (e: React.PointerEvent<HTMLElement>) => void
  }
  onKeyMove: (dx: number, dy: number) => void
  onKeyReset: () => void
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      className={styles.launcher}
      style={style}
      data-testid="navigator-launcher"
      aria-label="AI Navigator"
      aria-expanded={open}
      aria-controls={panelId}
      title="AI Navigator"
      {...handlers}
      onKeyDown={(e) => {
        if (e.altKey) {
          const step = 16
          const moves: Record<string, [number, number]> = {
            ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step],
          }
          if (moves[e.key]) {
            e.preventDefault()
            onKeyMove(...moves[e.key])
            return
          }
          if (e.key === 'Home') {
            e.preventDefault()
            onKeyReset()
            return
          }
        }
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onToggle()
        }
      }}
      onClick={(e) => {
        // Pointer clicks are handled on pointerup (a drag must not toggle); a click with no pointer
        // (assistive technology) still toggles.
        if (e.detail === 0) onToggle()
      }}
    >
      <Compass size={22} aria-hidden />
      {badge && <span className={styles.launcherBadge} aria-label="New answer" />}
    </button>
  )
}

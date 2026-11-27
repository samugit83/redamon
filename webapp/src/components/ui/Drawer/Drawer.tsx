'use client'

import { ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import styles from './Drawer.module.css'
import { useNavigatorObstacle } from '@/components/navigator/obstacles'

export interface DrawerProps {
  /** Whether the drawer is open */
  isOpen: boolean
  /** Callback when drawer should close */
  onClose: () => void
  /** Position of the drawer */
  position?: 'left' | 'right'
  /** Behavior mode: 'push' shrinks adjacent content, 'overlay' slides over content */
  mode?: 'push' | 'overlay'
  /** Width of the drawer (CSS value) */
  width?: string
  /** Title shown in drawer header */
  title?: ReactNode
  /** Optional action elements rendered in the header, immediately before the close button */
  headerActions?: ReactNode
  /** Content of the drawer */
  children: ReactNode
  /** Additional class name */
  className?: string
  /** Enable drag-to-resize handle on the inner edge */
  resizable?: boolean
  /** Minimum width in px when resizing */
  minWidth?: number
  /** Maximum width in px when resizing */
  maxWidth?: number
  /** Called with new width in px while the user drags the resize handle */
  onResize?: (widthPx: number) => void
  /** Called once when the user releases the resize handle (final width in px) */
  onResizeEnd?: (widthPx: number) => void
}

interface ActiveDrag {
  pointerId: number
  startClientX: number
  startWidth: number
  prevUserSelect: string
  prevCursor: string
}

function clampWidth(value: number, minWidth: number, maxWidth: number): number {
  return Math.min(Math.max(value, minWidth), maxWidth)
}

function parseWidthPx(width: string, minWidth: number, maxWidth: number): number {
  const match = width.trim().match(/^(\d+(?:\.\d+)?)px$/i)
  if (!match) return clampWidth(minWidth, minWidth, maxWidth)
  const parsed = Number.parseFloat(match[1])
  if (!Number.isFinite(parsed)) return clampWidth(minWidth, minWidth, maxWidth)
  return clampWidth(parsed, minWidth, maxWidth)
}

export function Drawer({
  isOpen,
  onClose,
  position = 'left',
  mode = 'push',
  width = '300px',
  title,
  headerActions,
  children,
  className = '',
  resizable = false,
  minWidth = 240,
  maxWidth = 1200,
  onResize,
  onResizeEnd,
}: DrawerProps) {
  const positionClass = position === 'left' ? styles.drawerLeft : styles.drawerRight
  const modeClass = mode === 'overlay' ? styles.drawerOverlay : styles.drawerPush
  const drawerRef = useRef<HTMLDivElement | null>(null)
  // AI Navigator steps aside while this drawer is open (components/navigator/obstacles.ts).
  useNavigatorObstacle(drawerRef, isOpen)

  const parsedPropWidth = parseWidthPx(width, minWidth, maxWidth)
  const [overrideWidth, setOverrideWidth] = useState<{ propWidth: number; value: number } | null>(null)
  const hasLocalOverride = overrideWidth !== null && overrideWidth.propWidth === parsedPropWidth
  const currentWidth = hasLocalOverride
    ? clampWidth(overrideWidth.value, minWidth, maxWidth)
    : parsedPropWidth

  const [isResizing, setIsResizing] = useState(false)
  const currentWidthRef = useRef<number>(currentWidth)
  const activeDragRef = useRef<ActiveDrag | null>(null)
  const lastWidthRef = useRef<number | null>(null)

  useEffect(() => {
    currentWidthRef.current = currentWidth
  }, [currentWidth])

  useEffect(() => {
    if (!isOpen && activeDragRef.current) {
      const drag = activeDragRef.current
      document.body.style.userSelect = drag.prevUserSelect
      document.body.style.cursor = drag.prevCursor
      activeDragRef.current = null
      lastWidthRef.current = null
    }
  }, [isOpen])

  useEffect(() => {
    return () => {
      const drag = activeDragRef.current
      if (drag) {
        document.body.style.userSelect = drag.prevUserSelect
        document.body.style.cursor = drag.prevCursor
        activeDragRef.current = null
      }
    }
  }, [])

  const getMeasuredWidth = useCallback(() => {
    const rectWidth = drawerRef.current?.getBoundingClientRect().width ?? 0
    if (rectWidth > 0) {
      return clampWidth(rectWidth, minWidth, maxWidth)
    }
    return currentWidthRef.current
  }, [minWidth, maxWidth])

  const handlePointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!resizable) return
      if (e.pointerType === 'mouse' && e.button !== 0) return

      e.preventDefault()
      e.currentTarget.setPointerCapture?.(e.pointerId)

      const startWidth = getMeasuredWidth()
      activeDragRef.current = {
        pointerId: e.pointerId ?? 0,
        startClientX: e.clientX,
        startWidth,
        prevUserSelect: document.body.style.userSelect,
        prevCursor: document.body.style.cursor,
      }
      lastWidthRef.current = null
      setIsResizing(true)
      document.body.style.userSelect = 'none'
      document.body.style.cursor = 'col-resize'
    },
    [resizable, getMeasuredWidth]
  )

  const handlePointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      const drag = activeDragRef.current
      if (!drag) return
      if (e.pointerId !== undefined && drag.pointerId !== e.pointerId) return

      const el = drawerRef.current
      if (!el) return

      const rect = el.getBoundingClientRect()
      const raw =
        rect.width > 0
          ? position === 'left'
            ? e.clientX - rect.left
            : rect.right - e.clientX
          : position === 'left'
            ? drag.startWidth + (e.clientX - drag.startClientX)
            : drag.startWidth - (e.clientX - drag.startClientX)

      const clamped = clampWidth(raw, minWidth, maxWidth)
      lastWidthRef.current = clamped
      currentWidthRef.current = clamped
      setOverrideWidth({ propWidth: parsedPropWidth, value: clamped })
      onResize?.(clamped)
    },
    [position, minWidth, maxWidth, parsedPropWidth, onResize]
  )

  const finishResize = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      const drag = activeDragRef.current
      if (!drag) return
      if (e.pointerId !== undefined && drag.pointerId !== e.pointerId) return

      activeDragRef.current = null
      document.body.style.userSelect = drag.prevUserSelect
      document.body.style.cursor = drag.prevCursor

      if (e.currentTarget.releasePointerCapture) {
        try {
          if (!e.currentTarget.hasPointerCapture || e.currentTarget.hasPointerCapture(drag.pointerId)) {
            e.currentTarget.releasePointerCapture(drag.pointerId)
          }
        } catch {
          // Capture may already be released on pointerup/cancel.
        }
      }

      setIsResizing(false)
      const finalWidth = lastWidthRef.current
      lastWidthRef.current = null
      if (finalWidth != null) {
        onResizeEnd?.(finalWidth)
      }
    },
    [onResizeEnd]
  )

  const handleResizeKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (!resizable) return

      const step = e.shiftKey ? 64 : 16
      const baseWidth = getMeasuredWidth()
      let next: number | null = null

      if (e.key === 'ArrowRight') {
        next = baseWidth + (position === 'left' ? step : -step)
      } else if (e.key === 'ArrowLeft') {
        next = baseWidth + (position === 'left' ? -step : step)
      } else if (e.key === 'Home') {
        next = minWidth
      } else if (e.key === 'End') {
        next = maxWidth
      }

      if (next === null) return

      e.preventDefault()
      const clamped = clampWidth(next, minWidth, maxWidth)
      currentWidthRef.current = clamped
      setOverrideWidth({ propWidth: parsedPropWidth, value: clamped })
      onResize?.(clamped)
      onResizeEnd?.(clamped)
    },
    [resizable, getMeasuredWidth, position, minWidth, maxWidth, parsedPropWidth, onResize, onResizeEnd]
  )

  const handleClass = position === 'left' ? styles.resizeHandleRight : styles.resizeHandleLeft
  const activelyResizing = isResizing && isOpen && resizable

  return (
    <div
      ref={drawerRef}
      className={`${styles.drawer} ${positionClass} ${modeClass} ${isOpen ? styles.drawerOpen : ''} ${activelyResizing ? styles.drawerResizing : ''} ${className}`}
      style={{ '--drawer-custom-width': hasLocalOverride ? `${currentWidth}px` : width } as React.CSSProperties}
    >
      {title && (
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>{title}</h2>
          {headerActions && (
            <div className={styles.drawerHeaderActions}>{headerActions}</div>
          )}
          <button
            type="button"
            className={styles.drawerClose}
            onClick={onClose}
            aria-label="Close drawer"
          >
            ×
          </button>
        </div>
      )}
      <div className={styles.drawerContent}>{children}</div>
      {resizable && isOpen && (
        <div
          className={`${styles.resizeHandle} ${handleClass} ${activelyResizing ? styles.resizeHandleActive : ''}`}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={finishResize}
          onPointerCancel={finishResize}
          onLostPointerCapture={finishResize}
          onKeyDown={handleResizeKeyDown}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize drawer"
          tabIndex={0}
          aria-valuemin={minWidth}
          aria-valuemax={maxWidth}
          aria-valuenow={Math.round(currentWidth)}
        />
      )}
    </div>
  )
}

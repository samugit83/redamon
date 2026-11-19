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
  const [isResizing, setIsResizing] = useState(false)
  const lastWidthRef = useRef<number | null>(null)

  const handleResizeStart = useCallback(
    (e: React.MouseEvent) => {
      if (!resizable) return
      e.preventDefault()
      lastWidthRef.current = null
      setIsResizing(true)
    },
    [resizable],
  )

  useEffect(() => {
    if (!isResizing) return

    const handleMouseMove = (e: MouseEvent) => {
      const el = drawerRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const raw = position === 'left' ? e.clientX - rect.left : rect.right - e.clientX
      const clamped = Math.min(Math.max(raw, minWidth), maxWidth)
      lastWidthRef.current = clamped
      onResize?.(clamped)
    }

    const handleMouseUp = () => {
      setIsResizing(false)
      if (lastWidthRef.current != null) {
        onResizeEnd?.(lastWidthRef.current)
      }
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    const prevUserSelect = document.body.style.userSelect
    const prevCursor = document.body.style.cursor
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.userSelect = prevUserSelect
      document.body.style.cursor = prevCursor
    }
  }, [isResizing, position, minWidth, maxWidth, onResize, onResizeEnd])

  const handleClass = position === 'left' ? styles.resizeHandleRight : styles.resizeHandleLeft

  return (
    <div
      ref={drawerRef}
      className={`${styles.drawer} ${positionClass} ${modeClass} ${isOpen ? styles.drawerOpen : ''} ${isResizing ? styles.drawerResizing : ''} ${className}`}
      style={{ '--drawer-custom-width': width } as React.CSSProperties}
    >
      {title && (
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>{title}</h2>
          {headerActions && (
            <div className={styles.drawerHeaderActions}>{headerActions}</div>
          )}
          <button
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
          className={`${styles.resizeHandle} ${handleClass} ${isResizing ? styles.resizeHandleActive : ''}`}
          onMouseDown={handleResizeStart}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize drawer"
        />
      )}
    </div>
  )
}

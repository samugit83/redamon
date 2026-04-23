'use client'

import { useRef, useState, useEffect, useCallback, useMemo } from 'react'
import { Link2 } from 'lucide-react'
import { NODE_COLORS } from '../../config'
import { GraphData } from '../../types'
import type { ViewMode, TableViewMode } from '../ViewTabs'
import styles from './PageBottomBar.module.css'

interface PageBottomBarProps {
  data: GraphData | undefined
  is3D: boolean
  showLabels: boolean
  activeView: ViewMode
  tableViewMode?: TableViewMode
  // Table view filter props
  activeNodeTypes?: Set<string>
  nodeTypeCounts?: Record<string, number>
  onToggleNodeType?: (type: string) => void
  onSelectAllTypes?: () => void
  onClearAllTypes?: () => void
  // Session visibility props
  sessionChainIds?: string[]
  sessionTitles?: Record<string, string>
  hiddenSessions?: Set<string>
  onToggleSession?: (chainId: string) => void
  onShowAllSessions?: () => void
  onHideAllSessions?: () => void
}

export function PageBottomBar({
  data,
  is3D,
  showLabels,
  activeView,
  tableViewMode = 'all',
  activeNodeTypes,
  nodeTypeCounts,
  onToggleNodeType,
  onSelectAllTypes,
  onClearAllTypes,
  sessionChainIds = [],
  sessionTitles = {},
  hiddenSessions,
  onToggleSession,
  onShowAllSessions,
  onHideAllSessions,
}: PageBottomBarProps) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [canScrollLeft, setCanScrollLeft] = useState(false)
  const [canScrollRight, setCanScrollRight] = useState(false)
  const [sessionMenuOpen, setSessionMenuOpen] = useState(false)
  const sessionMenuRef = useRef<HTMLDivElement>(null)
  const sessionBtnRef = useRef<HTMLButtonElement>(null)
  const [menuPos, setMenuPos] = useState<{ left: number; bottom: number } | null>(null)

  const checkScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    setCanScrollLeft(el.scrollLeft > 0)
    setCanScrollRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 1)
  }, [])

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    checkScroll()
    const observer = new ResizeObserver(checkScroll)
    observer.observe(el)
    return () => observer.disconnect()
  }, [checkScroll])

  // Close session menu on outside click
  useEffect(() => {
    if (!sessionMenuOpen) return
    const handleClick = (e: MouseEvent) => {
      const target = e.target as Node
      // Keep open if click is on the menu or the toggle button
      if (sessionMenuRef.current?.contains(target)) return
      if (sessionBtnRef.current?.contains(target)) return
      setSessionMenuOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [sessionMenuOpen])

  const scroll = (direction: 'left' | 'right') => {
    const el = scrollRef.current
    if (!el) return
    el.scrollBy({ left: direction === 'left' ? -120 : 120, behavior: 'smooth' })
  }

  const sortedTypes = useMemo(
    () => nodeTypeCounts ? Object.keys(nodeTypeCounts).sort() : [],
    [nodeTypeCounts]
  )

  const visibleSessionCount = sessionChainIds.length - (hiddenSessions?.size ?? 0)

  const hideBar = activeView === 'sessions' || activeView === 'terminal' || activeView === 'roe' || (activeView === 'table' && tableViewMode !== 'all')

  if (hideBar) return null

  return (
    <div className={styles.bottomBar}>
      <div className={styles.legend}>
        <span className={styles.sectionTitle}>Filter:</span>
        {onToggleNodeType && (
          <div className={styles.chipActions}>
            <button className={styles.chipAction} onClick={onSelectAllTypes}>All</button>
            <button className={styles.chipAction} onClick={onClearAllTypes}>None</button>
          </div>
        )}
        {canScrollLeft && (
          <button className={styles.scrollBtn} onClick={() => scroll('left')}>
            ‹
          </button>
        )}
        <div
          ref={scrollRef}
          className={styles.legendItems}
          onScroll={checkScroll}
        >
          {sortedTypes.map(type => {
            const color = NODE_COLORS[type] || NODE_COLORS.Default
            const isActive = activeNodeTypes?.has(type) ?? true
            return (
              <button
                key={type}
                className={`${styles.typeChip} ${isActive ? styles.typeChipActive : ''}`}
                onClick={() => onToggleNodeType?.(type)}
                style={{ '--chip-color': color } as React.CSSProperties}
                aria-pressed={isActive}
              >
                <span className={styles.chipDot} />
                <span className={styles.chipLabel}>{type}</span>
                <span className={styles.chipCount}>{nodeTypeCounts?.[type] ?? 0}</span>
              </button>
            )
          })}
        </div>
        {canScrollRight && (
          <button className={styles.scrollBtn} onClick={() => scroll('right')}>
            ›
          </button>
        )}
      </div>

      {sessionChainIds.length > 0 && (
        <>
          <div className={styles.divider} />
          <div className={styles.sessionSection}>
            <button
              ref={sessionBtnRef}
              className={`${styles.sessionToggle} ${sessionMenuOpen ? styles.sessionToggleActive : ''}`}
              onClick={() => {
                if (!sessionMenuOpen && sessionBtnRef.current) {
                  const rect = sessionBtnRef.current.getBoundingClientRect()
                  setMenuPos({
                    left: rect.left + rect.width / 2,
                    bottom: window.innerHeight - rect.top + 8,
                  })
                }
                setSessionMenuOpen((prev: boolean) => !prev)
              }}
            >
              <Link2 size={12} />
              <span>Sessions</span>
              <span className={styles.sessionBadge}>
                {visibleSessionCount}/{sessionChainIds.length}
              </span>
            </button>

            {sessionMenuOpen && menuPos && (
              <div
                ref={sessionMenuRef}
                className={styles.sessionMenu}
                style={{
                  position: 'fixed',
                  left: menuPos.left,
                  bottom: menuPos.bottom,
                  transform: 'translateX(-50%)',
                }}
              >
                <div className={styles.sessionMenuHeader}>
                  <span>Attack Chain Sessions</span>
                  <div className={styles.sessionMenuActions}>
                    <button className={styles.chipAction} onClick={onShowAllSessions}>All</button>
                    <button className={styles.chipAction} onClick={onHideAllSessions}>None</button>
                  </div>
                </div>
                <div className={styles.sessionMenuList}>
                  {sessionChainIds.map(chainId => {
                    const isVisible = !hiddenSessions?.has(chainId)
                    return (
                      <button
                        key={chainId}
                        className={`${styles.sessionItem} ${isVisible ? styles.sessionItemActive : ''}`}
                        onClick={() => onToggleSession?.(chainId)}
                      >
                        <span className={styles.sessionDot} />
                        <span className={styles.sessionCode} title={sessionTitles[chainId] || chainId}>
                          {sessionTitles[chainId]
                            ? (sessionTitles[chainId].length > 30
                                ? sessionTitles[chainId].slice(0, 30) + '...'
                                : sessionTitles[chainId])
                            : chainId.slice(-8)}
                        </span>
                        <span className={styles.sessionStatus}>{isVisible ? 'ON' : 'OFF'}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      <div className={styles.divider} />

      <div className={styles.stats}>
        <span className={styles.sectionTitle}>Stats:</span>
        <div className={styles.statItems}>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>Nodes:</span>
            <span className={styles.statValue}>{data?.nodes.length ?? '-'}</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statLabel}>Links:</span>
            <span className={styles.statValue}>{data?.links.length ?? '-'}</span>
          </div>
        </div>
      </div>

    </div>
  )
}

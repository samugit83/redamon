'use client'

import { memo, type ReactNode } from 'react'
import { Loader2, AlertTriangle, Database, Search, Download, RefreshCw, SearchX } from 'lucide-react'
import styles from './RedZoneTableShell.module.css'

interface RedZoneTableShellProps {
  title: string
  meta?: string
  search: string
  onSearchChange: (value: string) => void
  searchPlaceholder?: string
  onExport?: () => void
  onRefresh?: () => void
  isLoading: boolean
  error: string | null
  rowCount: number
  filteredRowCount: number
  emptyLabel?: string
  noMatchLabel?: string
  children: ReactNode
}

export const RedZoneTableShell = memo(function RedZoneTableShell({
  title,
  meta,
  search,
  onSearchChange,
  searchPlaceholder = 'Search...',
  onExport,
  onRefresh,
  isLoading,
  error,
  rowCount,
  filteredRowCount,
  emptyLabel = 'No findings yet. Run a recon scan to populate this table.',
  noMatchLabel = 'No rows match your search.',
  children,
}: RedZoneTableShellProps) {
  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <span className={styles.title}>{title}</span>
          {meta && <span className={styles.meta}>{meta}</span>}
          <span className={styles.rowCount}>
            {filteredRowCount === rowCount ? `${rowCount}` : `${filteredRowCount}/${rowCount}`} rows
          </span>
        </div>
        <div className={styles.headerRight}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder={searchPlaceholder}
              value={search}
              onChange={e => onSearchChange(e.target.value)}
              aria-label={`Search ${title}`}
            />
          </div>
          {onRefresh && (
            <button className={styles.iconBtn} onClick={onRefresh} aria-label="Refresh" title="Refresh">
              <RefreshCw size={12} />
            </button>
          )}
          {onExport && (
            <button className={styles.exportBtn} onClick={onExport} aria-label="Export to Excel">
              <Download size={12} />
              <span>XLSX</span>
            </button>
          )}
        </div>
      </div>

      <div className={styles.body}>
        {isLoading ? (
          <div className={styles.stateContainer}>
            <Loader2 size={24} className={styles.spinner} />
            <p className={styles.stateText}>Loading...</p>
          </div>
        ) : error ? (
          <div className={styles.stateContainer}>
            <AlertTriangle size={24} className={styles.errorIcon} />
            <p className={styles.stateText}>Failed to load</p>
            <p className={styles.stateSubtext}>{error}</p>
          </div>
        ) : rowCount === 0 ? (
          <div className={styles.stateContainer}>
            <Database size={24} className={styles.emptyIcon} />
            <p className={styles.stateText}>{emptyLabel}</p>
          </div>
        ) : filteredRowCount === 0 ? (
          <div className={styles.stateContainer}>
            <SearchX size={24} className={styles.emptyIcon} />
            <p className={styles.stateText}>{noMatchLabel}</p>
            <p className={styles.stateSubtext}>{rowCount} total rows — clear the search to see them.</p>
          </div>
        ) : (
          <div className={styles.tableScroll}>{children}</div>
        )}
      </div>
    </div>
  )
})

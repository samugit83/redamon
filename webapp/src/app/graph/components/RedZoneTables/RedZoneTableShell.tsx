'use client'

import { memo, useCallback, useState, type ReactNode } from 'react'
import { Loader2, AlertTriangle, Database, Search, Download, RefreshCw, SearchX } from 'lucide-react'
import styles from './RedZoneTableShell.module.css'
import { ColumnFilterButton, ActiveFilterChips } from '../ColumnFilterPanel'
import type { RedZoneFilterUi } from './useRedZoneFilters'
import {
  exportRedZoneCsv,
  exportRedZoneJson,
  exportRedZoneMarkdown,
  type RedZoneExportConfig,
} from './exportCsv'

interface RedZoneTableShellProps {
  /** Per-column filtering, from `useRedZoneFilters`. Omit for an unfilterable sheet. */
  filterUi?: RedZoneFilterUi<unknown>
  title: string
  meta?: string
  search: string
  onSearchChange: (value: string) => void
  searchPlaceholder?: string
  /** Provide rows + columns to render CSV/JSON/MD export buttons. */
  exportConfig?: RedZoneExportConfig
  /** Legacy single-button CSV callback (kept for back-compat). */
  onExport?: () => void
  onRefresh?: () => void
  isLoading: boolean
  error: string | null
  rowCount: number
  filteredRowCount: number
  emptyLabel?: string
  noMatchLabel?: string
  /** Always-visible controls (e.g. a sheet/tab selector) shown above the body
   * in every state, so navigation never disappears when a sheet is empty. */
  toolbar?: ReactNode
  children: ReactNode
}

export const RedZoneTableShell = memo(function RedZoneTableShell({
  filterUi,
  title,
  meta,
  search,
  onSearchChange,
  searchPlaceholder = 'Search...',
  exportConfig,
  onExport,
  onRefresh,
  isLoading,
  error,
  rowCount,
  filteredRowCount,
  emptyLabel = 'No findings yet. Run a recon scan to populate this table.',
  noMatchLabel = 'No rows match your search.',
  toolbar,
  children,
}: RedZoneTableShellProps) {
  const [exporting, setExporting] = useState<'csv' | 'json' | 'md' | null>(null)
  const runExport = useCallback(
    async (format: 'csv' | 'json' | 'md', fn: () => Promise<void>) => {
      if (exporting) return
      setExporting(format)
      try { await fn() } finally { setExporting(null) }
    },
    [exporting],
  )
  const handleCsv = useCallback(() => {
    if (!exportConfig) return
    runExport('csv', () =>
      exportRedZoneCsv(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug),
    )
  }, [exportConfig, runExport])
  const handleJson = useCallback(() => {
    if (!exportConfig) return
    runExport('json', () =>
      exportRedZoneJson(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug),
    )
  }, [exportConfig, runExport])
  const handleMd = useCallback(() => {
    if (!exportConfig) return
    runExport('md', () =>
      exportRedZoneMarkdown(exportConfig.rows, exportConfig.sheetName, exportConfig.columns, exportConfig.fileSlug),
    )
  }, [exportConfig, runExport])

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
          {exportConfig ? (
            <>
              <button className={styles.exportBtn} onClick={handleCsv} disabled={!!exporting} aria-label="Export to CSV" title="Export to CSV">
                {exporting === 'csv'
                  ? <Loader2 size={12} className={styles.spinner} />
                  : <Download size={12} />}
                <span>CSV</span>
              </button>
              <button className={styles.exportBtn} onClick={handleJson} disabled={!!exporting} aria-label="Export to JSON" title="Export to JSON">
                {exporting === 'json'
                  ? <Loader2 size={12} className={styles.spinner} />
                  : <Download size={12} />}
                <span>JSON</span>
              </button>
              <button className={styles.exportBtn} onClick={handleMd} disabled={!!exporting} aria-label="Export to Markdown" title="Export to Markdown">
                {exporting === 'md'
                  ? <Loader2 size={12} className={styles.spinner} />
                  : <Download size={12} />}
                <span>MD</span>
              </button>
            </>
          ) : onExport ? (
            <button className={styles.exportBtn} onClick={onExport} aria-label="Export to CSV">
              <Download size={12} />
              <span>CSV</span>
            </button>
          ) : null}

          {filterUi && (
            <ColumnFilterButton
              profiles={filterUi.profiles}
              filters={filterUi.filters}
              kinds={filterUi.kinds}
              rows={filterUi.rows}
              accessor={filterUi.accessor}
              activeCount={filterUi.chips.length}
              onChange={filterUi.onChange}
              onClearColumn={filterUi.onClearColumn}
              onClearAll={filterUi.onClearAll}
              onArm={filterUi.onArm}
              disabled={rowCount === 0}
            />
          )}
        </div>
      </div>

      {filterUi && filterUi.chips.length > 0 && (
        <div className={styles.chipRow}>
          <ActiveFilterChips
            chips={filterUi.chips}
            onRemove={filterUi.onClearColumn}
            onClearAll={filterUi.onClearAll}
          />
        </div>
      )}

      <div className={styles.body}>
        {toolbar}
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
            <p className={styles.stateSubtext}>
              {rowCount} total rows - clear the search{filterUi && filterUi.chips.length > 0 ? ' or the active filters' : ''} to see them.
            </p>
          </div>
        ) : (
          <div className={styles.tableScroll}>{children}</div>
        )}
      </div>
    </div>
  )
})

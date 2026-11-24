'use client'

/**
 * Fixed-size client-side pagination for the three Scans-tab tables (Scheduled
 * scans, Scan queue, Run history). The page size is a constant (30) that the user
 * cannot change - each table shows at most 30 rows and pages through the rest.
 */
import { useState } from 'react'
import styles from './ScanScheduleTable.module.css'

/** Rows shown per page. Fixed by design; not user-adjustable. */
export const PAGE_SIZE = 30

/** Hard ceiling on how many rows a table will ever hold (across all pages). */
export const MAX_ROWS = 1000

export function usePaged<T>(rows: readonly T[]) {
  const [page, setPage] = useState(0)
  // Cap the whole table at MAX_ROWS before paging, so no table ever renders (or
  // pages through) more than the ceiling regardless of how much the source returns.
  const capped = rows.length > MAX_ROWS ? rows.slice(0, MAX_ROWS) : rows
  rows = capped
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  // Clamp back into range when the row set shrinks (a delete, a filter, a poll
  // that returned fewer rows) so the view never lands on an empty page.
  if (page > pageCount - 1) setPage(pageCount - 1)
  const start = page * PAGE_SIZE
  return {
    slice: rows.slice(start, start + PAGE_SIZE),
    page,
    pageCount,
    total: rows.length,
    setPage,
  }
}

export function Pager({
  page, pageCount, total, onPage,
}: {
  page: number
  pageCount: number
  total: number
  onPage: (p: number) => void
}) {
  // Nothing to page through: a single page fits entirely, so no controls.
  if (total <= PAGE_SIZE) return null
  return (
    <div className={styles.pager}>
      <button
        type="button"
        className={styles.pagerBtn}
        disabled={page <= 0}
        onClick={() => onPage(page - 1)}
        aria-label="Previous page"
      >
        ‹ Prev
      </button>
      <span className={styles.pagerLabel}>
        Page {page + 1} of {pageCount} · {total} total
      </span>
      <button
        type="button"
        className={styles.pagerBtn}
        disabled={page >= pageCount - 1}
        onClick={() => onPage(page + 1)}
        aria-label="Next page"
      >
        Next ›
      </button>
    </div>
  )
}

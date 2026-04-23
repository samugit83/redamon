'use client'

import { useState, useMemo, memo, Fragment } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getExpandedRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
  type ExpandedState,
} from '@tanstack/react-table'
import {
  ChevronDown,
  ChevronRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  Loader2,
  AlertCircle,
  Database,
} from 'lucide-react'
import type { GraphData } from '../../types'
import { NODE_COLORS } from '../../config'
import type { TableRow } from '../../hooks/useTableData'
import { ExpandedRowDetail } from './ExpandedRowDetail'
import styles from './DataTable.module.css'

interface DataTableProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  rows: TableRow[]
  globalFilter: string
  onGlobalFilterChange: (value: string) => void
}

const columnHelper = createColumnHelper<TableRow>()

export const DataTable = memo(function DataTable({
  data,
  isLoading,
  error,
  rows,
  globalFilter,
  onGlobalFilterChange,
}: DataTableProps) {
  const [sorting, setSorting] = useState<SortingState>([])
  const [expanded, setExpanded] = useState<ExpandedState>({})

  const columns = useMemo(() => [
    columnHelper.display({
      id: 'expand',
      header: '',
      size: 40,
      cell: ({ row }) => (
        <button
          className={styles.expandBtn}
          onClick={row.getToggleExpandedHandler()}
          aria-expanded={row.getIsExpanded()}
          aria-label={row.getIsExpanded() ? 'Collapse row' : 'Expand row'}
        >
          {row.getIsExpanded() ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
      ),
    }),
    columnHelper.accessor(row => row.node.type, {
      id: 'type',
      header: 'Type',
      size: 160,
      cell: info => {
        const type = info.getValue()
        const color = NODE_COLORS[type] || NODE_COLORS.Default
        return (
          <span className={styles.typeBadge} style={{ background: color }}>
            {type}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => row.node.name, {
      id: 'name',
      header: 'Name',
      size: 400,
      cell: info => (
        <span className={styles.nameCell} title={info.getValue()}>
          {info.getValue()}
        </span>
      ),
    }),
    columnHelper.accessor(row => Object.keys(row.node.properties).filter(k => k !== 'project_id' && k !== 'user_id').length, {
      id: 'properties',
      header: 'Props',
      size: 70,
      cell: info => (
        <span className={styles.connBadge}>{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor(row => row.connectionsIn.length, {
      id: 'connectionsIn',
      header: 'In',
      size: 70,
      cell: info => {
        const count = info.getValue()
        return count > 0 ? (
          <span className={styles.connBadge}>{count}</span>
        ) : (
          <span className={styles.connEmpty}>0</span>
        )
      },
    }),
    columnHelper.accessor(row => row.connectionsOut.length, {
      id: 'connectionsOut',
      header: 'Out',
      size: 70,
      cell: info => {
        const count = info.getValue()
        return count > 0 ? (
          <span className={styles.connBadge}>{count}</span>
        ) : (
          <span className={styles.connEmpty}>0</span>
        )
      },
    }),
    columnHelper.accessor(row => row.connectionsIn.length + row.connectionsOut.length, {
      id: 'totalConns',
      header: 'Conns',
      size: 60,
      cell: info => {
        const count = info.getValue()
        return count > 0 ? (
          <span className={styles.connBadge}>{count}</span>
        ) : (
          <span className={styles.connEmpty}>0</span>
        )
      },
    }),
  ], [])

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter, expanded },
    onSortingChange: setSorting,
    onGlobalFilterChange: onGlobalFilterChange,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    globalFilterFn: (row, _columnId, filterValue) => {
      const search = filterValue.toLowerCase()
      const name = row.original.node.name?.toLowerCase() || ''
      const type = row.original.node.type?.toLowerCase() || ''
      return name.includes(search) || type.includes(search)
    },
    initialState: {
      pagination: { pageSize: 50 },
    },
    getRowCanExpand: () => true,
  })

  const filteredRowCount = table.getFilteredRowModel().rows.length

  // Loading state
  if (isLoading) {
    return (
      <div className={styles.stateContainer}>
        <Loader2 size={32} className={styles.spinner} />
        <p className={styles.stateText}>Loading graph data...</p>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className={styles.stateContainer}>
        <AlertCircle size={32} className={styles.errorIcon} />
        <p className={styles.stateText}>Failed to load graph data</p>
        <p className={styles.stateSubtext}>{error.message}</p>
      </div>
    )
  }

  // Empty state
  if (!data || data.nodes.length === 0) {
    return (
      <div className={styles.stateContainer}>
        <Database size={32} className={styles.emptyIcon} />
        <p className={styles.stateText}>No data yet</p>
        <p className={styles.stateSubtext}>Run a reconnaissance scan to populate the graph.</p>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    className={styles.th}
                    style={{ width: header.getSize() }}
                    onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                    aria-sort={
                      header.column.getIsSorted() === 'asc'
                        ? 'ascending'
                        : header.column.getIsSorted() === 'desc'
                          ? 'descending'
                          : 'none'
                    }
                  >
                    <div className={styles.thContent}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getCanSort() && (
                        <span className={styles.sortIcon}>
                          {header.column.getIsSorted() === 'asc' ? (
                            <ArrowUp size={12} />
                          ) : header.column.getIsSorted() === 'desc' ? (
                            <ArrowDown size={12} />
                          ) : (
                            <ArrowUpDown size={12} />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => (
              <Fragment key={row.id}>
                <tr
                  className={`${styles.tr} ${row.getIsExpanded() ? styles.trExpanded : ''}`}
                >
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className={styles.td}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {row.getIsExpanded() && (
                  <tr className={styles.trExpandedDetail}>
                    <td colSpan={columns.length} className={styles.tdExpanded}>
                      <ExpandedRowDetail row={row.original} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className={styles.pagination}>
        <div className={styles.paginationInfo}>
          Page {table.getState().pagination.pageIndex + 1} of{' '}
          {table.getPageCount() || 1}
          <span className={styles.paginationRows}>
            ({filteredRowCount} rows)
          </span>
        </div>

        <div className={styles.paginationControls}>
          <button
            className={styles.pageBtn}
            onClick={() => table.setPageIndex(0)}
            disabled={!table.getCanPreviousPage()}
            aria-label="First page"
          >
            <ChevronsLeft size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="Previous page"
          >
            <ChevronLeft size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Next page"
          >
            <ChevronRight size={14} />
          </button>
          <button
            className={styles.pageBtn}
            onClick={() => table.setPageIndex(table.getPageCount() - 1)}
            disabled={!table.getCanNextPage()}
            aria-label="Last page"
          >
            <ChevronsRight size={14} />
          </button>
        </div>

        <div className={styles.pageSizeSelect}>
          <select
            value={table.getState().pagination.pageSize}
            onChange={e => table.setPageSize(Number(e.target.value))}
            className={styles.select}
            aria-label="Rows per page"
          >
            {[10, 25, 50, 100].map(size => (
              <option key={size} value={size}>
                {size} rows
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
})

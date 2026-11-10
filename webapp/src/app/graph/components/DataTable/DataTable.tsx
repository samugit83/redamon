'use client'

import { useState, useMemo, useEffect, useRef, memo, Fragment } from 'react'
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
  type ColumnFiltersState,
  type FilterFn,
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
import { badgeColors } from '../../utils'
import type { TableRow } from '../../hooks/useTableData'
import { ExpandedRowDetail } from './ExpandedRowDetail'
import { ColumnFilterButton, ActiveFilterChips } from '../ColumnFilterPanel'
import { useColumnFilterState } from '../../hooks/useColumnFilterState'
import { tableFilterScope } from '@/hooks/useUserPreferences'
import {
  describeFilter,
  isFilterActive,
  matchesFilter,
  profileColumn,
  regexFor,
  toDateMs,
  type CellAccessor,
  type ColumnFilter,
  type ColumnKind,
} from '../../utils/columnFilters'
import { UPDATED_AT_KEY, UpdatedAtCell, nodeUpdatedAt } from '../RedZoneTables/updatedAt'
import { NODE_ID_HEADER, NODE_ID_KEY, NodeIdCell, formatNodeId } from '../RedZoneTables/nodeId'
import { GraphNodeMuteButton } from '../MuteNode'
import styles from './DataTable.module.css'

/**
 * All Nodes has a FIXED column set (unlike the Node Inspector, whose columns
 * come from whatever the selected type carries), so the accessor is a small
 * explicit map rather than a property lookup. It must agree with the column
 * definitions below or a row would filter on one value and display another.
 */
const HIDDEN_PROP_KEYS = new Set(['project_id', 'user_id'])

const cellValue: CellAccessor<TableRow> = (row, columnId) => {
  switch (columnId) {
    case NODE_ID_KEY: return formatNodeId(row.node.id) ?? undefined
    case 'type': return row.node.type
    case 'name': return row.node.name
    case 'properties':
      return Object.keys(row.node.properties).filter(k => !HIDDEN_PROP_KEYS.has(k)).length
    case 'connectionsIn': return row.connectionsIn.length
    case 'connectionsOut': return row.connectionsOut.length
    case 'totalConns': return row.connectionsIn.length + row.connectionsOut.length
    case UPDATED_AT_KEY: return nodeUpdatedAt(row.node.properties)
    default: return undefined
  }
}

const FILTERABLE_COLUMNS = [
  { columnId: NODE_ID_KEY, label: NODE_ID_HEADER },
  { columnId: 'type', label: 'Type' },
  { columnId: 'name', label: 'Name' },
  { columnId: 'properties', label: 'Props' },
  { columnId: 'connectionsIn', label: 'In' },
  { columnId: 'connectionsOut', label: 'Out' },
  { columnId: 'totalConns', label: 'Conns' },
  { columnId: UPDATED_AT_KEY, label: 'Updated' },
]

interface AdvancedFilterValue {
  filter: ColumnFilter
  kind: ColumnKind
  rx: RegExp | null
}

/** Registered per column so pagination and the row counter see one row model. */
const advancedFilterFn: FilterFn<TableRow> = (row, columnId, value) => {
  const v = value as AdvancedFilterValue | undefined
  if (!v) return true
  return matchesFilter(cellValue(row.original, columnId), v.filter, v.kind, v.rx)
}

interface DataTableProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  rows: TableRow[]
  globalFilter: string
  onGlobalFilterChange: (value: string) => void
  /** Scopes persisted column filters; without it they simply are not saved. */
  projectId?: string | null
}

const columnHelper = createColumnHelper<TableRow>()

export const DataTable = memo(function DataTable({
  data,
  isLoading,
  error,
  rows,
  globalFilter,
  onGlobalFilterChange,
  projectId = null,
}: DataTableProps) {
  // Newest first on load, so a table opened after a scan leads with what that
  // scan just touched.
  const [sorting, setSorting] = useState<SortingState>([{ id: UPDATED_AT_KEY, desc: true }])
  const [expanded, setExpanded] = useState<ExpandedState>({})

  const [panelOpened, setPanelOpened] = useState(false)
  const {
    filters: colFilters,
    setColumnFilter,
    clearColumnFilter,
    clearAllFilters,
  } = useColumnFilterState(projectId, tableFilterScope('allNodes', null))

  // Restored filters arm the profiles too - the chips and the per-column kinds
  // both come from them, and a saved filter with no profile would narrow the
  // table while the UI showed nothing.
  const filtersArmed = panelOpened || Object.keys(colFilters).length > 0
  const profiles = useMemo(
    () => (filtersArmed ? FILTERABLE_COLUMNS.map(c => profileColumn(c.columnId, c.label, rows, cellValue)) : []),
    [filtersArmed, rows]
  )
  const kinds = useMemo(() => {
    const m: Record<string, ColumnKind> = {}
    for (const p of profiles) m[p.columnId] = p.kind
    return m
  }, [profiles])

  const columnFilters: ColumnFiltersState = useMemo(
    () =>
      Object.entries(colFilters)
        .filter(([, f]) => isFilterActive(f))
        .map(([id, f]) => ({
          id,
          value: { filter: f, kind: kinds[id] ?? 'text', rx: regexFor(f) } satisfies AdvancedFilterValue,
        })),
    [colFilters, kinds]
  )

  const activeChips = useMemo(
    () =>
      profiles
        .filter(p => isFilterActive(colFilters[p.columnId]))
        .map(p => ({ columnId: p.columnId, text: describeFilter(p.label, colFilters[p.columnId]) })),
    [profiles, colFilters]
  )

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
    columnHelper.accessor(row => formatNodeId(row.node.id) ?? undefined, {
      id: NODE_ID_KEY,
      filterFn: advancedFilterFn,
      header: NODE_ID_HEADER,
      size: 90,
      sortUndefined: 'last',
      // Numeric, or "10" would sort before "9".
      sortingFn: (a, b, id) => Number(a.getValue(id)) - Number(b.getValue(id)),
      cell: info => <NodeIdCell value={info.getValue()} />,
    }),
    columnHelper.accessor(row => row.node.type, {
      id: 'type',
      filterFn: advancedFilterFn,
      header: 'Type',
      size: 160,
      cell: info => {
        const type = info.getValue()
        const color = NODE_COLORS[type] || NODE_COLORS.Default
        return (
          <span className={styles.typeBadge} style={badgeColors(color)}>
            {type}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => row.node.name, {
      id: 'name',
      filterFn: advancedFilterFn,
      header: 'Name',
      size: 400,
      cell: info => {
        const name = info.getValue()
        const node = info.row.original.node
        const props = node.properties as Record<string, unknown>
        const method = typeof props.method === 'string' ? props.method.toUpperCase() : ''

        if (node.type === 'Endpoint' && method === 'GET') {
          // The full archived link (secret included) before the masked one.
          const fullUrl = typeof props.unmasked_url === 'string' && props.unmasked_url
            ? props.unmasked_url
            : typeof props.full_url === 'string' ? props.full_url : ''
          const baseurl = typeof props.baseurl === 'string' ? props.baseurl : ''
          const path = typeof props.path === 'string' ? props.path : ''
          let href = fullUrl
          if (!href && baseurl) {
            href = path
              ? `${baseurl.replace(/\/$/, '')}/${path.replace(/^\//, '')}`
              : baseurl
          }
          if (href) {
            return (
              <a
                className={styles.nameCell}
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                title={href}
                onClick={e => e.stopPropagation()}
              >
                {name}
              </a>
            )
          }
        }

        return (
          <span className={styles.nameCell} title={name}>
            {name}
          </span>
        )
      },
    }),
    columnHelper.accessor(row => Object.keys(row.node.properties).filter(k => k !== 'project_id' && k !== 'user_id').length, {
      id: 'properties',
      filterFn: advancedFilterFn,
      header: 'Props',
      size: 70,
      cell: info => (
        <span className={styles.connBadge}>{info.getValue()}</span>
      ),
    }),
    columnHelper.accessor(row => row.connectionsIn.length, {
      id: 'connectionsIn',
      filterFn: advancedFilterFn,
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
      filterFn: advancedFilterFn,
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
      filterFn: advancedFilterFn,
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
    columnHelper.accessor(
      // `nodeUpdatedAt` yields `undefined` for a node with no readable write
      // time, so `sortUndefined` below governs ALL unknowns uniformly.
      row => nodeUpdatedAt(row.node.properties),
      {
        id: UPDATED_AT_KEY,
        filterFn: advancedFilterFn,
        header: 'Updated',
        size: 150,
        // 'last' is direction-INDEPENDENT: a node with no timestamp is unknown,
        // not oldest, so reversing the sort must not float it to the top over
        // the recent rows the user just asked to see.
        sortUndefined: 'last',
        // Compared as epoch millis: a Cypher temporal is an object, and the
        // default comparator would sort every row as "[object Object]".
        sortingFn: (a, b) =>
          (toDateMs(nodeUpdatedAt(a.original.node.properties)) ?? 0) -
          (toDateMs(nodeUpdatedAt(b.original.node.properties)) ?? 0),
        cell: info => <UpdatedAtCell value={info.getValue()} />,
      },
    ),
    columnHelper.display({
      id: 'mute',
      header: '',
      size: 80,
      cell: ({ row }) => <GraphNodeMuteButton node={row.original.node} />,
    }),
  ], [])

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter, expanded, columnFilters },
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
      {/* Chips grow from the left; the control itself stays pinned to the
          right edge, as it is on every other table. */}
      <div className={styles.filterBar}>
        <div className={styles.filterBarChips}>
          <ActiveFilterChips
            chips={activeChips}
            onRemove={clearColumnFilter}
            onClearAll={clearAllFilters}
          />
        </div>
        <ColumnFilterButton
          profiles={profiles}
          filters={colFilters}
          kinds={kinds}
          rows={rows}
          accessor={cellValue}
          activeCount={activeChips.length}
          onChange={setColumnFilter}
          onClearColumn={clearColumnFilter}
          onClearAll={clearAllFilters}
          onArm={() => setPanelOpened(true)}
        />
      </div>

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

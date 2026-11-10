'use client'

import { useState, useMemo, useEffect, useRef, useCallback, Fragment } from 'react'
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
  type VisibilityState,
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
  Columns3,
  Search,
  Download,
} from 'lucide-react'
import type { GraphData } from '../../types'
import { NODE_COLORS } from '../../config'
import { HIDDEN_KEYS, getNodeUrl } from '../../utils'
import { propertyTitle, renderPropertyValue } from '../../utils/renderPropertyValue'
import { ExpandedRowDetail } from '../DataTable/ExpandedRowDetail'
import { ExternalLink } from '@/components/ui'
import { useTableData, type TableRow } from '../../hooks/useTableData'
import { useNodeDetailsPrefs, tableFilterScope } from '@/hooks/useUserPreferences'
import { useColumnFilterState } from '../../hooks/useColumnFilterState'
import {
  groupRowsByType,
  deriveDynamicColumnKeys,
  toggleHiddenColumn,
} from './nodeDetailsHelpers'
import {
  exportNodeDetailsCsv,
  exportNodeDetailsJson,
  exportNodeDetailsMarkdown,
} from './exportNodeDetails'
import { ColumnFilterButton, ActiveFilterChips } from '../ColumnFilterPanel'
import {
  describeFilter,
  getCellValue,
  isFilterActive,
  matchesFilter,
  profileColumn,
  propColumnId,
  regexFor,
  toDateMs,
  valueText,
  IN_COLUMN_ID,
  NAME_COLUMN_ID,
  NODE_ID_COLUMN_ID,
  OUT_COLUMN_ID,
  UPDATED_AT_COLUMN_ID,
  type ColumnFilter,
  type ColumnKind,
} from './nodeFilterHelpers'
import { UPDATED_AT_PROP, UpdatedAtCell, nodeUpdatedAt } from '../RedZoneTables/updatedAt'
import { NODE_ID_HEADER, NodeIdCell, formatNodeId } from '../RedZoneTables/nodeId'
import { GraphNodeMuteButton } from '../MuteNode'
import styles from './NodeDetailsTable.module.css'

interface NodeDetailsTableProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  /** Scopes persisted column filters. Without it the table still filters, it
   *  just forgets between visits (which is what tests and any embedding
   *  without a project context get). */
  projectId?: string | null
}

const columnHelper = createColumnHelper<TableRow>()

/**
 * The per-column filter value carried through TanStack. The compiled regex
 * rides along so `matchesFilter` never compiles one inside the row loop.
 */
interface AdvancedFilterValue {
  filter: ColumnFilter
  kind: ColumnKind
  rx: RegExp | null
}

/**
 * One filterFn for every column: the behaviour is chosen by the inferred kind
 * carried in the value, not by which column it is attached to.
 *
 * Registering these as real column filters (rather than filtering `rows` before
 * handing them to the table) is what keeps pagination, the row counter, sorting
 * and the CSV/JSON/MD export all reading from a single filtered row model.
 */
const advancedFilterFn: FilterFn<TableRow> = (row, columnId, value) => {
  const v = value as AdvancedFilterValue | undefined
  if (!v) return true
  return matchesFilter(getCellValue(row.original, columnId), v.filter, v.kind, v.rx)
}

export function NodeDetailsTable({ data, isLoading, error, projectId = null }: NodeDetailsTableProps) {
  // Build full TableRow set (rows + connection maps) using the existing hook.
  const allRows = useTableData(data)

  const { sortedTypes, typeCounts, rowsByType } = useMemo(
    () => groupRowsByType(allRows),
    [allRows]
  )

  // -- Selected type --------------------------------------------------------
  const [selectedNodeType, setSelectedNodeType] = useState<string | null>(null)
  useEffect(() => {
    if (selectedNodeType && typeCounts.has(selectedNodeType)) return
    setSelectedNodeType(sortedTypes[0] ?? null)
  }, [sortedTypes, typeCounts, selectedNodeType])

  const rows = useMemo(
    () => (selectedNodeType ? rowsByType.get(selectedNodeType) ?? [] : []),
    [rowsByType, selectedNodeType]
  )

  const UPDATED_AT_COL_ID = UPDATED_AT_COLUMN_ID

  // `updated_at` is lifted out of the alphabetical property columns and pinned
  // rightmost, so it sits in the same place whichever node type is selected -
  // and it is appended unconditionally, so a type whose nodes predate the
  // timestamp still shows the column (empty) rather than losing it.
  const dynamicColumnKeys = useMemo(
    () => deriveDynamicColumnKeys(rows).filter(k => k !== UPDATED_AT_PROP),
    [rows]
  )

  // -- Hideable column registry --------------------------------------------
  // Storage keys MUST be stable across data shapes since they're persisted
  // per-user. Property storage keys are the bare property name; the connection
  // count columns get fixed keys that can't collide with `prop:*` IDs.
  const FIXED_HIDEABLE = useMemo(
    () => [
      { storageKey: 'connectionsIn', columnId: 'connectionsIn', label: 'In' },
      { storageKey: 'connectionsOut', columnId: 'connectionsOut', label: 'Out' },
      { storageKey: UPDATED_AT_PROP, columnId: UPDATED_AT_COL_ID, label: 'Updated' },
    ],
    [UPDATED_AT_COL_ID]
  )
  const hideableColumns = useMemo(
    () => [
      ...dynamicColumnKeys.map(k => ({ storageKey: k, columnId: `prop:${k}`, label: k })),
      ...FIXED_HIDEABLE,
    ],
    [dynamicColumnKeys, FIXED_HIDEABLE]
  )

  // -- Persistent column visibility per node type --------------------------
  const { hiddenColumns, setHiddenColumns } = useNodeDetailsPrefs(selectedNodeType)
  const hiddenSet = useMemo(() => new Set(hiddenColumns), [hiddenColumns])
  const columnVisibility: VisibilityState = useMemo(() => {
    const v: VisibilityState = {}
    for (const c of hideableColumns) v[c.columnId] = !hiddenSet.has(c.storageKey)
    return v
  }, [hideableColumns, hiddenSet])

  // -- Build columns -------------------------------------------------------
  // Order: [expand, Node ID, name, ...dynamic, In, Out, Updated]
  // Node ID is pinned leftmost and not hideable: it is how a row is handed to
  // an external agent. In/Out/Updated are rightmost and user-hideable.
  const columns = useMemo(() => {
    const leading = [
      columnHelper.display({
        id: 'expand',
        header: '',
        size: 40,
        enableHiding: false,
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
        id: NODE_ID_COLUMN_ID,
        header: NODE_ID_HEADER,
        size: 90,
        enableHiding: false,
        filterFn: advancedFilterFn,
        sortUndefined: 'last',
        // Numeric, or "10" would sort before "9".
        sortingFn: (a, b, id) => Number(a.getValue(id)) - Number(b.getValue(id)),
        cell: info => <NodeIdCell value={info.getValue()} />,
      }),
      columnHelper.accessor(row => row.node.name, {
        id: NAME_COLUMN_ID,
        header: 'Name',
        size: 320,
        enableHiding: false,
        filterFn: advancedFilterFn,
        cell: info => {
          const name = info.getValue()
          const url = getNodeUrl(info.row.original.node)
          if (url) {
            return (
              <span className={styles.nameCell} title={name}>
                <ExternalLink href={url}>{name}</ExternalLink>
              </span>
            )
          }
          return (
            <span className={styles.nameCell} title={name}>
              {name}
            </span>
          )
        },
      }),
    ]

    const dynamic = dynamicColumnKeys.map(key =>
      columnHelper.accessor(row => row.node.properties[key], {
        id: propColumnId(key),
        header: key,
        size: 200,
        filterFn: advancedFilterFn,
        cell: info => (
          <span className={styles.propCell}
            title={propertyTitle(info.getValue(), key, info.row.original.node.type)}>
            {renderPropertyValue(info.getValue(), key, info.row.original.node.type)}
          </span>
        ),
      })
    )

    const trailing = [
      columnHelper.accessor(row => row.connectionsIn.length, {
        id: IN_COLUMN_ID,
        header: 'In',
        size: 70,
        filterFn: advancedFilterFn,
        cell: info => {
          const n = info.getValue()
          return n > 0 ? (
            <span className={styles.connBadge}>{n}</span>
          ) : (
            <span className={styles.connEmpty}>0</span>
          )
        },
      }),
      columnHelper.accessor(row => row.connectionsOut.length, {
        id: OUT_COLUMN_ID,
        header: 'Out',
        size: 70,
        filterFn: advancedFilterFn,
        cell: info => {
          const n = info.getValue()
          return n > 0 ? (
            <span className={styles.connBadge}>{n}</span>
          ) : (
            <span className={styles.connEmpty}>0</span>
          )
        },
      }),
      columnHelper.accessor(
        row => nodeUpdatedAt(row.node.properties),
        {
          id: UPDATED_AT_COL_ID,
          header: 'Updated',
          size: 150,
          filterFn: advancedFilterFn,
          // Direction-independent: an undated node is unknown, not oldest.
          sortUndefined: 'last',
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
        enableHiding: false,
        cell: ({ row }) => <GraphNodeMuteButton node={row.original.node} />,
      }),
    ]

    return [...leading, ...dynamic, ...trailing]
  }, [dynamicColumnKeys, UPDATED_AT_COL_ID])

  // -- Search + sorting + expansion ---------------------------------------
  const [globalFilter, setGlobalFilter] = useState('')
  // Newest first on load.
  const [sorting, setSorting] = useState<SortingState>([{ id: UPDATED_AT_COL_ID, desc: true }])
  const [expanded, setExpanded] = useState<ExpandedState>({})

  // -- Per-column filters ---------------------------------------------------
  // Scoped to the node type: a filter on `registrar` is meaningless once the
  // table is showing Ports, so each type carries its own set - saved, restored
  // and cleared independently.
  const filterScope = selectedNodeType ? tableFilterScope('nodeInspector', selectedNodeType) : null
  const {
    filters: colFilters,
    setColumnFilter,
    clearColumnFilter,
    clearAllFilters,
    pruneUnknown,
  } = useColumnFilterState(projectId, filterScope)

  // Reset transient state when type changes. Filters are NOT reset here - they
  // are restored per type by `useColumnFilterState`.
  useEffect(() => {
    setExpanded({})
    setSorting([])
    setGlobalFilter('')
  }, [selectedNodeType])

  /**
   * Every column a user can filter on, including ones currently hidden: wanting
   * to narrow by a property without also displaying it is normal, and the
   * active-filter chips keep a hidden column's filter from being invisible.
   */
  const filterableColumns = useMemo(
    () => [
      { columnId: NODE_ID_COLUMN_ID, label: NODE_ID_HEADER },
      { columnId: NAME_COLUMN_ID, label: 'Name' },
      ...dynamicColumnKeys.map(k => ({ columnId: propColumnId(k), label: k })),
      { columnId: IN_COLUMN_ID, label: 'In' },
      { columnId: OUT_COLUMN_ID, label: 'Out' },
    ],
    [dynamicColumnKeys]
  )

  useEffect(() => {
    pruneUnknown(filterableColumns.map(c => c.columnId))
  }, [filterableColumns, pruneUnknown])

  /**
   * Inference is a full pass over every row for every column, so it is deferred
   * until the user actually opens the filter panel once. A node type with 60
   * properties and 20k rows would otherwise pay for 1.2M value inspections on
   * every type switch, for a panel that is usually never opened.
   *
   * Keyed on the row set so it re-runs on type switch / refetch, but never on a
   * keystroke inside the panel.
   *
   * RESTORED filters arm it too. The chips and the correct per-column kinds are
   * both derived from these profiles, so a saved filter with no profile behind
   * it would narrow the table on load while the UI showed no filter at all -
   * the one state a filter bar must never be in.
   */
  const [panelOpened, setPanelOpened] = useState(false)
  const filtersArmed = panelOpened || Object.keys(colFilters).length > 0
  const profiles = useMemo(
    () => (filtersArmed ? filterableColumns.map(c => profileColumn(c.columnId, c.label, rows, getCellValue)) : []),
    [filtersArmed, filterableColumns, rows]
  )

  const kinds = useMemo(() => {
    const m: Record<string, ColumnKind> = {}
    for (const p of profiles) m[p.columnId] = p.kind
    return m
  }, [profiles])

  // Handed to TanStack. Inactive columns are dropped entirely so an untouched
  // filter object never costs a pass over the rows.
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


  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter, expanded, columnVisibility, columnFilters },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    globalFilterFn: (row, _columnId, filterValue) => {
      const search = String(filterValue).toLowerCase()
      if (!search) return true
      const name = row.original.node.name?.toLowerCase() || ''
      if (name.includes(search)) return true
      const props = row.original.node.properties as Record<string, unknown>
      for (const k of Object.keys(props)) {
        if (HIDDEN_KEYS.has(k)) continue
        const v = props[k]
        if (v == null) continue
        // `valueText`, not `String(v)`: Neo4j integers and timestamps are
        // objects, and stringifying them gives "[object Object]" - so searching
        // for a port or a date would silently match nothing.
        if (valueText(v).toLowerCase().includes(search)) return true
      }
      return false
    },
    initialState: { pagination: { pageSize: 50 } },
    getRowCanExpand: () => true,
  })

  const filteredRowCount = table.getFilteredRowModel().rows.length
  const visibleColCount = table.getVisibleLeafColumns().length

  // -- Type / column dropdown UI state ------------------------------------
  const [typeMenuOpen, setTypeMenuOpen] = useState(false)
  const [colsMenuOpen, setColsMenuOpen] = useState(false)
  const typeMenuRef = useRef<HTMLDivElement>(null)
  const colsMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!typeMenuOpen) return
    const onClick = (e: MouseEvent) => {
      if (!typeMenuRef.current?.contains(e.target as Node)) setTypeMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [typeMenuOpen])

  useEffect(() => {
    if (!colsMenuOpen) return
    const onClick = (e: MouseEvent) => {
      if (!colsMenuRef.current?.contains(e.target as Node)) setColsMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [colsMenuOpen])

  function toggleColumn(storageKey: string) {
    setHiddenColumns(toggleHiddenColumn(hiddenColumns, storageKey))
  }
  function showAllColumns() {
    setHiddenColumns([])
  }
  function hideAllColumns() {
    setHiddenColumns(hideableColumns.map(c => c.storageKey))
  }

  const visibleHideableCount = hideableColumns.filter(c => !hiddenSet.has(c.storageKey)).length
  const totalHideableCount = hideableColumns.length

  // -- Export handlers -----------------------------------------------------
  // Exports honor: (1) the selected node type, (2) the active search filter,
  // (3) the user's per-type column visibility prefs.
  const buildExportInput = () => ({
    nodeType: selectedNodeType ?? 'Nodes',
    rows: table.getFilteredRowModel().rows.map(r => r.original),
    visibleDynamicKeys: dynamicColumnKeys.filter(k => !hiddenSet.has(k)),
    showIn: !hiddenSet.has('connectionsIn'),
    showOut: !hiddenSet.has('connectionsOut'),
  })
  const [exporting, setExporting] = useState<'csv' | 'json' | 'md' | null>(null)
  const runExport = async (format: 'csv' | 'json' | 'md', fn: () => Promise<void>) => {
    if (exporting) return
    setExporting(format)
    try { await fn() } finally { setExporting(null) }
  }
  const handleExportCsv = () => runExport('csv', () => exportNodeDetailsCsv(buildExportInput()))
  const handleExportJson = () => runExport('json', () => exportNodeDetailsJson(buildExportInput()))
  const handleExportMarkdown = () => runExport('md', () => exportNodeDetailsMarkdown(buildExportInput()))

  // -- States --------------------------------------------------------------
  if (isLoading) {
    return (
      <div className={styles.stateContainer}>
        <Loader2 size={32} className={styles.spinner} />
        <p className={styles.stateText}>Loading graph data...</p>
      </div>
    )
  }
  if (error) {
    return (
      <div className={styles.stateContainer}>
        <AlertCircle size={32} className={styles.errorIcon} />
        <p className={styles.stateText}>Failed to load graph data</p>
        <p className={styles.stateSubtext}>{error.message}</p>
      </div>
    )
  }
  if (!data || data.nodes.length === 0 || sortedTypes.length === 0) {
    return (
      <div className={styles.stateContainer}>
        <Database size={32} className={styles.emptyIcon} />
        <p className={styles.stateText}>No data yet</p>
        <p className={styles.stateSubtext}>Run a reconnaissance scan to populate the graph.</p>
      </div>
    )
  }

  const selectedColor =
    (selectedNodeType && NODE_COLORS[selectedNodeType]) || NODE_COLORS.Default

  return (
    <div className={styles.container}>
      {/* Toolbar */}
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search…"
              value={globalFilter}
              onChange={e => setGlobalFilter(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <span className={styles.rowCount}>
            {filteredRowCount === rows.length ? `${rows.length}` : `${filteredRowCount}/${rows.length}`}
          </span>
        </div>
        <div className={styles.toolbarRight}>
          {/* Export buttons */}
          <button
            className={styles.exportBtn}
            onClick={handleExportCsv}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to CSV"
            title="Export to CSV"
          >
            {exporting === 'csv'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>CSV</span>
          </button>
          <button
            className={styles.exportBtn}
            onClick={handleExportJson}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to JSON"
            title="Export to JSON"
          >
            {exporting === 'json'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>JSON</span>
          </button>
          <button
            className={styles.exportBtn}
            onClick={handleExportMarkdown}
            disabled={rows.length === 0 || !!exporting}
            aria-label="Export to Markdown"
            title="Export to Markdown"
          >
            {exporting === 'md'
              ? <Loader2 size={12} className={styles.spinner} />
              : <Download size={12} />}
            <span>MD</span>
          </button>

          {/* Type selector */}
          <div ref={typeMenuRef} className={styles.menuContainer}>
            <button
              className={styles.menuButton}
              onClick={() => setTypeMenuOpen(o => !o)}
              aria-haspopup="listbox"
              aria-expanded={typeMenuOpen}
            >
              <span className={styles.typeDot} style={{ background: selectedColor }} />
              <span className={styles.menuButtonLabel}>{selectedNodeType ?? 'Select type'}</span>
              {selectedNodeType && (
                <span className={styles.menuButtonCount}>
                  {typeCounts.get(selectedNodeType)}
                </span>
              )}
              <ChevronDown size={14} />
            </button>
            {typeMenuOpen && (
              <div className={styles.dropdownMenu} role="listbox">
                {sortedTypes.map(type => (
                  <button
                    key={type}
                    role="option"
                    aria-selected={type === selectedNodeType}
                    className={`${styles.dropdownItem} ${type === selectedNodeType ? styles.dropdownItemActive : ''}`}
                    onClick={() => {
                      setSelectedNodeType(type)
                      setTypeMenuOpen(false)
                    }}
                  >
                    <span
                      className={styles.typeDot}
                      style={{ background: NODE_COLORS[type] || NODE_COLORS.Default }}
                    />
                    <span className={styles.dropdownItemLabel}>{type}</span>
                    <span className={styles.dropdownItemCount}>{typeCounts.get(type)}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Columns menu */}
          <div ref={colsMenuRef} className={styles.menuContainer}>
            <button
              className={styles.menuButton}
              onClick={() => setColsMenuOpen(o => !o)}
              disabled={totalHideableCount === 0}
              aria-haspopup="menu"
              aria-expanded={colsMenuOpen}
            >
              <Columns3 size={14} />
              <span className={styles.menuButtonLabel}>Columns</span>
              <span className={styles.menuButtonCount}>
                {visibleHideableCount}/{totalHideableCount}
              </span>
              <ChevronDown size={14} />
            </button>
            {colsMenuOpen && (
              <div className={styles.dropdownMenu} role="menu">
                <div className={styles.dropdownActions}>
                  <button className={styles.dropdownActionBtn} onClick={showAllColumns}>
                    Show all
                  </button>
                  <button className={styles.dropdownActionBtn} onClick={hideAllColumns}>
                    Hide all
                  </button>
                </div>
                <div className={styles.dropdownList}>
                  {hideableColumns.map(col => {
                    const visible = !hiddenSet.has(col.storageKey)
                    return (
                      <label key={col.storageKey} className={styles.dropdownCheckRow}>
                        <input
                          type="checkbox"
                          checked={visible}
                          onChange={() => toggleColumn(col.storageKey)}
                        />
                        <span>{col.label}</span>
                      </label>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
          <ColumnFilterButton
            profiles={profiles}
            filters={colFilters}
            kinds={kinds}
            rows={rows}
            accessor={getCellValue}
            activeCount={activeChips.length}
            onChange={setColumnFilter}
            onClearColumn={clearColumnFilter}
            onClearAll={clearAllFilters}
            onArm={() => setPanelOpened(true)}
            disabled={filterableColumns.length === 0}
          />
        </div>
      </div>

      <ActiveFilterChips
        chips={activeChips}
        onRemove={clearColumnFilter}
        onClearAll={clearAllFilters}
      />

      {/* Table */}
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
            {filteredRowCount === 0 && (
              <tr className={styles.noMatchRow}>
                <td colSpan={visibleColCount}>
                  No rows match the current filters. {rows.length} row{rows.length === 1 ? '' : 's'} in{' '}
                  {selectedNodeType ?? 'this type'}.
                </td>
              </tr>
            )}
            {table.getRowModel().rows.map(row => (
              <Fragment key={row.id}>
                <tr className={`${styles.tr} ${row.getIsExpanded() ? styles.trExpanded : ''}`}>
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className={styles.td}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {row.getIsExpanded() && (
                  <tr className={styles.trExpandedDetail}>
                    <td colSpan={visibleColCount} className={styles.tdExpanded}>
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
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount() || 1}
          <span className={styles.paginationRows}>({filteredRowCount} rows)</span>
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
}

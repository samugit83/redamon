'use client'

import { memo, useState, useRef, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { CalendarClock, GitCompare, Waypoints, Table2, Terminal, Shield, Search, Download, Loader2, SquareTerminal, Filter, Plus, Trash2, X, ChevronDown, Code, Target, Zap, Flag, Key, Server, Boxes, LockKeyhole, Bug, Network, Mail, ShieldAlert, Package, PackageSearch, History, Layers, Bot, Radiation, Swords, Droplets, ListOrdered } from 'lucide-react'
import { Toggle } from '@/components/ui'
import { AUTO_2D_THRESHOLD } from '../GraphCanvas'
import styles from './ViewTabs.module.css'

export type ViewMode = 'graph' | 'graphViews' | 'table' | 'sessions' | 'terminal' | 'roe'

export type TableViewMode =
  | 'nodeDetails'
  | 'all'
  | 'jsRecon'
  | 'aiSurface'
  | 'aiRisk'
  | 'killChain'
  | 'blastRadius'
  | 'takeover'
  | 'secrets'
  | 'netInitAccess'
  | 'graphql'
  | 'webInitAccess'
  | 'paramMatrix'
  | 'sharedInfra'
  | 'dnsEmail'
  | 'threatIntel'
  | 'jsDepSignals'
  | 'supplyChainSca'
  | 'dnsDrift'
  | 'webCachePoison'
  | 'reconDelta'
  | 'scanSchedule'
  | 'triage'

const TABLE_MODE_LABELS: Record<TableViewMode, string> = {
  nodeDetails: 'Node Inspector',
  all: 'All Nodes',
  jsRecon: 'JS Recon',
  aiSurface: 'AI Surface',
  aiRisk: 'AI Risk (LLM)',
  killChain: 'Kill-Chain',
  blastRadius: 'Blast Radius',
  takeover: 'Takeover',
  secrets: 'Secrets',
  netInitAccess: 'Net Init-Access',
  graphql: 'GraphQL',
  webInitAccess: 'Web Init-Access',
  paramMatrix: 'Parameter Matrix',
  sharedInfra: 'Shared Infra',
  dnsEmail: 'DNS & Email',
  threatIntel: 'Threat Intel',
  jsDepSignals: 'JS Dep Signals',
  supplyChainSca: 'Supply-Chain SCA',
  dnsDrift: 'DNS Drift',
  webCachePoison: 'Web Cache Poisoning',
  reconDelta: 'Recon Delta',
  scanSchedule: 'Scans',
  triage: 'Priority Board',
}

/**
 * Modes that have their own top-level tab, so the table dropdown must NOT also
 * advertise them - it would render a second, identical-looking tab beside the
 * real one. Kept as one list because the icon and the label used to compute this
 * separately and drifted apart the moment a tab was added.
 */
const OWN_TAB_MODES: readonly TableViewMode[] = ['reconDelta', 'scanSchedule', 'triage']

/** The mode the table dropdown should present itself as. */
export function dropdownMode(mode: TableViewMode | null | undefined): TableViewMode {
  return !mode || OWN_TAB_MODES.includes(mode) ? 'all' : mode
}

const TABLE_VIEW_MODES = new Set<string>(Object.keys(TABLE_MODE_LABELS))

/**
 * Deep links carry the table mode as a raw query param (`/graph?table=aiRisk`),
 * so the value is untrusted and may be stale. Two failure modes this closes:
 *
 *  1. An unknown value used to be cast straight to TableViewMode, matched no
 *     render branch, and silently fell through to All Nodes - the deep link
 *     appeared to work while showing the wrong table.
 *  2. `supplyChain` was renamed to `jsDepSignals` when the package/OSV feature
 *     took the "Supply-Chain" name, which would break every bookmark pointing
 *     at the old table. The alias keeps them working.
 */
// A Map, not an object literal: an object literal inherits from
// Object.prototype, so `?table=constructor` would look up a truthy function and
// be returned as if it were a valid mode - in a parser whose only job is to
// reject unknown input.
const LEGACY_TABLE_MODES = new Map<string, TableViewMode>([
  ['supplyChain', 'jsDepSignals'],
])

export function parseTableViewMode(raw: string | null | undefined): TableViewMode | null {
  if (!raw) return null
  if (TABLE_VIEW_MODES.has(raw)) return raw as TableViewMode
  return LEGACY_TABLE_MODES.get(raw) ?? null
}

/**
 * The unseen-rows count on a tab, or nothing at all when there is none.
 *
 * Rendering `0` would put a permanent grey dot on twenty tabs, which is the
 * opposite of what a badge is for - it only earns its place when it is telling
 * the user something changed. Capped at 999+ so a post-scan four-digit count
 * cannot push the dropdown wider than the menu.
 */
function UnseenBadge({ count }: { count?: number }) {
  if (!count || count < 1) return null
  return (
    <span className={styles.unseenBadge} title={`${count.toLocaleString()} new or updated since you last looked`}>
      {count > 999 ? '999+' : count}
    </span>
  )
}

export interface TunnelInfo {
  active: boolean
  host?: string
  port?: number
  srvPort?: number
}

export interface TunnelStatus {
  ngrok: TunnelInfo
  chisel: TunnelInfo
}

interface DataFilterView {
  id: string
  name: string
  description?: string
}

interface ViewTabsProps {
  activeView: ViewMode
  onViewChange: (view: ViewMode) => void
  // Table-only controls
  globalFilter?: string
  onGlobalFilterChange?: (value: string) => void
  onExport?: () => void
  onExportJson?: () => void
  onExportMarkdown?: () => void
  /** Which All-Nodes export format is currently being generated, if any. */
  allNodesExporting?: 'csv' | 'json' | 'md' | null
  totalRows?: number
  filteredRows?: number
  // Sessions badge
  sessionCount?: number
  // Tunnel status
  tunnelStatus?: TunnelStatus
  // Data filter selector
  dataFilters?: DataFilterView[]
  selectedFilterId?: string | null
  onSelectFilter?: (id: string | null) => void
  onDeleteFilter?: (id: string) => void
  // Table view mode (All Nodes vs specialized views vs red-zone analytics)
  tableViewMode?: TableViewMode
  onTableViewModeChange?: (mode: TableViewMode) => void
  /** Rows written since this user last opened each table tab. See `useUnseenCounts`. */
  unseenCounts?: Partial<Record<TableViewMode, number>>
  /** Sum of the above, badged on the table tab itself. */
  unseenTotal?: number
  // JS Recon table controls
  jsReconSearch?: string
  onJsReconSearchChange?: (value: string) => void
  onJsReconExportCsv?: () => void
  onJsReconExportJson?: () => void
  onJsReconExportMarkdown?: () => void
  /** Which JS Recon export format is currently being generated, if any. */
  jsReconExporting?: 'csv' | 'json' | 'md' | null
  jsReconMeta?: string
  // View mode toggles (shown in right section when graph active)
  is3D?: boolean
  showLabels?: boolean
  onToggle3D?: (value: boolean) => void
  onToggleLabels?: (value: boolean) => void
  /** False when the graph map is deliberately not fetched or drawn. */
  renderEnabled?: boolean
  onToggleRender?: (value: boolean) => void
  nodeCount?: number
}

export const ViewTabs = memo(function ViewTabs({
  activeView,
  onViewChange,
  globalFilter,
  onGlobalFilterChange,
  onExport,
  onExportJson,
  onExportMarkdown,
  allNodesExporting,
  totalRows,
  filteredRows,
  sessionCount,
  tunnelStatus,
  dataFilters,
  selectedFilterId,
  onSelectFilter,
  onDeleteFilter,
  tableViewMode = 'all',
  onTableViewModeChange,
  unseenCounts,
  unseenTotal,
  jsReconSearch,
  onJsReconSearchChange,
  onJsReconExportCsv,
  onJsReconExportJson,
  onJsReconExportMarkdown,
  jsReconExporting,
  jsReconMeta,
  is3D,
  showLabels,
  onToggle3D,
  onToggleLabels,
  renderEnabled = true,
  onToggleRender,
  nodeCount = 0,
}: ViewTabsProps) {
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const [tableMenuOpen, setTableMenuOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const tableMenuRef = useRef<HTMLDivElement>(null)

  const selectedFilter = dataFilters?.find(f => f.id === selectedFilterId)
  const hasFilters = dataFilters && dataFilters.length > 0

  // Close dropdown on outside click
  useEffect(() => {
    if (!dropdownOpen) return
    const handleClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [dropdownOpen])

  // Close table menu on outside click
  useEffect(() => {
    if (!tableMenuOpen) return
    const handleClick = (e: MouseEvent) => {
      if (tableMenuRef.current && !tableMenuRef.current.contains(e.target as Node)) {
        setTableMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [tableMenuOpen])

  const handleSelectFilter = useCallback((id: string) => {
    if (id === selectedFilterId) {
      onSelectFilter?.(null)
    } else {
      onSelectFilter?.(id)
    }
    setDropdownOpen(false)
  }, [selectedFilterId, onSelectFilter])

  const handleDeleteFilter = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    onDeleteFilter?.(id)
  }, [onDeleteFilter])

  const handleClearFilter = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onSelectFilter?.(null)
    setDropdownOpen(false)
  }, [onSelectFilter])

  return (
    <div className={styles.tabBar}>
      <div className={styles.tabs} role="tablist" aria-label="View mode">
        {/* Filter group -- create + select as a unified element */}
        <div className={styles.filterGroup}>
          <button
            role="tab"
            aria-selected={activeView === 'graphViews'}
            className={`${styles.filterGroupCreate} ${activeView === 'graphViews' ? styles.filterGroupCreateActive : ''}`}
            onClick={() => onViewChange('graphViews')}
            title="Surface Shaper"
          >
            <Filter size={13} />
            <Plus size={10} className={styles.createFilterPlus} />
          </button>

          {hasFilters && (
            <div className={styles.filterGroupSelect} ref={dropdownRef}>
              <button
                className={`${styles.filterGroupPill} ${selectedFilter ? styles.filterGroupPillActive : ''}`}
                onClick={() => setDropdownOpen(prev => !prev)}
                title={selectedFilter ? `Active surface: ${selectedFilter.name}` : 'Select a surface'}
              >
                {selectedFilter ? (
                  <>
                    <span className={styles.filterPillName}>{selectedFilter.name}</span>
                    <span
                      className={styles.filterPillClear}
                      onClick={handleClearFilter}
                      title="Clear surface"
                    >
                      <X size={10} />
                    </span>
                  </>
                ) : (
                  <span className={styles.filterPillLabel}>Surfaces</span>
                )}
              </button>

              {dropdownOpen && (
                <div className={styles.filterDropdown}>
                  <div className={styles.filterDropdownHeader}>Surface Shapers</div>
                  <div className={styles.filterDropdownList}>
                    {dataFilters!.map(f => (
                      <div
                        key={f.id}
                        className={`${styles.filterDropdownItem} ${f.id === selectedFilterId ? styles.filterDropdownItemActive : ''}`}
                        onClick={() => handleSelectFilter(f.id)}
                      >
                        <div className={styles.filterDropdownInfo}>
                          <span className={styles.filterDropdownName}>{f.name}</span>
                          {f.description && (
                            <span className={styles.filterDropdownDesc}>{f.description}</span>
                          )}
                        </div>
                        <button
                          className={styles.filterDropdownDelete}
                          onClick={(e) => handleDeleteFilter(f.id, e)}
                          title="Delete surface"
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        <button
          role="tab"
          aria-selected={activeView === 'graph'}
          className={`${styles.tab} ${activeView === 'graph' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('graph')}
        >
          <Waypoints size={14} />
          <span>Graph Map</span>
        </button>

        {/* Scan Timeline: Recon Delta + Scans are their own top-level tabs
            (not buried in the table dropdown). */}
        <button
          role="tab"
          aria-selected={activeView === 'table' && tableViewMode === 'reconDelta'}
          className={`${styles.tab} ${activeView === 'table' && tableViewMode === 'reconDelta' ? styles.tabActive : ''}`}
          onClick={() => { onTableViewModeChange?.('reconDelta'); onViewChange('table') }}
        >
          <GitCompare size={14} />
          <span>Recon Delta</span>
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'table' && tableViewMode === 'scanSchedule'}
          className={`${styles.tab} ${activeView === 'table' && tableViewMode === 'scanSchedule' ? styles.tabActive : ''}`}
          onClick={() => { onTableViewModeChange?.('scanSchedule'); onViewChange('table') }}
        >
          <CalendarClock size={14} />
          <span>Scans</span>
        </button>
        {/* Triage lives beside the graph it suppresses findings from, rather
            than as a separate top-level page. */}
        <button
          role="tab"
          aria-selected={activeView === 'table' && tableViewMode === 'triage'}
          className={`${styles.tab} ${activeView === 'table' && tableViewMode === 'triage' ? styles.tabActive : ''}`}
          onClick={() => { onTableViewModeChange?.('triage'); onViewChange('table') }}
        >
          <ListOrdered size={14} />
          <span>Priority Board</span>
        </button>

        <div ref={tableMenuRef} className={styles.tableMenuContainer}>
          <button
            role="tab"
            aria-selected={activeView === 'table' && tableViewMode !== 'reconDelta' && tableViewMode !== 'scanSchedule' && tableViewMode !== 'triage'}
            className={`${styles.tab} ${activeView === 'table' && tableViewMode !== 'reconDelta' && tableViewMode !== 'scanSchedule' && tableViewMode !== 'triage' ? styles.tabActive : ''}`}
            onClick={() => onViewChange('table')}
          >
            {(() => {
              const mode = dropdownMode(tableViewMode)
              const Icon =
                mode === 'nodeDetails' ? Layers
                : mode === 'jsRecon' ? Code
                : mode === 'aiSurface' ? Bot
                : mode === 'aiRisk' ? Radiation
                : mode === 'killChain' ? Target
                : mode === 'blastRadius' ? Zap
                : mode === 'takeover' ? Flag
                : mode === 'secrets' ? Key
                : mode === 'netInitAccess' ? Server
                : mode === 'graphql' ? Boxes
                : mode === 'webInitAccess' ? LockKeyhole
                : mode === 'paramMatrix' ? Bug
                : mode === 'sharedInfra' ? Network
                : mode === 'dnsEmail' ? Mail
                : mode === 'threatIntel' ? ShieldAlert
                : mode === 'jsDepSignals' ? Package
                : mode === 'supplyChainSca' ? PackageSearch
                : mode === 'dnsDrift' ? History
                : mode === 'webCachePoison' ? Droplets
                : Table2
              return <Icon size={14} />
            })()}
            <span>{TABLE_MODE_LABELS[dropdownMode(tableViewMode)]}</span>
            <UnseenBadge count={unseenTotal} />
            <ChevronDown
              size={18}
              strokeWidth={3}
              className={styles.tabDropdownIcon}
              onClick={(e) => { e.stopPropagation(); setTableMenuOpen(!tableMenuOpen) }}
            />
          </button>
          {tableMenuOpen && (
            <div className={styles.tableDropdownMenu}>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'nodeDetails' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('nodeDetails'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Layers size={12} /> Node Inspector
                <UnseenBadge count={unseenCounts?.nodeDetails} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'all' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('all'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Table2 size={12} /> All Nodes
                <UnseenBadge count={unseenCounts?.all} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'jsRecon' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('jsRecon'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Code size={12} /> JS Recon
                <UnseenBadge count={unseenCounts?.jsRecon} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'aiSurface' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('aiSurface'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Bot size={12} /> AI Surface
                <UnseenBadge count={unseenCounts?.aiSurface} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'aiRisk' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('aiRisk'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Radiation size={12} /> AI Risk (LLM)
                <UnseenBadge count={unseenCounts?.aiRisk} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'killChain' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('killChain'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Target size={12} /> Kill-Chain Explorer
                <UnseenBadge count={unseenCounts?.killChain} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'blastRadius' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('blastRadius'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Zap size={12} /> Technology Blast Radius
                <UnseenBadge count={unseenCounts?.blastRadius} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'takeover' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('takeover'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Flag size={12} /> Subdomain Takeover
                <UnseenBadge count={unseenCounts?.takeover} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'secrets' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('secrets'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Key size={12} /> Secrets & Credentials
                <UnseenBadge count={unseenCounts?.secrets} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'netInitAccess' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('netInitAccess'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Server size={12} /> Net Initial-Access
                <UnseenBadge count={unseenCounts?.netInitAccess} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'graphql' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('graphql'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Boxes size={12} /> GraphQL Risk Ledger
                <UnseenBadge count={unseenCounts?.graphql} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'webInitAccess' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('webInitAccess'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <LockKeyhole size={12} /> Web Initial-Access
                <UnseenBadge count={unseenCounts?.webInitAccess} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'paramMatrix' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('paramMatrix'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Bug size={12} /> Parameter Matrix
                <UnseenBadge count={unseenCounts?.paramMatrix} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'sharedInfra' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('sharedInfra'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Network size={12} /> Shared Infrastructure
                <UnseenBadge count={unseenCounts?.sharedInfra} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'dnsEmail' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('dnsEmail'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Mail size={12} /> DNS & Email Posture
                <UnseenBadge count={unseenCounts?.dnsEmail} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'threatIntel' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('threatIntel'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <ShieldAlert size={12} /> Threat Intel Overlay
                <UnseenBadge count={unseenCounts?.threatIntel} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'jsDepSignals' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('jsDepSignals'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Package size={12} /> JS Dep Signals
                <UnseenBadge count={unseenCounts?.jsDepSignals} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'supplyChainSca' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('supplyChainSca'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <PackageSearch size={12} /> Supply-Chain SCA
                <UnseenBadge count={unseenCounts?.supplyChainSca} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'dnsDrift' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('dnsDrift'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <History size={12} /> Historic DNS Drift
                <UnseenBadge count={unseenCounts?.dnsDrift} />
              </button>
              <button
                className={`${styles.tableDropdownItem} ${tableViewMode === 'webCachePoison' ? styles.tableDropdownItemActive : ''}`}
                onClick={() => { onTableViewModeChange?.('webCachePoison'); setTableMenuOpen(false); onViewChange('table') }}
              >
                <Droplets size={12} /> Web Cache Poisoning
                <UnseenBadge count={unseenCounts?.webCachePoison} />
              </button>
            </div>
          )}
        </div>
        <button
          role="tab"
          aria-selected={activeView === 'sessions'}
          className={`${styles.tab} ${activeView === 'sessions' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('sessions')}
        >
          <Terminal size={14} />
          <span>Reverse Shell</span>
          {sessionCount != null && sessionCount > 0 && (
            <span className={styles.badge}>{sessionCount}</span>
          )}
        </button>
        <button
          role="tab"
          aria-selected={activeView === 'terminal'}
          className={`${styles.tab} ${activeView === 'terminal' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('terminal')}
        >
          <SquareTerminal size={14} />
          <span>RedAmon Terminal</span>
        </button>
        {/* Navigates to the dedicated AI Attack Surface page (not a graph view). */}
        <Link href="/ai-attack-surface" className={styles.tab}>
          <Swords size={14} />
          <span>AI Gauntlet</span>
        </Link>
        <button
          role="tab"
          aria-selected={activeView === 'roe'}
          className={`${styles.tab} ${activeView === 'roe' ? styles.tabActive : ''}`}
          onClick={() => onViewChange('roe')}
        >
          <Shield size={14} />
          <span>RoE</span>
        </button>
      </div>

      <div className={styles.rightSection}>
      {activeView === 'graph' && onToggle3D && onToggleLabels && (
        <div className={styles.viewToggles}>
          {onToggleRender && (
            <div title={renderEnabled ? 'Stop fetching and drawing the graph (the tables keep working)' : 'Graph rendering is off - nothing is fetched or drawn'}>
              <Toggle
                checked={renderEnabled}
                onChange={onToggleRender}
                labelOn="Render"
                aria-label="Toggle graph rendering"
              />
            </div>
          )}
          {/* With rendering off there is no layout to switch or label, so both
              stay visible (no jumping toolbar) but inert. */}
          <div title={!renderEnabled ? 'Graph rendering is off' : nodeCount > AUTO_2D_THRESHOLD ? `3D disabled: graph has ${nodeCount.toLocaleString()} nodes (max ${AUTO_2D_THRESHOLD.toLocaleString()} for 3D)` : undefined}>
            <Toggle
              checked={nodeCount > AUTO_2D_THRESHOLD ? false : (is3D ?? false)}
              onChange={onToggle3D}
              labelOff="2D"
              labelOn="3D"
              disabled={!renderEnabled || nodeCount > AUTO_2D_THRESHOLD}
              aria-label="Toggle 2D/3D view"
            />
          </div>
          <Toggle
            checked={showLabels ?? false}
            onChange={onToggleLabels}
            labelOn="Labels"
            disabled={!renderEnabled}
            aria-label="Toggle labels"
          />
        </div>
      )}

      {activeView === 'table' && tableViewMode === 'all' && onGlobalFilterChange && (
        <div className={styles.tableControls}>
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search..."
              value={globalFilter || ''}
              onChange={e => onGlobalFilterChange(e.target.value)}
              aria-label="Search nodes"
            />
          </div>
          <span className={styles.rowCount}>
            {filteredRows === totalRows
              ? `${totalRows}`
              : `${filteredRows}/${totalRows}`}
          </span>
          <button className={styles.exportBtn} onClick={onExport} disabled={!!allNodesExporting} aria-label="Export to CSV" title="Export to CSV">
            {allNodesExporting === 'csv'
              ? <Loader2 size={12} className={styles.exportSpinner} />
              : <Download size={12} />}
            <span>CSV</span>
          </button>
          {onExportJson && (
            <button className={styles.exportBtn} onClick={onExportJson} disabled={!!allNodesExporting} aria-label="Export to JSON" title="Export to JSON">
              {allNodesExporting === 'json'
                ? <Loader2 size={12} className={styles.exportSpinner} />
                : <Download size={12} />}
              <span>JSON</span>
            </button>
          )}
          {onExportMarkdown && (
            <button className={styles.exportBtn} onClick={onExportMarkdown} disabled={!!allNodesExporting} aria-label="Export to Markdown" title="Export to Markdown">
              {allNodesExporting === 'md'
                ? <Loader2 size={12} className={styles.exportSpinner} />
                : <Download size={12} />}
              <span>MD</span>
            </button>
          )}
        </div>
      )}

      {activeView === 'table' && tableViewMode === 'jsRecon' && onJsReconSearchChange && (
        <div className={styles.tableControls}>
          {jsReconMeta && <span className={styles.rowCount}>{jsReconMeta}</span>}
          <div className={styles.searchWrapper}>
            <Search size={12} className={styles.searchIcon} />
            <input
              type="text"
              className={styles.searchInput}
              placeholder="Search JS Recon..."
              value={jsReconSearch || ''}
              onChange={e => onJsReconSearchChange(e.target.value)}
              aria-label="Search JS Recon findings"
            />
          </div>
          {onJsReconExportCsv && (
            <button className={styles.exportBtn} onClick={onJsReconExportCsv} disabled={!!jsReconExporting} aria-label="Export to CSV" title="Export to CSV">
              {jsReconExporting === 'csv'
                ? <Loader2 size={12} className={styles.exportSpinner} />
                : <Download size={12} />}
              <span>CSV</span>
            </button>
          )}
          {onJsReconExportJson && (
            <button className={styles.exportBtn} onClick={onJsReconExportJson} disabled={!!jsReconExporting} aria-label="Export to JSON" title="Export to JSON">
              {jsReconExporting === 'json'
                ? <Loader2 size={12} className={styles.exportSpinner} />
                : <Download size={12} />}
              <span>JSON</span>
            </button>
          )}
          {onJsReconExportMarkdown && (
            <button className={styles.exportBtn} onClick={onJsReconExportMarkdown} disabled={!!jsReconExporting} aria-label="Export to Markdown" title="Export to Markdown">
              {jsReconExporting === 'md'
                ? <Loader2 size={12} className={styles.exportSpinner} />
                : <Download size={12} />}
              <span>MD</span>
            </button>
          )}
        </div>
      )}
      </div>
    </div>
  )
})

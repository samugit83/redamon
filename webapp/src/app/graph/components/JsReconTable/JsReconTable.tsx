'use client'

import { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react'
import { Loader2, AlertTriangle } from 'lucide-react'
import { ExternalLink, SecretValue } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './JsReconTable.module.css'
import { ColumnFilterButton, ActiveFilterChips } from '../ColumnFilterPanel'
import { useRedZoneFilters, type RedZoneFilterColumn } from '../RedZoneTables/useRedZoneFilters'
import {
  UPDATED_AT_COLUMN,
  UpdatedAtCell,
  UpdatedAtTh,
  sortByUpdatedAt,
  useUpdatedAtSortDir,
  type SortDir,
} from '../RedZoneTables/updatedAt'
import { NODE_ID_KEY, NodeIdCell, NodeIdTh, withNodeId } from '../RedZoneTables/nodeId'
import { MuteNodeButton, useMuteNodeContext } from '../MuteNode'
import { type ValidationTone, validationLabel, validationRank, validationTone } from '@/lib/secrets/validationStatus'
import { alternateNameLabel, detectionMethodLabel } from '@/lib/secrets/jsReconSecret'
import {
  timestampSlug,
  downloadStreaming,
  streamCsvChunks,
  streamJsonArrayChunks,
  streamMarkdownTableChunks,
  CSV_MIME,
} from '../../utils/exportHelpers'

export type { JsReconData }

interface JsReconTableProps {
  projectId: string | null
  search: string
  onDataLoaded?: (data: JsReconData | null) => void
}

interface JsReconData {
  scan_metadata?: { scan_timestamp?: string; js_files_analyzed?: number; duration_seconds?: number }
  secrets?: any[]
  endpoints?: any[]
  dependencies?: any[]
  source_maps?: any[]
  dom_sinks?: any[]
  frameworks?: any[]
  dev_comments?: any[]
  cloud_assets?: any[]
  emails?: any[]
  ip_addresses?: any[]
  dev_references?: any[]
  object_references?: any[]
  discovered_subdomains?: string[]
  external_domains?: any[]
  summary?: Record<string, any>
}

const SUB_TABS = [
  { id: 'secrets', label: 'Secrets' },
  { id: 'endpoints', label: 'Endpoints' },
  { id: 'dependencies', label: 'Dependencies' },
  { id: 'sourcemaps', label: 'Source Maps' },
  { id: 'security', label: 'Security' },
  { id: 'surface', label: 'Attack Surface' },
] as const

const PAGE_SIZE = 50

/**
 * Filterable columns per sub-tab.
 *
 * Only the four homogeneous tabs are here. `security` and `surface` each stack
 * several different row shapes into one view (DOM sinks + frameworks + dev
 * comments; subdomains + cloud assets + emails + IPs + external domains), and a
 * single column set cannot describe them - a "severity" filter would silently
 * drop every row from the lists that have no severity at all.
 */
const TAB_FILTER_COLUMNS: Record<string, RedZoneFilterColumn[]> = {
  secrets: withNodeId([
    { key: 'severity', header: 'Severity' },
    { key: 'name', header: 'Type' },
    { key: 'category', header: 'Category' },
    { key: 'source_url', header: 'Source URL' },
    { key: 'detection_method', header: 'Detection' },
    { key: 'validation.status', header: 'Validation' },
    { key: 'confidence', header: 'Confidence' },
    { key: 'line_number', header: 'Line' },
    { key: 'alternate_names', header: 'Also matched as' },
    UPDATED_AT_COLUMN,
  ]),
  endpoints: withNodeId([
    { key: 'severity', header: 'Severity' },
    { key: 'method', header: 'Method' },
    { key: 'path', header: 'Path' },
    { key: 'full_url', header: 'Full URL' },
    { key: 'type', header: 'Type' },
    { key: 'category', header: 'Category' },
    { key: 'base_url', header: 'BaseURL' },
    { key: 'source_js', header: 'Source JS' },
    UPDATED_AT_COLUMN,
  ]),
  dependencies: withNodeId([
    { key: 'severity', header: 'Severity' },
    { key: 'finding_type', header: 'Finding Type' },
    { key: 'package_name', header: 'Package' },
    { key: 'scope', header: 'Scope' },
    { key: 'npm_exists', header: 'On npm' },
    { key: 'confidence', header: 'Confidence' },
    UPDATED_AT_COLUMN,
  ]),
  sourcemaps: withNodeId([
    { key: 'severity', header: 'Severity' },
    { key: 'finding_type', header: 'Finding Type' },
    { key: 'js_url', header: 'JS URL' },
    { key: 'map_url', header: 'Map URL' },
    { key: 'accessible', header: 'Accessible' },
    { key: 'discovery_method', header: 'Discovery' },
    { key: 'files_count', header: 'Files' },
    UPDATED_AT_COLUMN,
  ]),
}

const NO_COLUMNS: RedZoneFilterColumn[] = []

/** Rows for one tab, or [] for the tabs that stack several row shapes. */
function tabRows(data: JsReconData | null, tab: string): any[] {
  if (!data) return []
  if (tab === 'secrets') return data.secrets || []
  if (tab === 'endpoints') return data.endpoints || []
  if (tab === 'dependencies') return data.dependencies || []
  if (tab === 'sourcemaps') return data.source_maps || []
  return []
}

interface JsReconSheet {
  name: string
  rows: any[]
  columns: string[]
}

function getCol(row: any, col: string): unknown {
  return col.includes('.') ? col.split('.').reduce((o: any, k) => o?.[k], row) : row[col]
}

/** The stored names, not their display form, so an export greps like the graph. */
function withJoinedAlternateNames(row: any): any {
  return Array.isArray(row?.alternate_names) ? { ...row, alternate_names: row.alternate_names.join('; ') } : row
}

function buildJsReconSheets(data: JsReconData): JsReconSheet[] {
  const N = NODE_ID_KEY
  // Subdomains are bare strings with no node behind them, so no Node ID.
  return [
    { name: 'Secrets', rows: (data.secrets || []).map(withJoinedAlternateNames), columns: [N, 'severity', 'name', 'alternate_names', 'redacted_value', 'matched_text', 'secret_value', 'paired_secret', 'category', 'source_url', 'line_number', 'context', 'raw_context', 'detection_method', 'validation.status', 'confidence', 'validator_ref', 'updatedAt'] },
    { name: 'Endpoints', rows: data.endpoints || [], columns: [N, 'severity', 'method', 'path', 'full_url', 'type', 'category', 'base_url', 'source_js', 'parameters', 'line_number', 'updatedAt'] },
    { name: 'Dependencies', rows: data.dependencies || [], columns: [N, 'severity', 'finding_type', 'package_name', 'scope', 'npm_exists', 'confidence', 'title', 'detail', 'recommendation', 'source_urls', 'updatedAt'] },
    { name: 'Source Maps', rows: data.source_maps || [], columns: [N, 'severity', 'finding_type', 'js_url', 'map_url', 'accessible', 'discovery_method', 'files_count', 'source_files', 'secrets_in_source', 'secrets', 'updatedAt'] },
    { name: 'DOM Sinks', rows: data.dom_sinks || [], columns: [N, 'severity', 'finding_type', 'type', 'pattern', 'description', 'source_url', 'line', 'confidence', 'updatedAt'] },
    { name: 'Frameworks', rows: data.frameworks || [], columns: [N, 'name', 'version', 'severity', 'finding_type', 'source_url', 'confidence', 'updatedAt'] },
    { name: 'Dev Comments', rows: data.dev_comments || [], columns: [N, 'severity', 'type', 'content', 'source_url', 'line', 'confidence', 'updatedAt'] },
    { name: 'Cloud Assets', rows: data.cloud_assets || [], columns: [N, 'provider', 'type', 'url', 'source_url', 'updatedAt'] },
    { name: 'Emails', rows: data.emails || [], columns: [N, 'email', 'category', 'source_url', 'context', 'updatedAt'] },
    { name: 'IPs', rows: data.ip_addresses || [], columns: [N, 'ip', 'type', 'source_url', 'context', 'updatedAt'] },
    { name: 'Dev References', rows: data.dev_references || [], columns: [N, 'type', 'value', 'source_url', 'line', 'context', 'updatedAt'] },
    { name: 'Object Refs', rows: data.object_references || [], columns: [N, 'type', 'value', 'source_url', 'context', 'potential_idor', 'updatedAt'] },
    { name: 'Subdomains', rows: (data.discovered_subdomains || []).map(s => ({ subdomain: s })), columns: ['subdomain'] },
    { name: 'External Domains', rows: data.external_domains || [], columns: [N, 'domain', 'times_seen', 'updatedAt'] },
  ]
}

/**
 * Multi-section CSV: each non-empty section gets a "# Section: <name>" marker
 * row followed by its own header + data rows, separated by a blank line.
 * Streamed end-to-end (showSaveFilePicker if available) so the largest
 * findings dumps don't pin the file in browser memory.
 */
export async function exportJsReconCsv(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  function* dictRows(sheet: { rows: any[]; columns: string[] }): Iterable<Record<string, unknown>> {
    for (const r of sheet.rows) {
      const row: Record<string, unknown> = {}
      for (const col of sheet.columns) row[col] = getCol(r, col)
      yield row
    }
  }

  async function* combined(): AsyncGenerator<string> {
    yield '\uFEFF'
    let first = true
    for (const sheet of sheets) {
      if (!first) yield '\r\n'
      first = false
      yield `# Section: ${sheet.name}\r\n`
      // streamCsvChunks emits its own BOM + trailing CRLF; drop the BOM
      // (we already wrote one) but keep the trailing CRLF so the next
      // section's marker starts on a fresh line.
      let bomDropped = false
      for await (const chunk of streamCsvChunks(sheet.columns, dictRows(sheet))) {
        if (!bomDropped && chunk === '\uFEFF') { bomDropped = true; continue }
        yield chunk
      }
    }
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.csv`,
    CSV_MIME,
    () => combined(),
  )
}

export async function exportJsReconJson(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  function* dictRows(sheet: { rows: any[]; columns: string[] }): Iterable<Record<string, unknown>> {
    for (const r of sheet.rows) {
      const row: Record<string, unknown> = {}
      for (const col of sheet.columns) row[col] = getCol(r, col) ?? null
      yield row
    }
  }

  async function* combined(): AsyncGenerator<string> {
    if (sheets.length === 0) { yield '{}\n'; return }
    yield '{\n'
    for (let s = 0; s < sheets.length; s++) {
      const sheet = sheets[s]
      yield `  ${JSON.stringify(sheet.name)}: `
      yield* streamJsonArrayChunks(dictRows(sheet), { outerIndent: 2 })
      yield s === sheets.length - 1 ? '\n' : ',\n'
    }
    yield '}\n'
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.json`,
    'application/json;charset=utf-8',
    () => combined(),
  )
}

export async function exportJsReconMarkdown(data: JsReconData) {
  const sheets = buildJsReconSheets(data).filter(s => s.rows.length > 0)

  async function* combined(): AsyncGenerator<string> {
    yield `# JS Recon Findings\n\nGenerated: ${new Date().toISOString()}\n\n`
    for (const sheet of sheets) {
      yield `## ${sheet.name} (${sheet.rows.length})\n\n`
      yield* streamMarkdownTableChunks(
        sheet.columns,
        sheet.rows,
        (row, col) => getCol(row, col),
      )
      yield '\n\n'
    }
  }

  await downloadStreaming(
    `js-recon-${timestampSlug()}.md`,
    'text/markdown;charset=utf-8',
    () => combined(),
  )
}

function sevBadge(severity: string) {
  const cls = { critical: styles.badgeCritical, high: styles.badgeHigh, medium: styles.badgeMedium, low: styles.badgeLow, info: styles.badgeInfo }[severity] || styles.badgeInfo
  return <span className={`${styles.badge} ${cls}`}>{severity}</span>
}

const TONE_BADGE: Record<ValidationTone, string> = {
  live: styles.badgeLive,
  warn: styles.badgeFormatValid,
  dead: styles.badgeInvalid,
  none: styles.badgeUnvalidated,
}

function valBadge(status: string) {
  if (!status) return <span className={`${styles.badge} ${styles.badgeUnvalidated}`}>n/a</span>
  return (
    <span className={`${styles.badge} ${TONE_BADGE[validationTone(status)]}`}>{validationLabel(status)}</span>
  )
}
const SEVERITY_PRIORITY: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

function sortSecrets(rows: any[]): any[] {
  return [...rows].sort((a, b) => {
    const va = validationRank(a.validation?.status)
    const vb = validationRank(b.validation?.status)
    if (va !== vb) return va - vb
    const sa = SEVERITY_PRIORITY[a.severity ?? 'info'] ?? 4
    const sb = SEVERITY_PRIORITY[b.severity ?? 'info'] ?? 4
    return sa - sb
  })
}

export const JsReconTable = memo(function JsReconTable({
  projectId, search, onDataLoaded,
}: JsReconTableProps) {
  const [data, setData] = useState<JsReconData | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<string>('secrets')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const fetchData = useCallback(async (fresh = false) => {
    if (!projectId) return
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/js-recon/${projectId}/download${fresh ? '?fresh=1' : ''}`)
      if (res.status === 404) { setError('No JS Recon data. Run a recon scan with JS Recon enabled.'); return }
      if (!res.ok) throw await readApiError(res, 'Failed to load JS Recon data')
      const json = await res.json()
      setData(json)
      onDataLoaded?.(json)
    } catch (e) {
      setError(toApiError(e, 'Failed to load JS Recon data').message)
    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  useEffect(() => { fetchData() }, [fetchData])
  useEffect(() => { setLimit(PAGE_SIZE) }, [activeTab, search])

  // A mute anywhere on the page drops the node from this list. Fresh, because
  // the route's 10 s cache would otherwise hand the muted row straight back.
  const { epoch: muteEpoch } = useMuteNodeContext()
  const seenMuteEpoch = useRef(muteEpoch)
  useEffect(() => {
    if (muteEpoch === seenMuteEpoch.current) return
    seenMuteEpoch.current = muteEpoch
    void fetchData(true)
  }, [muteEpoch, fetchData])

  const tabCounts = useMemo(() => {
    if (!data) return {}
    return {
      secrets: data.secrets?.length || 0,
      endpoints: data.endpoints?.length || 0,
      dependencies: data.dependencies?.length || 0,
      sourcemaps: data.source_maps?.length || 0,
      security: (data.dom_sinks?.length || 0) + (data.frameworks?.length || 0) + (data.dev_comments?.length || 0),
      surface: (data.discovered_subdomains?.length || 0) + (data.cloud_assets?.length || 0) + (data.emails?.length || 0) + (data.ip_addresses?.length || 0) + (data.dev_references?.length || 0) + (data.external_domains?.length || 0),
    }
  }, [data])

  // Every hook below must run before the early returns further down, so they
  // sit here rather than beside the JSX that uses them.
  const filterColumns = TAB_FILTER_COLUMNS[activeTab] ?? NO_COLUMNS
  const rowsForTab = tabRows(data, activeTab)
  const { sortDir, toggleSort } = useUpdatedAtSortDir()
  const { filteredRows, filterUi } = useRedZoneFilters({
    rows: rowsForTab,
    columns: filterColumns,
    projectId,
    slug: 'jsRecon',
    sheet: activeTab,
    // `validation.status` is a dotted path into a nested object.
    accessor: (row: any, columnId: string) => getCol(row, columnId),
  })

  if (!projectId) return <div className={styles.stateContainer}>Select a project.</div>
  if (isLoading) return <div className={styles.stateContainer}><Loader2 size={24} className={styles.spinner} /> Loading JS Recon data...</div>
  if (error) return <div className={styles.stateContainer}><AlertTriangle size={20} />{error}</div>
  if (!data) return <div className={styles.stateContainer}>No data loaded.</div>

  return (
    <div className={styles.container}>
      {/* Sub-tabs */}
      <div className={styles.subTabsRow}>
      <div className={styles.subTabs}>
        {SUB_TABS.map(tab => (
          <button
            key={tab.id}
            className={activeTab === tab.id ? styles.subTabActive : styles.subTab}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {(tabCounts as any)[tab.id] > 0 && <span className={styles.subTabBadge}>{(tabCounts as any)[tab.id]}</span>}
          </button>
        ))}
      </div>
        {filterColumns.length > 0 && (
          <div className={styles.filterMenu}>
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
              disabled={rowsForTab.length === 0}
            />
          </div>
        )}
      </div>

      {filterUi.chips.length > 0 && (
        <div className={styles.chipRow}>
          <ActiveFilterChips
            chips={filterUi.chips}
            onRemove={filterUi.onClearColumn}
            onClearAll={filterUi.onClearAll}
          />
        </div>
      )}

      {/* Content */}
      <div className={styles.tableWrapper}>
        {activeTab === 'secrets' && <SecretsTable rows={filteredRows} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
        {activeTab === 'endpoints' && <EndpointsTable rows={filteredRows} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
        {activeTab === 'dependencies' && <DepsTable rows={filteredRows} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
        {activeTab === 'sourcemaps' && <SourceMapsTable rows={filteredRows} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
        {activeTab === 'security' && <SecurityTable data={data} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
        {activeTab === 'surface' && <SurfaceTable data={data} search={search} limit={limit} sortDir={sortDir} onToggleSort={toggleSort} />}
      </div>

      {/* Pagination */}
      {(() => {
        const totalForTab = (tabCounts as any)[activeTab] || 0
        if (limit < totalForTab) return (
          <div className={styles.pagination}>
            <button className={styles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
              Showing {Math.min(limit, totalForTab)} of {totalForTab} -- Load more
            </button>
          </div>
        )
        return null
      })()}
    </div>
  )
})

// ============================================================
// Sub-table components
// ============================================================

function filterRows(rows: readonly any[], search: string): any[] {
  if (!search) return [...rows]
  const s = search.toLowerCase()
  return rows.filter(r => {
    // Search ALL string/number values in the object (universal search)
    for (const v of Object.values(r)) {
      if (v == null) continue
      if (typeof v === 'object' && !Array.isArray(v)) {
        // Check one level deep (e.g., validation.status)
        for (const sv of Object.values(v as Record<string, unknown>)) {
          if (typeof sv === 'string' && sv.toLowerCase().includes(s)) return true
        }
      } else if (String(v).toLowerCase().includes(s)) {
        return true
      }
    }
    return false
  })
}

function SecretsTable({ rows, search, limit, sortDir, onToggleSort }: { rows: readonly any[]; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const filtered = sortByUpdatedAt(sortSecrets(filterRows(rows, search)), sortDir).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No secrets found.</div>
  return (
    <table className={styles.table}>
      <thead><tr><NodeIdTh /><th>Severity</th><th>Type</th><th>Secret</th><th>Source</th><th>Line</th><th>Detection</th><th>Validation</th><th>Confidence</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
      <tbody>
        {filtered.map((s, i) => (
          <tr key={s.id || i}>
            <td><NodeIdCell value={s.nodeId} /></td>
            <td>{sevBadge(s.severity)}</td>
            <td>
              {s.name}
              {Array.isArray(s.alternate_names) && s.alternate_names.length > 0 && (
                <span className={styles.alsoNames}>also: {s.alternate_names.map(alternateNameLabel).join(', ')}</span>
              )}
            </td>
            <td>
              <span className={styles.secretStack}>
                <SecretValue value={s.secret_value || s.matched_text} />
                {s.paired_secret && <SecretValue label="secret" value={s.paired_secret} />}
              </span>
            </td>
            <td className={styles.truncate} title={s.source_url}><ExternalLink href={s.source_url}>{s.source_url}</ExternalLink></td>
            <td>{typeof s.line_number === 'number' ? s.line_number : <span className={styles.nullCell}>—</span>}</td>
            <td>{detectionMethodLabel(s.detection_method) ?? <span className={styles.nullCell}>—</span>}</td>
            <td>{valBadge(s.validation?.status)}</td>
            <td>{s.confidence}</td>
            <td><UpdatedAtCell value={s.updatedAt} /></td>
            <td><MuteNodeButton name={s.name} graphId={s.nodeId} nodeId={s.id} label="Secret" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function EndpointsTable({ rows, search, limit, sortDir, onToggleSort }: { rows: readonly any[]; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No endpoints extracted.</div>
  return (
    <table className={styles.table}>
      <thead><tr><NodeIdTh /><th>Severity</th><th>Method</th><th>Path</th><th>Type</th><th>Category</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
      <tbody>
        {filtered.map((ep, i) => (
          <tr key={ep.id || i}>
            <td><NodeIdCell value={ep.nodeId} /></td>
            <td>{sevBadge(ep.severity || 'info')}</td>
            <td><code className={styles.mono}>{ep.method}</code></td>
            <td className={styles.truncate} title={ep.full_url || ep.path}><code className={styles.mono}>{ep.path}</code></td>
            <td>{ep.type}</td>
            <td>{ep.category}</td>
            <td className={styles.truncate} title={ep.source_js}><ExternalLink href={ep.source_js}>{ep.source_js}</ExternalLink></td>
            <td><UpdatedAtCell value={ep.updatedAt} /></td>
            <td><MuteNodeButton name={ep.path} graphId={ep.nodeId} label="Endpoint" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function DepsTable({ rows, search, limit, sortDir, onToggleSort }: { rows: readonly any[]; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No dependency confusion findings.</div>
  return (
    <table className={styles.table}>
      <thead><tr><NodeIdTh /><th>Severity</th><th>Package</th><th>Scope</th><th>On npm?</th><th>Detail</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
      <tbody>
        {filtered.map((d, i) => (
          <tr key={d.id || i}>
            <td><NodeIdCell value={d.nodeId} /></td>
            <td>{sevBadge(d.severity)}</td>
            <td><code className={styles.mono}>{d.package_name}</code></td>
            <td>{d.scope}</td>
            <td>{d.npm_exists ? 'Yes' : 'No'}</td>
            <td className={styles.truncate} title={d.detail}>{d.title}</td>
            <td><UpdatedAtCell value={d.updatedAt} /></td>
            <td><MuteNodeButton name={d.package_name} graphId={d.nodeId} nodeId={d.id} label="JsReconFinding" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function SourceMapsTable({ rows, search, limit, sortDir, onToggleSort }: { rows: readonly any[]; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const filtered = filterRows(rows, search).slice(0, limit)
  if (!filtered.length) return <div className={styles.stateContainer}>No source maps discovered.</div>
  return (
    <table className={styles.table}>
      <thead><tr><NodeIdTh /><th>JS File</th><th>Map URL</th><th>Accessible</th><th>Files</th><th>Secrets</th><th>Discovery</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
      <tbody>
        {filtered.map((sm, i) => (
          <tr key={sm.id || i}>
            <td><NodeIdCell value={sm.nodeId} /></td>
            <td className={styles.truncate} title={sm.js_url}><code className={styles.mono}><ExternalLink href={sm.js_url}>{sm.js_url}</ExternalLink></code></td>
            <td className={styles.truncate} title={sm.map_url}><code className={styles.mono}><ExternalLink href={sm.map_url}>{sm.map_url}</ExternalLink></code></td>
            <td>{sm.accessible ? 'Yes' : 'No'}</td>
            <td>{sm.files_count || 0}</td>
            <td>{sm.secrets_in_source || 0}</td>
            <td>{sm.discovery_method}</td>
            <td><UpdatedAtCell value={sm.updatedAt} /></td>
            <td><MuteNodeButton name={sm.js_url} graphId={sm.nodeId} nodeId={sm.id} label="JsReconFinding" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function SecurityTable({ data, search, limit, sortDir, onToggleSort }: { data: JsReconData; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const frameworks = sortByUpdatedAt(filterRows(data.frameworks || [], search), sortDir)
  const sinks = sortByUpdatedAt(filterRows(data.dom_sinks || [], search), sortDir)
  const comments = sortByUpdatedAt(filterRows(data.dev_comments || [], search), sortDir)
  const refs = sortByUpdatedAt(filterRows(data.object_references || [], search), sortDir)

  if (!frameworks.length && !sinks.length && !comments.length && !refs.length)
    return <div className={styles.stateContainer}>No security pattern findings.</div>

  // Calculate per-section limits upfront (not during render)
  let budget = limit
  const fwLimit = Math.min(frameworks.length, budget); budget -= fwLimit
  const sinkLimit = Math.min(sinks.length, budget); budget -= sinkLimit
  const cmtLimit = Math.min(comments.length, budget); budget -= cmtLimit
  const refLimit = Math.min(refs.length, budget)

  return (
    <>
      {frameworks.length > 0 && (
        <>
          <div className={styles.sectionTitle}>Frameworks ({frameworks.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Framework</th><th>Version</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{frameworks.slice(0, fwLimit).map((f, i) => (
              <tr key={f.id || i}><td><NodeIdCell value={f.nodeId} /></td><td>{f.name}</td><td>{f.version || '-'}</td><td className={styles.truncate} title={f.source_url}><ExternalLink href={f.source_url}>{f.source_url}</ExternalLink></td><td><UpdatedAtCell value={f.updatedAt} /></td><td><MuteNodeButton name={f.name} graphId={f.nodeId} nodeId={f.id} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {sinks.length > 0 && sinkLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>DOM Sinks ({sinks.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Severity</th><th>Type</th><th>Pattern</th><th>Source</th><th>Line</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{sinks.slice(0, sinkLimit).map((s, i) => (
              <tr key={s.id || i}>
                <td><NodeIdCell value={s.nodeId} /></td>
                <td>{sevBadge(s.severity)}</td>
                <td><code className={styles.mono}>{s.type}</code></td>
                <td className={styles.truncate} title={s.pattern}><code className={styles.mono}>{s.pattern}</code></td>
                <td className={styles.truncate} title={s.source_url}><ExternalLink href={s.source_url}>{s.source_url}</ExternalLink></td>
                <td>{s.line}</td>
                <td><UpdatedAtCell value={s.updatedAt} /></td>
                <td><MuteNodeButton name={s.type} graphId={s.nodeId} nodeId={s.id} label="JsReconFinding" /></td>
              </tr>
            ))}</tbody>
          </table>
        </>
      )}
      {comments.length > 0 && cmtLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Developer Comments ({comments.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Severity</th><th>Type</th><th>Content</th><th>Source</th><th>Line</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{comments.slice(0, cmtLimit).map((c, i) => (
              <tr key={c.id || i}>
                <td><NodeIdCell value={c.nodeId} /></td>
                <td>{sevBadge(c.severity)}</td>
                <td>{c.type}</td>
                <td className={styles.truncate} title={c.content}>{c.content}</td>
                <td className={styles.truncate} title={c.source_url}><ExternalLink href={c.source_url}>{c.source_url}</ExternalLink></td>
                <td>{c.line}</td>
                <td><UpdatedAtCell value={c.updatedAt} /></td>
                <td><MuteNodeButton name={c.type} graphId={c.nodeId} nodeId={c.id} label="JsReconFinding" /></td>
              </tr>
            ))}</tbody>
          </table>
        </>
      )}
      {refs.length > 0 && refLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Object References / IDOR ({refs.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Type</th><th>Value</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{refs.slice(0, refLimit).map((r, i) => (
              <tr key={i}><td><NodeIdCell value={r.nodeId} /></td><td>{r.type}</td><td><code className={styles.mono}>{r.value}</code></td><td className={styles.truncate} title={r.source_url}><ExternalLink href={r.source_url}>{r.source_url}</ExternalLink></td><td><UpdatedAtCell value={r.updatedAt} /></td><td><MuteNodeButton name={r.value} graphId={r.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
    </>
  )
}

function SurfaceTable({ data, search, limit, sortDir, onToggleSort }: { data: JsReconData; search: string; limit: number; sortDir: SortDir; onToggleSort: () => void }) {
  const subs = (data.discovered_subdomains || []).filter(s => !search || s.toLowerCase().includes(search.toLowerCase()))
  const cloud = sortByUpdatedAt(filterRows(data.cloud_assets || [], search), sortDir)
  const emails = sortByUpdatedAt(filterRows(data.emails || [], search), sortDir)
  const ips = sortByUpdatedAt(filterRows(data.ip_addresses || [], search), sortDir)
  const devRefs = sortByUpdatedAt(filterRows(data.dev_references || [], search), sortDir)
  const extDomains = sortByUpdatedAt(filterRows(data.external_domains || [], search), sortDir)

  if (!subs.length && !cloud.length && !emails.length && !ips.length && !devRefs.length && !extDomains.length)
    return <div className={styles.stateContainer}>No attack surface data found.</div>

  // Calculate per-section limits upfront
  let budget = limit
  const subsLimit = Math.min(subs.length, budget); budget -= subsLimit
  const cloudLimit = Math.min(cloud.length, budget); budget -= cloudLimit
  const emailsLimit = Math.min(emails.length, budget); budget -= emailsLimit
  const ipsLimit = Math.min(ips.length, budget); budget -= ipsLimit
  const devRefsLimit = Math.min(devRefs.length, budget); budget -= devRefsLimit
  const extLimit = Math.min(extDomains.length, budget)

  return (
    <>
      {subs.length > 0 && (
        <>
          <div className={styles.sectionTitle}>New Subdomains ({subs.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Subdomain</th><th>Updated</th></tr></thead>
            <tbody>{subs.slice(0, subsLimit).map(s => (
              <tr key={s}><td><NodeIdCell value={undefined} /></td><td><code className={styles.mono}>{s}</code></td><td><UpdatedAtCell value={undefined} /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {cloud.length > 0 && cloudLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Cloud Assets ({cloud.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Provider</th><th>Type</th><th>URL</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{cloud.slice(0, cloudLimit).map((a, i) => (
              <tr key={i}><td><NodeIdCell value={a.nodeId} /></td><td>{a.provider}</td><td>{a.type}</td><td className={styles.truncate} title={a.url}><code className={styles.mono}><ExternalLink href={a.url}>{a.url}</ExternalLink></code></td><td className={styles.truncate} title={a.source_url}><ExternalLink href={a.source_url}>{a.source_url}</ExternalLink></td><td><UpdatedAtCell value={a.updatedAt} /></td><td><MuteNodeButton name={a.url} graphId={a.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {emails.length > 0 && emailsLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Email Addresses ({emails.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Email</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{emails.slice(0, emailsLimit).map((e, i) => (
              <tr key={i}><td><NodeIdCell value={e.nodeId} /></td><td>{e.email}</td><td className={styles.truncate} title={e.source_url}><ExternalLink href={e.source_url}>{e.source_url}</ExternalLink></td><td><UpdatedAtCell value={e.updatedAt} /></td><td><MuteNodeButton name={e.email} graphId={e.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {ips.length > 0 && ipsLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Internal IPs ({ips.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>IP</th><th>Type</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{ips.slice(0, ipsLimit).map((ip, i) => (
              <tr key={i}><td><NodeIdCell value={ip.nodeId} /></td><td><code className={styles.mono}>{ip.ip}</code></td><td>{ip.type}</td><td className={styles.truncate} title={ip.source_url}><ExternalLink href={ip.source_url}>{ip.source_url}</ExternalLink></td><td><UpdatedAtCell value={ip.updatedAt} /></td><td><MuteNodeButton name={ip.ip} graphId={ip.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {devRefs.length > 0 && devRefsLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>Developer References ({devRefs.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Type</th><th>Value</th><th>Source</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{devRefs.slice(0, devRefsLimit).map((r, i) => (
              <tr key={i}><td><NodeIdCell value={r.nodeId} /></td><td>{r.type}</td><td className={styles.truncate} title={r.context || r.value}><code className={styles.mono}>{r.value}</code></td><td className={styles.truncate} title={r.source_url}><ExternalLink href={r.source_url}>{r.source_url}</ExternalLink></td><td><UpdatedAtCell value={r.updatedAt} /></td><td><MuteNodeButton name={r.value} graphId={r.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
      {extDomains.length > 0 && extLimit > 0 && (
        <>
          <div className={styles.sectionTitle}>External Domains ({extDomains.length})</div>
          <table className={styles.table}>
            <thead><tr><NodeIdTh /><th>Domain</th><th>Times Seen</th><UpdatedAtTh dir={sortDir} onToggle={onToggleSort} /><th /></tr></thead>
            <tbody>{extDomains.slice(0, extLimit).map((d, i) => (
              <tr key={i}><td><NodeIdCell value={d.nodeId} /></td><td><code className={styles.mono}>{d.domain}</code></td><td>{d.times_seen}</td><td><UpdatedAtCell value={d.updatedAt} /></td><td><MuteNodeButton name={d.domain} graphId={d.nodeId} label="JsReconFinding" /></td></tr>
            ))}</tbody>
          </table>
        </>
      )}
    </>
  )
}

'use client'

import { memo, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import type { RedZoneExportConfig } from './exportCsv'
import { useRedZoneFilters, type RedZoneFilterColumn } from './useRedZoneFilters'
import {
  UPDATED_AT_COLUMN,
  UpdatedAtCell,
  UpdatedAtTh,
  useUpdatedAtSort,
} from './updatedAt'
import { NODE_ID_COLUMN, NodeIdCell, NodeIdTh } from './nodeId'
import { MuteNodeButton } from '../MuteNode'
import {
  SeverityBadge,
  Mono,
  Truncated,
  ListCell,
  NumCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

interface TakeoverRow {
  nodeId: string | null
  id: string
  /** "takeover scan", "urlscan history" or "live check". */
  foundBy: string
  hostname: string
  parentType: string
  cnameTarget: string | null
  provider: string
  method: string
  verdict: string
  /** The problem-page outcome (likely_takeover, possible_takeover, dangling_dns). */
  outcome: string | null
  confidence: number | null
  severity: string
  sources: string[]
  confirmationCount: number | null
  evidence: string | null
  firstSeen: string | null
  lastSeen: string | null
  detectedAt: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 100

/** Module-level so the filter profiles are not rebuilt on every render. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'hostname', header: 'Hostname' },
  { key: 'foundBy', header: 'Found by' },
  { key: 'cnameTarget', header: 'CNAME Target' },
  { key: 'provider', header: 'Provider' },
  { key: 'method', header: 'Method' },
  { key: 'verdict', header: 'Verdict' },
  { key: 'confidence', header: 'Confidence' },
  { key: 'severity', header: 'Severity' },
  { key: 'sources', header: 'Sources' },
  { key: 'confirmationCount', header: '# Confirm' },
  { key: 'evidence', header: 'Evidence' },
  { key: 'firstSeen', header: 'First Seen' },
  { key: 'lastSeen', header: 'Last Seen' },
  UPDATED_AT_COLUMN,
]

const VERDICT_CLASS: Record<string, string> = {
  confirmed: rowStyles.sevCritical,
  likely: rowStyles.sevHigh,
  manual_review: rowStyles.sevInfo,
}

function VerdictChip({ verdict }: { verdict: string }) {
  const cls = VERDICT_CLASS[verdict] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{verdict.replace('_', ' ')}</span>
}

interface Props { projectId: string | null }

export const TakeoverTable = memo(function TakeoverTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<TakeoverRow>('takeover', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'takeover',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() =>
    rows.length > 0
      ? {
          rows: sortedRows,
          sheetName: 'Takeover',
          fileSlug: 'redzone-takeover',
          columns: COLUMNS,
        }
      : undefined,
    [sortedRows, rows.length],
  )

  const meta =
    data?.meta && rows.length
      ? `${(data.meta as any).confirmed ?? 0} confirmed / ${(data.meta as any).likely ?? 0} likely / ${(data.meta as any).manualReview ?? 0} manual`
      : undefined

  return (
    <RedZoneTableShell
      title="Subdomain Takeover Watchlist"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search hostname, provider, CNAME target..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No takeover findings yet. Enable Subdomain Takeover in project settings and run recon."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Hostname</th>
            <th>Found by</th>
            <th>CNAME Target</th>
            <th>Provider</th>
            <th>Method</th>
            <th>Verdict</th>
            <th>Conf.</th>
            <th>Severity</th>
            <th>Sources</th>
            <th>#</th>
            <th>Evidence</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={r.id || `${r.hostname}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td>{r.hostname ? <HostCell host={r.hostname} /> : <Truncated text={r.hostname} max={220} />}</td>
              <td><Mono>{r.foundBy}</Mono></td>
              <td>{r.cnameTarget ? <HostCell host={r.cnameTarget} /> : <Truncated text={r.cnameTarget} max={220} />}</td>
              <td><Mono>{r.provider}</Mono></td>
              <td><Mono>{r.method}</Mono></td>
              <td><VerdictChip verdict={r.verdict} /></td>
              <td>{r.confidence != null ? <span className={rowStyles.numCell}>{r.confidence}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><ListCell items={r.sources} max={3} /></td>
              <td><NumCell value={r.confirmationCount} /></td>
              <td><Truncated text={r.evidence} max={260} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.hostname} graphId={r.nodeId} nodeId={r.id} label="Vulnerability" /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {limit < filtered.length && (
        <div className={rowStyles.loadMoreBar}>
          <button className={rowStyles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
            Showing {sliced.length} of {filtered.length} - Load more
          </button>
        </div>
      )}
    </RedZoneTableShell>
  )
})

'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  SeverityBadge,
  Mono,
  Truncated,
  ListCell,
  NumCell,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

interface TakeoverRow {
  id: string
  hostname: string
  parentType: string
  cnameTarget: string | null
  provider: string
  method: string
  verdict: string
  confidence: number | null
  severity: string
  sources: string[]
  confirmationCount: number | null
  evidence: string | null
  firstSeen: string | null
  lastSeen: string | null
  detectedAt: string | null
}

const PAGE_SIZE = 100

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
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Takeover',
      [
        { key: 'hostname', header: 'Hostname' },
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
      ],
      'redzone-takeover',
    )
  }, [filtered])

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
      onExport={rows.length > 0 ? handleExport : undefined}
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
            <th>Hostname</th>
            <th>CNAME Target</th>
            <th>Provider</th>
            <th>Method</th>
            <th>Verdict</th>
            <th>Conf.</th>
            <th>Severity</th>
            <th>Sources</th>
            <th>#</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={r.id || `${r.hostname}-${i}`}>
              <td><Truncated text={r.hostname} max={220} /></td>
              <td><Truncated text={r.cnameTarget} max={220} /></td>
              <td><Mono>{r.provider}</Mono></td>
              <td><Mono>{r.method}</Mono></td>
              <td><VerdictChip verdict={r.verdict} /></td>
              <td>{r.confidence != null ? <span className={rowStyles.numCell}>{r.confidence}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><ListCell items={r.sources} max={3} /></td>
              <td><NumCell value={r.confirmationCount} /></td>
              <td><Truncated text={r.evidence} max={260} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {limit < filtered.length && (
        <div className={rowStyles.loadMoreBar}>
          <button className={rowStyles.loadMoreBtn} onClick={() => setLimit(l => l + PAGE_SIZE)}>
            Showing {sliced.length} of {filtered.length} — Load more
          </button>
        </div>
      )}
    </RedZoneTableShell>
  )
})

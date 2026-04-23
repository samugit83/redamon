'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  Mono,
  Truncated,
  NumCell,
  CvssCell,
  ListCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface BlastRadiusRow {
  techName: string
  techVersion: string | null
  cveCount: number
  maxCvss: number | null
  kevCount: number
  baseUrlCount: number
  ipCount: number
  severities: string[]
  topCveIds: string[]
}

const PAGE_SIZE = 100

interface Props { projectId: string | null }

export const BlastRadiusTable = memo(function BlastRadiusTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<BlastRadiusRow>('blastRadius', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Blast-Radius',
      [
        { key: 'techName', header: 'Technology' },
        { key: 'techVersion', header: 'Version' },
        { key: 'cveCount', header: 'CVE Count' },
        { key: 'maxCvss', header: 'Max CVSS' },
        { key: 'kevCount', header: 'KEV Count' },
        { key: 'baseUrlCount', header: 'BaseURLs' },
        { key: 'ipCount', header: 'IPs' },
        { key: 'severities', header: 'Severities' },
        { key: 'topCveIds', header: 'Top CVE IDs' },
      ],
      'redzone-blast-radius',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="Technology Blast Radius"
      meta={rows.length ? `${rows.length} technologies with known CVEs` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search tech name, CVE, version..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No technologies with mapped CVEs. Run nmap + vuln scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Technology</th>
            <th>Version</th>
            <th>CVEs</th>
            <th>Max CVSS</th>
            <th>KEV</th>
            <th>BaseURLs</th>
            <th>IPs</th>
            <th>Top CVEs</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.techName}-${r.techVersion || ''}-${i}`}>
              <td><Truncated text={r.techName} max={200} /></td>
              <td>{r.techVersion ? <Mono>{r.techVersion}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><NumCell value={r.cveCount} /></td>
              <td><CvssCell score={r.maxCvss} /></td>
              <td>
                {r.kevCount > 0 ? (
                  <span className={rowStyles.kevChip}>{r.kevCount} KEV</span>
                ) : (
                  <span className={rowStyles.nullCell}>-</span>
                )}
              </td>
              <td><NumCell value={r.baseUrlCount} /></td>
              <td><NumCell value={r.ipCount} /></td>
              <td><ListCell items={r.topCveIds} max={3} /></td>
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

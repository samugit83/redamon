'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  Mono,
  Truncated,
  ListCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface WebInitAccessRow {
  baseUrl: string
  scheme: string | null
  statusCode: number | null
  server: string | null
  subdomain: string | null
  authEndpointPaths: string[]
  authEndpointMethods: string[]
  authCategories: string[]
  authEndpointCount: number
  totalEndpointCount: number
  vulnTags: string[]
  headerGrid: Record<string, boolean>
  grade: string
}

const PAGE_SIZE = 100

const HEADER_CHECKS = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']
const HEADER_SHORT: Record<string, string> = {
  'Content-Security-Policy': 'CSP',
  'Strict-Transport-Security': 'HSTS',
  'X-Frame-Options': 'XFO',
  'X-Content-Type-Options': 'XCTO',
  'Referrer-Policy': 'Ref-Pol',
  'Permissions-Policy': 'Perm-Pol',
}

const GRADE_CLASS: Record<string, string> = {
  A: rowStyles.sevLow,
  B: rowStyles.sevLow,
  C: rowStyles.sevMedium,
  D: rowStyles.sevHigh,
  F: rowStyles.sevCritical,
}

function GradeChip({ grade }: { grade: string }) {
  const cls = GRADE_CLASS[grade] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`} style={{ minWidth: 20, display: 'inline-block', textAlign: 'center' }}>{grade}</span>
}

function HeaderCell({ present }: { present: boolean }) {
  return (
    <span className={present ? rowStyles.boolTrue : rowStyles.boolFalse} title={present ? 'present' : 'MISSING'}>
      {present ? '✓' : '✗'}
    </span>
  )
}

interface Props { projectId: string | null }

export const WebInitAccessTable = memo(function WebInitAccessTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<WebInitAccessRow>('webInitAccess', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    const flat = filtered.map(r => ({
      baseUrl: r.baseUrl,
      subdomain: r.subdomain,
      scheme: r.scheme,
      statusCode: r.statusCode,
      server: r.server,
      grade: r.grade,
      authEndpointCount: r.authEndpointCount,
      totalEndpointCount: r.totalEndpointCount,
      authEndpointPaths: r.authEndpointPaths,
      authCategories: r.authCategories,
      vulnTags: r.vulnTags,
      CSP: r.headerGrid['Content-Security-Policy'],
      HSTS: r.headerGrid['Strict-Transport-Security'],
      'X-Frame-Options': r.headerGrid['X-Frame-Options'],
      'X-Content-Type-Options': r.headerGrid['X-Content-Type-Options'],
      'Referrer-Policy': r.headerGrid['Referrer-Policy'],
      'Permissions-Policy': r.headerGrid['Permissions-Policy'],
    }))
    exportRedZoneXlsx(
      flat,
      'Web-Init-Access',
      [
        { key: 'baseUrl', header: 'BaseURL' },
        { key: 'subdomain', header: 'Subdomain' },
        { key: 'scheme', header: 'Scheme' },
        { key: 'statusCode', header: 'Status' },
        { key: 'server', header: 'Server' },
        { key: 'grade', header: 'Grade' },
        { key: 'authEndpointCount', header: 'Auth Endpoints' },
        { key: 'totalEndpointCount', header: 'Total Endpoints' },
        { key: 'authEndpointPaths', header: 'Auth Paths' },
        { key: 'authCategories', header: 'Auth Categories' },
        { key: 'vulnTags', header: 'Vuln Tags' },
        { key: 'CSP', header: 'CSP' },
        { key: 'HSTS', header: 'HSTS' },
        { key: 'X-Frame-Options', header: 'X-Frame-Options' },
        { key: 'X-Content-Type-Options', header: 'X-Content-Type-Options' },
        { key: 'Referrer-Policy', header: 'Referrer-Policy' },
        { key: 'Permissions-Policy', header: 'Permissions-Policy' },
      ],
      'redzone-web-init-access',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="Web Initial-Access Panel"
      meta={rows.length ? `${rows.length} BaseURLs with auth endpoints or header/auth findings` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search BaseURL, subdomain, vuln, auth path..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No auth endpoints or web-layer security findings yet. Run resource_enum + vuln_scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>BaseURL</th>
            <th>Subdomain</th>
            <th>Auth EPs</th>
            <th>Grade</th>
            {HEADER_CHECKS.map(h => <th key={h} title={h}>{HEADER_SHORT[h]}</th>)}
            <th>Vuln Tags</th>
            <th>Server</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.baseUrl}-${i}`}>
              <td><Truncated text={r.baseUrl} max={260} /></td>
              <td><Truncated text={r.subdomain} max={160} /></td>
              <td>
                {r.authEndpointCount > 0 ? (
                  <span title={r.authEndpointPaths.slice(0, 5).join('\n')}>
                    <span className={rowStyles.numCell}>{r.authEndpointCount}</span>
                  </span>
                ) : <span className={rowStyles.nullCell}>0</span>}
              </td>
              <td><GradeChip grade={r.grade} /></td>
              {HEADER_CHECKS.map(h => (
                <td key={h} style={{ textAlign: 'center' }}><HeaderCell present={!!r.headerGrid[h]} /></td>
              ))}
              <td><ListCell items={r.vulnTags} max={3} /></td>
              <td><Truncated text={r.server} max={120} /></td>
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

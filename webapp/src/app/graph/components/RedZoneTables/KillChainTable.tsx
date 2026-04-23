'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  SeverityBadge,
  Mono,
  Truncated,
  CvssCell,
  KevChip,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

interface KillChainRow {
  subdomain: string | null
  ipAddress: string | null
  port: number | null
  protocol: string | null
  serviceName: string | null
  serviceProduct: string | null
  serviceVersion: string | null
  techName: string | null
  techVersion: string | null
  cveId: string
  cvss: number | null
  cveSeverity: string
  cisaKev: boolean
  cweId: string | null
  cweName: string | null
  capecId: string | null
  capecName: string | null
  capecSeverity: string | null
}

const PAGE_SIZE = 100

interface Props { projectId: string | null }

export const KillChainTable = memo(function KillChainTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<KillChainRow>('killChain', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Kill-Chain',
      [
        { key: 'subdomain', header: 'Subdomain' },
        { key: 'ipAddress', header: 'IP' },
        { key: 'port', header: 'Port' },
        { key: 'protocol', header: 'Proto' },
        { key: 'serviceName', header: 'Service' },
        { key: 'serviceProduct', header: 'Product' },
        { key: 'serviceVersion', header: 'SvcVer' },
        { key: 'techName', header: 'Technology' },
        { key: 'techVersion', header: 'TechVer' },
        { key: 'cveId', header: 'CVE' },
        { key: 'cvss', header: 'CVSS' },
        { key: 'cveSeverity', header: 'Severity' },
        { key: 'cisaKev', header: 'CISA KEV' },
        { key: 'cweId', header: 'CWE' },
        { key: 'cweName', header: 'CWE Name' },
        { key: 'capecId', header: 'CAPEC' },
        { key: 'capecName', header: 'CAPEC Name' },
      ],
      'redzone-kill-chain',
    )
  }, [filtered])

  const kevCount = (data?.meta?.kevCount as number | undefined) ?? 0
  const meta = rows.length ? `${kevCount} KEV match${kevCount === 1 ? '' : 'es'}` : undefined

  return (
    <RedZoneTableShell
      title="Kill-Chain Explorer"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search subdomain, CVE, tech, CWE..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No Subdomain → IP → Port → Tech → CVE chains found. Run recon + vuln scan to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Subdomain</th>
            <th>IP</th>
            <th>Port</th>
            <th>Service</th>
            <th>Technology</th>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Sev</th>
            <th>KEV</th>
            <th>CWE</th>
            <th>CAPEC</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.subdomain}-${r.port}-${r.cveId}-${i}`}>
              <td><Truncated text={r.subdomain} max={180} /></td>
              <td><Mono>{r.ipAddress || '-'}</Mono></td>
              <td>
                {r.port != null ? <Mono>{r.port}/{r.protocol || 'tcp'}</Mono> : '-'}
              </td>
              <td>
                <Truncated
                  text={[r.serviceName, r.serviceProduct, r.serviceVersion].filter(Boolean).join(' ')}
                  max={160}
                />
              </td>
              <td>
                <Truncated
                  text={[r.techName, r.techVersion].filter(Boolean).join(' ')}
                  max={160}
                />
              </td>
              <td><Mono>{r.cveId || '-'}</Mono></td>
              <td><CvssCell score={r.cvss} /></td>
              <td><SeverityBadge severity={normalizeSeverity(r.cveSeverity)} /></td>
              <td><KevChip value={r.cisaKev} /></td>
              <td><Truncated text={r.cweId ? `${r.cweId}${r.cweName ? ' ' + r.cweName : ''}` : null} max={180} /></td>
              <td><Truncated text={r.capecId ? `${r.capecId}${r.capecName ? ' ' + r.capecName : ''}` : null} max={180} /></td>
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

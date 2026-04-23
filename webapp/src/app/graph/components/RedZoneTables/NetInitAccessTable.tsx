'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  Mono,
  Truncated,
  ListCell,
  BoolChip,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface NetInitAccessRow {
  origin: string
  ipAddress: string
  port: number | null
  protocol: string
  category: string | null
  serviceName: string | null
  serviceProduct: string | null
  serviceVersion: string | null
  techs: string[]
  subdomains: string[]
  vulnTags: string[]
  isCdn: boolean | null
  cdnName: string | null
  asn: string | null
  country: string | null
  isp: string | null
}

const PAGE_SIZE = 100

const CATEGORY_CLASS: Record<string, string> = {
  database: rowStyles.sevCritical,
  k8s: rowStyles.sevCritical,
  ssh: rowStyles.sevHigh,
  rdp: rowStyles.sevHigh,
  telnet: rowStyles.sevCritical,
  winrm: rowStyles.sevHigh,
  smtp: rowStyles.sevMedium,
  snmp: rowStyles.sevMedium,
  ipmi: rowStyles.sevHigh,
  smb: rowStyles.sevHigh,
  vnc: rowStyles.sevHigh,
}

function CategoryChip({ category }: { category: string | null }) {
  if (!category) return <span className={rowStyles.nullCell}>-</span>
  const cls = CATEGORY_CLASS[category] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{category}</span>
}

interface Props { projectId: string | null }

export const NetInitAccessTable = memo(function NetInitAccessTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<NetInitAccessRow>('netInitAccess', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Net-Init-Access',
      [
        { key: 'ipAddress', header: 'IP' },
        { key: 'port', header: 'Port' },
        { key: 'protocol', header: 'Proto' },
        { key: 'category', header: 'Category' },
        { key: 'serviceName', header: 'Service' },
        { key: 'serviceProduct', header: 'Product' },
        { key: 'serviceVersion', header: 'Version' },
        { key: 'techs', header: 'Technologies' },
        { key: 'subdomains', header: 'Subdomains' },
        { key: 'vulnTags', header: 'Findings' },
        { key: 'isCdn', header: 'CDN' },
        { key: 'cdnName', header: 'CDN Name' },
        { key: 'asn', header: 'ASN' },
        { key: 'country', header: 'Country' },
        { key: 'isp', header: 'ISP' },
      ],
      'redzone-net-init-access',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="Network Initial-Access Surface"
      meta={rows.length ? `${rows.length} sensitive exposures (DB / mgmt / origin)` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search IP, port, tag, service, country..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No sensitive network exposures yet. Run port scan + security checks to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>IP</th>
            <th>Port</th>
            <th>Category</th>
            <th>Service</th>
            <th>Subdomains</th>
            <th>Findings</th>
            <th>CDN</th>
            <th>ASN / Country</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.ipAddress}-${r.port}-${i}`}>
              <td><Mono>{r.ipAddress}</Mono></td>
              <td>
                {r.port != null ? <Mono>{r.port}/{r.protocol}</Mono> : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><CategoryChip category={r.category} /></td>
              <td>
                <Truncated
                  text={[r.serviceName, r.serviceProduct, r.serviceVersion].filter(Boolean).join(' ')}
                  max={180}
                />
              </td>
              <td><ListCell items={r.subdomains} max={2} /></td>
              <td><ListCell items={r.vulnTags} max={3} /></td>
              <td>
                <BoolChip value={r.isCdn} trueLabel={r.cdnName || 'yes'} falseLabel="direct" />
              </td>
              <td>
                <Truncated text={[r.asn, r.country].filter(Boolean).join(' · ')} max={140} />
              </td>
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

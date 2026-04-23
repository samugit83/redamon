'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  Mono,
  Truncated,
  ListCell,
  NumCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface SharedInfraRow {
  clusterType: 'certificate' | 'asn' | 'ip' | string
  clusterKey: string
  certCn: string | null
  certIssuer: string | null
  certNotAfter: string | null
  tlsVersion: string | null
  cipher: string | null
  hostCount: number
  hosts: string[]
  baseurls: string[]
  asn: string | null
  country: string | null
  ipAddress: string | null
}

const PAGE_SIZE = 50

const TYPE_CLASS: Record<string, string> = {
  certificate: rowStyles.sevMedium,
  asn: rowStyles.sevInfo,
  ip: rowStyles.sevHigh,
}

function TypeChip({ t }: { t: string }) {
  const cls = TYPE_CLASS[t] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{t}</span>
}

function daysToExpiry(iso: string | null): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (isNaN(d.getTime())) return null
  return Math.floor((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
}

interface Props { projectId: string | null }

export const SharedInfraTable = memo(function SharedInfraTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<SharedInfraRow>('sharedInfra', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    const flat = filtered.map(r => ({
      ...r,
      daysToExpiry: daysToExpiry(r.certNotAfter),
    }))
    exportRedZoneXlsx(
      flat,
      'Shared-Infra',
      [
        { key: 'clusterType', header: 'Type' },
        { key: 'clusterKey', header: 'Cluster Key' },
        { key: 'hostCount', header: 'Host Count' },
        { key: 'hosts', header: 'Hosts' },
        { key: 'baseurls', header: 'BaseURLs' },
        { key: 'certCn', header: 'Cert CN' },
        { key: 'certIssuer', header: 'Cert Issuer' },
        { key: 'certNotAfter', header: 'Cert Not After' },
        { key: 'daysToExpiry', header: 'Days To Expiry' },
        { key: 'tlsVersion', header: 'TLS Version' },
        { key: 'cipher', header: 'Cipher' },
        { key: 'asn', header: 'ASN' },
        { key: 'country', header: 'Country' },
        { key: 'ipAddress', header: 'IP' },
      ],
      'redzone-shared-infra',
    )
  }, [filtered])

  const m = data?.meta as any
  const meta =
    rows.length && m
      ? `${m.certClusters ?? 0} cert · ${m.asnClusters ?? 0} asn · ${m.ipClusters ?? 0} ip`
      : undefined

  return (
    <RedZoneTableShell
      title="Shared Infrastructure Cluster"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search CN, ASN, IP, hostname..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No shared-infrastructure clusters yet. Run http_probe (certificates) + port scan (ASN enrichment)."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Type</th>
            <th>Cluster Key</th>
            <th>Hosts</th>
            <th>Hostnames</th>
            <th>Cert CN / Issuer</th>
            <th>TLS / Cipher</th>
            <th>Days to expiry</th>
            <th>ASN / Country</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => {
            const days = daysToExpiry(r.certNotAfter)
            return (
              <tr key={`${r.clusterType}-${r.clusterKey}-${i}`}>
                <td><TypeChip t={r.clusterType} /></td>
                <td><Mono>{r.clusterKey}</Mono></td>
                <td><NumCell value={r.hostCount} /></td>
                <td><ListCell items={r.hosts} max={4} /></td>
                <td>
                  {r.clusterType === 'certificate' && (r.certCn || r.certIssuer) ? (
                    <Truncated
                      text={[r.certCn, r.certIssuer].filter(Boolean).join(' · ')}
                      max={240}
                    />
                  ) : <span className={rowStyles.nullCell}>-</span>}
                </td>
                <td>
                  {r.clusterType === 'certificate' && (r.tlsVersion || r.cipher) ? (
                    <Truncated
                      text={[r.tlsVersion, r.cipher].filter(Boolean).join(' · ')}
                      max={180}
                    />
                  ) : <span className={rowStyles.nullCell}>-</span>}
                </td>
                <td>
                  {days != null ? (
                    <span className={days < 30 ? rowStyles.sevHigh + ' ' + rowStyles.sevBadge : rowStyles.numCell}>
                      {days}d
                    </span>
                  ) : <span className={rowStyles.nullCell}>-</span>}
                </td>
                <td>
                  <Truncated text={[r.asn, r.country].filter(Boolean).join(' · ')} max={140} />
                </td>
              </tr>
            )
          })}
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

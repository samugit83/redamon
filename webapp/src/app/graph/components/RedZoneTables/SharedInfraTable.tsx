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
import { ExternalLink } from '@/components/ui'
import { resolveLinkable } from '@/lib/url-utils'
import {
  Mono,
  Truncated,
  ListCell,
  NumCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface SharedInfraRow {
  nodeId: string | null
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
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
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

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
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
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const SharedInfraTable = memo(function SharedInfraTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<SharedInfraRow>('sharedInfra', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'sharedInfra',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() => {
    if (rows.length === 0) return undefined
    const flat = sortedRows.map(r => ({
      ...r,
      daysToExpiry: daysToExpiry(r.certNotAfter),
    }))
    return {
      rows: flat,
      sheetName: 'Shared-Infra',
      fileSlug: 'redzone-shared-infra',
      columns: COLUMNS,
    }
  }, [sortedRows, rows.length])

  const m = data?.meta
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
      exportConfig={exportConfig}
      filterUi={filterUi}
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
            <NodeIdTh />
            <th>Type</th>
            <th>Cluster Key</th>
            <th>Hosts</th>
            <th>Hostnames</th>
            <th>Cert CN / Issuer</th>
            <th>TLS / Cipher</th>
            <th>Days to expiry</th>
            <th>ASN / Country</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => {
            const days = daysToExpiry(r.certNotAfter)
            return (
              <tr key={`${r.clusterType}-${r.clusterKey}-${i}`}>
                <td><NodeIdCell value={r.nodeId} /></td>
                <td><TypeChip t={r.clusterType} /></td>
                <td><Mono>{(() => {
                  const href = resolveLinkable(r.clusterKey)
                  return href ? <ExternalLink href={href}>{r.clusterKey}</ExternalLink> : r.clusterKey
                })()}</Mono></td>
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
                <td><UpdatedAtCell value={r.updatedAt} /></td>
                <td><MuteNodeButton name={r.clusterKey} graphId={r.nodeId} label={r.clusterType === 'ip' ? 'IP' : 'Certificate'} /></td>
              </tr>
            )
          })}
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

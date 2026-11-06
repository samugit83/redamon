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
  Truncated,
  ListCell,
  NumCell,
  HostCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface HistoricResolution {
  address: string | null
  asn: string | null
  country: string | null
  firstSeen: string | null
  lastSeen: string | null
  recordType: string | null
  // 'otx' for the Domain's passive DNS; 'urlscan' for an address a public
  // urlscan visit of a subdomain recorded (`host`).
  source?: string | null
  host?: string | null
}

function describeResolution(h: HistoricResolution): string {
  const seen = [h.firstSeen, h.lastSeen].filter(Boolean).join(' to ')
  const where = h.host ? `${h.host} -> ` : ''
  const via = h.source ? ` (${h.source === 'urlscan' ? 'urlscan history' : h.source})` : ''
  return `${where}${h.address}${via}${seen ? `, seen ${seen}` : ''}`
}

interface ExternalDomainSighting {
  domain: string
  sources: string[]
  timesSeen: number | null
  countriesSeen: string[]
  firstSeenAt: string | null
  redirectFromUrls: string[]
}

interface DnsDriftRow {
  nodeId: string | null
  domain: string
  historicIpCount: number
  historicResolutions: HistoricResolution[]
  currentIps: string[]
  currentAsns: string[]
  currentCountries: string[]
  asnDrift: string[]
  countryDrift: string[]
  externalDomains: ExternalDomainSighting[]
  externalDomainCount: number
  danglingSubs: string[]
  danglingSubCount: number
  lastResolutionDate: string | null
  /** Graph `updated_at` of the node this row is built from. */
  updatedAt: unknown
}

const PAGE_SIZE = 50

/** Module-level: the filter profiles are keyed off these, and a fresh array
 *  literal per render would re-profile every row. */
const COLUMNS: RedZoneFilterColumn[] = [
  NODE_ID_COLUMN,
  { key: 'domain', header: 'Domain' },
  { key: 'historicIpCount', header: 'Historic IP Count' },
  { key: 'historicIps', header: 'Historic IPs' },
  { key: 'historicAsns', header: 'Historic ASNs' },
  { key: 'historicCountries', header: 'Historic Countries' },
  { key: 'lastResolutionDate', header: 'Last Resolution' },
  { key: 'currentIps', header: 'Current IPs' },
  { key: 'currentAsns', header: 'Current ASNs' },
  { key: 'currentCountries', header: 'Current Countries' },
  { key: 'asnDrift', header: 'ASN Drift' },
  { key: 'countryDrift', header: 'Country Drift' },
  { key: 'externalDomainCount', header: 'External Domain Count' },
  { key: 'externalDomains', header: 'External Domains' },
  { key: 'danglingSubCount', header: 'Dangling Subdomain Count' },
  { key: 'danglingSubs', header: 'Dangling Subdomains' },
  UPDATED_AT_COLUMN,
]

interface Props { projectId: string | null }

export const DnsDriftTable = memo(function DnsDriftTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<DnsDriftRow>('dnsDrift', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const searched = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const { filteredRows: filtered, filterUi } = useRedZoneFilters({
    rows: searched, columns: COLUMNS, projectId, slug: 'dnsDrift',
  })
  const { sortedRows, sortDir, toggleSort } = useUpdatedAtSort(filtered)
  const sliced = useMemo(() => sortedRows.slice(0, limit), [sortedRows, limit])

  const exportConfig = useMemo<RedZoneExportConfig | undefined>(() => {
    if (rows.length === 0) return undefined
    const flat = sortedRows.map(r => ({
      nodeId: r.nodeId,
      domain: r.domain,
      historicIpCount: r.historicIpCount,
      historicIps: r.historicResolutions.map(h => h.address).filter(Boolean).join(', '),
      historicSources: Array.from(new Set(r.historicResolutions.map(h => h.source).filter(Boolean) as string[])).join(', '),
      historicAsns: Array.from(new Set(r.historicResolutions.map(h => h.asn).filter(Boolean) as string[])).join(', '),
      historicCountries: Array.from(new Set(r.historicResolutions.map(h => h.country).filter(Boolean) as string[])).join(', '),
      lastResolutionDate: r.lastResolutionDate,
      currentIps: r.currentIps.join(', '),
      currentAsns: r.currentAsns.join(', '),
      currentCountries: r.currentCountries.join(', '),
      asnDrift: r.asnDrift.join(', '),
      countryDrift: r.countryDrift.join(', '),
      externalDomainCount: r.externalDomainCount,
      externalDomains: r.externalDomains.map(e => e.domain).join(', '),
      danglingSubCount: r.danglingSubCount,
      danglingSubs: r.danglingSubs.join(', '),
      updatedAt: r.updatedAt,
    }))
    return {
      rows: flat,
      sheetName: 'DNS-Drift',
      fileSlug: 'redzone-dns-drift',
      columns: COLUMNS,
    }
  }, [sortedRows, rows.length])

  return (
    <RedZoneTableShell
      title="Historic DNS Drift & Orphaned Asset Watch"
      meta={rows.length ? `${rows.length} domain${rows.length === 1 ? '' : 's'} with drift signal` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search domain, ASN, country, external, dangling sub..."
      exportConfig={exportConfig}
      filterUi={filterUi}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No historic DNS drift or external-domain sightings yet. Enable OTX / passive-DNS enrichment to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <NodeIdTh />
            <th>Domain</th>
            <th>Historic IPs</th>
            <th>Current IPs</th>
            <th>ASN drift</th>
            <th>Country drift</th>
            <th>Last hist. seen</th>
            <th>External sightings</th>
            <th>Dangling subs</th>
            <UpdatedAtTh dir={sortDir} onToggle={toggleSort} />
            <th />
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.domain}-${i}`}>
              <td><NodeIdCell value={r.nodeId} /></td>
              <td><HostCell host={r.domain} /></td>
              <td>
                {r.historicIpCount > 0 ? (
                  <span title={r.historicResolutions.filter(h => h.address).map(describeResolution).join('\n')}>
                    <span className={rowStyles.numCell}>{r.historicIpCount}</span>
                  </span>
                ) : <span className={rowStyles.nullCell}>0</span>}
              </td>
              <td><ListCell items={r.currentIps} max={2} /></td>
              <td>
                {r.asnDrift.length > 0 ? <ListCell items={r.asnDrift} max={3} /> : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td>
                {r.countryDrift.length > 0 ? <ListCell items={r.countryDrift} max={3} /> : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td>
                <Truncated
                  text={r.lastResolutionDate ? new Date(r.lastResolutionDate).toISOString().slice(0, 10) : null}
                  max={120}
                />
              </td>
              <td>
                {r.externalDomainCount > 0 ? (
                  <span title={r.externalDomains.map(e => e.domain).join('\n')}>
                    <span className={rowStyles.numCell}>{r.externalDomainCount}</span>
                  </span>
                ) : <span className={rowStyles.nullCell}>0</span>}
              </td>
              <td><NumCell value={r.danglingSubCount} /></td>
              <td><UpdatedAtCell value={r.updatedAt} /></td>
              <td><MuteNodeButton name={r.domain} graphId={r.nodeId} label="Domain" /></td>
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

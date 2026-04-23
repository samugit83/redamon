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

interface HistoricResolution {
  address: string | null
  asn: string | null
  country: string | null
  firstSeen: string | null
  lastSeen: string | null
  recordType: string | null
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
}

const PAGE_SIZE = 50

interface Props { projectId: string | null }

export const DnsDriftTable = memo(function DnsDriftTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<DnsDriftRow>('dnsDrift', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    const flat = filtered.map(r => ({
      domain: r.domain,
      historicIpCount: r.historicIpCount,
      historicIps: r.historicResolutions.map(h => h.address).filter(Boolean).join(', '),
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
    }))
    exportRedZoneXlsx(
      flat,
      'DNS-Drift',
      [
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
      ],
      'redzone-dns-drift',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="Historic DNS Drift & Orphaned Asset Watch"
      meta={rows.length ? `${rows.length} domain${rows.length === 1 ? '' : 's'} with drift signal` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search domain, ASN, country, external, dangling sub..."
      onExport={rows.length > 0 ? handleExport : undefined}
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
            <th>Domain</th>
            <th>Historic IPs</th>
            <th>Current IPs</th>
            <th>ASN drift</th>
            <th>Country drift</th>
            <th>Last hist. seen</th>
            <th>External sightings</th>
            <th>Dangling subs</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.domain}-${i}`}>
              <td><Mono>{r.domain}</Mono></td>
              <td>
                {r.historicIpCount > 0 ? (
                  <span title={r.historicResolutions.map(h => h.address).filter(Boolean).join('\n')}>
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

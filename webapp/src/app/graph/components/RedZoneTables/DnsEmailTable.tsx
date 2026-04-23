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
  NumCell,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface DnsEmailRow {
  domain: string
  spfPresent: boolean
  spfStrict: boolean
  spfRecord: string | null
  dmarcPresent: boolean
  dmarcPolicy: string | null
  dnssec: string | null
  dnssecEnabled: boolean
  zoneTransferOpen: boolean
  mxRecords: string[]
  mxCount: number
  nameServers: string[]
  nameServerCount: number
  nsDistinctProviders: number | null
  whoisEmails: string[]
  registrar: string | null
  organization: string | null
  country: string | null
  expirationDate: string | null
  daysToExpiry: number | null
  registrarStatus: string[]
  vtMaliciousCount: number | null
  vtReputation: number | null
  otxPulseCount: number | null
  vulnTags: string[]
  spfMissing: boolean
  dmarcMissing: boolean
  dnssecMissing: boolean
}

const PAGE_SIZE = 50

function PolicyChip({ policy }: { policy: string | null }) {
  if (!policy) return <span className={rowStyles.nullCell}>-</span>
  let cls = rowStyles.sevHigh
  if (policy === 'reject') cls = rowStyles.sevLow
  else if (policy === 'quarantine') cls = rowStyles.sevMedium
  else if (policy === 'none') cls = rowStyles.sevHigh
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{policy}</span>
}

interface Props { projectId: string | null }

export const DnsEmailTable = memo(function DnsEmailTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<DnsEmailRow>('dnsEmail', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'DNS-Email',
      [
        { key: 'domain', header: 'Domain' },
        { key: 'spfPresent', header: 'SPF Present' },
        { key: 'spfStrict', header: 'SPF Strict' },
        { key: 'spfRecord', header: 'SPF Record' },
        { key: 'dmarcPresent', header: 'DMARC Present' },
        { key: 'dmarcPolicy', header: 'DMARC Policy' },
        { key: 'dnssec', header: 'DNSSEC' },
        { key: 'dnssecEnabled', header: 'DNSSEC Enabled' },
        { key: 'zoneTransferOpen', header: 'Zone Transfer Open' },
        { key: 'mxRecords', header: 'MX Records' },
        { key: 'mxCount', header: 'MX Count' },
        { key: 'nameServers', header: 'Name Servers' },
        { key: 'nameServerCount', header: 'NS Count' },
        { key: 'nsDistinctProviders', header: 'NS Providers' },
        { key: 'whoisEmails', header: 'WHOIS Emails' },
        { key: 'registrar', header: 'Registrar' },
        { key: 'organization', header: 'Organization' },
        { key: 'country', header: 'Country' },
        { key: 'expirationDate', header: 'Expiration' },
        { key: 'daysToExpiry', header: 'Days To Expiry' },
        { key: 'registrarStatus', header: 'Registrar Status' },
        { key: 'vtMaliciousCount', header: 'VT Malicious' },
        { key: 'vtReputation', header: 'VT Reputation' },
        { key: 'otxPulseCount', header: 'OTX Pulses' },
        { key: 'vulnTags', header: 'Vuln Tags' },
      ],
      'redzone-dns-email',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="DNS & Email Security Posture"
      meta={rows.length ? `${rows.length} domain${rows.length === 1 ? '' : 's'}` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search domain, NS, registrar..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No Domain nodes yet. Run domain_recon + security_checks to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Domain</th>
            <th>SPF</th>
            <th>SPF strict</th>
            <th>DMARC</th>
            <th>DMARC policy</th>
            <th>DNSSEC</th>
            <th>Zone xfer</th>
            <th>MX</th>
            <th>NS</th>
            <th>Expires in</th>
            <th>VT mal.</th>
            <th>OTX</th>
            <th>Registrar</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.domain}-${i}`}>
              <td><Mono>{r.domain}</Mono></td>
              <td><BoolChip value={r.spfPresent} /></td>
              <td><BoolChip value={r.spfStrict} trueLabel="-all" falseLabel="weak" /></td>
              <td><BoolChip value={r.dmarcPresent} /></td>
              <td><PolicyChip policy={r.dmarcPolicy} /></td>
              <td><BoolChip value={r.dnssecEnabled} /></td>
              <td>
                <BoolChip value={r.zoneTransferOpen} trueLabel="OPEN" falseLabel="closed" />
              </td>
              <td><ListCell items={r.mxRecords} max={2} /></td>
              <td><ListCell items={r.nameServers} max={2} /></td>
              <td>
                {r.daysToExpiry != null ? (
                  <span className={r.daysToExpiry < 30 ? rowStyles.sevBadge + ' ' + rowStyles.sevHigh : rowStyles.numCell}>
                    {r.daysToExpiry}d
                  </span>
                ) : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><NumCell value={r.vtMaliciousCount} /></td>
              <td><NumCell value={r.otxPulseCount} /></td>
              <td><Truncated text={r.registrar} max={160} /></td>
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

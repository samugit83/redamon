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
  BoolChip,
  filterRowsByText,
} from './formatters'
import rowStyles from './RedZoneTableRow.module.css'

interface ThreatIntelRow {
  assetType: 'Domain' | 'IP' | string
  asset: string
  vtMaliciousCount: number | null
  vtSuspiciousCount: number | null
  vtReputation: number | null
  vtTags: string[]
  vtLastAnalysisDate: number | null
  vtJarm: string | null
  otxPulseCount: number
  otxUrlCount: number | null
  otxAdversaries: string[]
  otxMalwareFamilies: string[]
  otxTlp: string | null
  otxAttackIds: string[]
  criminalipRiskGrade: string | null
  criminalipAbuseCount: number | null
  criminalipCurrentService: string | null
  criminalipScoreInbound: number | null
  criminalipIsTor: boolean | null
  criminalipIsProxy: boolean | null
  criminalipIsVpn: boolean | null
  criminalipIsDarkweb: boolean | null
  criminalipIsHosting: boolean | null
  criminalipIsScanner: boolean | null
  criminalipCountry: string | null
  subdomains: string[]
  pulseNames: string[]
  pulseAdversaries: string[]
  pulseCount: number
  malwareHashes: string[]
  malwareCount: number
}

const PAGE_SIZE = 100

const GRADE_CLASS: Record<string, string> = {
  A: rowStyles.sevLow,
  B: rowStyles.sevLow,
  C: rowStyles.sevMedium,
  D: rowStyles.sevHigh,
  F: rowStyles.sevCritical,
}

function GradeChip({ grade }: { grade: string | null }) {
  if (!grade) return <span className={rowStyles.nullCell}>-</span>
  const cls = GRADE_CLASS[grade] || rowStyles.sevInfo
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{grade}</span>
}

interface Props { projectId: string | null }

export const ThreatIntelTable = memo(function ThreatIntelTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<ThreatIntelRow>('threatIntel', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Threat-Intel',
      [
        { key: 'assetType', header: 'Type' },
        { key: 'asset', header: 'Asset' },
        { key: 'vtMaliciousCount', header: 'VT Malicious' },
        { key: 'vtSuspiciousCount', header: 'VT Suspicious' },
        { key: 'vtReputation', header: 'VT Reputation' },
        { key: 'vtTags', header: 'VT Tags' },
        { key: 'vtJarm', header: 'VT JARM' },
        { key: 'otxPulseCount', header: 'OTX Pulses' },
        { key: 'otxUrlCount', header: 'OTX URLs' },
        { key: 'otxAdversaries', header: 'OTX Adversaries' },
        { key: 'otxMalwareFamilies', header: 'OTX Malware Families' },
        { key: 'otxTlp', header: 'OTX TLP' },
        { key: 'otxAttackIds', header: 'MITRE ATT&CK' },
        { key: 'criminalipRiskGrade', header: 'CriminalIP Grade' },
        { key: 'criminalipAbuseCount', header: 'CriminalIP Abuse' },
        { key: 'criminalipCurrentService', header: 'CriminalIP Service' },
        { key: 'criminalipScoreInbound', header: 'CriminalIP Score Inbound' },
        { key: 'criminalipIsTor', header: 'Is Tor' },
        { key: 'criminalipIsProxy', header: 'Is Proxy' },
        { key: 'criminalipIsVpn', header: 'Is VPN' },
        { key: 'criminalipIsDarkweb', header: 'Is Darkweb' },
        { key: 'criminalipCountry', header: 'Country' },
        { key: 'subdomains', header: 'Subdomains' },
        { key: 'pulseNames', header: 'Pulse Names' },
        { key: 'pulseAdversaries', header: 'Pulse Adversaries' },
        { key: 'pulseCount', header: 'Pulse Count' },
        { key: 'malwareHashes', header: 'Malware Hashes' },
        { key: 'malwareCount', header: 'Malware Count' },
      ],
      'redzone-threat-intel',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="OSINT Threat Intelligence Overlay"
      meta={rows.length ? `${(data?.meta as any)?.domainCount ?? 0} domain · ${(data?.meta as any)?.ipCount ?? 0} ip flagged` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search asset, adversary, malware, tag..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No threat-intel signal on any asset. Run OSINT enrichment (OTX, VT, CriminalIP) to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Type</th>
            <th>Asset</th>
            <th>VT mal.</th>
            <th>VT rep.</th>
            <th>OTX pulses</th>
            <th>Adversaries</th>
            <th>Malware fams</th>
            <th>ATT&amp;CK</th>
            <th>CrimIP</th>
            <th>Proxy/Tor/VPN</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.assetType}-${r.asset}-${i}`}>
              <td><span className={rowStyles.listChip}>{r.assetType}</span></td>
              <td><Mono>{r.asset}</Mono></td>
              <td><NumCell value={r.vtMaliciousCount} /></td>
              <td>
                {r.vtReputation != null ? (
                  <span className={r.vtReputation < 0 ? rowStyles.sevBadge + ' ' + rowStyles.sevHigh : rowStyles.numCell}>
                    {r.vtReputation}
                  </span>
                ) : <span className={rowStyles.nullCell}>-</span>}
              </td>
              <td><NumCell value={r.otxPulseCount} /></td>
              <td><ListCell items={r.otxAdversaries} max={2} /></td>
              <td><ListCell items={r.otxMalwareFamilies} max={2} /></td>
              <td><ListCell items={r.otxAttackIds} max={3} /></td>
              <td>
                {r.assetType === 'Domain'
                  ? <GradeChip grade={r.criminalipRiskGrade} />
                  : (r.criminalipScoreInbound != null ? <span className={rowStyles.numCell}>{r.criminalipScoreInbound}</span> : <span className={rowStyles.nullCell}>-</span>)}
              </td>
              <td>
                <span className={rowStyles.listCell}>
                  {r.criminalipIsProxy && <span className={rowStyles.listChip}>proxy</span>}
                  {r.criminalipIsTor && <span className={rowStyles.listChip}>tor</span>}
                  {r.criminalipIsVpn && <span className={rowStyles.listChip}>vpn</span>}
                  {r.criminalipIsDarkweb && <span className={rowStyles.listChip}>dark</span>}
                  {!r.criminalipIsProxy && !r.criminalipIsTor && !r.criminalipIsVpn && !r.criminalipIsDarkweb && <span className={rowStyles.nullCell}>-</span>}
                </span>
              </td>
              <td><ListCell items={r.vtTags} max={2} /></td>
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

'use client'

import { memo, useCallback, useMemo, useState } from 'react'
import { RedZoneTableShell } from './RedZoneTableShell'
import { useRedZoneTable } from './useRedZoneTable'
import { exportRedZoneXlsx } from './exportXlsx'
import {
  SeverityBadge,
  Mono,
  Truncated,
  UrlCell,
  CvssCell,
  BoolChip,
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import rowStyles from './RedZoneTableRow.module.css'

interface ParamRow {
  paramName: string
  position: string
  endpointPath: string | null
  paramBaseUrl: string | null
  sampleValue: string | null
  isInjectable: boolean
  paramType: string | null
  paramCategory: string | null
  endpointMethod: string | null
  endpointFullUrl: string | null
  endpointCategory: string | null
  baseUrl: string | null
  subdomain: string | null
  vulnId: string | null
  templateId: string | null
  vulnName: string | null
  vulnSeverity: string | null
  vulnSource: string | null
  matcherName: string | null
  extractorName: string | null
  fuzzingMethod: string | null
  fuzzingPosition: string | null
  matchedAt: string | null
  cvssScore: number | null
}

const PAGE_SIZE = 100

const POSITION_CLASS: Record<string, string> = {
  query: rowStyles.listChip,
  body: rowStyles.listChip,
  header: rowStyles.listChip,
  cookie: rowStyles.listChip,
  path: rowStyles.listChip,
  form: rowStyles.listChip,
}

function PositionChip({ position }: { position: string }) {
  const cls = POSITION_CLASS[position] || rowStyles.listChip
  return <span className={cls}>{position}</span>
}

interface Props { projectId: string | null }

export const ParamMatrixTable = memo(function ParamMatrixTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<ParamRow>('paramMatrix', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered,
      'Param-Matrix',
      [
        { key: 'paramName', header: 'Parameter' },
        { key: 'position', header: 'Position' },
        { key: 'endpointMethod', header: 'Method' },
        { key: 'endpointPath', header: 'Endpoint Path' },
        { key: 'endpointFullUrl', header: 'Full URL' },
        { key: 'baseUrl', header: 'BaseURL' },
        { key: 'subdomain', header: 'Subdomain' },
        { key: 'paramType', header: 'Param Type' },
        { key: 'paramCategory', header: 'Param Category' },
        { key: 'isInjectable', header: 'Injectable' },
        { key: 'sampleValue', header: 'Sample Value' },
        { key: 'vulnId', header: 'Vuln ID' },
        { key: 'vulnName', header: 'Vuln Name' },
        { key: 'vulnSeverity', header: 'Severity' },
        { key: 'vulnSource', header: 'Source' },
        { key: 'templateId', header: 'Template ID' },
        { key: 'matcherName', header: 'Matcher' },
        { key: 'extractorName', header: 'Extractor' },
        { key: 'fuzzingMethod', header: 'Fuzz Method' },
        { key: 'fuzzingPosition', header: 'Fuzz Position' },
        { key: 'matchedAt', header: 'Matched At' },
        { key: 'cvssScore', header: 'CVSS' },
      ],
      'redzone-param-matrix',
    )
  }, [filtered])

  const injectableCount = (data?.meta?.injectableCount as number | undefined) ?? 0
  const withVulnCount = (data?.meta?.withVulnCount as number | undefined) ?? 0
  const meta = rows.length ? `${injectableCount} injectable · ${withVulnCount} with linked DAST vuln` : undefined

  return (
    <RedZoneTableShell
      title="Injectable & Reflected Parameter Matrix"
      meta={meta}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search parameter, endpoint, vuln type..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No injectable or DAST-linked parameters yet. Run vuln_scan with fuzzing enabled to populate."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Parameter</th>
            <th>Position</th>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Injectable</th>
            <th>Vuln</th>
            <th>Sev</th>
            <th>CVSS</th>
            <th>Matched At</th>
            <th>Subdomain</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={`${r.paramName}-${r.endpointPath}-${r.vulnId || ''}-${i}`}>
              <td><Mono>{r.paramName}</Mono></td>
              <td><PositionChip position={r.position} /></td>
              <td>{r.endpointMethod ? <Mono>{r.endpointMethod}</Mono> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><Truncated text={r.endpointPath || r.endpointFullUrl} max={220} /></td>
              <td><BoolChip value={r.isInjectable} /></td>
              <td><Truncated text={r.vulnName || r.templateId} max={220} /></td>
              <td>{r.vulnSeverity ? <SeverityBadge severity={normalizeSeverity(r.vulnSeverity)} /> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><CvssCell score={r.cvssScore} /></td>
              <td><UrlCell url={r.matchedAt} max={240} /></td>
              <td><Truncated text={r.subdomain} max={160} /></td>
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

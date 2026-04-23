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
  filterRowsByText,
} from './formatters'
import { normalizeSeverity } from './types'
import { redactSecret } from './redact'
import rowStyles from './RedZoneTableRow.module.css'

interface SecretRow {
  origin: 'Secret' | 'JsReconFinding' | string
  id: string
  secretType: string
  valueSample: string | null
  matchedText: string | null
  entropy: number | null
  confidence: string | number | null
  severity: string
  sourceModule: string | null
  sourceUrl: string | null
  secretBaseUrl: string | null
  keyType: string | null
  detectionMethod: string | null
  validationStatus: string | null
  baseUrl: string | null
  subdomain: string | null
  jsFileUrl: string | null
}

const PAGE_SIZE = 100

const VALIDATION_CLASS: Record<string, string> = {
  validated:        rowStyles.sevCritical,
  format_validated: rowStyles.sevMedium,
  unvalidated:      rowStyles.sevInfo,
  skipped:          rowStyles.sevInfo,
  invalid:          rowStyles.sevLow,
}

function ValidationChip({ status }: { status: string | null }) {
  if (!status) return <span className={rowStyles.nullCell}>-</span>
  const cls = VALIDATION_CLASS[status] || rowStyles.sevInfo
  const label = status === 'validated' ? 'LIVE' : status.replace('_', ' ')
  return <span className={`${rowStyles.sevBadge} ${cls}`}>{label}</span>
}

interface Props { projectId: string | null }

export const SecretsTable = memo(function SecretsTable({ projectId }: Props) {
  const { data, isLoading, error, refetch } = useRedZoneTable<SecretRow>('secrets', projectId)
  const [search, setSearch] = useState('')
  const [limit, setLimit] = useState(PAGE_SIZE)

  const rows = useMemo(() => data?.rows ?? [], [data])
  const filtered = useMemo(() => filterRowsByText(rows, search), [rows, search])
  const sliced = useMemo(() => filtered.slice(0, limit), [filtered, limit])

  const handleExport = useCallback(() => {
    exportRedZoneXlsx(
      filtered.map(r => ({ ...r, valueSample: redactSecret(r.valueSample), matchedText: redactSecret(r.matchedText) })),
      'Secrets',
      [
        { key: 'origin', header: 'Origin' },
        { key: 'secretType', header: 'Type' },
        { key: 'keyType', header: 'Category' },
        { key: 'valueSample', header: 'Redacted Sample' },
        { key: 'matchedText', header: 'Redacted Match' },
        { key: 'entropy', header: 'Entropy' },
        { key: 'confidence', header: 'Confidence' },
        { key: 'severity', header: 'Severity' },
        { key: 'validationStatus', header: 'Validation' },
        { key: 'detectionMethod', header: 'Detection' },
        { key: 'sourceModule', header: 'Source Module' },
        { key: 'sourceUrl', header: 'Source URL' },
        { key: 'jsFileUrl', header: 'Parent JS File' },
        { key: 'baseUrl', header: 'BaseURL' },
        { key: 'subdomain', header: 'Subdomain' },
      ],
      'redzone-secrets',
    )
  }, [filtered])

  return (
    <RedZoneTableShell
      title="Secrets & Credential Exposure"
      meta={rows.length ? `${rows.length} credential finding${rows.length === 1 ? '' : 's'}` : undefined}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search secret type, category, URL, subdomain..."
      onExport={rows.length > 0 ? handleExport : undefined}
      onRefresh={refetch}
      isLoading={isLoading}
      error={error}
      rowCount={rows.length}
      filteredRowCount={filtered.length}
      emptyLabel="No leaked secrets found. Run js_recon or resource_enum to discover credentials."
    >
      <table className={rowStyles.table}>
        <thead>
          <tr>
            <th>Type</th>
            <th>Category</th>
            <th>Redacted Sample</th>
            <th>Entropy</th>
            <th>Conf.</th>
            <th>Sev</th>
            <th>Validation</th>
            <th>Origin</th>
            <th>Source URL</th>
            <th>Subdomain</th>
          </tr>
        </thead>
        <tbody>
          {sliced.map((r, i) => (
            <tr key={r.id || `${r.sourceUrl}-${i}`}>
              <td><Mono>{r.secretType}</Mono></td>
              <td>{r.keyType ? <span className={rowStyles.listChip}>{r.keyType}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><Mono>{redactSecret(r.valueSample || r.matchedText)}</Mono></td>
              <td>{r.entropy != null ? <span className={rowStyles.numCell}>{r.entropy.toFixed(2)}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td>{r.confidence != null ? <span className={rowStyles.numCell}>{String(r.confidence)}</span> : <span className={rowStyles.nullCell}>-</span>}</td>
              <td><SeverityBadge severity={normalizeSeverity(r.severity)} /></td>
              <td><ValidationChip status={r.validationStatus} /></td>
              <td><span className={rowStyles.listChip}>{r.origin}</span></td>
              <td><UrlCell url={r.sourceUrl} max={260} /></td>
              <td><Truncated text={r.subdomain} max={180} /></td>
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

/**
 * The audit export's file (step 6.6; GV-07, AU-04): the rows lib/authz/auditReader.ts reads, as CSV or
 * as JSON, one batch at a time, so the route streams them. Each table has its columns; an account is
 * named by id and email (the email a deleted actor's row recorded), `before` and `after` come with
 * their secrets withheld (auditReader `withoutSecrets`), and a CSV cell that a spreadsheet would read
 * as a formula is prefixed with a quote.
 */
import {
  auditBatches, type ActAsEntry, type AuditEntryView, type AuditFilters, type AuditLogDetail, type AuditPerson,
  type AuditTable, type FireteamEntry,
} from './auditReader'

/** At most this many rows in one export; the response says when more matched (OQ-40 has no say). */
export const AUDIT_EXPORT_MAX_ROWS = 100_000
export const AUDIT_EXPORT_BATCH = 1_000

export const AUDIT_EXPORT_FORMATS = ['csv', 'json'] as const
export type AuditExportFormat = (typeof AUDIT_EXPORT_FORMATS)[number]

type Column<E> = readonly [name: string, value: (e: E) => unknown]

const email = (p: AuditPerson | null) => p?.email ?? null
const accountType = (p: AuditPerson | null) => (p ? (p.deleted ? 'deleted' : p.accountType) : null)

const LOG_COLUMNS: readonly Column<AuditLogDetail>[] = [
  ['id', (e) => e.id],
  ['at', (e) => e.at],
  ['action', (e) => e.action],
  ['label', (e) => e.label],
  ['actor_id', (e) => e.actor?.id ?? null],
  ['actor_email', (e) => email(e.actor)],
  ['actor_type', (e) => accountType(e.actor)],
  ['on_behalf_of_id', (e) => e.onBehalfOf?.id ?? null],
  ['on_behalf_of_email', (e) => email(e.onBehalfOf)],
  ['target_type', (e) => e.target.type],
  ['target_id', (e) => e.target.id],
  ['target_email', (e) => email(e.target.account)],
  ['project_id', (e) => e.project?.id ?? null],
  ['project_name', (e) => e.project?.name ?? null],
  ['permission', (e) => e.permission],
  ['source', (e) => e.source],
  ['before', (e) => e.before],
  ['after', (e) => e.after],
]

const ACT_AS_COLUMNS: readonly Column<ActAsEntry>[] = [
  ['id', (e) => e.id],
  ['at', (e) => e.at],
  ['event', (e) => e.event],
  ['admin_id', (e) => e.admin.id],
  ['admin_email', (e) => email(e.admin)],
  ['target_id', (e) => e.target.id],
  ['target_email', (e) => email(e.target)],
  ['source', (e) => e.source],
  ['reason', (e) => e.reason],
  ['duration_minutes', (e) => e.durationMinutes],
  ['ended_by', (e) => e.endedBy],
]

const FIRETEAM_COLUMNS: readonly Column<FireteamEntry>[] = [
  ['id', (e) => e.id],
  ['at', (e) => e.at],
  ['project_id', (e) => e.project.id],
  ['project_name', (e) => e.project.name],
  ['field', (e) => e.field],
  ['user_id', (e) => e.user?.id ?? null],
  ['user_email', (e) => email(e.user)],
  ['old_value', (e) => e.oldValue],
  ['new_value', (e) => e.newValue],
  ['source', (e) => e.source],
]

function columnsOf(table: AuditTable): readonly Column<AuditEntryView>[] {
  if (table === 'act_as') return ACT_AS_COLUMNS as readonly Column<AuditEntryView>[]
  if (table === 'fireteam') return FIRETEAM_COLUMNS as readonly Column<AuditEntryView>[]
  return LOG_COLUMNS as readonly Column<AuditEntryView>[]
}

export function exportColumns(table: AuditTable): string[] {
  return columnsOf(table).map(([name]) => name)
}

/** One entry as the export's flat record (column name to value). */
export function exportRecord(table: AuditTable, entry: AuditEntryView): Record<string, unknown> {
  return Object.fromEntries(columnsOf(table).map(([name, value]) => [name, value(entry) ?? null]))
}

// A spreadsheet runs a cell starting with one of these as a formula (CSV injection).
const FORMULA_START = /^[=+\-@\t\r]/

export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return ''
  let text = typeof value === 'string' ? value : typeof value === 'object' ? JSON.stringify(value) : String(value)
  if (typeof value === 'string' && FORMULA_START.test(text)) text = `'${text}`
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function csvLine(values: readonly unknown[]): string {
  return `${values.map(csvCell).join(',')}\r\n`
}

export interface ExportHead {
  table: AuditTable
  exportedAt: string
  /** Rows the filters select. */
  total: number
  /** Rows in this file: at most AUDIT_EXPORT_MAX_ROWS. */
  rows: number
  truncated: boolean
}

/**
 * The file as text chunks: the CSV header then one line per row, or a JSON object (`table`,
 * `exportedAt`, `total`, `truncated`) whose `rows` array is written a batch at a time. The batches are
 * read only as the chunks are taken.
 */
export async function* exportChunks(f: AuditFilters, format: AuditExportFormat, head: ExportHead): AsyncGenerator<string> {
  const batches = auditBatches({ ...f, cursor: null }, { batch: AUDIT_EXPORT_BATCH, max: AUDIT_EXPORT_MAX_ROWS })
  if (format === 'csv') {
    yield csvLine(exportColumns(f.table))
    for await (const batch of batches) {
      yield batch.map((e) => csvLine(Object.values(exportRecord(f.table, e)))).join('')
    }
    return
  }
  // The head's row count is the array's length; the file says how many matched and whether it stops short.
  const { table, exportedAt, total, truncated } = head
  yield `${JSON.stringify({ table, exportedAt, total, truncated }).slice(0, -1)},"rows":[`
  let first = true
  for await (const batch of batches) {
    const text = batch.map((e) => JSON.stringify(exportRecord(f.table, e))).join(',')
    yield first ? text : `,${text}`
    first = false
  }
  yield ']}'
}

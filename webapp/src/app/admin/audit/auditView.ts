/**
 * What the audit viewer page (step 6.6) shows and sends, kept apart from React: the tabs, the filters
 * each tab offers (the API refuses any other, lib/authz/auditReader.ts AUDIT_TABLE_FILTERS), the query
 * string the address and the API share, and the words for a person or a value. Pure: no server import.
 */
import { AUDIT_GROUPS, type AuditGroup } from '@/lib/authz/auditLabels'
import type { AuditPerson, AuditTable } from '@/lib/authz/auditReader'

export const TABS: ReadonlyArray<{ id: AuditTable; label: string }> = [
  { id: 'audit', label: 'Audit log' },
  { id: 'act_as', label: 'Act-as' },
  { id: 'fireteam', label: 'Fireteam settings' },
]

export type FilterKey = 'actor' | 'onBehalfOf' | 'target' | 'targetType' | 'project' | 'action' | 'group' | 'from' | 'to'

export interface FilterField {
  key: FilterKey
  label: string
  kind: 'text' | 'date' | 'group'
  hint?: string
}

const ACTOR: FilterField = { key: 'actor', label: 'Actor', kind: 'text', hint: 'Email or account id' }
const FROM: FilterField = { key: 'from', label: 'From', kind: 'date' }
const TO: FilterField = { key: 'to', label: 'To', kind: 'date' }

/** The same filters, per table, as the API's AUDIT_TABLE_FILTERS. */
export const TAB_FILTERS: Readonly<Record<AuditTable, readonly FilterField[]>> = {
  audit: [
    ACTOR,
    { key: 'onBehalfOf', label: 'On behalf of', kind: 'text', hint: 'The account an admin acted as' },
    { key: 'target', label: 'Target', kind: 'text', hint: 'Email or id' },
    { key: 'targetType', label: 'Target type', kind: 'text', hint: 'user, project, instance…' },
    { key: 'project', label: 'Project id', kind: 'text' },
    { key: 'action', label: 'Action', kind: 'text', hint: 'project.share.grant, or project.share.*' },
    { key: 'group', label: 'Kind', kind: 'group' },
    FROM,
    TO,
  ],
  act_as: [
    { ...ACTOR, label: 'Admin' },
    { key: 'target', label: 'Account acted as', kind: 'text', hint: 'Email or id' },
    { key: 'action', label: 'Event', kind: 'text', hint: 'start or end' },
    FROM,
    TO,
  ],
  fireteam: [
    { ...ACTOR, label: 'Changed by' },
    { key: 'project', label: 'Project id', kind: 'text' },
    { key: 'action', label: 'Setting', kind: 'text', hint: 'fireteamEnabled, or fireteam*' },
    FROM,
    TO,
  ],
}

export type Filters = Partial<Record<FilterKey, string>>

export interface ViewState {
  table: AuditTable
  filters: Filters
}

const isTable = (v: string | null): v is AuditTable => TABS.some((t) => t.id === v)

/** The view the address names; filters the table does not take are dropped. */
export function viewFrom(params: URLSearchParams | null): ViewState {
  const raw = params?.get('table') ?? null
  const table: AuditTable = isTable(raw) ? raw : 'audit'
  const filters: Filters = {}
  for (const f of TAB_FILTERS[table]) {
    const v = params?.get(f.key)?.trim()
    if (v) filters[f.key] = v
  }
  return { table, filters }
}

/** The query string of a view (and a cursor or a format), for the address and the API alike. */
export function queryOf(view: ViewState, extra: Record<string, string> = {}): string {
  const qs = new URLSearchParams()
  if (view.table !== 'audit') qs.set('table', view.table)
  for (const f of TAB_FILTERS[view.table]) {
    const v = view.filters[f.key]?.trim()
    if (v) qs.set(f.key, v)
  }
  for (const [k, v] of Object.entries(extra)) qs.set(k, v)
  return qs.toString()
}

export const hasFilters = (view: ViewState) => Object.values(view.filters).some((v) => v && v.trim() !== '')

export const GROUP_OPTIONS = Object.entries(AUDIT_GROUPS) as Array<[AuditGroup, string]>

/** A person in words, for a cell without a label (a deleted account, the system). */
export function personText(p: AuditPerson | null): string {
  if (!p) return 'The system'
  if (p.deleted) return p.email ? `Deleted account (${p.email})` : 'Deleted account'
  return p.email ?? p.id ?? 'Unknown account'
}

/** A recorded value (JSON) as one line. */
export function valueText(v: unknown): string {
  if (v === null || v === undefined) return '—'
  return typeof v === 'string' ? v : JSON.stringify(v)
}

/** The file name a download's Content-Disposition gives, or a fallback. */
export function downloadName(disposition: string | null, fallback: string): string {
  const m = disposition?.match(/filename="([^"]+)"/)
  return m ? m[1] : fallback
}

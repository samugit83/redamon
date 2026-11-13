/**
 * The Instance page's quota editor logic (step 6.8; GV-09..GV-13), kept apart from the screen so it
 * is tested alone. The fields and bounds are a browser copy of lib/authz/quotas.ts (a server module:
 * it reads the database), pinned against it by quotaModel.test.ts.
 *
 * A field of the defaults is unlimited or a limit. A field of a set's or an account's entry is also
 * "not set here" (the next level decides): the editor keeps the three states apart, as the store does
 * (left out / null / a number).
 */

export const QUOTA_FIELDS = [
  'maxProjects',
  'maxConcurrentScans',
  'maxConcurrentAgentRuns',
  'maxMcpTokens',
  'maxMcpTokenExpiryDays',
  'llmDailyCalls',
] as const

export type QuotaField = (typeof QUOTA_FIELDS)[number]
export type QuotaEntry = Partial<Record<QuotaField, number | null>>

export interface QuotaStoreView {
  defaults: QuotaEntry
  perSet: Record<string, QuotaEntry>
  perUser: Record<string, QuotaEntry>
}

export interface QuotaFieldSpec { field: QuotaField; label: string; unit: string; min: number; max: number }

export const QUOTA_FIELD_SPECS: readonly QuotaFieldSpec[] = [
  { field: 'maxProjects', label: 'Projects owned', unit: 'projects', min: 0, max: 100_000 },
  { field: 'maxConcurrentScans', label: 'Scans at once', unit: 'scans', min: 0, max: 1_000 },
  { field: 'maxConcurrentAgentRuns', label: 'Agent runs at once', unit: 'runs', min: 0, max: 1_000 },
  { field: 'maxMcpTokens', label: 'MCP tokens', unit: 'tokens', min: 0, max: 1_000 },
  { field: 'maxMcpTokenExpiryDays', label: 'Longest MCP token lifetime', unit: 'days', min: 1, max: 3_650 },
  { field: 'llmDailyCalls', label: 'Model calls a day (instance providers)', unit: 'calls', min: 0, max: 10_000_000 },
]

export type CellMode = 'inherit' | 'unlimited' | 'limit'
export interface Cell { mode: CellMode; value: string }
export type Cells = Record<QuotaField, Cell>

export interface QuotaDraft {
  defaults: Cells
  perSet: Record<string, Cells>
  perUser: Record<string, Cells>
}

function cellsOf(entry: QuotaEntry | undefined, absent: CellMode): Cells {
  const cells = {} as Cells
  for (const field of QUOTA_FIELDS) {
    const has = !!entry && Object.hasOwn(entry, field)
    const v = has ? entry![field] : undefined
    cells[field] = typeof v === 'number'
      ? { mode: 'limit', value: String(v) }
      : { mode: has || absent === 'unlimited' ? 'unlimited' : 'inherit', value: '' }
  }
  return cells
}

/** A new entry's cells: every field left to the next level. */
export const emptyEntryCells = (): Cells => cellsOf(undefined, 'inherit')

export function draftOf(store: QuotaStoreView | undefined): QuotaDraft {
  const map = (m: Record<string, QuotaEntry> | undefined) =>
    Object.fromEntries(Object.entries(m ?? {}).map(([id, e]) => [id, cellsOf(e, 'inherit')]))
  return { defaults: cellsOf(store?.defaults, 'unlimited'), perSet: map(store?.perSet), perUser: map(store?.perUser) }
}

const SPEC = new Map(QUOTA_FIELD_SPECS.map((s) => [s.field, s]))

function cellError(field: QuotaField, cell: Cell): string | null {
  if (cell.mode !== 'limit') return null
  const { min, max, unit } = SPEC.get(field)!
  const text = cell.value.trim()
  const n = Number(text)
  return /^\d+$/.test(text) && n >= min && n <= max ? null : `A whole number of ${unit} from ${min} to ${max}.`
}

/** Why each typed limit is refused, keyed `defaults.<field>`, `perSet.<id>.<field>`, `perUser.<id>.<field>`. */
export function draftErrors(draft: QuotaDraft): Record<string, string> {
  const errors: Record<string, string> = {}
  const check = (prefix: string, cells: Cells) => {
    for (const field of QUOTA_FIELDS) {
      const e = cellError(field, cells[field])
      if (e) errors[`${prefix}.${field}`] = e
    }
  }
  check('defaults', draft.defaults)
  for (const key of ['perSet', 'perUser'] as const) {
    for (const [id, cells] of Object.entries(draft[key])) check(`${key}.${id}`, cells)
  }
  return errors
}

export function entryOf(cells: Cells): QuotaEntry {
  const entry: QuotaEntry = {}
  for (const field of QUOTA_FIELDS) {
    const c = cells[field]
    if (c.mode === 'unlimited') entry[field] = null
    else if (c.mode === 'limit') entry[field] = Number(c.value.trim())
  }
  return entry
}

const defaultsEntryOf = (cells: Cells): QuotaEntry =>
  Object.fromEntries(Object.entries(entryOf(cells)).filter(([, v]) => v !== null))

const same = (a: QuotaEntry, b: QuotaEntry) =>
  QUOTA_FIELDS.every((f) => Object.hasOwn(a, f) === Object.hasOwn(b, f) && a[f] === b[f])

export interface QuotaPatchBody {
  defaults?: QuotaEntry
  perSet?: Record<string, QuotaEntry | null>
  perUser?: Record<string, QuotaEntry | null>
}

/** The route's patch for what differs from the saved draft; null when nothing does. */
export function quotaPatch(saved: QuotaDraft, draft: QuotaDraft): QuotaPatchBody | null {
  const patch: QuotaPatchBody = {}
  const d = defaultsEntryOf(draft.defaults)
  if (!same(defaultsEntryOf(saved.defaults), d)) patch.defaults = d
  for (const key of ['perSet', 'perUser'] as const) {
    const changes: Record<string, QuotaEntry | null> = {}
    for (const id of new Set([...Object.keys(saved[key]), ...Object.keys(draft[key])])) {
      const before = saved[key][id] ? entryOf(saved[key][id]) : null
      const after = draft[key][id] ? entryOf(draft[key][id]) : null
      const afterOrNull = after && Object.keys(after).length ? after : null
      if (before === null && afterOrNull === null) continue
      if (before && afterOrNull && same(before, afterOrNull)) continue
      changes[id] = afterOrNull
    }
    if (Object.keys(changes).length) patch[key] = changes
  }
  return Object.keys(patch).length ? patch : null
}

/** One entry in words for a summary line: "Projects owned 2, Scans at once unlimited". */
export function entrySummary(entry: QuotaEntry): string {
  const parts = QUOTA_FIELD_SPECS.filter((s) => Object.hasOwn(entry, s.field))
    .map((s) => `${s.label} ${entry[s.field] === null ? 'unlimited' : entry[s.field]}`)
  return parts.length ? parts.join(', ') : 'nothing set'
}

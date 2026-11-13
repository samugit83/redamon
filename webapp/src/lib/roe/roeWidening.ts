/**
 * Does a change WIDEN the engagement: more traffic, more targets, more time,
 * more permission?
 *
 * A widening row is flagged in the review, pauses every enabled scan schedule
 * (a schedule has no fingerprint guard, so it would silently run under the new
 * terms), and on a third-party engagement needs an authorization first.
 *
 * Most rules follow from the registry: a rate field's unit, a tool's `*Enabled`
 * flag, a `roeAllow*` permission, a `tighten_only` safety switch. The engagement
 * limits each mean something different (removing an excluded host widens,
 * removing a scanning day narrows), so they are a table, and a test fails if a
 * limit is added without a row here.
 */
import { field, type RegistryField } from '@/lib/reconSettings/registry'
import { sameValue } from '@/lib/reconSettings/roeParse'

export type Direction =
  /** A ceiling: 0 means none, so dropping it to 0 or raising it widens. */
  | 'ceiling'
  /** A list of exclusions: an entry removed widens. */
  | 'removal'
  /** A list of allowances: an entry added widens. */
  | 'addition'
  | 'disable'
  | 'enable'
  /** A date: moving earlier (or clearing it) widens. */
  | 'earlier'
  | 'later'
  /**
   * One end of the daily window, judged with the other end as the minutes of a day the window
   * admits: a minute added widens, whichever end moved.
   */
  | 'window'
  | 'any'
  /** Moving up the field's ordered `values` widens. */
  | 'higher'
  | 'never'

export const ENGAGEMENT_DIRECTIONS: Readonly<Record<string, Direction>> = {
  roeGlobalMaxRps: 'ceiling',
  roeExcludedHosts: 'removal',
  roeExcludedHostReasons: 'never',
  roeTimeWindowEnabled: 'disable',
  roeTimeWindowDays: 'addition',
  roeTimeWindowStartTime: 'window',
  roeTimeWindowEndTime: 'window',
  roeTimeWindowTimezone: 'any',
  roeForbiddenTools: 'removal',
  roeForbiddenCategories: 'removal',
  roeMaxSeverityPhase: 'higher',
  roeEngagementStartDate: 'earlier',
  roeEngagementEndDate: 'later',
  scanModules: 'addition',
  stealthMode: 'disable',
}

/** The window's own switch: its days, hours and zone only matter while it is on. */
const WINDOW_SWITCH = 'roeTimeWindowEnabled'
const WINDOW_START = 'roeTimeWindowStartTime'
const WINDOW_END = 'roeTimeWindowEndTime'
const WINDOW_PARTS = new Set(['roeTimeWindowDays', WINDOW_START, WINDOW_END, 'roeTimeWindowTimezone'])

/**
 * The text the readers parse in the fields the registry can only type as free text: HH:MM, the
 * form every reader compares the current time in, and YYYY-MM-DD, the agent's `strptime` and the
 * schedules' check. A value the readers cannot read is not narrower by any order: they compare a
 * malformed time as text and skip a malformed date, which is no end date at all.
 */
const TIME_OF_DAY = /^([01]\d|2[0-3]):[0-5]\d$/
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/

function isCalendarDate(v: string): boolean {
  if (!ISO_DATE.test(v)) return false
  const [y, m, d] = v.split('-').map(Number)
  const date = new Date(Date.UTC(y, m - 1, d))
  return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d
}

const READ_FORMATS: Readonly<Record<string, { ok: (v: unknown) => boolean; problem: string }>> = {
  [WINDOW_START]: { ok: v => typeof v === 'string' && TIME_OF_DAY.test(v), problem: 'is not a time of day as HH:MM, which the readers compare as text' },
  [WINDOW_END]: { ok: v => typeof v === 'string' && TIME_OF_DAY.test(v), problem: 'is not a time of day as HH:MM, which the readers compare as text' },
  roeEngagementStartDate: { ok: v => v === '' || (typeof v === 'string' && isCalendarDate(v)), problem: 'is not a date as YYYY-MM-DD, which the readers skip: no date at all' },
  roeEngagementEndDate: { ok: v => v === '' || (typeof v === 'string' && isCalendarDate(v)), problem: 'is not a date as YYYY-MM-DD, which the readers skip: no date at all' },
}

/** Why the readers would not read `value` of `key` as written, for a free-text field with a format; or null. */
export function formatProblem(key: string, value: unknown): string | null {
  const format = Object.prototype.hasOwnProperty.call(READ_FORMATS, key) ? READ_FORMATS[key] : undefined
  return format && !format.ok(value) ? format.problem : null
}

const MINUTES_PER_DAY = 24 * 60
const hhmm = (minute: number): string =>
  `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`

/**
 * The minutes of a day a window admits, computed as every reader does (recon `_time_in_window`, the
 * orchestrator's start check, the agent's warning, `insideScanWindow`): the stored HH:MM text
 * compared as text, both ends inclusive, a start after the end crossing midnight, and a value that
 * is not text read as the default 09:00 / 18:00. Comparing as the readers compare, rather than
 * parsing, keeps a malformed stored value judged by what it actually admits.
 */
function windowMinutes(start: unknown, end: unknown): boolean[] {
  const s = typeof start === 'string' ? start : '09:00'
  const e = typeof end === 'string' ? end : '18:00'
  return Array.from({ length: MINUTES_PER_DAY }, (_, m) => {
    const t = hhmm(m)
    return s <= e ? t >= s && t <= e : t >= s || t <= e
  })
}

/** Why the window `beforeRow` -> `afterRow` admits a minute it did not, or null. */
function widerWindow(key: string, before: unknown, after: unknown, beforeRow: Record<string, unknown>, afterRow: Record<string, unknown>): string | null {
  const wasStart = key === WINDOW_START ? before : beforeRow[WINDOW_START]
  const wasEnd = key === WINDOW_END ? before : beforeRow[WINDOW_END]
  const nowStart = key === WINDOW_START ? after : afterRow[WINDOW_START]
  const nowEnd = key === WINDOW_END ? after : afterRow[WINDOW_END]
  const was = windowMinutes(wasStart, wasEnd)
  const added = windowMinutes(nowStart, nowEnd).filter((inside, m) => inside && !was[m]).length
  if (added === 0) return null
  const label = (s: unknown, e: unknown) => `${typeof s === 'string' ? s : '09:00'}-${typeof e === 'string' ? e : '18:00'}`
  return `the daily window ${label(wasStart, wasEnd)} becomes ${label(nowStart, nowEnd)}, ` +
    `${added} more minutes a day (it starts earlier or ends later; an end before the start crosses midnight)`
}

/** How a change to `key` is judged, or undefined when it can never widen. */
export function directionOf(key: string, spec: RegistryField | undefined = field(key)): Direction | undefined {
  if (Object.prototype.hasOwnProperty.call(ENGAGEMENT_DIRECTIONS, key)) return ENGAGEMENT_DIRECTIONS[key]
  if (!spec) return undefined
  if (spec.type === 'boolean' && (key.startsWith('roeAllow') || key.endsWith('Enabled'))) return 'enable'
  if (spec.unit === 'rps') return 'ceiling'
  return undefined
}

const asList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : [])
const asText = (v: unknown): string => (typeof v === 'string' ? v.trim() : v == null ? '' : String(v))

/**
 * Why `before -> after` widens the engagement, or null.
 *
 * `beforeRow` and `afterRow` are the whole project before and after the change,
 * for the rules that depend on another field (the window parts).
 */
export function wideningReason(
  key: string,
  before: unknown,
  after: unknown,
  beforeRow: Record<string, unknown> = {},
  afterRow: Record<string, unknown> = {},
): string | null {
  if (sameValue(before, after)) return null
  const spec = field(key)
  if (!spec) return null

  if (spec.roe_parse === 'tighten_only') {
    return sameValue(after, spec.roe_safe_value) ? null : 'relaxes a safety control'
  }
  if (WINDOW_PARTS.has(key) && !(beforeRow[WINDOW_SWITCH] === true && afterRow[WINDOW_SWITCH] === true)) {
    // Turning the window off is flagged on the switch itself; turning it on, or
    // editing a window that is not in force, cannot widen anything.
    return null
  }

  const direction = directionOf(key, spec)
  if (direction === 'window') return formatProblem(key, after) ?? widerWindow(key, before, after, beforeRow, afterRow)
  return direction ? byDirection(direction, spec, before, after) : null
}

function byDirection(direction: Direction, spec: RegistryField, before: unknown, after: unknown): string | null {
  switch (direction) {
    case 'ceiling': {
      const b = Number(before ?? 0)
      const a = Number(after ?? 0)
      if (!(b > 0)) return null
      // 0 is no ceiling at all (effectiveCeiling), unless the field says it
      // switches the tool off.
      if (a === 0) return spec.zero_means === 'disabled' ? null : 'removes a rate ceiling'
      return a > b ? 'raises a rate ceiling' : null
    }
    case 'removal': {
      const gone = asList(before).filter(v => !asList(after).includes(v))
      return gone.length ? `removes ${gone.join(', ')}` : null
    }
    case 'addition': {
      const added = asList(after).filter(v => !asList(before).includes(v))
      return added.length ? `adds ${added.join(', ')}` : null
    }
    case 'disable':
      return before === true && after !== true ? 'turns off a restriction' : null
    case 'enable':
      return before !== true && after === true ? 'turns on something the engagement had off' : null
    case 'earlier':
    case 'later': {
      const b = asText(before)
      const a = asText(after)
      if (a && !isCalendarDate(a)) return 'is not a date as YYYY-MM-DD, which the readers skip: no date at all'
      // No date the readers could read was no bound: nothing to widen from.
      if (!b || !isCalendarDate(b)) return null
      if (direction === 'earlier') return !a || a < b ? 'moves earlier' : null
      return !a || a > b ? 'moves later' : null
    }
    case 'any':
      return 'changes the window'
    case 'window':
      // Judged with the other end, in wideningReason.
      return null
    case 'higher': {
      const order = spec.values ?? []
      // An unknown value is no step of the order: the agent reads an unknown phase cap as the widest.
      if (!order.includes(asText(after))) return `is not one of ${order.join(', ')}, which the readers take as the widest`
      return order.indexOf(asText(after)) > order.indexOf(asText(before)) ? 'allows a later phase' : null
    }
    case 'never':
      return null
  }
}

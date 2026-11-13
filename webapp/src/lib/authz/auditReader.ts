/**
 * Reading the instance audit log for the admin console: one account's latest rows (step 6.2) and the
 * audit viewer with its filters, details and export (step 6.6). A list carries only the row's who,
 * what and when: `before` and `after` can hold personal data, so only one row's details panel and the
 * export show them, with credentials, tokens, hashes and step-up fields withheld (master plan §9.8).
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { auditActionLabel, auditGroupTerms, isAuditGroup, type AuditGroup } from './auditLabels'
import { accountTypeOf, loadInstanceRoot, type AccountType } from './root'

export interface AuditRowView {
  id: string
  action: string
  createdAt: string
  actorId: string | null
  /** The actor's address when the row was written, so a deleted account is still named. */
  actorEmail: string | null
  onBehalfOfUserId: string | null
  targetType: string
  targetId: string | null
  projectId: string | null
  permission: string | null
  source: string
}

const ROW_SELECT = {
  id: true, action: true, createdAt: true, actorId: true, actorEmail: true, onBehalfOfUserId: true,
  targetType: true, targetId: true, projectId: true, permission: true, source: true,
} as const

/**
 * The latest rows where the account is the actor or the target (`targetType: 'user'`), newest first:
 * each side has its index (`actorId, createdAt` and `targetType, targetId, createdAt`). Rows written
 * by someone acting as the account carry it in `onBehalfOfUserId`, which has no index, so they are
 * not read here; the audit viewer finds them.
 */
export async function recentAuditAbout(userId: string, limit: number): Promise<AuditRowView[]> {
  const rows = await prisma.auditLog.findMany({
    where: { OR: [{ actorId: userId }, { targetType: 'user', targetId: userId }] },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: limit,
    select: ROW_SELECT,
  })
  return rows.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() }))
}

// ---------------------------------------------------------------------------------------------------
// The audit viewer and its export (step 6.6; GV-07, AU-07, AU-04): GET /api/admin/audit (audit:read),
// GET /api/admin/audit/[id] and GET /api/admin/audit/export (audit:export). Three tables: `audit_log`
// (`audit`), the act-as rows (`act_as`) and the Fireteam settings changes (`fireteam`).

export const AUDIT_TABLES = ['audit', 'act_as', 'fireteam'] as const
export type AuditTable = (typeof AUDIT_TABLES)[number]

export const AUDIT_PAGE_SIZE = 50
export const AUDIT_MAX_PAGE_SIZE = 100

export const AUDIT_FILTER_KEYS = ['actor', 'onBehalfOf', 'target', 'targetType', 'project', 'action', 'group', 'from', 'to'] as const
export type AuditFilterKey = (typeof AUDIT_FILTER_KEYS)[number]

/**
 * The filters each table takes. `action` is the act-as row's event (start, end) and the Fireteam row's
 * field. A filter a table cannot apply is refused (400), never silently ignored: an export narrower or
 * wider than the person asked would read as the whole answer.
 */
export const AUDIT_TABLE_FILTERS: Readonly<Record<AuditTable, readonly AuditFilterKey[]>> = Object.freeze({
  audit: AUDIT_FILTER_KEYS,
  act_as: ['actor', 'target', 'action', 'from', 'to'],
  fireteam: ['actor', 'project', 'action', 'from', 'to'],
})

export interface AuditFilters {
  table: AuditTable
  /** An account id, or an email (a deleted actor is found by the email its rows recorded). */
  actor: string | null
  onBehalfOf: string | null
  /** A target id, or an account's email. */
  target: string | null
  targetType: string | null
  project: string | null
  /** The `action` filter: an exact action, or a prefix ending in `*` (`project.share.*`). */
  actionPattern: string | null
  group: AuditGroup | null
  from: Date | null
  /** Inclusive; a bare date (`2026-11-13`) means the whole day. */
  to: Date | null
  cursor: { at: Date; id: string } | null
  limit: number
}

export interface AuditFilterProblem {
  error: string
  code: 'invalid_filter'
  field: string
}

const filterProblem = (field: string, error: string): AuditFilterProblem => ({ error, code: 'invalid_filter', field })

const ID_SHAPE = /^[A-Za-z0-9_:.-]{1,128}$/
const EMAIL_SHAPE = /^[^\s@]{1,128}@[^\s@]{1,190}$/
const TARGET_TYPE_SHAPE = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/
const ACTION_SHAPE = /^[A-Za-z0-9_.-]{1,120}\*?$/
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/
const CURSOR_ID = /^[A-Za-z0-9_-]{1,64}$/
const DAY_MS = 86_400_000

export function encodeAuditCursor(at: Date, id: string): string {
  return Buffer.from(`${at.toISOString()}|${id}`, 'utf8').toString('base64url')
}

function decodeAuditCursor(raw: string): AuditFilters['cursor'] {
  const text = Buffer.from(raw, 'base64url').toString('utf8')
  const bar = text.indexOf('|')
  if (bar <= 0) return null
  const at = new Date(text.slice(0, bar))
  const id = text.slice(bar + 1)
  if (Number.isNaN(at.getTime()) || at.toISOString() !== text.slice(0, bar) || !CURSOR_ID.test(id)) return null
  return { at, id }
}

function parseInstant(raw: string, end: boolean): Date | null {
  if (DATE_ONLY.test(raw)) {
    const day = new Date(`${raw}T00:00:00.000Z`)
    if (Number.isNaN(day.getTime()) || day.toISOString().slice(0, 10) !== raw) return null
    return end ? new Date(day.getTime() + DAY_MS - 1) : day
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(raw)) return null
  const at = new Date(raw)
  return Number.isNaN(at.getTime()) ? null : at
}

/** The viewer's and the export's query string, or the first field that is not one they take. */
export function parseAuditQuery(params: URLSearchParams): AuditFilters | AuditFilterProblem {
  const text = (key: string) => {
    const v = params.get(key)
    return v === null || v.trim() === '' ? null : v.trim()
  }
  const rawTable = text('table') ?? 'audit'
  if (!(AUDIT_TABLES as readonly string[]).includes(rawTable)) return filterProblem('table', `table must be one of ${AUDIT_TABLES.join(', ')}`)
  const table = rawTable as AuditTable
  const allowed = AUDIT_TABLE_FILTERS[table]
  for (const key of AUDIT_FILTER_KEYS) {
    if (text(key) !== null && !allowed.includes(key)) return filterProblem(key, `${key} is not a filter of the ${table} table`)
  }

  const account = (key: 'actor' | 'onBehalfOf' | 'target'): string | null | AuditFilterProblem => {
    const v = text(key)
    if (v === null) return null
    if (v.includes('@') ? !EMAIL_SHAPE.test(v) : !ID_SHAPE.test(v)) return filterProblem(key, `${key} must be an id or an email address`)
    return v
  }
  const actor = account('actor')
  if (actor && typeof actor === 'object') return actor
  const onBehalfOf = account('onBehalfOf')
  if (onBehalfOf && typeof onBehalfOf === 'object') return onBehalfOf
  const target = account('target')
  if (target && typeof target === 'object') return target

  const targetType = text('targetType')
  if (targetType && !TARGET_TYPE_SHAPE.test(targetType)) return filterProblem('targetType', 'targetType is not a target type')
  const project = text('project')
  if (project && !ID_SHAPE.test(project)) return filterProblem('project', 'project must be a project id')
  const action = text('action')
  if (action && (!ACTION_SHAPE.test(action) || action === '*')) {
    return filterProblem('action', 'action must be an action name, or a prefix ending in *')
  }
  const rawGroup = text('group')
  if (rawGroup && !isAuditGroup(rawGroup)) return filterProblem('group', 'group must be one of the audit groups')

  const rawFrom = text('from')
  const from = rawFrom ? parseInstant(rawFrom, false) : null
  if (rawFrom && !from) return filterProblem('from', 'from must be a date (YYYY-MM-DD) or an ISO time')
  const rawTo = text('to')
  const to = rawTo ? parseInstant(rawTo, true) : null
  if (rawTo && !to) return filterProblem('to', 'to must be a date (YYYY-MM-DD) or an ISO time')
  if (from && to && from > to) return filterProblem('to', 'to must not be before from')

  const rawCursor = text('cursor')
  const cursor = rawCursor ? decodeAuditCursor(rawCursor) : null
  if (rawCursor && !cursor) return filterProblem('cursor', 'cursor must be the nextCursor of a previous page')

  const rawLimit = text('limit')
  const limit = rawLimit === null ? AUDIT_PAGE_SIZE : Number(rawLimit)
  if (!Number.isInteger(limit) || limit < 1 || limit > AUDIT_MAX_PAGE_SIZE) {
    return filterProblem('limit', `limit must be a whole number from 1 to ${AUDIT_MAX_PAGE_SIZE}`)
  }

  return {
    table, actor, onBehalfOf, target, targetType, project, actionPattern: action,
    group: rawGroup ? (rawGroup as AuditGroup) : null, from, to, cursor, limit,
  }
}

/** The account ids a filter value names: the id itself, or the account an email names (if any). */
interface AccountRef { ids: string[]; email: string | null }

async function resolveAccount(value: string | null): Promise<AccountRef | null> {
  if (value === null) return null
  if (!value.includes('@')) return { ids: [value], email: null }
  const account = await prisma.user.findFirst({
    where: { email: { equals: value, mode: 'insensitive' } },
    select: { id: true },
  })
  return { ids: account ? [account.id] : [], email: value }
}

interface ResolvedRefs { actor: AccountRef | null; onBehalfOf: AccountRef | null; target: AccountRef | null }

async function resolveRefs(f: AuditFilters): Promise<ResolvedRefs> {
  const [actor, onBehalfOf, target] = await Promise.all([resolveAccount(f.actor), resolveAccount(f.onBehalfOf), resolveAccount(f.target)])
  return { actor, onBehalfOf, target }
}

function timeWhere(f: AuditFilters): { createdAt?: { gte?: Date; lte?: Date } } {
  if (!f.from && !f.to) return {}
  return { createdAt: { ...(f.from ? { gte: f.from } : {}), ...(f.to ? { lte: f.to } : {}) } }
}

function cursorWhere(f: AuditFilters) {
  return f.cursor ? [{ OR: [{ createdAt: { lt: f.cursor.at } }, { createdAt: f.cursor.at, id: { lt: f.cursor.id } }] }] : []
}

function actionWhere(action: string): { equals: string } | { startsWith: string } {
  return action.endsWith('*') ? { startsWith: action.slice(0, -1) } : { equals: action }
}

export function auditLogWhere(f: AuditFilters, refs: ResolvedRefs): Prisma.AuditLogWhereInput {
  const and: Prisma.AuditLogWhereInput[] = []
  if (refs.actor) {
    and.push({
      OR: [
        { actorId: { in: refs.actor.ids } },
        ...(refs.actor.email ? [{ actorEmail: { equals: refs.actor.email, mode: 'insensitive' as const } }] : []),
      ],
    })
  }
  if (refs.onBehalfOf) and.push({ onBehalfOfUserId: { in: refs.onBehalfOf.ids } })
  if (refs.target) and.push({ targetId: { in: refs.target.ids } })
  if (f.targetType) and.push({ targetType: f.targetType })
  // The rows written about a project before step 2.1 added `projectId` name it as their target.
  if (f.project) and.push({ OR: [{ projectId: f.project }, { targetType: 'project', targetId: f.project }] })
  if (f.actionPattern) and.push({ action: actionWhere(f.actionPattern) })
  if (f.group) {
    const { actions, prefixes } = auditGroupTerms(f.group)
    const terms: Prisma.AuditLogWhereInput[] = [
      ...(actions.length ? [{ action: { in: actions } }] : []),
      ...prefixes.map((prefix) => ({ action: { startsWith: prefix } })),
    ]
    if (f.group === 'acting') terms.push({ onBehalfOfUserId: { not: null } })
    and.push({ OR: terms })
  }
  and.push(timeWhere(f), ...cursorWhere(f))
  return { AND: and }
}

export function actAsWhere(f: AuditFilters, refs: ResolvedRefs): Prisma.ActAsAuditWhereInput {
  const and: Prisma.ActAsAuditWhereInput[] = []
  if (refs.actor) and.push({ adminId: { in: refs.actor.ids } })
  if (refs.target) and.push({ targetUserId: { in: refs.target.ids } })
  if (f.actionPattern) and.push({ event: actionWhere(f.actionPattern) })
  and.push(timeWhere(f), ...cursorWhere(f))
  return { AND: and }
}

export function fireteamWhere(f: AuditFilters, refs: ResolvedRefs): Prisma.FireteamSettingsAuditWhereInput {
  const and: Prisma.FireteamSettingsAuditWhereInput[] = []
  if (refs.actor) and.push({ userId: { in: refs.actor.ids } })
  if (f.project) and.push({ projectId: f.project })
  if (f.actionPattern) and.push({ field: actionWhere(f.actionPattern) })
  and.push(timeWhere(f), ...cursorWhere(f))
  return { AND: and }
}

/** A person as the viewer names them (IdentityLabel's fields, and the id the console links to). */
export interface AuditPerson {
  id: string | null
  /** Empty for a deleted account. */
  name: string
  /** The account's email; for a deleted actor the one the row recorded; null when nothing names it. */
  email: string | null
  accountType: AccountType | null
  deleted: boolean
}

export interface AuditLogEntry {
  kind: 'audit'
  id: string
  at: string
  action: string
  label: string
  group: AuditGroup | null
  /** Null for the system, a host script, or a row that names no one. */
  actor: AuditPerson | null
  onBehalfOf: AuditPerson | null
  /** What the row is about; `account` names it when it is an account. */
  target: { type: string; id: string | null; account: AuditPerson | null }
  project: { id: string; name: string | null } | null
  permission: string | null
  source: string
}

export interface ActAsEntry {
  kind: 'act_as'
  id: string
  at: string
  event: string
  label: string
  admin: AuditPerson
  target: AuditPerson
  source: string
  reason: string | null
  durationMinutes: number | null
  endedBy: string | null
}

export interface FireteamEntry {
  kind: 'fireteam'
  id: string
  at: string
  field: string
  project: { id: string; name: string | null }
  user: AuditPerson | null
  oldValue: unknown
  newValue: unknown
  source: string
}

export type AuditEntryView = AuditLogEntry | ActAsEntry | FireteamEntry

export interface AuditPage {
  table: AuditTable
  entries: AuditEntryView[]
  nextCursor: string | null
}

/** One audit_log row with what it recorded, for the details panel (secrets withheld). */
export interface AuditLogDetail extends AuditLogEntry {
  actorEmailRecorded: string | null
  before: unknown
  after: unknown
}

const LOG_SELECT = { ...ROW_SELECT } as const
const ACT_AS_SELECT = {
  id: true, adminId: true, targetUserId: true, event: true, source: true, createdAt: true, reason: true,
  durationMinutes: true, endedBy: true,
} as const
const FIRETEAM_SELECT = {
  id: true, projectId: true, userId: true, field: true, oldValue: true, newValue: true, source: true, createdAt: true,
} as const
const ORDER = [{ createdAt: 'desc' as const }, { id: 'desc' as const }]

type LogRow = Prisma.AuditLogGetPayload<{ select: typeof LOG_SELECT }>
type ActAsRow = Prisma.ActAsAuditGetPayload<{ select: typeof ACT_AS_SELECT }>
type FireteamRow = Prisma.FireteamSettingsAuditGetPayload<{ select: typeof FIRETEAM_SELECT }>

/** Names the accounts and projects a batch of rows mentions, with two reads whatever its size. */
async function directory(accountIds: Set<string>, projectIds: Set<string>) {
  const [people, root, projects] = await Promise.all([
    accountIds.size
      ? prisma.user.findMany({ where: { id: { in: [...accountIds] } }, select: { id: true, name: true, email: true, role: true } })
      : Promise.resolve([]),
    accountIds.size ? loadInstanceRoot() : Promise.resolve(null),
    projectIds.size
      ? prisma.project.findMany({ where: { id: { in: [...projectIds] } }, select: { id: true, name: true } })
      : Promise.resolve([]),
  ])
  const byId = new Map(people.map((p) => [p.id, p]))
  const projectNames = new Map(projects.map((p) => [p.id, p.name]))
  const person = (id: string | null, recordedEmail: string | null = null): AuditPerson | null => {
    if (!id) return recordedEmail ? { id: null, name: '', email: recordedEmail, accountType: null, deleted: false } : null
    const account = byId.get(id)
    if (!account) return { id, name: '', email: recordedEmail, accountType: null, deleted: true }
    return { id, name: account.name ?? '', email: account.email, accountType: accountTypeOf(account, root), deleted: false }
  }
  const project = (id: string) => ({ id, name: projectNames.get(id) ?? null })
  return { person, project, isAccount: (id: string) => byId.has(id) }
}

// The act-as table's events are labelled as the audit_log's `act_as.<event>` rows are.
const actAsLabel = (event: string) => auditActionLabel(`act_as.${event}`).label

type LogRowWithChanges = LogRow & { before?: Prisma.JsonValue; after?: Prisma.JsonValue }

async function logEntries(rows: LogRowWithChanges[]): Promise<AuditLogEntry[]> {
  const accounts = new Set<string>()
  const projects = new Set<string>()
  for (const r of rows) {
    if (r.actorId) accounts.add(r.actorId)
    if (r.onBehalfOfUserId) accounts.add(r.onBehalfOfUserId)
    if (r.targetType === 'user' && r.targetId) accounts.add(r.targetId)
    const project = r.projectId ?? (r.targetType === 'project' ? r.targetId : null)
    if (project) projects.add(project)
  }
  const d = await directory(accounts, projects)
  return rows.map((r) => {
    const { label, group } = auditActionLabel(r.action)
    const project = r.projectId ?? (r.targetType === 'project' ? r.targetId : null)
    return {
      kind: 'audit',
      id: r.id,
      at: r.createdAt.toISOString(),
      action: r.action,
      label,
      group,
      actor: d.person(r.actorId, r.actorEmail),
      onBehalfOf: r.onBehalfOfUserId ? d.person(r.onBehalfOfUserId) : null,
      target: { type: r.targetType, id: r.targetId, account: r.targetType === 'user' && r.targetId ? d.person(r.targetId) : null },
      project: project ? d.project(project) : null,
      permission: r.permission,
      source: r.source,
      ...('before' in r || 'after' in r
        ? { actorEmailRecorded: r.actorEmail, before: withoutSecrets(r.before ?? null), after: withoutSecrets(r.after ?? null) }
        : {}),
    }
  })
}

async function actAsEntries(rows: ActAsRow[]): Promise<ActAsEntry[]> {
  const d = await directory(new Set(rows.flatMap((r) => [r.adminId, r.targetUserId])), new Set())
  return rows.map((r) => ({
    kind: 'act_as',
    id: r.id,
    at: r.createdAt.toISOString(),
    event: r.event,
    label: actAsLabel(r.event),
    admin: d.person(r.adminId)!,
    target: d.person(r.targetUserId)!,
    source: r.source,
    reason: r.reason,
    durationMinutes: r.durationMinutes,
    endedBy: r.endedBy,
  }))
}

async function fireteamEntries(rows: FireteamRow[]): Promise<FireteamEntry[]> {
  const d = await directory(
    new Set(rows.flatMap((r) => (r.userId ? [r.userId] : []))),
    new Set(rows.map((r) => r.projectId)),
  )
  return rows.map((r) => ({
    kind: 'fireteam',
    id: r.id,
    at: r.createdAt.toISOString(),
    field: r.field,
    project: d.project(r.projectId),
    user: d.person(r.userId),
    oldValue: r.oldValue,
    newValue: r.newValue,
    source: r.source,
  }))
}

/**
 * Up to `take` rows of the table, newest first, as the viewer shows them; with `changes`, each audit
 * log row also carries its recorded email, `before` and `after` (secrets withheld), as AuditLogDetail.
 */
async function readEntries(
  f: AuditFilters,
  refs: ResolvedRefs,
  take: number,
  changes = false,
): Promise<{ entries: AuditEntryView[]; last: { at: Date; id: string } | null; more: boolean }> {
  const page = <T extends { createdAt: Date; id: string }>(rows: T[]) => {
    const kept = rows.slice(0, take)
    const tail = kept[kept.length - 1]
    return { kept, last: tail ? { at: tail.createdAt, id: tail.id } : null, more: rows.length > take }
  }
  if (f.table === 'act_as') {
    const { kept, last, more } = page(await prisma.actAsAudit.findMany({ where: actAsWhere(f, refs), orderBy: ORDER, take: take + 1, select: ACT_AS_SELECT }))
    return { entries: await actAsEntries(kept), last, more }
  }
  if (f.table === 'fireteam') {
    const { kept, last, more } = page(await prisma.fireteamSettingsAudit.findMany({ where: fireteamWhere(f, refs), orderBy: ORDER, take: take + 1, select: FIRETEAM_SELECT }))
    return { entries: await fireteamEntries(kept), last, more }
  }
  const select = changes ? { ...LOG_SELECT, before: true, after: true } : LOG_SELECT
  const { kept, last, more } = page(await prisma.auditLog.findMany({ where: auditLogWhere(f, refs), orderBy: ORDER, take: take + 1, select }))
  return { entries: await logEntries(kept), last, more }
}

/** One page of the viewer: newest first, a keyset cursor (rows of one instant neither repeat nor go missing). */
export async function readAuditPage(f: AuditFilters): Promise<AuditPage> {
  const { entries, last, more } = await readEntries(f, await resolveRefs(f), f.limit)
  return { table: f.table, entries, nextCursor: more && last ? encodeAuditCursor(last.at, last.id) : null }
}

/** How many rows the filters select (the cursor left out); the export's header and its audit row. */
export async function countAuditRows(f: AuditFilters): Promise<number> {
  const refs = await resolveRefs(f)
  const all = { ...f, cursor: null }
  if (f.table === 'act_as') return prisma.actAsAudit.count({ where: actAsWhere(all, refs) })
  if (f.table === 'fireteam') return prisma.fireteamSettingsAudit.count({ where: fireteamWhere(all, refs) })
  return prisma.auditLog.count({ where: auditLogWhere(all, refs) })
}

/**
 * The export's rows, newest first, `batch` at a time, at most `max` in all; audit log rows come with
 * their changes (AuditLogDetail). Each batch is read after the previous one was handed on, so a slow
 * download holds one batch in memory, not the export.
 */
export async function* auditBatches(f: AuditFilters, { batch, max }: { batch: number; max: number }): AsyncGenerator<AuditEntryView[]> {
  const refs = await resolveRefs(f)
  let cursor = f.cursor
  let sent = 0
  while (sent < max) {
    const take = Math.min(batch, max - sent)
    const { entries, last, more } = await readEntries({ ...f, cursor }, refs, take, true)
    if (entries.length) yield entries
    sent += entries.length
    if (!more || !last) return
    cursor = last
  }
}

// Keys whose value an export or the details panel never shows: credentials, tokens and their
// prefixes, hashes (a share lookup's email hash), step-up fields (master plan §9.8). Wider than the
// forwarder's exact list on purpose: what is withheld here is only shown, never stored differently.
const WITHHELD_KEY = /token|hash|sha\d|password|passphrase|secret|step_?up|api_?key|private_?key|cookie|authorization|credential/i
export const WITHHELD = '[withheld]'

export function withoutSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutSecrets)
  if (value === null || typeof value !== 'object' || value instanceof Date) return value
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, v]) => (
    WITHHELD_KEY.test(key) ? [key, WITHHELD] : [key, withoutSecrets(v)]
  )))
}

/** One audit_log row with its before and after, secrets withheld; null when there is none. */
export async function readAuditLogDetail(id: string): Promise<AuditLogDetail | null> {
  const row = await prisma.auditLog.findUnique({ where: { id }, select: { ...LOG_SELECT, before: true, after: true } })
  if (!row) return null
  const [entry] = await logEntries([row])
  return entry as AuditLogDetail
}

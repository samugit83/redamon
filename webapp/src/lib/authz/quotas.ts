/**
 * Quotas per permission set and per account (step 6.8; GV-09, GV-10, GV-11, GV-13; OQ-39).
 *
 * Stored in `InstanceSettings.quotas` (a JSON column, `{}` by default) as
 *
 *   { defaults: q, perSet: { <setId>: q }, perUser: { <userId>: q } }
 *
 * where `q` names any of QUOTA_FIELDS. In `defaults` a field left out or `null` is unlimited. In a
 * per-set or per-user entry a field left out is not set there (the next level decides) and `null`
 * is unlimited: a set can lift a default limit for its holders. Every default is unlimited until an
 * admin sets one (`PLACEHOLDER(OQ-39)`); a stored value this module cannot read (hand-edited) reads
 * as unlimited and is logged once, the way `{}` reads (fail open for availability, by design).
 *
 * A person's quota, field by field: their per-user value, else the most permissive value among the
 * sets in force for them (the admin profile and the member sets, defaults included, as
 * capabilities.ts resolves them: sets are a union, so a set that allows more wins), else the default.
 * Root is never limited: Root holds instance:quotas and could lift any limit on itself.
 *
 * With RBAC_GOVERNANCE_ENABLED off nothing is read and everyone is unlimited (DV-30). With it on the
 * quota is read fresh at each check (a check guards a write that creates the counted thing, which is
 * rare), and a failed read throws: the write is refused with a 500, never let through.
 *
 * Readers outside this module use only:
 *   - `quotaLimit(userId, field)`: one value, `null` = unlimited (step 6.11 reads `llmDailyCalls`);
 *   - `quotaFor(userId)`: every value with where it came from (the account and admin screens);
 *   - the refusal helpers below, which answer 409 `{error, code: 'quota_exceeded', quota, limit}` and
 *     log `[rbac] quota_exceeded quota=<field> user=<id> limit=<n> used=<n>`: how an operator learns a
 *     quota refused something.
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { instanceSettingsInForce } from '@/lib/sharedInstanceSettings'
import { rbacFlags } from './flags'
import { now } from './clock'
import { loadPrincipal } from './principal'
import { resolveCapabilities } from './capabilities'
import { BUILTIN_SETS, builtinSet, isBuiltinSetId } from './builtinSets'

export const QUOTA_FIELDS = [
  'maxProjects',
  'maxConcurrentScans',
  'maxConcurrentAgentRuns',
  'maxMcpTokens',
  'maxMcpTokenExpiryDays',
  'llmDailyCalls',
] as const

export type QuotaField = (typeof QUOTA_FIELDS)[number]
/** A limit, or null = unlimited. */
export type QuotaValue = number | null
export type Quota = Readonly<Record<QuotaField, QuotaValue>>
/** One level's values: a field left out is not set at this level. */
export type QuotaEntry = Partial<Record<QuotaField, QuotaValue>>

export interface QuotaStore {
  defaults: QuotaEntry
  perSet: Record<string, QuotaEntry>
  perUser: Record<string, QuotaEntry>
}

/** The values a write accepts, each a whole number in its range. */
export const QUOTA_BOUNDS: Readonly<Record<QuotaField, { min: number; max: number }>> = Object.freeze({
  maxProjects: { min: 0, max: 100_000 },
  maxConcurrentScans: { min: 0, max: 1_000 },
  maxConcurrentAgentRuns: { min: 0, max: 1_000 },
  maxMcpTokens: { min: 0, max: 1_000 },
  maxMcpTokenExpiryDays: { min: 1, max: 3_650 },
  llmDailyCalls: { min: 0, max: 10_000_000 },
})

export const UNLIMITED: Quota = Object.freeze(Object.fromEntries(QUOTA_FIELDS.map((f) => [f, null])) as Record<QuotaField, QuotaValue>)

/** Where a value came from: the account's entry, a set's, the default, or no limit applies at all. */
export type QuotaSource =
  | { kind: 'user' }
  | { kind: 'set'; setId: string }
  | { kind: 'default' }
  /** RBAC_GOVERNANCE_ENABLED off, or Root: nothing is limited. */
  | { kind: 'off' | 'root' }

export interface ResolvedQuota {
  /** False when no quota applies to this person (the switch off, or Root). */
  enforced: boolean
  quota: Quota
  sources: Readonly<Record<QuotaField, QuotaSource>>
}

const MAX_KEY_LENGTH = 200
// More rows than any instance has sets or accounts with their own quota; bounds a write.
const MAX_ENTRIES = 5_000

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

function validValue(field: QuotaField, v: unknown): v is QuotaValue {
  if (v === null) return true
  const { min, max } = QUOTA_BOUNDS[field]
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max
}

const warned = new Set<string>()
function warnInvalid(path: string): void {
  if (warned.has(path)) return
  warned.add(path)
  console.warn(`[rbac] quotas: the stored value at ${path} is not valid: read as unlimited`)
}

function readEntry(raw: unknown, path: string): QuotaEntry {
  const entry: QuotaEntry = {}
  if (!isRecord(raw)) {
    if (raw !== undefined) warnInvalid(path)
    return entry
  }
  for (const field of QUOTA_FIELDS) {
    if (!Object.hasOwn(raw, field)) continue
    const v = raw[field]
    if (validValue(field, v)) entry[field] = v
    else {
      warnInvalid(`${path}.${field}`)
      entry[field] = null
    }
  }
  return entry
}

function readEntries(raw: unknown, path: string): Record<string, QuotaEntry> {
  const out: Record<string, QuotaEntry> = {}
  if (!isRecord(raw)) {
    if (raw !== undefined) warnInvalid(path)
    return out
  }
  for (const [key, value] of Object.entries(raw)) {
    if (!key || key.length > MAX_KEY_LENGTH) continue
    out[key] = readEntry(value, `${path}.${key.slice(0, 80)}`)
  }
  return out
}

/** The stored column as quotas; anything unreadable is unlimited. Never throws. */
export function parseQuotaStore(raw: unknown): QuotaStore {
  if (!isRecord(raw)) {
    if (raw !== undefined && raw !== null) warnInvalid('quotas')
    return { defaults: {}, perSet: {}, perUser: {} }
  }
  return {
    defaults: readEntry(raw.defaults, 'defaults'),
    perSet: readEntries(raw.perSet, 'perSet'),
    perUser: readEntries(raw.perUser, 'perUser'),
  }
}

/** True when no level sets any limit: nothing to resolve, everyone is unlimited. */
export function storeIsEmpty(store: QuotaStore): boolean {
  const empty = (e: QuotaEntry) => Object.values(e).every((v) => v === null || v === undefined)
  return empty(store.defaults) && Object.values(store.perSet).every(empty) && Object.values(store.perUser).every(empty)
}

/** The more permissive of two values: null (unlimited) beats any number, else the larger. */
const morePermissive = (a: QuotaValue, b: QuotaValue): QuotaValue => (a === null || b === null ? null : Math.max(a, b))

/** One person's quota from the stored levels and the ids of the sets in force for them. Pure. */
export function resolveQuota(store: QuotaStore, who: { userId: string; setIds: readonly string[] }): ResolvedQuota {
  const own = store.perUser[who.userId] ?? {}
  const quota = {} as Record<QuotaField, QuotaValue>
  const sources = {} as Record<QuotaField, QuotaSource>
  for (const field of QUOTA_FIELDS) {
    if (Object.hasOwn(own, field)) {
      quota[field] = own[field] as QuotaValue
      sources[field] = { kind: 'user' }
      continue
    }
    let best: { value: QuotaValue; setId: string } | null = null
    for (const setId of who.setIds) {
      const entry = store.perSet[setId]
      if (!entry || !Object.hasOwn(entry, field)) continue
      const value = entry[field] as QuotaValue
      if (best === null || morePermissive(best.value, value) !== best.value) best = { value, setId }
    }
    if (best) {
      quota[field] = best.value
      sources[field] = { kind: 'set', setId: best.setId }
    } else {
      quota[field] = store.defaults[field] ?? null
      sources[field] = { kind: 'default' }
    }
  }
  return { enforced: true, quota: Object.freeze(quota), sources: Object.freeze(sources) }
}

const allSources = (source: QuotaSource) =>
  Object.freeze(Object.fromEntries(QUOTA_FIELDS.map((f) => [f, source])) as Record<QuotaField, QuotaSource>)

const NOT_ENFORCED_OFF: ResolvedQuota = Object.freeze({ enforced: false, quota: UNLIMITED, sources: allSources({ kind: 'off' }) })
const NOT_ENFORCED_ROOT: ResolvedQuota = Object.freeze({ enforced: false, quota: UNLIMITED, sources: allSources({ kind: 'root' }) })

/** Whether quotas are enforced on this instance at all (RBAC_GOVERNANCE_ENABLED). */
export function quotasInForce(): boolean {
  return rbacFlags().governance
}

/** The stored quotas, or null with the switch off (nothing read). A failed read throws. */
export async function readQuotaStore(): Promise<QuotaStore | null> {
  if (!quotasInForce()) return null
  const row = await instanceSettingsInForce()
  return parseQuotaStore(row?.quotas)
}

/** One person's quota, read fresh. Unlimited with the switch off (nothing read) and for Root. */
export async function quotaFor(userId: string): Promise<ResolvedQuota> {
  const store = await readQuotaStore()
  if (store === null) return NOT_ENFORCED_OFF
  if (storeIsEmpty(store)) return resolveQuota(store, { userId, setIds: [] })
  const principal = await loadPrincipal(userId, { fresh: true })
  if (!principal) return resolveQuota(store, { userId, setIds: [] })
  const caps = await resolveCapabilities(principal, { fresh: true })
  if (caps.accountType === 'root') return NOT_ENFORCED_ROOT
  return resolveQuota(store, { userId, setIds: caps.sets.map((s) => s.id) })
}

/** One value of a person's quota; null = unlimited. The interface step 6.11 reads `llmDailyCalls` through. */
export async function quotaLimit(userId: string, field: QuotaField): Promise<QuotaValue> {
  return (await quotaFor(userId)).quota[field]
}

const FIELD_WORDS: Readonly<Record<QuotaField, string>> = {
  maxProjects: 'projects you own',
  maxConcurrentScans: 'scans running at once',
  maxConcurrentAgentRuns: 'agent runs at once',
  maxMcpTokens: 'MCP tokens',
  maxMcpTokenExpiryDays: 'days an MCP token may last',
  llmDailyCalls: 'model calls a day on instance providers',
}

/** The 409 every quota refusal answers, logged with the fixed `[rbac] quota_exceeded` code. */
export function quotaExceededResponse(field: QuotaField, limit: number, userId: string, used: number | null): NextResponse {
  console.warn(`[rbac] quota_exceeded quota=${field} user=${userId} limit=${limit} used=${used ?? '-'}`)
  return NextResponse.json(
    {
      error: `Quota reached: your limit is ${limit} ${FIELD_WORDS[field]}. Ask an administrator to raise it.`,
      code: 'quota_exceeded',
      quota: field,
      limit,
    },
    { status: 409 },
  )
}

/** The projects an account owns: what maxProjects counts (a share or a transfer offer is not a creation). */
export function ownedProjectCount(userId: string): Promise<number> {
  return prisma.project.count({ where: { userId } })
}

/**
 * Before a project is created for `ownerId` (the project create, the import, MCP create_project):
 * the 409 when they already own their limit, else null.
 */
export async function projectQuotaRefusal(ownerId: string): Promise<NextResponse | null> {
  const limit = await quotaLimit(ownerId, 'maxProjects')
  if (limit === null) return null
  const owned = await ownedProjectCount(ownerId)
  return owned < limit ? null : quotaExceededResponse('maxProjects', limit, ownerId, owned)
}

/** The MCP tokens that can still be used: not revoked, not expired. What maxMcpTokens counts. */
export function activeMcpTokenCount(userId: string): Promise<number> {
  return prisma.mcpAccessToken.count({
    where: { userId, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] },
  })
}

/**
 * The scan start's field for the orchestrator (step 5.5's actor carries it): the actor's
 * maxConcurrentScans, which the orchestrator's admission applies as the smaller of it and
 * RECON_MAX_CONCURRENT_PER_USER. Empty when the actor is unlimited or the switch is off.
 */
export async function actorScanCap(actorUserId: string): Promise<{ actor_max_concurrent?: number }> {
  const limit = await quotaLimit(actorUserId, 'maxConcurrentScans')
  return limit === null ? {} : { actor_max_concurrent: limit }
}

/** One account's quota as the account and admin screens show it: each value, where it came from, and the use counted here. */
export interface QuotaReport {
  enforced: boolean
  quota: Quota
  sources: Readonly<Record<QuotaField, QuotaSource & { setName?: string }>>
  /**
   * What the webapp counts: owned projects and MCP tokens that still work. Concurrent scans and agent
   * runs are counted where they run (the orchestrator, the agent), and the day's model calls by
   * step 6.11, so they are not reported here.
   */
  use: Partial<Record<QuotaField, number>>
}

export async function quotaReport(userId: string): Promise<QuotaReport> {
  const resolved = await quotaFor(userId)
  const setIds = [...new Set(Object.values(resolved.sources).flatMap((s) => (s.kind === 'set' ? [s.setId] : [])))]
  const stored = setIds.filter((id) => !isBuiltinSetId(id))
  const [rows, projects, tokens] = await Promise.all([
    stored.length ? prisma.permissionSet.findMany({ where: { id: { in: stored } }, select: { id: true, name: true } }) : [],
    ownedProjectCount(userId),
    activeMcpTokenCount(userId),
  ])
  const names = new Map<string, string>([
    ...setIds.flatMap((id) => { const b = builtinSet(id); return b ? [[id, b.name] as [string, string]] : [] }),
    ...rows.map((r) => [r.id, r.name] as [string, string]),
  ])
  const sources = Object.fromEntries(QUOTA_FIELDS.map((f) => {
    const s = resolved.sources[f]
    return [f, s.kind === 'set' && names.has(s.setId) ? { ...s, setName: names.get(s.setId)! } : s]
  })) as Record<QuotaField, QuotaSource & { setName?: string }>
  return { enforced: resolved.enforced, quota: resolved.quota, sources, use: { maxProjects: projects, maxMcpTokens: tokens } }
}

// ---------------------------------------------------------------------------------------------
// Writes (the instance:quotas group of /api/admin/instance-settings)
// ---------------------------------------------------------------------------------------------

/**
 * A change: `defaults` replaces the defaults; each `perSet` / `perUser` key replaces that entry, or
 * removes it when null or empty. Keys not named keep their entry, so two admins changing two
 * accounts never undo each other.
 */
export interface QuotaPatch {
  defaults?: QuotaEntry
  perSet?: Record<string, QuotaEntry | null>
  perUser?: Record<string, QuotaEntry | null>
}

type PatchError = { error: { field: string; message: string } }

function parseEntry(raw: unknown, path: string): { entry: QuotaEntry } | PatchError {
  if (!isRecord(raw)) return { error: { field: path, message: `${path} must be an object of quota values` } }
  const entry: QuotaEntry = {}
  for (const [key, value] of Object.entries(raw)) {
    if (!(QUOTA_FIELDS as readonly string[]).includes(key)) {
      return { error: { field: `${path}.${key}`, message: `${key} is not a quota` } }
    }
    const field = key as QuotaField
    if (value === undefined) continue
    if (!validValue(field, value)) {
      const { min, max } = QUOTA_BOUNDS[field]
      return { error: { field: `${path}.${field}`, message: `${field} must be a whole number from ${min} to ${max}, or null for unlimited` } }
    }
    entry[field] = value
  }
  return { entry }
}

function parseEntryMap(raw: unknown, path: string): { map: Record<string, QuotaEntry | null> } | PatchError {
  if (!isRecord(raw)) return { error: { field: path, message: `${path} must be an object` } }
  const keys = Object.keys(raw)
  if (keys.length > MAX_ENTRIES) return { error: { field: path, message: `${path} names too many entries` } }
  const map: Record<string, QuotaEntry | null> = {}
  for (const key of keys) {
    if (!key || key.length > MAX_KEY_LENGTH) return { error: { field: path, message: `${path} has an invalid id` } }
    if (raw[key] === null) {
      map[key] = null
      continue
    }
    const parsed = parseEntry(raw[key], `${path}.${key.slice(0, 80)}`)
    if ('error' in parsed) return parsed
    map[key] = parsed.entry
  }
  return { map }
}

/** The `quotas` member of a PUT body, checked; nothing outside QUOTA_FIELDS and their bounds passes. */
export function parseQuotaPatch(raw: unknown): { patch: QuotaPatch } | PatchError {
  if (!isRecord(raw)) return { error: { field: 'quotas', message: 'quotas must be an object' } }
  const patch: QuotaPatch = {}
  for (const key of Object.keys(raw)) {
    if (key !== 'defaults' && key !== 'perSet' && key !== 'perUser') {
      return { error: { field: `quotas.${key}`, message: `${key} is not part of the quotas` } }
    }
  }
  if (raw.defaults !== undefined) {
    const parsed = parseEntry(raw.defaults, 'quotas.defaults')
    if ('error' in parsed) return parsed
    patch.defaults = parsed.entry
  }
  for (const key of ['perSet', 'perUser'] as const) {
    if (raw[key] === undefined) continue
    const parsed = parseEntryMap(raw[key], `quotas.${key}`)
    if ('error' in parsed) return parsed
    patch[key] = parsed.map
  }
  return { patch }
}

/** The ids a patch adds an entry for that name no set (built-in or stored) or no account. Removals are never refused. */
export async function unknownQuotaTargets(patch: QuotaPatch): Promise<{ sets: string[]; users: string[] }> {
  const added = (m: Record<string, QuotaEntry | null> | undefined) =>
    Object.entries(m ?? {}).filter(([, e]) => e !== null && Object.keys(e).length > 0).map(([k]) => k)
  const setIds = added(patch.perSet).filter((id) => !isBuiltinSetId(id))
  const userIds = added(patch.perUser)
  const [sets, users] = await Promise.all([
    setIds.length ? prisma.permissionSet.findMany({ where: { id: { in: setIds } }, select: { id: true } }) : [],
    userIds.length ? prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true } }) : [],
  ])
  const knownSets = new Set(sets.map((s) => s.id))
  const knownUsers = new Set(users.map((u) => u.id))
  return {
    sets: setIds.filter((id) => !knownSets.has(id)),
    users: userIds.filter((id) => !knownUsers.has(id)),
  }
}

const sameEntry = (a: QuotaEntry | undefined, b: QuotaEntry | undefined): boolean =>
  QUOTA_FIELDS.every((f) => Object.hasOwn(a ?? {}, f) === Object.hasOwn(b ?? {}, f) && (a ?? {})[f] === (b ?? {})[f])

/** The stored quotas after a patch. Pure; never changes `store`. */
export function applyQuotaPatch(store: QuotaStore, patch: QuotaPatch): QuotaStore {
  const next: QuotaStore = {
    defaults: patch.defaults ? { ...patch.defaults } : { ...store.defaults },
    perSet: { ...store.perSet },
    perUser: { ...store.perUser },
  }
  for (const key of ['perSet', 'perUser'] as const) {
    for (const [id, entry] of Object.entries(patch[key] ?? {})) {
      if (entry === null || Object.keys(entry).length === 0) delete next[key][id]
      else next[key][id] = { ...entry }
    }
  }
  return next
}

/**
 * What changed, as names for the audit row (`defaults.maxProjects`, `perSet.<id>`, `perUser.<id>`),
 * never the values (the `instance.settings_changed` row names fields only).
 */
export function changedQuotaKeys(before: QuotaStore, after: QuotaStore): string[] {
  const out: string[] = []
  for (const f of QUOTA_FIELDS) {
    const a = before.defaults[f] ?? null
    const b = after.defaults[f] ?? null
    if (a !== b) out.push(`defaults.${f}`)
  }
  for (const key of ['perSet', 'perUser'] as const) {
    const ids = new Set([...Object.keys(before[key]), ...Object.keys(after[key])])
    for (const id of [...ids].sort()) {
      if (!sameEntry(before[key][id], after[key][id])) out.push(`${key}.${id}`)
    }
  }
  return out
}

/** What the quota editor names: every set and profile, and the accounts the per-user entries name. */
export interface QuotaTargets {
  quotaSets: { id: string; name: string; kind: string }[]
  /** Present only for whoever may read the user directory (users:read); otherwise the editor shows ids. */
  quotaUsers?: { id: string; email: string; name: string }[]
}

export async function quotaTargetsView(store: QuotaStore, { withUsers }: { withUsers: boolean }): Promise<QuotaTargets> {
  const userIds = Object.keys(store.perUser)
  const [stored, users] = await Promise.all([
    prisma.permissionSet.findMany({ select: { id: true, name: true, kind: true }, orderBy: { name: 'asc' } }),
    withUsers && userIds.length
      ? prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, email: true, name: true } })
      : null,
  ])
  return {
    quotaSets: [...BUILTIN_SETS.map((s) => ({ id: s.id, name: s.name, kind: s.kind })), ...stored],
    ...(withUsers ? { quotaUsers: users ?? [] } : {}),
  }
}

/** The value written to the column. */
export function quotaStoreToJson(store: QuotaStore): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(store)) as Prisma.InputJsonValue
}

/** Tests only. */
export function clearQuotaWarningsForTests(): void {
  warned.clear()
}

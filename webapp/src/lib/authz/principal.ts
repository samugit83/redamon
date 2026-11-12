/**
 * The signed-in account as the database holds it now. The login JWT lives 7 days
 * and carries a role, so trusting it kept a demoted or deleted admin's powers until
 * the cookie expired; the session helpers read role and existence here instead, so a
 * change takes effect on the account's next request.
 *
 * While the identity switch is on, each process keeps an account it read for
 * RBAC_AUTHZ_CACHE_MS (one query per request when cold, none when warm). A writer in
 * this process drops the account it changed (`invalidatePrincipal`), so its own next
 * request sees the change; another process (a second webapp copy, a host command) sees
 * it within the bound. An action a stale account must never allow reads with `fresh`.
 * With the switch off nothing is cached: one indexed read by primary key per call.
 *
 * With the permissions switch on, the same read also brings the account's permission sets and
 * overrides (step 3.4), for capabilities.ts; off, the query and the principal are Phase 2's.
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'

export interface Principal {
  id: string
  email: string
  name: string
  role: string
  /** active | invited | disabled */
  status: string
  /** Raised to sign the account out everywhere; a login token carries the value it was issued with. */
  sessionVersion: number
  mustChangePassword: boolean
  /** The admin profile narrowing this admin; null = a full admin. */
  adminProfileId: string | null
  /** False for a passwordless (managed) account, which can never sign in itself. */
  hasPassword: boolean
  createdAt: Date
  lastLoginAt: Date | null
  /** The shared tools the account kept at the RBAC upgrade (authz/sharedTools.ts). */
  legacyGrants: readonly string[]
  /**
   * The permission set ids assigned to the account (none = never assigned). Present only when
   * the account was read with the permissions switch on.
   */
  permissionSets?: readonly string[]
  /** Every override row, expired ones included: capabilities.ts judges expiry on the clock. */
  permissionOverrides?: readonly PermissionOverrideRow[]
}

export interface PermissionOverrideRow {
  permission: string
  /** grant | deny */
  effect: string
  expiresAt: Date | null
  reason: string | null
}

export interface LoadPrincipalOptions {
  /** Read the database even when this process holds the account, and keep what it read. */
  fresh?: boolean
}

// PLACEHOLDER(OQ-38): the authorization cache bound.
const DEFAULT_CACHE_MS = 5000
// A larger bound would leave a revoked account signed in on the other copies for longer
// than an operator expects from "the next request".
const MAX_CACHE_MS = 60_000
// One entry per account that signed in recently; a cap keeps a flood of distinct ids from
// growing the map without bound.
const MAX_ENTRIES = 10_000

const cache = new Map<string, { principal: Principal; expiresAt: number }>()
// Raised by every invalidation: a read that started before one may hold what the writer
// just changed, so it is returned to its caller but not kept.
let generation = 0

const warned = new Set<string>()
function warnOnce(line: string): void {
  if (warned.has(line)) return
  warned.add(line)
  console.warn(line)
}

/** The cache bound in milliseconds; 0 turns the cache off. The value is never logged. */
export function principalCacheMs(): number {
  const raw = (process.env.RBAC_AUTHZ_CACHE_MS ?? '').trim()
  if (raw === '') return DEFAULT_CACHE_MS
  if (!/^\d+$/.test(raw)) {
    warnOnce(`[rbac] unrecognised value for RBAC_AUTHZ_CACHE_MS; using ${DEFAULT_CACHE_MS}`)
    return DEFAULT_CACHE_MS
  }
  const ms = Number(raw)
  if (ms > MAX_CACHE_MS) {
    warnOnce(`[rbac] RBAC_AUTHZ_CACHE_MS is above ${MAX_CACHE_MS}; using ${MAX_CACHE_MS}`)
    return MAX_CACHE_MS
  }
  return ms
}

/** The cache bound in force now: 0 while the identity switch is off. */
export function principalCacheTtl(): number {
  return rbacFlags().identity ? principalCacheMs() : 0
}

/**
 * The account `userId` names, or null when it no longer exists. A failed read throws.
 * The returned object may be shared with other requests: it is frozen.
 */
export async function loadPrincipal(userId: string, { fresh = false }: LoadPrincipalOptions = {}): Promise<Principal | null> {
  if (!userId) return null
  if (!fresh) {
    const hit = cachedPrincipal(userId)
    if (hit) return hit
  }
  const ttl = principalCacheTtl()
  const startedAt = generation
  const principal = await readPrincipal(userId)
  // A fresh read that finds no account must not leave an older entry answering for it.
  if (!principal) cache.delete(userId)
  else if (ttl > 0 && startedAt === generation) remember(principal, ttl)
  return principal
}

/** The account this process holds for `userId` within the bound, or null. Reads nothing. */
export function cachedPrincipal(userId: string): Principal | null {
  if (principalCacheTtl() <= 0) return null
  const hit = cache.get(userId)
  if (!hit || hit.expiresAt <= now().getTime()) return null
  // Read under the other permissions switch state, it lacks (or carries) the assignments.
  return (hit.principal.permissionSets !== undefined) === rbacFlags().permissions ? hit.principal : null
}

/** A writer in this process changed the account: its next read goes to the database. */
export function invalidatePrincipal(userId: string): void {
  generation += 1
  cache.delete(userId)
}

/** Tests only: forget every account. */
export function clearPrincipalCacheForTests(): void {
  generation += 1
  cache.clear()
}

function remember(principal: Principal, ttl: number): void {
  const at = now().getTime()
  if (cache.size >= MAX_ENTRIES && !cache.has(principal.id)) {
    for (const [id, entry] of cache) if (entry.expiresAt <= at) cache.delete(id)
    // Still full: drop the oldest insertion.
    if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value as string)
  }
  cache.set(principal.id, { principal, expiresAt: at + ttl })
}

const PERMISSION_ROWS = {
  permissionSets: { select: { setId: true } },
  permissionOverrides: { select: { permission: true, effect: true, expiresAt: true, reason: true } },
} as const

interface PermissionRows {
  permissionSets?: Array<{ setId: string }>
  permissionOverrides?: Array<{ permission: string; effect: string; expiresAt: Date | null; reason: string | null }>
}

function permissionFields(row: PermissionRows): Pick<Principal, 'permissionSets' | 'permissionOverrides'> {
  return {
    permissionSets: Object.freeze((row.permissionSets ?? []).map((r) => r.setId)),
    permissionOverrides: Object.freeze((row.permissionOverrides ?? []).map((r) => Object.freeze({
      permission: r.permission, effect: r.effect, expiresAt: r.expiresAt ?? null, reason: r.reason ?? null,
    }))),
  }
}

async function readPrincipal(userId: string): Promise<Principal | null> {
  const withPermissions = rbacFlags().permissions
  // Prisma cannot select `password <> ''`, so the hash is read and reduced to a
  // boolean here; it never leaves this function.
  const row = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true, email: true, name: true, role: true, password: true, createdAt: true, legacyGrants: true,
      status: true, sessionVersion: true, mustChangePassword: true, adminProfileId: true, lastLoginAt: true,
      ...(withPermissions ? PERMISSION_ROWS : {}),
    },
  })
  if (!row) return null
  // The database always returns every column (each has a default). A missing one reads
  // as the value every account had before the column existed.
  return Object.freeze({
    id: row.id,
    email: row.email,
    name: row.name ?? '',
    role: row.role,
    status: row.status ?? 'active',
    sessionVersion: typeof row.sessionVersion === 'number' ? row.sessionVersion : 0,
    mustChangePassword: row.mustChangePassword === true,
    adminProfileId: row.adminProfileId ?? null,
    hasPassword: row.password !== '',
    createdAt: row.createdAt,
    lastLoginAt: row.lastLoginAt ?? null,
    legacyGrants: Object.freeze(Array.isArray(row.legacyGrants) ? [...row.legacyGrants] : []),
    ...(withPermissions ? permissionFields(row as PermissionRows) : {}),
  })
}

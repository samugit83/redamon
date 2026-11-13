/**
 * The instance sharing policy (step 4.2, SH-21; feature document §6.5): the shape of the JSON
 * column `InstanceSettings.sharingPolicy`, how a stored value reads, how Root's change is checked,
 * and the reader the share routes, `projectAccess()` and /api/auth/me use.
 *
 * Sharing is in force only with RBAC_SHARING_ENABLED on AND `enabled` here (Root's). The column's
 * default `{}` reads as the defaults, so an upgraded instance shares nothing until Root turns it
 * on. A stored value that is not an object, or holds a known setting with a wrong value, reads as
 * the defaults AS A WHOLE (sharing off) with a warning naming the setting, never the value: a
 * policy half read could widen what Root meant. An unknown setting is ignored, and kept when Root
 * saves, so a copy of an older release never strips a newer release's setting during a deploy.
 *
 * Read only with the switch on; the row is one for the process, cached for RBAC_AUTHZ_CACHE_MS
 * like the Root (root.ts), so a request costs at most one indexed read per bound, and a write in
 * this process drops it. Another copy follows within the bound (§9.6).
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { principalCacheTtl } from './principal'
import { INSTANCE_SETTINGS_ROW } from './root'

export type ShareLevel = 'read' | 'write'

export interface SharingPolicy {
  /** Sharing on for the instance (the second key beside RBAC_SHARING_ENABLED). */
  enabled: boolean
  /** The highest level a share may have; write counts only once Phase 5's write switch is on. */
  maxLevel: ShareLevel
  /** Whether a member may grant the Exploitation & shells toggle (otherwise admins only). */
  membersMayGrantExploit: boolean
  /** The expiry a new share gets when the person sharing sets none; null = none. */
  defaultExpiryDays: number | null
  /** Whether admins holding users:read see every share (the shares overview). */
  adminsSeeAllShares: boolean
}

export type SharingPolicyField = keyof SharingPolicy

export const SHARING_POLICY_FIELDS = [
  'enabled', 'maxLevel', 'membersMayGrantExploit', 'defaultExpiryDays', 'adminsSeeAllShares',
] as const satisfies readonly SharingPolicyField[]

export const SHARING_POLICY_DEFAULTS: Readonly<SharingPolicy> = Object.freeze({
  enabled: false,
  maxLevel: 'write',
  membersMayGrantExploit: false,
  defaultExpiryDays: null,
  adminsSeeAllShares: true,
})

/** Whole days; 3650 (ten years) bounds a typo, not an engagement. */
export const DEFAULT_EXPIRY_DAYS_BOUNDS = [1, 3650] as const

const LEVELS: readonly ShareLevel[] = ['read', 'write']

/** Null when `value` is acceptable for `field`, else why not (no value quoted). */
function refusal(field: SharingPolicyField, value: unknown): string | null {
  switch (field) {
    case 'enabled':
    case 'membersMayGrantExploit':
    case 'adminsSeeAllShares':
      return typeof value === 'boolean' ? null : `${field} must be true or false`
    case 'maxLevel':
      return LEVELS.includes(value as ShareLevel) ? null : 'maxLevel must be "read" or "write"'
    case 'defaultExpiryDays': {
      const [min, max] = DEFAULT_EXPIRY_DAYS_BOUNDS
      if (value === null) return null
      return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max
        ? null
        : `defaultExpiryDays must be empty (no default expiry) or a whole number of days from ${min} to ${max}`
    }
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

const warned = new Set<string>()

function warnOnce(line: string): void {
  if (warned.has(line)) return
  warned.add(line)
  console.warn(line)
}

function invalid(what: string): SharingPolicy {
  warnOnce(`[rbac] the stored sharing policy is invalid (${what}): sharing stays off with the default policy until Root saves it again`)
  return { ...SHARING_POLICY_DEFAULTS }
}

/** The policy a stored value means: the defaults for `{}`, a missing setting, or anything invalid. */
export function parseSharingPolicy(stored: unknown): SharingPolicy {
  if (!isPlainObject(stored)) return invalid('not an object')
  const policy: SharingPolicy = { ...SHARING_POLICY_DEFAULTS }
  for (const field of SHARING_POLICY_FIELDS) {
    if (!(field in stored)) continue
    if (refusal(field, stored[field]) !== null) return invalid(field)
    ;(policy as unknown as Record<string, unknown>)[field] = stored[field]
  }
  return policy
}

export type SharingPolicyPatch = Partial<SharingPolicy>

/**
 * Root's change, from the body's `sharingPolicy` object: known settings only, each valid. `field`
 * names the first refused one as `sharingPolicy.<setting>` (or `sharingPolicy` for a non-object).
 */
export function parseSharingPolicyPatch(raw: unknown):
  | { patch: SharingPolicyPatch }
  | { error: { field: string; message: string } } {
  if (!isPlainObject(raw)) {
    return { error: { field: 'sharingPolicy', message: 'sharingPolicy must be an object of sharing policy settings' } }
  }
  const patch: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(raw)) {
    if (!(SHARING_POLICY_FIELDS as readonly string[]).includes(key)) {
      return { error: { field: `sharingPolicy.${key}`, message: `sharingPolicy.${key} is not a sharing policy setting` } }
    }
    const why = refusal(key as SharingPolicyField, value)
    if (why) return { error: { field: `sharingPolicy.${key}`, message: `sharingPolicy.${why}` } }
    patch[key] = value
  }
  return { patch: patch as SharingPolicyPatch }
}

/** The patch's settings whose value differs from the policy in force, in the policy's order. */
export function changedSharingPolicyFields(current: SharingPolicy, patch: SharingPolicyPatch): SharingPolicyField[] {
  return SHARING_POLICY_FIELDS.filter((f) => f in patch && patch[f] !== current[f])
}

/**
 * The JSON to store: every setting written out with the change applied, over the policy the stored
 * value means (an invalid one is replaced), keeping the stored object's unknown settings.
 */
export function sharingPolicyToStore(stored: unknown, patch: SharingPolicyPatch): Record<string, unknown> {
  const kept = isPlainObject(stored) ? stored : {}
  return { ...kept, ...parseSharingPolicy(stored), ...patch }
}

let cached: { policy: Readonly<SharingPolicy>; expiresAt: number } | null = null
// Raised by every invalidation: a read that started before one is returned but not kept.
let generation = 0

/**
 * The policy in force, or null with RBAC_SHARING_ENABLED off (nothing read). A missing instance row
 * (the boot backfill has not filled it, and logs why) reads as the defaults. A failed read throws
 * and caches nothing.
 */
export async function sharingPolicyInForce({ fresh = false }: { fresh?: boolean } = {}): Promise<Readonly<SharingPolicy> | null> {
  if (!rbacFlags().sharing) return null
  const ttl = principalCacheTtl()
  if (!fresh && ttl > 0 && cached && cached.expiresAt > now().getTime()) return cached.policy
  const startedAt = generation
  const row = await prisma.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { sharingPolicy: true },
  })
  const policy = Object.freeze(row ? parseSharingPolicy(row.sharingPolicy) : { ...SHARING_POLICY_DEFAULTS })
  if (ttl > 0 && startedAt === generation) cached = { policy, expiresAt: now().getTime() + ttl }
  return policy
}

export interface SharingInForce {
  /** RBAC_SHARING_ENABLED on and the policy enabled. */
  enabled: boolean
  /** The highest level a share may be granted at now: read unless the write switch is on and the policy allows write. */
  maxLevel: ShareLevel
}

/** Whether sharing is in force, for the screens (/api/auth/me). Switch off: off, nothing read. */
export async function sharingInForce(): Promise<SharingInForce> {
  const policy = await sharingPolicyInForce()
  if (!policy) return { enabled: false, maxLevel: 'read' }
  return {
    enabled: policy.enabled,
    maxLevel: rbacFlags().sharingWrite && policy.maxLevel === 'write' ? 'write' : 'read',
  }
}

/** A writer of the policy in this process (the instance settings PUT): the next read goes to the database. */
export function invalidateSharingPolicy(): void {
  generation += 1
  cached = null
}

/** Tests only: the cache and the once-per-process warnings. */
export function clearSharingPolicyCacheForTests(): void {
  invalidateSharingPolicy()
  warned.clear()
}

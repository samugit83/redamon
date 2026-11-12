/**
 * The legacy grants under the permission engine (step 3.15, HD-02, OQ-26). The first boot with
 * RBAC_PERMISSIONS_ENABLED on converts them (scripts/backfill-rbac-legacy-overrides.mjs, which
 * repeats these constants; a test holds them equal): a grant an admin kept becomes an override
 * grant of its platform permission with the reason "kept from 7.7.x" and a 90-day end, and the
 * rest lapse. Until that conversion's marker exists the resolution still counts the column
 * (capabilities.ts); from then on only overrides do.
 */
import prisma from '@/lib/prisma'
import { now } from './clock'
import type { PermissionId } from './permissions'
import { principalCacheTtl } from './principal'

export const LEGACY_OVERRIDES_MARKER = 'system.rbac_legacy_overrides_backfill'
export const KEPT_LEGACY_REASON = 'kept from 7.7.x'
export const LEGACY_KEEP_DAYS = 90 // PLACEHOLDER(OQ-26)

export const LEGACY_GRANT_PERMISSION: ReadonlyMap<string, PermissionId> = new Map<string, PermissionId>([
  ['kali_terminal', 'platform:kali_terminal'],
  ['shell_sessions', 'platform:shell_sessions'],
  ['tunnels', 'platform:tunnels'],
])

/** When a grant kept now ends. */
export function legacyKeepExpiry(from: Date = now()): Date {
  return new Date(from.getTime() + LEGACY_KEEP_DAYS * 86_400_000)
}

let converted: { value: boolean; expiresAt: number } | null = null

/**
 * Whether the boot has converted the legacy grants (its marker exists). A "yes" is kept for
 * the process: a conversion is never undone while it runs. A "no" is kept for the
 * authorization cache bound, unless `fresh`. A failed read throws.
 */
export async function legacyGrantsConverted({ fresh = false }: { fresh?: boolean } = {}): Promise<boolean> {
  if (converted?.value) return true
  const ttl = principalCacheTtl()
  if (!fresh && ttl > 0 && converted && converted.expiresAt > now().getTime()) return false
  const row = await prisma.auditLog.findFirst({ where: { action: LEGACY_OVERRIDES_MARKER }, select: { id: true } })
  converted = { value: row !== null, expiresAt: now().getTime() + ttl }
  return converted.value
}

/** Tests only. */
export function clearLegacyConversionCacheForTests(): void {
  converted = null
}

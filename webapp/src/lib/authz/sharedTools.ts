/**
 * Who may use the five instance-wide tools every signed-in account reached before the
 * RBAC hardening: the Kali terminal, every shell session, the tunnel settings, the global
 * emergency stop and every Nuclei template. Each is a platform permission (§5.2,
 * SHARED_TOOL_PERMISSIONS), and the call sites ask through here so the escape hatch stays
 * with them (PE-31):
 *
 * - with RBAC_PERMISSIONS_ENABLED on, `can(principal, 'platform:…')`: an admin profile that
 *   holds it (`admin`; Root holds every one), or a member's override (`override`, which is how
 *   a kept legacy grant lives on after step 3.15's conversion; `legacy` while a legacy grant
 *   still counts before it). The account type alone no longer decides: a User manager has none;
 * - with it off, Phase 1's rule, reading nothing more: `admin`, the database role, as the
 *   principal carries it; `legacy`, a grant the account kept at the upgrade
 *   (scripts/backfill-rbac-legacy-grants.mjs): `kali_terminal`, `shell_sessions` (every
 *   session) or `tunnels`. The stop and the templates have no legacy grant;
 * - either way, `compat`: the escape hatch REDAMON_SHARED_TOOLS_COMPAT, only for an account
 *   that existed when the new code first started (the backfill's cutoff row, read once per
 *   process). Every use logs a warning and writes `rbac.compat_used`, at most once per
 *   account, tool and hour in a process.
 *
 * Only these five tools are known here, so no other path (the MCP reload and manifest, the
 * tunnel credentials, service credentials, another account's settings, WebSocket tickets:
 * F-02, F-04, F-14, F-18, F-19, F-20) can reach the escape hatch.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import { can } from './can'
import type { CapabilityReason } from './capabilities'
import { now } from './clock'
import { rbacFlags } from './flags'
import type { PermissionId } from './permissions'
import { loadPrincipal, type Principal } from './principal'

export const SHARED_TOOLS = [
  'kali_terminal', 'shell_sessions_all', 'tunnels', 'emergency_stop_all', 'nuclei_templates_all',
] as const
export type SharedTool = (typeof SHARED_TOOLS)[number]

/** The platform permission each tool is (§5.2); routePermissions.test.ts reads it too. */
export const SHARED_TOOL_PERMISSIONS: Readonly<Record<SharedTool, PermissionId>> = Object.freeze({
  kali_terminal: 'platform:kali_terminal',
  shell_sessions_all: 'platform:shell_sessions',
  tunnels: 'platform:tunnels',
  emergency_stop_all: 'platform:emergency_stop',
  nuclei_templates_all: 'platform:nuclei_templates',
})

export interface SharedToolAccess {
  allowed: boolean
  via: 'admin' | 'legacy' | 'override' | 'compat' | null
}

export type SharedToolPrincipal = Pick<Principal, 'id' | 'role' | 'legacyGrants' | 'createdAt'> & { email?: string }

// The backfill script's CUTOFF_ACTION (a test keeps them equal).
export const LEGACY_GRANTS_CUTOFF_ACTION = 'system.rbac_legacy_grants_cutoff'
export const COMPAT_USED_ACTION = 'rbac.compat_used'
const COMPAT_AUDIT_INTERVAL_MS = 60 * 60 * 1000

const LEGACY_GRANT_FOR: Partial<Record<SharedTool, string>> = {
  kali_terminal: 'kali_terminal',
  shell_sessions_all: 'shell_sessions',
  tunnels: 'tunnels',
}

const DENIED: SharedToolAccess = Object.freeze({ allowed: false, via: null })

let cutoff: Date | null = null
const lastCompatAudit = new Map<string, number>()

/**
 * When the hardened code first started, or null before the backfill wrote it. Only a
 * found row is kept: it is written once and never changes. A failed read throws.
 */
export async function legacyCutoff(): Promise<Date | null> {
  if (cutoff) return cutoff
  const row = await prisma.auditLog.findFirst({
    where: { action: LEGACY_GRANTS_CUTOFF_ACTION },
    orderBy: { createdAt: 'asc' },
    select: { createdAt: true },
  })
  if (row) cutoff = row.createdAt
  return cutoff
}

async function recordCompatUse(userId: string, tool: SharedTool, email: string | undefined): Promise<void> {
  console.warn(`[rbac] shared-tools compat used user=${userId} tool=${tool}`)
  const key = `${userId}\u0000${tool}`
  const at = now().getTime()
  const last = lastCompatAudit.get(key)
  if (last !== undefined && at - last < COMPAT_AUDIT_INTERVAL_MS) return
  // Set before the write, so concurrent uses do not each write a row.
  lastCompatAudit.set(key, at)
  await writeAudit({
    ...actorFields(auditActorOf({ id: userId, email })),
    action: COMPAT_USED_ACTION, targetType: 'shared_tool', targetId: tool,
  })
}

/** How a person who holds the tool's permission holds it, from can()'s reasons. */
function viaOf(reasons: readonly CapabilityReason[]): 'admin' | 'legacy' | 'override' {
  if (reasons.some(r => r.effect === 'grant' && r.kind === 'override')) return 'override'
  if (reasons.some(r => r.kind === 'legacy_grant')) return 'legacy'
  return 'admin'
}

/** The permission's answer (see the header), or null when it does not admit the person. */
async function heldThroughPermission(principal: SharedToolPrincipal, tool: SharedTool): Promise<SharedToolAccess | null> {
  if (!rbacFlags().permissions) {
    if (principal.role === 'admin') return { allowed: true, via: 'admin' }
    const grant = LEGACY_GRANT_FOR[tool]
    return grant && principal.legacyGrants.includes(grant) ? { allowed: true, via: 'legacy' } : null
  }
  // The switch-on resolution needs the sets and overrides, which only a full account read carries.
  const full = (principal as Partial<Principal>).permissionSets !== undefined ? principal as Principal : await loadPrincipal(principal.id)
  if (!full) return null
  const permission = SHARED_TOOL_PERMISSIONS[tool]
  const decision = await can(full, permission)
  return decision.allowed ? { allowed: true, via: viaOf(decision.capabilities.explain(permission).reasons) } : null
}

/**
 * `record: false` is for a screen deciding whether to offer the tool: that is not a use, so
 * it neither warns nor audits, and the record of who still needs the escape hatch stays true.
 */
export async function sharedToolAccess(
  principal: SharedToolPrincipal,
  tool: SharedTool,
  { record = true }: { record?: boolean } = {},
): Promise<SharedToolAccess> {
  if (!(SHARED_TOOLS as readonly string[]).includes(tool)) return DENIED
  const held = await heldThroughPermission(principal, tool)
  if (held) return held
  if (!rbacFlags().sharedToolsCompat) return DENIED
  // No cutoff row means the backfill never ran: no account is known to predate the upgrade.
  const since = await legacyCutoff()
  if (!since || principal.createdAt.getTime() > since.getTime()) return DENIED
  if (record) await recordCompatUse(principal.id, tool, principal.email)
  return { allowed: true, via: 'compat' }
}

/** Tests only: forgets the cached cutoff and the compat audit times. */
export function resetSharedToolsForTests(): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('resetSharedToolsForTests is for tests only')
  }
  cutoff = null
  lastCompatAudit.clear()
}

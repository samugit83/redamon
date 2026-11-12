/**
 * Who may use the five instance-wide tools every signed-in account reached before the
 * RBAC hardening: the Kali terminal, every shell session, the tunnel settings, the global
 * emergency stop and every Nuclei template. Phase 3 replaces the body with
 * `can('platform:…')`; the call sites stay.
 *
 * - `admin`: the database role, as the principal carries it;
 * - `legacy`: a grant the account kept at the upgrade (scripts/backfill-rbac-legacy-grants.mjs):
 *   `kali_terminal`, `shell_sessions` (every session) or `tunnels`. The stop and the
 *   templates have no legacy grant;
 * - `compat`: the escape hatch REDAMON_SHARED_TOOLS_COMPAT, only for an account that existed
 *   when the new code first started (the backfill's cutoff row, read once per process).
 *   Every use logs a warning and writes `rbac.compat_used`, at most once per account, tool
 *   and hour in a process.
 *
 * Only these five tools are known here, so no other path (the MCP reload and manifest, the
 * tunnel credentials, service credentials, another account's settings, WebSocket tickets:
 * F-02, F-04, F-14, F-18, F-19, F-20) can reach the escape hatch.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import { now } from './clock'
import { rbacFlags } from './flags'
import type { Principal } from './principal'

export const SHARED_TOOLS = [
  'kali_terminal', 'shell_sessions_all', 'tunnels', 'emergency_stop_all', 'nuclei_templates_all',
] as const
export type SharedTool = (typeof SHARED_TOOLS)[number]

export interface SharedToolAccess {
  allowed: boolean
  via: 'admin' | 'legacy' | 'compat' | null
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
  if (principal.role === 'admin') return { allowed: true, via: 'admin' }
  const grant = LEGACY_GRANT_FOR[tool]
  if (grant && principal.legacyGrants.includes(grant)) return { allowed: true, via: 'legacy' }
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

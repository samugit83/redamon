/**
 * What an MCP token may use: the scopes it was minted with, capped by what its owner may do now
 * (feature document §5.13, §9.3; PE-20, step 3.10). A token is a machine acting for one person, so it
 * never does more than that person could.
 *
 * Each scope maps onto the registry permissions whose `mcpScopes` name it, and needs ALL of them:
 * `recon:read` reads the graph as well as recon output, so an owner denied `graph:read` loses the
 * whole scope, never keeps half of it.
 *
 *  - At mint, and when an edit adds a scope, a scope the owner cannot use is refused
 *    (`scopeGrantRefusal`, read fresh: a credential is being granted).
 *  - On every call `resolveMcpToken` keeps only the minted scopes the owner can use now
 *    (`usableScopes`): a set change, a deny, an instance cap or a disabled account stops the token's
 *    next call within the authorization cache bound, and the scope comes back with the permission.
 *    The token row is never rewritten.
 *  - Project access stays `assertMcpProjectAccess` → `projectAccess()`.
 *
 * A token has no act-as: its owner's own capabilities decide. With RBAC_PERMISSIONS_ENABLED off
 * nothing is read and the minted scopes are the usable ones, as before (DV-30).
 *
 * No `next/*` import: mcpAuth.ts imports this, and the token screen imports mcpAuth.ts.
 */
import type { McpScope } from '@/lib/mcpAuth'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal } from '@/lib/authz/principal'
import { resolveCapabilities, type Capabilities } from '@/lib/authz/capabilities'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'

const BY_SCOPE: ReadonlyMap<McpScope, readonly PermissionId[]> = (() => {
  const map = new Map<McpScope, PermissionId[]>()
  for (const permission of PERMISSION_IDS) {
    for (const scope of PERMISSIONS[permission].mcpScopes) {
      const list = map.get(scope)
      if (list) list.push(permission)
      else map.set(scope, [permission])
    }
  }
  return map
})()

/** The permissions `scope` maps to (§5.13), in registry order. */
export function scopePermissions(scope: McpScope): readonly PermissionId[] {
  return BY_SCOPE.get(scope) ?? []
}

type Holds = Pick<Capabilities, 'has'>

/**
 * Null when the owner may use `scope`, else the permissions it lacks. A scope no permission maps to
 * is never usable (an empty list): a scope added without its registry mapping fails closed.
 */
export function scopeShortfall(scope: McpScope, caps: Holds): readonly PermissionId[] | null {
  const needed = scopePermissions(scope)
  const missing = needed.filter((p) => !caps.has(p))
  return needed.length > 0 && missing.length === 0 ? null : missing
}

/**
 * Every scope the owner cannot grant, with the permissions it lacks: what the token screen shows
 * disabled, and why.
 */
export function ungrantableScopes(caps: Holds): Partial<Record<McpScope, readonly PermissionId[]>> {
  const out: Partial<Record<McpScope, readonly PermissionId[]>> = {}
  for (const scope of BY_SCOPE.keys()) {
    const missing = scopeShortfall(scope, caps)
    if (missing) out[scope] = missing
  }
  return out
}

const HOLDS_NOTHING: Holds = { has: () => false }

/**
 * The capabilities a token of `userId` acts with; an account that no longer exists holds nothing.
 * A failed read throws: it never reads as the minted scopes.
 */
export async function ownerCapabilities(userId: string, { fresh = false }: { fresh?: boolean } = {}): Promise<Holds> {
  const principal = await loadPrincipal(userId, { fresh })
  return principal ? resolveCapabilities(principal, { fresh }) : HOLDS_NOTHING
}

/** The minted scopes the owner can use now, in the token's order (switch off: all of them). */
export async function usableScopes(userId: string, minted: readonly McpScope[]): Promise<McpScope[]> {
  if (!rbacFlags().permissions) return [...minted]
  let caps: Holds
  try {
    caps = await ownerCapabilities(userId)
  } catch (err) {
    console.error("[rbac] mcp_scope_cap_failed: could not read a token owner's permissions; the call is refused", err)
    throw err
  }
  return minted.filter((scope) => scopeShortfall(scope, caps) === null)
}

/** The 403 body of a scope its owner cannot grant (master plan §9.8's shape, plus the scope). */
export interface ScopeGrantRefusal {
  error: string
  code: 'forbidden'
  permission: PermissionId | null
  scope: McpScope
}

/**
 * Why a mint or an edit may not give a token these scopes: the first one its owner cannot use and
 * the permission it lacks, answered as a 403; null when every scope is grantable (switch off:
 * always). `scopes` are the scopes being granted: an edit passes only the ones it adds, since
 * taking power away is never refused and a kept scope stays capped on every call.
 */
export async function scopeGrantRefusal(userId: string, scopes: readonly McpScope[]): Promise<ScopeGrantRefusal | null> {
  if (!rbacFlags().permissions || scopes.length === 0) return null
  const caps = await ownerCapabilities(userId, { fresh: true })
  for (const scope of scopes) {
    const missing = scopeShortfall(scope, caps)
    if (!missing) continue
    const needs = missing.length > 0 ? missing.join(' and ') : 'a permission no account holds'
    return {
      error: `A token cannot be given ${scope}: it needs ${needs}, which your permissions do not include.`,
      code: 'forbidden',
      permission: missing[0] ?? null,
      scope,
    }
  }
  return null
}

/** For the token list: what the account cannot grant, or undefined with the switch off (no field). */
export async function ungrantableScopesOf(userId: string): Promise<Partial<Record<McpScope, readonly PermissionId[]>> | undefined> {
  if (!rbacFlags().permissions) return undefined
  return ungrantableScopes(await ownerCapabilities(userId))
}

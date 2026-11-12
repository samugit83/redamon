/**
 * The self-service permission (§5.3, step 3.9) of an account's own catalogs under
 * `/api/users/[id]/**`: LLM providers, API keys, MCP servers, skills, tradecraft.
 *
 * The route's account rule runs first (`requireUserAccess`, `requireOwnBrowserRequest`): it decides
 * WHOSE data the request may reach. This decides whether the person may use the catalog at all, and
 * only for their own data: the path names the signed-in account, or the account it acts as. Another
 * account reached through administration (an admin's directory read, a token revoked during an
 * incident) is that rule's answer alone; the admin's own catalogs are not what it touches.
 *
 * Under act-as both people must hold it, whichever of the two the path names (requirePermission's
 * act-as rule, §4.7): the act-as cookie is site-wide, so a request cannot say which hat it wears.
 *
 * The internal and scanner keys pass: a service reading an account's catalog for a run or a scan is
 * not a person using it, and the route already decided whether it accepts the key.
 *
 * Its permission is a literal at argument 3 at every call: routePermissions.test.ts reads it as the
 * route's permission.
 */
import { NextResponse, type NextRequest } from 'next/server'
import { getAuthzIdentity, isInternalRequest, isScannerRequest, type AuthzIdentity } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { actsOnProject } from './can'
import { requirePermission } from './guards'
import { PERMISSIONS, assertKnownPermission, type PermissionId } from './permissions'

function assertSelfService(permission: PermissionId): void {
  assertKnownPermission(permission)
  if (PERMISSIONS[permission].kind !== 'member' || actsOnProject(permission)) {
    throw new Error(`selfService: ${permission} is not a permission over an account's own data`)
  }
}

/**
 * Null when the request may go on: a service key, another account's data the route's account rule
 * admitted, or the person's own data with the permission held. Else the 401, the 403 naming the
 * permission, or the coded 500 the route returns.
 */
export async function requireSelfPermission(
  request: NextRequest,
  accountId: string,
  permission: PermissionId,
  { fresh = false }: { fresh?: boolean } = {},
): Promise<NextResponse | null> {
  assertSelfService(permission)
  if (isInternalRequest(request) || isScannerRequest(request)) return null
  let identity: AuthzIdentity | null
  try {
    identity = await getAuthzIdentity(fresh ? { fresh: true } : {})
  } catch (err) {
    return internalError(err, 'Could not read the signed-in account')
  }
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (accountId !== identity.principal.id && accountId !== identity.actingAs?.id) return null
  // `fresh`: a critical path (minting a credential) reads both accounts, the sets and the Root again.
  const auth = fresh ? await requirePermission(request, permission, { fresh: true }) : await requirePermission(request, permission)
  return auth instanceof NextResponse ? auth : null
}

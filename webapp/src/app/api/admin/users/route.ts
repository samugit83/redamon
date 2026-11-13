import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseDirectoryQuery, readDirectoryPage } from '@/lib/authz/userDirectory'

/**
 * The admin users directory (step 6.2; GV-01, ID-27). 404 with RBAC_GOVERNANCE_ENABLED off, as the
 * console's pages are.
 *
 * GET `?q&status&type&set&cursor&limit` (users:read): accounts newest first, each with its type,
 * status, sets or profile, last sign-in, owned and shared project counts, and the actions the
 * signed-in person may take on it (lib/authz/userDirectory.ts). `q` searches name and email;
 * `status` is active, invited or disabled; `type` is root, admin or member; `set` lists the holders
 * of one permission set or admin profile (the permission sets page uses it); `cursor` is the
 * `nextCursor` of the previous page; `limit` is 1-100 (50). An unknown value answers 400
 * `invalid_filter` naming the field.
 */
export const GET = withRouteErrors('Could not list the accounts', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'users:read')
  if (refused) return refused
  const filters = parseDirectoryQuery(request.nextUrl.searchParams)
  if ('code' in filters) return NextResponse.json(filters, { status: 400 })
  return NextResponse.json(await readDirectoryPage(session, filters))
})

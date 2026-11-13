import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseAuditQuery, readAuditPage } from '@/lib/authz/auditReader'

/**
 * The admin console's audit viewer (step 6.6; GV-07, AU-07). 404 with RBAC_GOVERNANCE_ENABLED off, as
 * the console's pages are.
 *
 * GET `?table&actor&onBehalfOf&target&targetType&project&action&group&from&to&cursor&limit`
 * (audit:read): one page of rows, newest first (lib/authz/auditReader.ts). `table` is `audit` (the
 * audit log, default), `act_as` or `fireteam`; each takes its own filters (AUDIT_TABLE_FILTERS) and
 * answers 400 `invalid_filter` naming a field it cannot apply or cannot read. A row names the actor by
 * account (email and type; a deleted account by the email the row recorded), never carries `before` or
 * `after` (the details route does, secrets withheld). Reading is not audited; exporting is.
 */
export const GET = withRouteErrors('Could not read the audit log', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'audit:read')
  if (refused) return refused
  const filters = parseAuditQuery(request.nextUrl.searchParams)
  if ('code' in filters) return NextResponse.json(filters, { status: 400 })
  return NextResponse.json(await readAuditPage(filters), { headers: { 'Cache-Control': 'no-store' } })
})

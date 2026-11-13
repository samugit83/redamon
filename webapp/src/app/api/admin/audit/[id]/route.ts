import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { readAuditLogDetail } from '@/lib/authz/auditReader'

const ROW_ID = /^[A-Za-z0-9_-]{1,64}$/

/**
 * One audit log row for the viewer's details panel (step 6.6; GV-07). 404 with RBAC_GOVERNANCE_ENABLED
 * off. GET (audit:read): the row as the list shows it, plus the email it recorded and its `before` and
 * `after`, with every credential, token, hash and step-up field withheld (master plan §9.8). The act-as
 * and Fireteam rows have no such fields: the list carries all of theirs.
 */
export const GET = withRouteErrors('Could not read the audit row', async (
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'audit:read')
  if (refused) return refused
  const { id } = await params
  const row = ROW_ID.test(id) ? await readAuditLogDetail(id) : null
  if (!row) return routeNotFound()
  return NextResponse.json({ row }, { headers: { 'Cache-Control': 'no-store' } })
})

import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { quotaReport, quotasInForce } from '@/lib/authz/quotas'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * One account's quota and use (step 6.8; GV-09..GV-13): each value (null = unlimited), where it came
 * from (the account's own entry, a permission set by name, the default; Root and the switch off are
 * never limited), and what the webapp counts of it (lib/authz/quotas.ts `quotaReport`). My account
 * reads its own; the admin user detail another's under users:read (requireUserAccess, read mode, as
 * the MCP token list). 404 with RBAC_GOVERNANCE_ENABLED off, before anything is read.
 */
export const GET = withRouteErrors("Could not read the account's quota", async (request: NextRequest, { params }: RouteParams) => {
  if (!quotasInForce()) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  const { id } = await params
  const denied = await requireUserAccess(request, id, { mode: 'read' })
  if (denied) return denied
  const account = await prisma.user.findUnique({ where: { id }, select: { id: true } })
  if (!account) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(await quotaReport(id))
})

import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { myAccessView, projectAccess } from '@/lib/authz/projectAccess'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'

// GET /api/projects/[id]/my-access - the signed-in account's own access to one project (step 4.3):
// level, toggles, how it was reached and the owner, as the project GET's `myAccess`. Cheap on
// purpose: an open project polls it to notice a share revoked, expired or narrowed (step 4.11).
// The effective user's (under act-as, the account acted as). A project the account cannot see is
// 404, the same as one that does not exist; asking about oneself needs no permission. With
// RBAC_SHARING_ENABLED off the route does not exist: 404 before anything is read (DV-30).
export const GET = withRouteErrors('Could not read your access to the project', async (
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const { id } = await params
  const access = await projectAccess(eff, id)
  if (!access) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  const owner = await prisma.user.findUnique({ where: { id: access.project.userId }, select: { name: true, email: true } })
  return NextResponse.json({ myAccess: myAccessView(access, owner) })
})

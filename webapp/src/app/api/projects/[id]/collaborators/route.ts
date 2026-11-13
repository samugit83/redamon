import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { rbacFlags } from '@/lib/authz/flags'
import { requirePermission } from '@/lib/authz/guards'
import { grantShare, requireShareListAccess, shareListAnswer, sharingPolicyForRoutes } from '@/lib/authz/projectShares'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/projects/[id]/collaborators (step 4.4): who holds a share of the project, expired shares
 * marked. The owner and a co-owner (project:share at Manage), an admin reading the project by
 * oversight when Root's policy lets admins see every share, Root's break-glass. Sharing in force only
 * (404 otherwise). With write sharing in force each share's toggles too, and what the owner or
 * co-owner asking may grant (`grantable`, step 5.14).
 */
export const GET = withRouteErrors("Could not list the project's shares", async (_request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const policy = await sharingPolicyForRoutes()
  if (!policy) return routeNotFound()
  const allowed = await requireShareListAccess(id, policy)
  if (allowed instanceof NextResponse) return allowed
  return NextResponse.json(await shareListAnswer(id, policy, allowed.grantor))
})

/**
 * POST /api/projects/[id]/collaborators (step 4.4): share the project at Read, optionally with Raw
 * data & files, an expiry and a note, with the account `{email}` names (lib/authz/projectShares.ts).
 * With write sharing in force also at Read + Write with toggles, within Root's policy and what the
 * person sharing holds; Exploitation & shells takes their password (`stepUpPassword`, step 5.14).
 * Same-origin JSON; refused while acting as the owner.
 */
export const POST = withRouteErrors('Could not share the project', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:share', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  const policy = await sharingPolicyForRoutes({ fresh: true })
  if (!policy) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: auth.access?.project.userId }, 'change_shares')
  if (acting) return acting
  return grantShare(auth, policy, parsed.body, request)
})

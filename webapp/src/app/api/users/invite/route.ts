import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { forbiddenToInvite, inviteMember, withInviteErrors } from '@/lib/authz/invites'

/**
 * POST /api/users/invite {name, email} (step 2.9, ID-14, ID-36): invite a person. Creates a
 * member account, `invited` and without a password, and answers its link once (never cached).
 * Any admin: an invite never makes an admin. Identity switch only (404 without it).
 */
export const POST = withInviteErrors('invite', 'Could not invite the user', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenToInvite(session)
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return inviteMember(request, session, parsed.body)
})

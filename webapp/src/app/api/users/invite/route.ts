import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { forbiddenToInvite, inviteMember, withInviteErrors } from '@/lib/authz/invites'
import { requireSessionPermission } from '@/lib/authz/adminPermission'

/**
 * POST /api/users/invite {name, email, sets?, stepUpPassword?}: invite a person. Creates a
 * member account, `invited` and without a password, and answers its link once (never cached).
 * Needs `users:create`; an invite never makes an admin. With RBAC_PERMISSIONS_ENABLED on, `sets`
 * names the member sets the account starts with, under the assignment rules (initialSets.ts);
 * off, the key is ignored. Identity switch only (404 without it).
 */
export const POST = withInviteErrors('invite', 'Could not invite the user', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenToInvite(session)
  const denied = await requireSessionPermission(session, 'users:create', { fresh: true })
  if (denied) return denied
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return inviteMember(request, session, parsed.body)
})

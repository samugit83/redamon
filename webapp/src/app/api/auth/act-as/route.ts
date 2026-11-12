import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireAdmin } from '@/lib/session'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { createActAsToken, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { writeActAsAudit } from '@/lib/audit'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requireStepUp } from '@/lib/authz/stepUp'
import { presentedActAs } from '@/lib/userAudit'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { requireRootPower } from '@/lib/authz/rootPowers'
import { rbacFlags } from '@/lib/authz/flags'
import { PHASE1_ACT_AS_SECONDS, actAsLifetimeSeconds } from '@/lib/authz/sessionLifetime'

// Impersonation ("switch user") is an ADMIN-only, server-authorized act. The
// client can no longer decide "which user am I" via a localStorage value: the
// effective user is derived server-side from this signed httpOnly cookie, and it
// is only ever consulted when the signed-in caller is an admin in the database.

// S12: `secure` is decided per-request (see cookieOpts); base opts hold the rest. The cookie
// lives as long as its token: 12 h, or with the identity switch on an admin session's length
// capped at 12 h (step 2.11).
function cookieOpts(request: NextRequest, maxAge = PHASE1_ACT_AS_SECONDS) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: isSecureRequest(request),
    path: '/',
    maxAge,
  }
}

// POST /api/auth/act-as  { targetUserId }  -> begin simulating targetUserId.
// Acting as self clears the cookie (equivalent to "stop simulating").
export const POST = withRouteErrors('Could not switch user', async (request: NextRequest) => {
  const admin = await requireAdmin({ fresh: true })
  if (admin instanceof NextResponse) return admin
  const denied = await requireSessionPermission(admin, 'users:impersonate', { fresh: true })
  if (denied) return denied

  // Same-origin JSON whatever the identity switch (ID-26, step 2.12): acting as someone is
  // taking over their data.
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const body = parsed.body
  const targetUserId = body.targetUserId
  if (!targetUserId || typeof targetUserId !== 'string') {
    return NextResponse.json({ error: 'targetUserId is required' }, { status: 400 })
  }

  if (targetUserId === admin.userId) {
    // Acting as self = stop simulating. Audit as an end event (R2).
    await writeActAsAudit({ adminId: admin.userId, targetUserId, event: 'end', source: 'self-clear' })
    const res = NextResponse.json({ actingAs: null })
    res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...cookieOpts(request), maxAge: 0 })
    return res
  }

  const target = await prisma.user.findUnique({
    where: { id: targetUserId },
    select: { id: true, role: true },
  })
  if (!target) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }
  const rootRefusal = await rootProtectedRefusal(request, admin, targetUserId, 'act_as')
  if (rootRefusal) return rootRefusal
  // Acting as another admin borrows that admin's account: the acting admin's own
  // password first, like a reset of it. With the identity switch on only the confirmed
  // Root may, until Phase 3's impersonation rules (step 2.6).
  if (target.role === 'admin') {
    const refusal = rbacFlags().identity
      ? await requireRootPower(request, admin, body.stepUpPassword, 'Only Root can act as another admin.')
      : await requireStepUp(request, body.stepUpPassword)
    if (refusal) return refusal
  }

  const identity = rbacFlags().identity
  const seconds = identity ? await actAsLifetimeSeconds() : undefined
  const token = await createActAsToken(admin.userId, targetUserId, seconds)
  await writeActAsAudit({ adminId: admin.userId, targetUserId, event: 'start' })
  const res = NextResponse.json({ actingAs: targetUserId })
  res.cookies.set(ACT_AS_COOKIE_NAME, token, cookieOpts(request, seconds))
  return res
})

// DELETE /api/auth/act-as -> stop simulating (back to the admin's own data).
export const DELETE = withRouteErrors('Could not stop switching user', async (request: NextRequest) => {
  const admin = await requireAdmin()
  if (admin instanceof NextResponse) return admin
  // No body to check: a browser form cannot send a DELETE.
  if (!sameOrigin(request)) return crossOriginResponse(request)

  // The cookie is decoded before it is cleared, so the end row names the target.
  // No cookie of this admin's means nothing was being acted as: the browser sends
  // this DELETE on every admin page load and after a refused restore, so a row
  // there would only be noise.
  const claims = await presentedActAs(request)
  if (claims && claims.sub === admin.userId) {
    await writeActAsAudit({ adminId: admin.userId, targetUserId: claims.act, event: 'end' })
  }
  const res = NextResponse.json({ actingAs: null })
  res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...cookieOpts(request), maxAge: 0 })
  return res
})

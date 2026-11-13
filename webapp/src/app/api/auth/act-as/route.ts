import { NextRequest, NextResponse } from 'next/server'
import { decodeJwt } from 'jose'
import prisma from '@/lib/prisma'
import { requireAdmin } from '@/lib/session'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { createActAsToken, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { writeActAsAudit } from '@/lib/audit'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { safeErrorCode, withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requireStepUp } from '@/lib/authz/stepUp'
import { presentedActAs, presentedActAsToken } from '@/lib/userAudit'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { requireRootPower } from '@/lib/authz/rootPowers'
import { rbacFlags } from '@/lib/authz/flags'
import { PHASE1_ACT_AS_SECONDS, actAsLifetimeSeconds } from '@/lib/authz/sessionLifetime'
import { endPresentedActAs, impersonationPolicy, parseActAsRequest, startImpersonation } from '@/lib/authz/actAs'
import { actedAsNotice, appendNotice } from '@/lib/authz/accountNotices'
import { sessionPrincipal } from '@/lib/authz/sessionPrincipal'
import { sessionDeviceId } from '@/lib/authz/deviceSessions'
import { loadPrincipal } from '@/lib/authz/principal'
import { now } from '@/lib/authz/clock'
import type { Session } from '@/lib/session'

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

/**
 * Tells the account acted as (IM-10), unless Root turned it off: its next sign-in shows who, when,
 * why and for how long. Never fails the impersonation, which its start row already records.
 */
async function noticeTarget(admin: Session, targetUserId: string, reason: string | null, durationMinutes: number): Promise<void> {
  try {
    const actor = sessionPrincipal(admin) ?? (await loadPrincipal(admin.userId))
    const notice = actedAsNotice({
      by: { id: admin.userId, name: actor?.name ?? '', email: actor?.email ?? '' },
      at: now(),
      reason,
      durationMinutes,
    })
    await appendNotice(targetUserId, notice)
  } catch (err) {
    console.error(`[rbac] act-as notice not written target=${targetUserId} code=${safeErrorCode(err)}`)
  }
}

// POST /api/auth/act-as  { targetUserId, reason?, durationMinutes?, stepUpPassword? }  -> begin
// simulating targetUserId. Acting as self clears the cookie (equivalent to "stop simulating").
// Permissions switch on (step 3.14): a reason (mandatory when Root says so), a duration held to the
// instance limit, and the admin's own password whatever the target.
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

  const enforced = rbacFlags().permissions
  if (targetUserId === admin.userId) {
    // Acting as self = stop simulating. Audit as an end event (R2).
    if (enforced) await endPresentedActAs(admin.userId, presentedActAsToken(request), 'stopped')
    else await writeActAsAudit({ adminId: admin.userId, targetUserId, event: 'end', source: 'self-clear' })
    const res = NextResponse.json({ actingAs: null })
    res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...cookieOpts(request), maxAge: 0 })
    return res
  }

  const target = await prisma.user.findUnique({
    where: { id: targetUserId },
    select: { id: true, role: true, ...(enforced ? { status: true } : {}) },
  })
  if (!target) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }
  const rootRefusal = await rootProtectedRefusal(request, admin, targetUserId, 'act_as')
  if (rootRefusal) return rootRefusal
  // The form is checked before any password, so a mistake there spends nothing of the step-up budget.
  const policy = enforced ? await impersonationPolicy() : null
  const asked = policy ? parseActAsRequest(body, policy) : null
  if (asked && 'code' in asked) {
    return NextResponse.json({ error: asked.error, code: asked.code, field: asked.field }, { status: asked.status })
  }
  if ('status' in target && target.status === 'disabled') {
    return NextResponse.json({ error: 'This account is disabled: nobody can act as it.', code: 'account_disabled' }, { status: 409 })
  }
  // Acting as another admin borrows that admin's account: the acting admin's own
  // password first, like a reset of it. With the identity switch on only the confirmed
  // Root may (step 2.6). With the permissions switch on any impersonation takes the
  // admin's own password (ID-25).
  if (target.role === 'admin') {
    const refusal = rbacFlags().identity
      ? await requireRootPower(request, admin, body.stepUpPassword, 'Only Root can act as another admin.')
      : await requireStepUp(request, body.stepUpPassword)
    if (refusal) return refusal
  } else if (enforced) {
    const refusal = await requireStepUp(request, body.stepUpPassword)
    if (refusal) return refusal
  }

  if (!asked) {
    const identity = rbacFlags().identity
    const seconds = identity ? await actAsLifetimeSeconds() : undefined
    const token = await createActAsToken(admin.userId, targetUserId, seconds)
    await writeActAsAudit({ adminId: admin.userId, targetUserId, event: 'start' })
    const res = NextResponse.json({ actingAs: targetUserId })
    res.cookies.set(ACT_AS_COOKIE_NAME, token, cookieOpts(request, seconds))
    return res
  }

  // The cookie lives the chosen duration, never longer than an admin session (or 12 h).
  const seconds = Math.min(asked.durationMinutes * 60, await actAsLifetimeSeconds())
  const durationMinutes = Math.ceil(seconds / 60)
  const actor = sessionPrincipal(admin) ?? (await loadPrincipal(admin.userId, { fresh: true }))
  if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  // The impersonation the browser held ends and this one starts in one write: no start row, no
  // impersonation (IM-09), and a failed start leaves the previous one running, as the log says.
  const token = await startImpersonation({
    admin: actor, targetUserId, seconds, reason: asked.reason, durationMinutes,
    presentedToken: presentedActAsToken(request),
    deviceSessionId: sessionDeviceId(admin),
  })
  if (policy!.notifyTarget) await noticeTarget(admin, targetUserId, asked.reason, durationMinutes)
  // The token's own expiry: the wall clock jose signs and checks it with.
  const endsAt = new Date(decodeJwt(token).exp! * 1000).toISOString()
  const res = NextResponse.json({ actingAs: targetUserId, durationMinutes, endsAt })
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
  if (rbacFlags().permissions) {
    await endPresentedActAs(admin.userId, presentedActAsToken(request), 'stopped')
  } else {
    const claims = await presentedActAs(request)
    if (claims && claims.sub === admin.userId) {
      await writeActAsAudit({ adminId: admin.userId, targetUserId: claims.act, event: 'end' })
    }
  }
  const res = NextResponse.json({ actingAs: null })
  res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...cookieOpts(request), maxAge: 0 })
  return res
})

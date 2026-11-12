import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { createToken, hashPassword } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { internalError } from '@/lib/routeErrors'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'
import { checkStepUp, requireStepUp } from '@/lib/authz/stepUp'
import { writeUserAudit } from '@/lib/userAudit'
import { invalidatePrincipal } from '@/lib/authz/principal'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { requireRootPower } from '@/lib/authz/rootPowers'
import { rbacFlags } from '@/lib/authz/flags'
import { setLoginCookie } from '@/lib/loginCookie'
import { parseReason, reasonRequired, resetCredentials, resetStatusRefusal } from '@/lib/authz/resetCredentials'

interface RouteParams {
  params: Promise<{ id: string }>
}

// PUT /api/users/[id]/password - Change user password
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const session = await getSession({ fresh: true })

    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { newPassword, currentPassword, stepUpPassword, requirePasswordChange, reason: rawReason } = await request.json()

    const check = validateNewPassword(typeof newPassword === 'string' ? newPassword : '')
    if (!check.ok) {
      return NextResponse.json({ error: check.message, code: check.code }, { status: 400 })
    }
    const identity = rbacFlags().identity
    if (identity && requirePasswordChange !== undefined && typeof requirePasswordChange !== 'boolean') {
      return NextResponse.json(
        { error: 'requirePasswordChange must be true or false', code: 'invalid_field', field: 'requirePasswordChange' },
        { status: 400 },
      )
    }

    const isAdmin = session.role === 'admin'
    const isSelf = session.userId === id

    // Standard users can only change their own password
    if (!isAdmin && !isSelf) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Identity switch on (step 2.10): a password set for someone else is a credentials reset.
    const reset = identity && !isSelf
    const reason = reset ? parseReason(rawReason) : null
    if (reason instanceof NextResponse) return reason

    let adminTarget = false
    if (isSelf) {
      // Everyone, admins included, proves the current password, through the shared
      // step-up limiter. The answers keep the statuses this form always had.
      const proof = await checkStepUp(request, currentPassword)
      if (proof.outcome === 'missing') {
        return NextResponse.json({ error: 'Current password is required', code: 'step_up_required' }, { status: 400 })
      }
      if (proof.outcome === 'wrong') {
        return NextResponse.json({ error: 'Current password is incorrect', code: 'step_up_failed' }, { status: 401 })
      }
      if (proof.outcome === 'locked') {
        return NextResponse.json(
          { error: `Too many incorrect passwords. Try again in ${proof.retryAfterSeconds}s.`, code: 'step_up_locked' },
          { status: 429, headers: { 'Retry-After': String(proof.retryAfterSeconds) } },
        )
      }
    } else {
      const rootRefusal = await rootProtectedRefusal(request, session, id, 'reset_password')
      if (rootRefusal) return rootRefusal
      // An admin resetting another admin takes over that account: the acting
      // admin's own password first, and with the identity switch on only the
      // confirmed Root may (step 2.6). A member's reset needs none.
      const target = await prisma.user.findUnique({ where: { id }, select: { role: true } })
      adminTarget = target?.role === 'admin'
      if (adminTarget) {
        const refusal = rbacFlags().identity
          ? await requireRootPower(request, session, stepUpPassword, 'Only Root can reset another admin\'s password.')
          : await requireStepUp(request, stepUpPassword)
        if (refusal) return refusal
      }
    }

    // Identity switch on: the policy in force (the instance minimum, the deny list and the two
    // rules), judged against the address of the account the password is for.
    const account = identity
      ? await prisma.user.findUnique({
        where: { id },
        select: { email: true, status: true, lastLoginAt: true, mustChangePassword: true, sessionVersion: true },
      })
      : null
    if (identity) {
      const full = validateNewPassword(newPassword, await passwordPolicyInForce(), { email: account?.email })
      if (!full.ok) {
        return NextResponse.json({ error: full.message, code: full.code }, { status: 400 })
      }
    }

    // The takeover a reset allows is made visible (ID-18, ID-19): the version rises and the
    // tokens end whether or not a change is required, the open links are cancelled, the person
    // gets a notice, and an account that has signed in before needs a reason; the change and its
    // row commit together. Same path as "Reset credentials" in temporary mode.
    if (reset) {
      if (!account) return NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
      const refused = resetStatusRefusal(account.status, 'temporary')
      if (refused) return refused
      if (account.lastLoginAt && !reason) return reasonRequired()
      const done = await resetCredentials(request, session, id, {
        mode: 'temporary',
        passwordHash: await hashPassword(newPassword),
        requireChange: requirePasswordChange !== false,
        reason,
        adminTarget,
        judgedEmail: account.email,
        attempted: 'reset_password',
      })
      if (done instanceof NextResponse) return done
      return NextResponse.json({ success: true, revokedMcpTokens: done.tokensRevoked })
    }

    const hashed = await hashPassword(newPassword)
    // Identity switch on: the account's own change clears the must-change flag (ID-17). Off:
    // Phase 1's write of the password alone.
    const data = identity ? { password: hashed, mustChangePassword: false } : { password: hashed }

    // Any password change revokes every MCP personal access token. An admin can
    // reset another user's password without knowing the current one (above), so
    // a reset must not leave live programmatic credentials behind. Same
    // transaction as the password write: a half-applied reset would be worse
    // than either outcome.
    const [, revoked] = await prisma.$transaction([
      prisma.user.update({ where: { id }, data }),
      prisma.mcpAccessToken.updateMany({
        where: { userId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ])
    invalidatePrincipal(id)

    if (revoked.count > 0) {
      await writeAudit({
        actorId: session.userId,
        action: 'mcp-token.revoke-all',
        targetType: 'user',
        targetId: id,
        after: { reason: 'password changed', revokedCount: revoked.count, byAdmin: isAdmin && !isSelf },
        source: 'api',
      })
    }

    // The host scripts write the same two actions with source `system`.
    await writeUserAudit(request, session, {
      action: isSelf ? 'user.password_changed' : 'user.credentials_reset',
      targetId: id,
      after: { revokedMcpTokens: revoked.count },
    })

    const response = NextResponse.json({ success: true, revokedMcpTokens: revoked.count })
    // A forced change done: this browser's cookie drops the must-change claim (same version),
    // so the person goes on without signing in again; any other cookie with the claim now
    // disagrees with the account and signs in again (session.ts).
    if (isSelf && account?.mustChangePassword) {
      setLoginCookie(response, request, await createToken(id, session.role, account.sessionVersion))
    }
    return response
  } catch (error) {
    return internalError(error, 'Failed to change password')
  }
}

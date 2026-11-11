import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { internalError } from '@/lib/routeErrors'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { checkStepUp, requireStepUp } from '@/lib/authz/stepUp'

interface RouteParams {
  params: Promise<{ id: string }>
}

// PUT /api/users/[id]/password - Change user password
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const session = await getSession()

    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { newPassword, currentPassword, stepUpPassword } = await request.json()

    const check = validateNewPassword(typeof newPassword === 'string' ? newPassword : '')
    if (!check.ok) {
      return NextResponse.json({ error: check.message, code: check.code }, { status: 400 })
    }

    const isAdmin = session.role === 'admin'
    const isSelf = session.userId === id

    // Standard users can only change their own password
    if (!isAdmin && !isSelf) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

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
      // An admin resetting another admin takes over that account: the acting
      // admin's own password first. A member's reset needs none.
      const target = await prisma.user.findUnique({ where: { id }, select: { role: true } })
      if (target?.role === 'admin') {
        const refusal = await requireStepUp(request, stepUpPassword)
        if (refusal) return refusal
      }
    }

    const hashed = await hashPassword(newPassword)

    // Any password change revokes every MCP personal access token. An admin can
    // reset another user's password without knowing the current one (above), so
    // a reset must not leave live programmatic credentials behind. Same
    // transaction as the password write: a half-applied reset would be worse
    // than either outcome.
    const [, revoked] = await prisma.$transaction([
      prisma.user.update({
        where: { id },
        data: { password: hashed },
      }),
      prisma.mcpAccessToken.updateMany({
        where: { userId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ])

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

    return NextResponse.json({ success: true, revokedMcpTokens: revoked.count })
  } catch (error) {
    return internalError(error, 'Failed to change password')
  }
}

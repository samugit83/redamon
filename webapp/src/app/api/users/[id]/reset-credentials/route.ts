import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/auth'
import { requireAdmin } from '@/lib/session'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { adminTargetGate } from '@/lib/authz/rootPowers'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'
import { privateJson, withInviteErrors } from '@/lib/authz/invites'
import {
  ROOT_ONLY_RESET,
  parseReason,
  reasonRequired,
  resetCredentials,
  resetStatusRefusal,
} from '@/lib/authz/resetCredentials'

interface RouteParams {
  params: Promise<{ id: string }>
}

function invalidField(field: string, error: string): NextResponse {
  return NextResponse.json({ error, code: 'invalid_field', field }, { status: 400 })
}

/**
 * POST {mode: 'link' | 'temporary', temporaryPassword?, reason?, stepUpPassword?} (step 2.10,
 * ID-18, ID-19): reset a member's credentials, or, for the confirmed Root with its own password,
 * an admin's. `link` answers a reset link once (the account signs in only through it); `temporary`
 * sets a password the person must change at the next sign-in. Either ends every login cookie and
 * MCP token of the account and leaves it a notice; an account that has signed in before needs a
 * `reason`. Never the own account (its password changes on /account) and never Root. Identity
 * switch only (404 without it).
 */
export const POST = withInviteErrors('credentials reset', 'Could not reset the credentials', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) {
    if (session.status !== 403) return session
    return NextResponse.json(
      { error: "Only an administrator can reset another account's credentials.", code: 'forbidden', permission: 'users:reset_credentials' },
      { status: 403 },
    )
  }
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  if (id === session.userId) {
    return NextResponse.json(
      { error: 'Your own password changes on the My account page, with your current one.', code: 'own_account' },
      { status: 400 },
    )
  }
  const protectedRoot = await rootProtectedRefusal(request, session, id, 'reset_credentials')
  if (protectedRoot) return protectedRoot

  const body = parsed.body
  const mode = body.mode
  if (mode !== 'link' && mode !== 'temporary') return invalidField('mode', "mode must be 'link' or 'temporary'.")
  if (mode === 'temporary' && (typeof body.temporaryPassword !== 'string' || body.temporaryPassword === '')) {
    return invalidField('temporaryPassword', 'A temporary password is required.')
  }
  if (mode === 'link' && body.temporaryPassword !== undefined) {
    return invalidField('temporaryPassword', 'A reset link carries no temporary password.')
  }
  const reason = parseReason(body.reason)
  if (reason instanceof NextResponse) return reason

  const gate = await adminTargetGate(request, session, id, body.stepUpPassword, ROOT_ONLY_RESET)
  if (gate instanceof NextResponse) return gate

  const target = await prisma.user.findUnique({ where: { id }, select: { status: true, email: true, lastLoginAt: true } })
  if (!target) return NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
  const refused = resetStatusRefusal(target.status, mode)
  if (refused) return refused
  if (target.lastLoginAt && !reason) return reasonRequired()

  let passwordHash: string | undefined
  if (mode === 'temporary') {
    const password = body.temporaryPassword as string
    let check = validateNewPassword(password)
    if (check.ok) check = validateNewPassword(password, await passwordPolicyInForce(), { email: target.email })
    if (!check.ok) return NextResponse.json({ error: check.message, code: check.code, field: 'temporaryPassword' }, { status: 400 })
    passwordHash = await hashPassword(password)
  }

  const done = await resetCredentials(request, session, id, {
    mode,
    passwordHash,
    requireChange: true,
    reason,
    adminTarget: gate.adminTarget,
    judgedEmail: mode === 'temporary' ? target.email : undefined,
    attempted: 'reset_credentials',
  })
  if (done instanceof NextResponse) return done
  if (done.link) {
    return privateJson({
      id,
      mode,
      link: done.link.link,
      expiresAt: done.link.expiresAt.toISOString(),
      localhostWarning: done.link.localhostWarning,
      tokensRevoked: done.tokensRevoked,
      agent: done.agent,
    })
  }
  return privateJson({ id, mode, mustChangePassword: done.mustChangePassword, tokensRevoked: done.tokensRevoked, agent: done.agent })
})

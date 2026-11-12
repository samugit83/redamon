import { NextRequest, NextResponse } from 'next/server'
import { ACT_AS_COOKIE_NAME, createToken, hashPassword } from '@/lib/auth'
import { readJsonBody } from '@/lib/jsonBody'
import { setLoginCookie } from '@/lib/loginCookie'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { afterResetEntry } from '@/lib/authz/accountNotices'
import { writeAudit } from '@/lib/audit'
import { getClientMeta } from '@/lib/requestMeta'
import { invalidatePrincipal } from '@/lib/authz/principal'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'
import { FAILED_ACCEPT_LIMIT, forgetFailedAccepts, recordFailedAccept } from '@/lib/authz/inviteLimits'
import {
  acceptLink,
  clearInviteCookie,
  invalidLinkResponse,
  linkFromCookie,
  lockLink,
  privateJson,
  withInviteErrors,
} from '@/lib/authz/invites'

/**
 * POST /api/invite/accept {password} (step 2.9, ID-14, ID-15): the person the invite cookie's
 * link was made for chooses a password. Public; same-origin JSON only. The password meets the
 * policy in force; a refusal counts against the link, and the fifth cancels it (DV-05). On
 * success the link is used, the account active with that password, the person signed in and the
 * invite cookie cleared. Any link that does not work: 410 `invite_invalid`. Identity switch only
 * (404 without it).
 */
export const POST = withInviteErrors('invite accept', 'Could not set the password. Try again in a moment.', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const link = await linkFromCookie(request)
  if (!link) return invalidLinkResponse(request)

  const password = typeof parsed.body.password === 'string' ? parsed.body.password : ''
  let check = validateNewPassword(password)
  if (check.ok) check = validateNewPassword(password, await passwordPolicyInForce(), { email: link.user.email })
  if (!check.ok) {
    const failures = recordFailedAccept(link.tokenHash)
    if (failures >= FAILED_ACCEPT_LIMIT) {
      await lockLink(link, failures)
      forgetFailedAccepts(link.tokenHash)
      return invalidLinkResponse(request)
    }
    return privateJson({ error: check.message, code: check.code, attemptsLeft: FAILED_ACCEPT_LIMIT - failures }, 400)
  }

  const account = await acceptLink(link, await hashPassword(password))
  forgetFailedAccepts(link.tokenHash)
  if (!account) return invalidLinkResponse(request)
  invalidatePrincipal(account.id)
  // A reset link's accept is the first sign-in after the reset (the reset emptied the password):
  // the one sign-in whose address and browser are recorded (step 2.10, DV-11).
  if (link.kind === 'reset') await writeAudit(afterResetEntry(account.id, getClientMeta(request), account.storedNotices))

  const res = privateJson({
    id: account.id, name: account.name, email: account.email, role: account.role,
    ...(account.notices.length ? { notices: account.notices } : {}),
  })
  setLoginCookie(res, request, await createToken(account.id, account.role, account.sessionVersion))
  clearInviteCookie(res, request)
  // A previous admin session's act-as cookie means nothing for this account.
  if (request.cookies.get(ACT_AS_COOKIE_NAME)) res.cookies.set(ACT_AS_COOKIE_NAME, '', { path: '/', maxAge: 0 })
  return res
})

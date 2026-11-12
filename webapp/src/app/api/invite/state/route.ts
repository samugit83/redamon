import { NextRequest } from 'next/server'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { MAX_PASSWORD_BYTES, describePasswordPolicy } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'
import { linkFromCookie, privateJson, withInviteErrors } from '@/lib/authz/invites'

/**
 * GET /api/invite/state (step 2.9, ID-15): what the public `/invite` page shows, from the invite
 * cookie. A working link answers who it is for, its kind and expiry, and the password policy in
 * force (the page has no session, so the policy comes with the link); anything else answers
 * `{valid: false}` and nothing more. Never cached. Identity switch only (404 without it).
 */
export const GET = withInviteErrors('invite state read', 'Could not read the link. Try again in a moment.', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const link = await linkFromCookie(request)
  if (!link) return privateJson({ valid: false })
  const { minLength, rules } = await passwordPolicyInForce()
  return privateJson({
    valid: true,
    kind: link.kind,
    name: link.user.name,
    email: link.user.email,
    expiresAt: link.expiresAt.toISOString(),
    policy: { minLength, maxBytes: MAX_PASSWORD_BYTES, rules, description: describePasswordPolicy({ minLength, rules }) },
  })
})

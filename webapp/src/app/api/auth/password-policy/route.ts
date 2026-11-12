import { NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { MAX_PASSWORD_BYTES, describePasswordPolicy } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'

/**
 * GET /api/auth/password-policy (step 2.8, ID-20): the policy every new password meets, for
 * the forms to show beside their fields and to check before sending. Any signed-in account,
 * one that must change its password included. Identity switch only (404 without it: the forms
 * then keep Phase 1's floor).
 */
export async function GET() {
  if (!rbacFlags().identity) return routeNotFound()
  try {
    const session = await getSession()
    if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const { minLength, rules } = await passwordPolicyInForce()
    return NextResponse.json({
      minLength,
      maxBytes: MAX_PASSWORD_BYTES,
      rules,
      description: describePasswordPolicy({ minLength, rules }),
    })
  } catch (error) {
    return internalError(error, 'Could not read the password policy')
  }
}

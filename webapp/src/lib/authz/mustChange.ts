/**
 * Root's optional sign-in prompt (step 2.8, ID-29): with `passwordAskChangeIfShort` on, an
 * account that signs in with a password shorter than the instance minimum must change it.
 * Policy only grows stricter over time, so a password set under an older minimum keeps
 * working until its owner signs in and is asked.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { safeErrorCode } from '@/lib/routeErrors'
import { passwordPolicyInForce } from './passwordPolicyInForce'

/**
 * Flags the account and raises its session version in one statement (older cookies end) when
 * the setting asks and `password`, the one just accepted, is shorter than the minimum.
 * Returns the new session version, or null when nothing was set. Never fails the sign-in: a
 * failed read or write is logged with its code (never the password) and the sign-in goes on.
 * Reached only with the identity switch on.
 */
export async function flagShortPasswordAtSignIn(userId: string, password: string): Promise<number | null> {
  try {
    const policy = await passwordPolicyInForce()
    if (!policy.askChangeIfShort || [...password].length >= policy.minLength) return null
    const rows = await prisma.$queryRaw<{ sessionVersion: number }[]>`
      UPDATE users SET must_change_password = true, session_version = session_version + 1
      WHERE id = ${userId} RETURNING session_version AS "sessionVersion"`
    if (!rows[0]) return null
    await writeAudit({
      actorId: userId, action: 'user.password_change_required', targetType: 'user', targetId: userId,
      after: { reason: 'short_password', minLength: policy.minLength },
    })
    return rows[0].sessionVersion
  } catch (err) {
    console.error(`[rbac] short-password check failed user=${userId} code=${safeErrorCode(err)}`)
    return null
  }
}

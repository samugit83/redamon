/**
 * Reset a user's password, end every session of the account (session version + 1),
 * revoke its MCP tokens and cancel its open invite and reset links, in one
 * transaction with the audit rows (source 'system'). A disabled or invited account
 * becomes usable again: status active, no held hash, no forced change (the host
 * operator is the trust anchor).
 * Called from redamon.sh reset-password via:
 *   docker compose exec -T -e RESET_EMAIL=... -e RESET_PASSWORD=... webapp node scripts/reset-password.mjs
 *
 * It never changes the role: PROMOTE_ADMIN is refused with exit 2. Promoting a
 * member is create-admin's job, and only with FORCE_PROMOTE=1. The new password meets
 * the one password policy (lib/passwordRules.mjs), as the webapp's forms do.
 *
 * Exit codes: 0 done, 1 bad input, unknown account or failure, 2 PROMOTE_ADMIN set.
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { identitySwitchOn } from './backfill-rbac-instance-settings.mjs'
import { checkNewPassword, passwordPolicyFromDatabase } from './lib/passwordRules.mjs'

const email = process.env.RESET_EMAIL
const password = process.env.RESET_PASSWORD

if (process.env.PROMOTE_ADMIN) {
  console.error(
    'ERROR: promotion is no longer done by reset-password; nothing was changed. ' +
    'To make a member an admin: FORCE_PROMOTE=1 ./redamon.sh create-admin',
  )
  process.exit(2)
}

if (!email || !password) {
  console.error('ERROR: RESET_EMAIL and RESET_PASSWORD environment variables are required')
  process.exit(1)
}

// The policy of src/lib/authz/passwordPolicy.ts through its script twin: Phase 1's floor and
// byte bound before anything is read; the policy in force (identity switch on: the instance
// minimum, the deny list and the two rules) once the account is known.
const base = checkNewPassword(password)
if (!base.ok) {
  console.error(`ERROR: ${base.message}`)
  process.exit(1)
}

const prisma = new PrismaClient()

async function audit(tx, action, targetId, before, after) {
  console.info(`[audit] ${action} actor=- target=user:${targetId} source=system`)
  await tx.auditLog.create({
    data: { actorId: null, action, targetType: 'user', targetId, before, after, source: 'system' },
  })
}

let exitCode = 0
try {
  // The account lookup of src/lib/authz/accountEmail.ts findSignInAccount (see
  // create-admin.mjs): exact email first, else the one case-insensitive match.
  const rows = await prisma.$queryRaw`
    SELECT id, name, email, status FROM users WHERE lower(email) = lower(${email})`
  const user = rows.find(r => r.email === email) ?? (rows.length === 1 ? rows[0] : null)

  if (!user && rows.length > 1) {
    console.error(`ERROR: several accounts differ only in case from "${email}"; type one of them exactly`)
    exitCode = 1
  } else if (!user) {
    console.error(`ERROR: No user found with email "${email}"`)
    exitCode = 1
  } else {
    const policy = await passwordPolicyFromDatabase(prisma, { identity: identitySwitchOn() })
    const check = checkNewPassword(password, policy, { email: user.email })
    if (!check.ok) {
      console.error(`ERROR: ${check.message}. Nothing was changed.`)
      exitCode = 1
    }
  }
  if (user && exitCode === 0) {
    const hash = await bcrypt.hash(password, 12)
    // As users/[id]/password/route.ts: a reset must not leave live sessions or
    // programmatic credentials behind, and a half-applied one is worse than either
    // outcome.
    const { revoked, cancelledLinks } = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`
        UPDATE users SET password = ${hash}, session_version = session_version + 1, status = 'active',
          password_on_hold = '', must_change_password = false, updated_at = now()
        WHERE id = ${user.id}`
      const revoked = await tx.mcpAccessToken.updateMany({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: new Date() },
      })
      const cancelledLinks = await tx.$executeRaw`
        UPDATE user_invites SET cancelled_at = now()
        WHERE user_id = ${user.id} AND used_at IS NULL AND cancelled_at IS NULL AND expires_at > now()`
      // The rows of src/lib/audit.ts writeAuditTx, source 'system', no actor: the
      // host operator is not an account.
      if (user.status !== 'active') {
        await audit(tx, 'user.enabled_by_host', user.id, { status: user.status }, { status: 'active' })
      }
      await audit(tx, 'user.credentials_reset', user.id, undefined,
        { revokedMcpTokens: revoked.count, ...(cancelledLinks ? { cancelledLinks } : {}) })
      return { revoked, cancelledLinks }
    })

    console.log(`Password updated for "${user.name}" <${user.email}>.`)
    if (user.status !== 'active') console.log(`The account was ${user.status}; it is active again.`)
    console.log(`Signed out everywhere. MCP tokens revoked: ${revoked.count}.`)
    if (cancelledLinks) console.log(`Open invite and reset links cancelled: ${cancelledLinks}.`)
  }
} catch (err) {
  console.error('ERROR: Failed to reset password:', err.message)
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

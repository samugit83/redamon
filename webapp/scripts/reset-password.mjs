/**
 * Reset a user's password and revoke the account's MCP tokens, in one transaction.
 * Called from redamon.sh reset-password via:
 *   docker compose exec -T -e RESET_EMAIL=... -e RESET_PASSWORD=... webapp node scripts/reset-password.mjs
 *
 * It never changes the role: PROMOTE_ADMIN is refused with exit 2. Promoting a
 * member is create-admin's job, and only with FORCE_PROMOTE=1.
 *
 * Exit codes: 0 done, 1 bad input, unknown account or failure, 2 PROMOTE_ADMIN set.
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

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

// The floor of src/lib/authz/passwordPolicy.ts, repeated because this standalone
// script cannot import TypeScript; passwordPolicy.drift.test.ts keeps them equal.
const MIN_PASSWORD_LENGTH = 12

if ([...password].length < MIN_PASSWORD_LENGTH) {
  console.error(`ERROR: Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  process.exit(1)
}

const prisma = new PrismaClient()

let exitCode = 0
try {
  // The account lookup of src/lib/authz/accountEmail.ts findSignInAccount (see
  // create-admin.mjs): exact email first, else the one case-insensitive match.
  const rows = await prisma.$queryRaw`
    SELECT id, name, email FROM users WHERE lower(email) = lower(${email})`
  const user = rows.find(r => r.email === email) ?? (rows.length === 1 ? rows[0] : null)

  if (!user && rows.length > 1) {
    console.error(`ERROR: several accounts differ only in case from "${email}"; type one of them exactly`)
    exitCode = 1
  } else if (!user) {
    console.error(`ERROR: No user found with email "${email}"`)
    exitCode = 1
  } else {
    const hash = await bcrypt.hash(password, 12)
    // As users/[id]/password/route.ts: a reset must not leave live programmatic
    // credentials behind, and a half-applied one is worse than either outcome.
    const [, revoked] = await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { password: hash } }),
      prisma.mcpAccessToken.updateMany({
        where: { userId: user.id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ])

    // The row shape of src/lib/audit.ts writeAudit, source 'system', no actor: the
    // host operator is not an account. Best effort, as there.
    console.info(`[audit] user.credentials_reset actor=- target=user:${user.id} source=system`)
    try {
      await prisma.auditLog.create({
        data: {
          actorId: null,
          action: 'user.credentials_reset',
          targetType: 'user',
          targetId: user.id,
          after: { revokedMcpTokens: revoked.count },
          source: 'system',
        },
      })
    } catch (e) {
      console.error('[audit] failed to persist user.credentials_reset:', e.message)
    }

    console.log(`Password updated for "${user.name}" <${user.email}>.`)
    console.log(`MCP tokens revoked: ${revoked.count}.`)
  }
} catch (err) {
  console.error('ERROR: Failed to reset password:', err.message)
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

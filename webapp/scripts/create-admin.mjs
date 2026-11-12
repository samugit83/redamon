/**
 * Create an admin, or reset an existing admin's password.
 * Called from redamon.sh _prompt_and_create_admin() and deploy.sh bootstrap_admin() via:
 *   docker compose exec -T -e ADMIN_NAME=... -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... [-e FORCE_PROMOTE=1] webapp node scripts/create-admin.mjs
 *
 * - a new email: creates an admin (email stored lowercase, like POST /api/users),
 *   which is the instance's confirmed Root when it has none (fresh install, deploy
 *   init);
 * - an existing admin: sets the new password, ends every session of the account
 *   (session version + 1), revokes its MCP tokens and cancels its open invite and
 *   reset links in one transaction; the unchanged password writes nothing, because
 *   deploy.sh re-runs this with the .env admin on every init and must not cut that
 *   admin's tokens;
 * - an existing member: refused with exit 3 and nothing written, unless
 *   FORCE_PROMOTE=1, which promotes it and resets it as above.
 * A reset also makes a disabled or invited account usable again (its password is
 * empty, so it is always a reset): status active, no held hash, no forced change.
 * The host operator is the trust anchor. Every change commits with its audit rows
 * (source 'system'), or nothing does.
 *
 * Exit codes: 0 done, 1 bad input or failure, 3 member not promoted.
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import { ensureInstanceSettingsRow } from './backfill-rbac-instance-settings.mjs'

const name = process.env.ADMIN_NAME
const email = process.env.ADMIN_EMAIL
const password = process.env.ADMIN_PASSWORD
const forcePromote = ['1', 'true'].includes((process.env.FORCE_PROMOTE ?? '').toLowerCase())

if (!name || !email || !password) {
  console.error('ERROR: ADMIN_NAME, ADMIN_EMAIL, and ADMIN_PASSWORD environment variables are required')
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

// The account lookup of src/lib/authz/accountEmail.ts findSignInAccount: the exact
// email, else the one account equal to it ignoring case (accounts made before
// emails were stored lowercase may hold capitals). lower() on both sides, never
// Prisma's mode: 'insensitive', which is ILIKE (`_` and `%` are wildcards).
async function findAccount(typed) {
  const rows = await prisma.$queryRaw`
    SELECT id, name, email, password, role, status FROM users WHERE lower(email) = lower(${typed})`
  const account = rows.find(r => r.email === typed) ?? (rows.length === 1 ? rows[0] : null)
  return { account, ambiguous: !account && rows.length > 1 }
}

async function samePassword(plain, hash) {
  if (!hash) return false
  try {
    return await bcrypt.compare(plain, hash)
  } catch {
    return false
  }
}

// The row of src/lib/audit.ts writeAuditTx with source 'system' and no actor (the
// host operator is not an account), inside the change's transaction.
async function audit(tx, action, targetId, before, after) {
  console.info(`[audit] ${action} actor=- target=user:${targetId} source=system`)
  await tx.auditLog.create({
    data: { actorId: null, action, targetType: 'user', targetId, before, after, source: 'system' },
  })
}

// The new admin becomes the confirmed Root when the instance has none: no Root id,
// or one naming no account. The lock (set-root.mjs takes it too) makes the check
// below run after any other claim committed, so two at once leave one Root; it is a
// statement of its own because a statement only sees rows committed before it began.
// A row no boot has filled yet is created with the tunnel and capture values in force.
async function claimRootIfNone(tx, userId) {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('rbac-root'))`
  await ensureInstanceSettingsRow(tx)
  return (await tx.$executeRaw`
    UPDATE instance_settings SET root_user_id = ${userId}, root_confirmed_at = now(),
      root_assigned_by = 'install', updated_at = now()
    WHERE id = 'instance' AND (root_user_id IS NULL
       OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = instance_settings.root_user_id))`) > 0
}

let exitCode = 0
try {
  const { account, ambiguous } = await findAccount(email)

  if (ambiguous) {
    console.error(`ERROR: several accounts differ only in case from "${email}"; type one of them exactly`)
    exitCode = 1
  } else if (!account) {
    const hash = await bcrypt.hash(password, 12)
    const [{ rootTable }] = await prisma.$queryRaw`
      SELECT to_regclass('instance_settings') IS NOT NULL AS "rootTable"`
    const { created, root } = await prisma.$transaction(async (tx) => {
      const created = await tx.user.create({
        data: { name, email: email.toLowerCase(), password: hash, role: 'admin' },
      })
      await audit(tx, 'user.create', created.id, undefined, { email: created.email, role: 'admin', passwordless: false })
      const root = rootTable && await claimRootIfNone(tx, created.id)
      if (root) await audit(tx, 'root.set_by_host', created.id, undefined, { rootUserId: created.id, rule: 'install' })
      return { created, root }
    })
    console.log(`Admin user "${name}" <${created.email}> created successfully.`)
    if (root) console.log('It is the instance\'s Root (confirmed): there was none.')
    if (!rootTable) console.log('Root not recorded: this database has no instance_settings table yet.')
  } else if (account.role !== 'admin' && !forcePromote) {
    console.error(
      `REFUSED: "${account.email}": account exists as a member; set FORCE_PROMOTE=1 to promote it. Nothing was changed.`,
    )
    exitCode = 3
  } else if (account.role === 'admin' && await samePassword(password, account.password)) {
    if (account.name !== name) {
      await prisma.user.update({ where: { id: account.id }, data: { name } })
    }
    console.log(`Admin user "${name}" <${account.email}> already has this password; nothing else changed (MCP tokens kept).`)
  } else {
    const promote = account.role !== 'admin'
    const hash = await bcrypt.hash(password, 12)
    // A new password must not leave live sessions or programmatic credentials behind,
    // and a token minted as a member would act as an admin after the promotion: same
    // transaction as the write, as users/[id]/password/route.ts does.
    const { revoked, cancelledLinks } = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`
        UPDATE users SET password = ${hash}, name = ${name}, role = 'admin',
          session_version = session_version + 1, status = 'active', password_on_hold = '',
          must_change_password = false, updated_at = now()
        WHERE id = ${account.id}`
      const revoked = await tx.mcpAccessToken.updateMany({
        where: { userId: account.id, revokedAt: null },
        data: { revokedAt: new Date() },
      })
      const cancelledLinks = await tx.$executeRaw`
        UPDATE user_invites SET cancelled_at = now()
        WHERE user_id = ${account.id} AND used_at IS NULL AND cancelled_at IS NULL AND expires_at > now()`
      if (account.status !== 'active') {
        await audit(tx, 'user.enabled_by_host', account.id, { status: account.status }, { status: 'active' })
      }
      if (promote) await audit(tx, 'user.role_changed', account.id, { role: account.role }, { role: 'admin' })
      await audit(tx, 'user.credentials_reset', account.id, undefined,
        { revokedMcpTokens: revoked.count, ...(cancelledLinks ? { cancelledLinks } : {}) })
      return { revoked, cancelledLinks }
    })
    console.log(
      promote
        ? `Member "${name}" <${account.email}> promoted to admin (FORCE_PROMOTE); password set.`
        : `Password reset for admin "${name}" <${account.email}>.`,
    )
    if (account.status !== 'active') console.log(`The account was ${account.status}; it is active again.`)
    console.log(`Signed out everywhere. MCP tokens revoked: ${revoked.count}.`)
    if (cancelledLinks) console.log(`Open invite and reset links cancelled: ${cancelledLinks}.`)
  }
} catch (err) {
  console.error('ERROR: Failed to create admin user:', err.message)
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

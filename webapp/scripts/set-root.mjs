/**
 * Make an account the instance's confirmed Root: the host's break-glass, and how
 * `./redamon.sh update` confirms the Root chosen at boot. Called from redamon.sh
 * cmd_set_root and _confirm_root via:
 *   docker compose exec -T -e ROOT_EMAIL=... webapp node scripts/set-root.mjs
 * or by hand: node scripts/set-root.mjs <email>
 *
 * - The account must exist and have a password (an invited or disabled account, or a
 *   member managed without login, has none: set one with reset-password first).
 * - It is already Root: an unconfirmed Root is confirmed and nothing else changes;
 *   a confirmed one, nothing at all.
 * - Otherwise Root moves to it: a member is made an admin, the singleton names it
 *   (confirmed, rootAssignedBy 'host'), a pending Root transfer is cancelled, every
 *   session of it and of the previous Root ends (session version + 1) and its MCP
 *   tokens are revoked. The previous Root stays an admin.
 * The change and its audit rows (source 'system', no actor: the host operator is not
 * an account) commit together, or nothing does.
 *
 * Exit codes: 0 done (or nothing to do), 1 bad input, unknown or passwordless
 * account, no instance_settings table, or failure.
 */

import { PrismaClient } from '@prisma/client'
import { ensureInstanceSettingsRow } from './backfill-rbac-instance-settings.mjs'

const email = process.argv[2] || process.env.ROOT_EMAIL

if (!email) {
  console.error('ERROR: usage: set-root.mjs <email> (or ROOT_EMAIL=<email>)')
  process.exit(1)
}

const prisma = new PrismaClient()

class Refused extends Error {}

// The account lookup of src/lib/authz/accountEmail.ts findSignInAccount (see
// create-admin.mjs): exact email first, else the one case-insensitive match.
async function findAccount(tx, typed) {
  const rows = await tx.$queryRaw`
    SELECT id, email, password, role, status FROM users WHERE lower(email) = lower(${typed})`
  const account = rows.find(r => r.email === typed) ?? (rows.length === 1 ? rows[0] : null)
  if (!account && rows.length > 1) {
    throw new Refused(`several accounts differ only in case from "${typed}"; type one of them exactly`)
  }
  if (!account) throw new Refused(`No user found with email "${typed}"`)
  return account
}

// The row of src/lib/audit.ts writeAuditTx, inside the change's transaction.
async function audit(tx, action, targetId, before, after) {
  console.info(`[audit] ${action} actor=- target=user:${targetId} source=system`)
  await tx.auditLog.create({
    data: { actorId: null, action, targetType: 'user', targetId, before, after, source: 'system' },
  })
}

let exitCode = 0
try {
  const [{ present }] = await prisma.$queryRaw`
    SELECT to_regclass('instance_settings') IS NOT NULL AS present`
  if (!present) {
    throw new Refused('this database has no instance_settings table yet; start the updated webapp first')
  }

  const report = await prisma.$transaction(async (tx) => {
    const account = await findAccount(tx, email)
    if (!account.password) {
      throw new Refused(
        `"${account.email}" has no password (invited, disabled or managed without login); ` +
        'set one first with ./redamon.sh reset-password',
      )
    }

    // The lock create-admin.mjs takes to claim Root, then the row lock any other
    // writer of the singleton meets: the Root read below is the one that is replaced. A
    // row no boot has filled yet is created with the tunnel and capture values in force.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('rbac-root'))`
    await ensureInstanceSettingsRow(tx)
    const [current] = await tx.$queryRaw`
      SELECT root_user_id, root_confirmed_at, root_assigned_by FROM instance_settings
      WHERE id = 'instance' FOR UPDATE`

    if (current.root_user_id === account.id && account.role === 'admin') {
      if (current.root_confirmed_at) return [`"${account.email}" is already the confirmed Root; nothing changed.`]
      await tx.$executeRaw`
        UPDATE instance_settings SET root_confirmed_at = now(), updated_at = now() WHERE id = 'instance'`
      await audit(tx, 'root.confirmed_by_host', account.id,
        { confirmed: false, rule: current.root_assigned_by },
        { confirmed: true, rule: current.root_assigned_by })
      return [`Root confirmed: "${account.email}".`]
    }

    // Root's cookies must not outlive the change, either side of it, and tokens the
    // account minted before it would act with Root's reach.
    await tx.$executeRaw`
      UPDATE users SET role = 'admin', session_version = session_version + 1, status = 'active',
        password_on_hold = '', must_change_password = false, updated_at = now()
      WHERE id = ${account.id}`
    const revoked = await tx.mcpAccessToken.updateMany({
      where: { userId: account.id, revokedAt: null },
      data: { revokedAt: new Date() },
    })
    const previous = current.root_user_id
    const previousSignedOut = previous && previous !== account.id
      ? await tx.$executeRaw`
          UPDATE users SET session_version = session_version + 1, updated_at = now() WHERE id = ${previous}`
      : 0
    await tx.$executeRaw`
      UPDATE instance_settings SET root_user_id = ${account.id}, root_confirmed_at = now(),
        root_assigned_by = 'host', pending_root_transfer_to = NULL, pending_root_transfer_expires = NULL,
        updated_at = now()
      WHERE id = 'instance'`

    if (account.status !== 'active') {
      await audit(tx, 'user.enabled_by_host', account.id, { status: account.status }, { status: 'active' })
    }
    if (account.role !== 'admin') {
      await audit(tx, 'user.role_changed', account.id, { role: account.role }, { role: 'admin' })
    }
    await audit(tx, 'root.set_by_host', account.id,
      { rootUserId: previous, confirmed: current.root_confirmed_at !== null, rule: current.root_assigned_by },
      { rootUserId: account.id, rule: 'host', revokedMcpTokens: revoked.count })

    return [
      ...(account.role !== 'admin' ? [`"${account.email}" was a member: made an admin.`] : []),
      `Root is now "${account.email}" (set by the host).`,
      `Signed out: "${account.email}"${previousSignedOut ? ' and the previous Root' : ''}. MCP tokens revoked: ${revoked.count}.`,
    ]
  })
  for (const line of report) console.log(line)
} catch (err) {
  if (err instanceof Refused) {
    console.error(`ERROR: ${err.message}`)
  } else {
    console.error('ERROR: Failed to set Root (nothing was changed):', err.message)
  }
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

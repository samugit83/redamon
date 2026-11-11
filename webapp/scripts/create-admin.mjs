/**
 * Create an admin, or reset an existing admin's password.
 * Called from redamon.sh _prompt_and_create_admin() and deploy.sh bootstrap_admin() via:
 *   docker compose exec -T -e ADMIN_NAME=... -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... [-e FORCE_PROMOTE=1] webapp node scripts/create-admin.mjs
 *
 * - a new email: creates an admin (email stored lowercase, like POST /api/users);
 * - an existing admin: sets the new password and revokes its MCP tokens in one
 *   transaction; the unchanged password writes nothing, because deploy.sh re-runs
 *   this with the .env admin on every init and must not cut that admin's tokens;
 * - an existing member: refused with exit 3 and nothing written, unless
 *   FORCE_PROMOTE=1, which promotes it, sets the password and revokes its tokens.
 *
 * Exit codes: 0 done, 1 bad input or failure, 3 member not promoted.
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

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
    SELECT id, name, email, password, role FROM users WHERE lower(email) = lower(${typed})`
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

// The row shape of src/lib/audit.ts writeAudit with source 'system' and no actor:
// the host operator is not an account. Best effort, as there.
async function audit(action, targetId, before, after) {
  console.info(`[audit] ${action} actor=- target=user:${targetId} source=system`)
  try {
    await prisma.auditLog.create({
      data: { actorId: null, action, targetType: 'user', targetId, before, after, source: 'system' },
    })
  } catch (e) {
    console.error(`[audit] failed to persist ${action}:`, e.message)
  }
}

let exitCode = 0
try {
  const { account, ambiguous } = await findAccount(email)

  if (ambiguous) {
    console.error(`ERROR: several accounts differ only in case from "${email}"; type one of them exactly`)
    exitCode = 1
  } else if (!account) {
    const hash = await bcrypt.hash(password, 12)
    const created = await prisma.user.create({
      data: { name, email: email.toLowerCase(), password: hash, role: 'admin' },
    })
    await audit('user.create', created.id, undefined, { email: created.email, role: 'admin', passwordless: false })
    console.log(`Admin user "${name}" <${created.email}> created successfully.`)
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
    // A new password must not leave live programmatic credentials behind, and a
    // token minted as a member would act as an admin after the promotion: same
    // transaction as the write, as users/[id]/password/route.ts does.
    const [, revoked] = await prisma.$transaction([
      prisma.user.update({
        where: { id: account.id },
        data: { password: hash, name, ...(promote ? { role: 'admin' } : {}) },
      }),
      prisma.mcpAccessToken.updateMany({
        where: { userId: account.id, revokedAt: null },
        data: { revokedAt: new Date() },
      }),
    ])
    if (promote) await audit('user.role_changed', account.id, { role: account.role }, { role: 'admin' })
    await audit('user.credentials_reset', account.id, undefined, { revokedMcpTokens: revoked.count })
    console.log(
      promote
        ? `Member "${name}" <${account.email}> promoted to admin (FORCE_PROMOTE); password set.`
        : `Password reset for admin "${name}" <${account.email}>.`,
    )
    console.log(`MCP tokens revoked: ${revoked.count}.`)
  }
} catch (err) {
  console.error('ERROR: Failed to create admin user:', err.message)
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

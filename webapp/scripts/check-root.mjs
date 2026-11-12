/**
 * Print who is the instance's Root and which accounts could be. Read-only.
 * Called from redamon.sh _confirm_root (with --lines) and by hand:
 *   docker compose exec -T webapp node scripts/check-root.mjs [--lines]
 *
 * JSON (default): {"root": {"email", "confirmed", "rule"} | null, "candidates": [email, ...]}
 * --lines, one tab-separated record per line for bash:
 *   root<TAB>email<TAB>confirmed|unconfirmed<TAB>rule
 *   candidate<TAB>email
 *
 * Candidates are the admins with a password, oldest first (createdAt, then id): the
 * order the boot-time Root choice ranks them in. A database without the
 * instance_settings table (older than the identity schema), or a Root id that names
 * no account, has no Root.
 *
 * Exit codes: 0 printed, 1 the database could not be read.
 */

import { PrismaClient } from '@prisma/client'

const lines = process.argv.slice(2).includes('--lines')
const prisma = new PrismaClient()

let exitCode = 0
try {
  const [{ present }] = await prisma.$queryRaw`
    SELECT to_regclass('instance_settings') IS NOT NULL AS present`
  const rows = present
    ? await prisma.$queryRaw`
        SELECT u.email, s.root_confirmed_at, s.root_assigned_by
        FROM instance_settings s JOIN users u ON u.id = s.root_user_id
        WHERE s.id = 'instance'`
    : []
  const root = rows.length
    ? { email: rows[0].email, confirmed: rows[0].root_confirmed_at !== null, rule: rows[0].root_assigned_by ?? 'unknown' }
    : null
  const candidates = (await prisma.$queryRaw`
    SELECT email FROM users WHERE role = 'admin' AND password <> '' ORDER BY created_at, id`).map(r => r.email)

  if (lines) {
    const out = []
    if (root) out.push(['root', root.email, root.confirmed ? 'confirmed' : 'unconfirmed', root.rule].join('\t'))
    for (const email of candidates) out.push(`candidate\t${email}`)
    if (out.length) console.log(out.join('\n'))
  } else {
    console.log(JSON.stringify({ root, candidates }))
  }
} catch (err) {
  console.error('ERROR: could not read the Root:', err.message)
  exitCode = 1
} finally {
  await prisma.$disconnect()
}
process.exit(exitCode)

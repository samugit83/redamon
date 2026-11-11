/**
 * Reset a user's password.
 * Called from redamon.sh reset-password via:
 *   docker compose exec -T -e RESET_EMAIL=... -e RESET_PASSWORD=... webapp node scripts/reset-password.mjs
 *
 * Optional: pass --admin flag via PROMOTE_ADMIN=true to also set role to admin.
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const email = process.env.RESET_EMAIL
const password = process.env.RESET_PASSWORD
const promoteAdmin = process.env.PROMOTE_ADMIN === 'true'

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

try {
  const user = await prisma.user.findUnique({ where: { email } })

  if (!user) {
    console.error(`ERROR: No user found with email "${email}"`)
    process.exit(1)
  }

  const hash = await bcrypt.hash(password, 12)
  const data = { password: hash }
  if (promoteAdmin) data.role = 'admin'

  await prisma.user.update({
    where: { email },
    data,
  })

  console.log(`Password updated for "${user.name}" <${email}>.`)
  if (promoteAdmin) console.log('User promoted to admin.')
} catch (err) {
  console.error('ERROR: Failed to reset password:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}

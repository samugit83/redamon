/**
 * Create or update admin user.
 * Called from redamon.sh ensure_admin() via:
 *   docker compose exec -T -e ADMIN_NAME=... -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... webapp node scripts/create-admin.mjs
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const name = process.env.ADMIN_NAME
const email = process.env.ADMIN_EMAIL
const password = process.env.ADMIN_PASSWORD

if (!name || !email || !password) {
  console.error('ERROR: ADMIN_NAME, ADMIN_EMAIL, and ADMIN_PASSWORD environment variables are required')
  process.exit(1)
}

if (password.length < 4) {
  console.error('ERROR: Password must be at least 4 characters')
  process.exit(1)
}

const prisma = new PrismaClient()

try {
  const hash = await bcrypt.hash(password, 12)

  await prisma.user.upsert({
    where: { email },
    update: { password: hash, role: 'admin', name },
    create: { name, email, password: hash, role: 'admin' },
  })

  console.log(`Admin user "${name}" <${email}> created successfully.`)
} catch (err) {
  console.error('ERROR: Failed to create admin user:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}

/**
 * Check if an admin user with a password exists.
 * Outputs "0" if no admin found, or the count if found.
 * Called from redamon.sh ensure_admin().
 */

import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

try {
  const count = await prisma.user.count({
    where: { role: 'admin', password: { not: '' } }
  })
  console.log(count)
} catch {
  console.log(0)
} finally {
  await prisma.$disconnect()
}

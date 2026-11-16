/**
 * Removes everything e2e-tradecraft-seed.mjs wrote: the account `tradecraft-e2e@e2e.local`, which
 * takes with it (the schema's cascades) its settings, resources, pages, entries, jobs, its project
 * and that project's choices, then its audit rows.
 *
 * Run: docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-tradecraft-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'

const EMAIL = 'tradecraft-e2e@e2e.local'
const prisma = new PrismaClient()

try {
  const user = await prisma.user.findUnique({ where: { email: EMAIL }, select: { id: true } })
  if (user) {
    await prisma.auditLog.deleteMany({ where: { OR: [{ actorId: user.id }, { targetId: user.id }] } })
    await prisma.user.delete({ where: { id: user.id } })
  }
  const left = await prisma.userTradecraftResource.count({ where: { url: { contains: '.tc-e2e.test' } } })
  console.log(`TC_CLEANED=${user ? 1 : 0}`)
  console.log(`TC_RESOURCES_LEFT=${left}`)
} finally {
  await prisma.$disconnect()
}

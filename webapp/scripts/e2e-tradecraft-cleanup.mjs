/**
 * Removes everything e2e-tradecraft-seed.mjs wrote: the accounts `tradecraft-e2e@e2e.local` and
 * `tradecraft-map-e2e@e2e.local`, each taking with it (the schema's cascades) its settings,
 * resources, pages, entries, curation, jobs, its project and that project's choices, then their
 * audit rows.
 *
 * Run: docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-tradecraft-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'

const EMAILS = ['tradecraft-e2e@e2e.local', 'tradecraft-map-e2e@e2e.local']
const prisma = new PrismaClient()

try {
  let cleaned = 0
  for (const email of EMAILS) {
    const user = await prisma.user.findUnique({ where: { email }, select: { id: true } })
    if (!user) continue
    await prisma.auditLog.deleteMany({ where: { OR: [{ actorId: user.id }, { targetId: user.id }] } })
    await prisma.user.delete({ where: { id: user.id } })
    cleaned += 1
  }
  const left = await prisma.userTradecraftResource.count({ where: { url: { contains: '.tc-e2e.test' } } })
  console.log(`TC_CLEANED=${cleaned}`)
  console.log(`TC_RESOURCES_LEFT=${left}`)
} finally {
  await prisma.$disconnect()
}

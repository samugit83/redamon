/**
 * Removes everything e2e-tradecraft-seed.mjs wrote: the accounts `tradecraft-e2e@e2e.local` and
 * `tradecraft-map-e2e@e2e.local`, each taking with it (the schema's cascades) its settings,
 * resources, pages, entries, curation, jobs, its project and that project's choices, then their
 * audit rows, and the graph nodes of those projects (creating a project writes its Domain node).
 *
 * Run: docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-tradecraft-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'

const EMAILS = ['tradecraft-e2e@e2e.local', 'tradecraft-map-e2e@e2e.local']
// The shared reference nodes no project owns (e2e-rbac-cleanup.mjs GLOBAL_REFERENCE_LABELS); that
// script runs its own cleanup when imported from stdin, so it is not imported here.
const GLOBAL_REFERENCE_LABELS = ['CVE', 'MitreData', 'Capec']
const prisma = new PrismaClient()

async function clearProjectGraph(projectIds) {
  if (!projectIds.length) return 0
  const { default: neo4j } = await import('neo4j-driver')
  const driver = neo4j.driver(
    process.env.NEO4J_URI || 'bolt://localhost:7687',
    neo4j.auth.basic(process.env.NEO4J_USER || 'neo4j', process.env.NEO4J_PASSWORD || 'password'),
  )
  try {
    const result = await driver.session().run(
      `MATCH (n) WHERE n.project_id IN $pids AND NONE(l IN labels(n) WHERE l IN $excluded) DETACH DELETE n`,
      { pids: projectIds, excluded: GLOBAL_REFERENCE_LABELS },
    )
    return result.summary.counters.updates().nodesDeleted
  } finally {
    await driver.close()
  }
}

try {
  let cleaned = 0
  const projectIds = []
  for (const email of EMAILS) {
    const user = await prisma.user.findUnique({ where: { email }, select: { id: true } })
    if (!user) continue
    projectIds.push(...(await prisma.project.findMany({ where: { userId: user.id }, select: { id: true } })).map(p => p.id))
    await prisma.auditLog.deleteMany({ where: { OR: [{ actorId: user.id }, { targetId: user.id }] } })
    await prisma.user.delete({ where: { id: user.id } })
    cleaned += 1
  }
  const left = await prisma.userTradecraftResource.count({ where: { url: { contains: '.tc-e2e.test' } } })
  let graphNodes = 0
  try {
    graphNodes = await clearProjectGraph(projectIds)
  } catch (err) {
    console.error(`CLEANUP_WARN: graph cleanup failed: ${err?.code || err?.name || 'error'}`)
  }
  console.log(`TC_CLEANED=${cleaned}`)
  console.log(`TC_GRAPH_NODES_DELETED=${graphNodes}`)
  console.log(`TC_RESOURCES_LEFT=${left}`)
} finally {
  await prisma.$disconnect()
}

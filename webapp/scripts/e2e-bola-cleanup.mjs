/**
 * Remove the two-user BOLA E2E fixtures. Deleting the users cascades to their
 * projects/conversations/etc. (onDelete: Cascade). Nuclei template rows and audit
 * rows have no foreign key, so they are removed here: the templates the test uploads
 * (all under its own folder, files and rows, plus any row a fixture owns elsewhere)
 * and the audit rows whose actor or target is a fixture account or project (sign-ins,
 * terminal tickets, refused stdio servers, emergency stops, template writes, act-as).
 * Idempotent: a second run finds nothing and prints CLEANED=0.
 *
 * Run: docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-bola-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'
import { rm } from 'node:fs/promises'
import path from 'node:path'

const EMAILS = ['bola-a@e2e.local', 'bola-b@e2e.local', 'bola-admin@e2e.local', 'bola-legacy@e2e.local']
// tests/test_e2e_bola_live.sh uploads into this folder only.
const TEMPLATE_FOLDER = 'bola-e2e'
const TEMPLATES_ROOT = path.resolve(process.env.NUCLEI_TEMPLATES_PATH || '/data/nuclei-templates')

/** The template's file, or null for a stored path that would leave the templates folder. */
function templateFile(relPath) {
  const full = path.resolve(TEMPLATES_ROOT, relPath)
  return full.startsWith(TEMPLATES_ROOT + path.sep) ? full : null
}

const prisma = new PrismaClient()
try {
  const users = await prisma.user.findMany({ where: { email: { in: EMAILS } }, select: { id: true } })
  const ids = users.map(u => u.id)
  const projectIds = ids.length
    ? (await prisma.project.findMany({ where: { userId: { in: ids } }, select: { id: true } })).map(p => p.id)
    : []

  const templates = await prisma.nucleiTemplate.findMany({
    where: { OR: [{ path: { startsWith: `${TEMPLATE_FOLDER}/` } }, ...(ids.length ? [{ ownerUserId: { in: ids } }] : [])] },
    select: { id: true, path: true },
  })
  // A row deleted without its file would turn the file into an instance template.
  for (const t of templates) {
    const file = templateFile(t.path)
    if (file) await rm(file, { force: true })
  }
  await rm(path.join(TEMPLATES_ROOT, TEMPLATE_FOLDER), { recursive: true, force: true })
  if (templates.length) await prisma.nucleiTemplate.deleteMany({ where: { id: { in: templates.map(t => t.id) } } })

  const audit = await prisma.auditLog.deleteMany({
    where: {
      OR: [
        ...(ids.length ? [{ actorId: { in: ids } }, { targetId: { in: [...ids, ...projectIds] } }] : []),
        { targetType: 'nuclei_template', targetId: { startsWith: `${TEMPLATE_FOLDER}/` } },
      ],
    },
  })
  const actAs = ids.length
    ? await prisma.actAsAudit.deleteMany({ where: { OR: [{ adminId: { in: ids } }, { targetUserId: { in: ids } }] } })
    : { count: 0 }

  const { count } = await prisma.user.deleteMany({ where: { email: { in: EMAILS } } })
  console.log(`CLEANED=${count}`)
  console.log(`TEMPLATES_DELETED=${templates.length}`)
  console.log(`AUDIT_ROWS_DELETED=${audit.count + actAs.count}`)
} catch (err) {
  console.error('CLEANUP_ERROR:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}

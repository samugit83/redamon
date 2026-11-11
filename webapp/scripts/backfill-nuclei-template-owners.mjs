/**
 * One-time backfill of the RBAC hardening: every custom Nuclei template present at the
 * upgrade becomes an instance template (HD-08, T18).
 *
 * Before the hardening every signed-in account changed every file of the shared
 * templates folder. Now the `NucleiTemplate` table records who owns each file: a member
 * changes only their own, and a row with no owner (an instance template) only an admin
 * changes. Nobody can tell who uploaded a file before the table existed, so every file
 * found here gets an instance row: any member may still select it (an existing
 * project's selection keeps scanning), only an admin replaces or deletes it. A file
 * added on the host later has no row and is an instance template too.
 *
 * Run once: the marker (`system.nuclei_template_owners_backfill`, with how many files it
 * found) is written in the same transaction as the rows, under an advisory lock, so
 * webapp copies booting together record once. It skips only when the marker exists AND
 * a row exists (or the marker found no file): a downgrade's `db push` drops the table
 * while the AuditLog marker survives, so a re-upgrade records the files again. Every row
 * the table lost that way had its owner lost with it, and the file becomes an instance
 * template; rows that survived are never changed (`skipDuplicates`).
 *
 * Runs from the webapp entrypoint AFTER `db push`, and from the dev container's command.
 * Never fatal: a failure is logged and the next boot tries again (no marker was written).
 */
import { PrismaClient } from '@prisma/client'
import { createHash } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

export const LOCK_KEY = 'system.nuclei_template_owners'
export const MARKER_ACTION = 'system.nuclei_template_owners_backfill'
const TEMPLATE_FILE = /\.ya?ml$/i

export function templatesRoot() {
  return process.env.NUCLEI_TEMPLATES_PATH || '/data/nuclei-templates'
}

/**
 * Every template file under `root`, as the templates route lists them (a regular
 * `.yaml`/`.yml` file, symlinks not followed): its posix path relative to `root`, its
 * sha256 and size. A folder that does not exist holds none.
 */
export async function listTemplateFiles(root) {
  const out = []
  async function walk(dir) {
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch (err) {
      if (err?.code === 'ENOENT' && dir === root) return
      throw err
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        await walk(full)
      } else if (entry.isFile() && TEMPLATE_FILE.test(entry.name)) {
        const content = await readFile(full)
        out.push({
          path: path.relative(root, full).split(path.sep).join('/'),
          sha256: createHash('sha256').update(content).digest('hex'),
          sizeBytes: content.length,
        })
      }
    }
  }
  await walk(root)
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
}

/** How many files a marker says it found; a marker without the count found none. */
export function recordedFiles(after) {
  return after !== null && typeof after === 'object' && Number.isFinite(after.files) ? after.files : 0
}

/**
 * Returns {done: false} when the marker and the rows were already there, else how many
 * files it found and how many rows it wrote.
 */
export async function backfillNucleiTemplateOwners(prisma, root = templatesRoot()) {
  // Read before the transaction: the lock is not held while the disk is walked.
  const files = await listTemplateFiles(root)
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    const marker = await tx.auditLog.findFirst({
      where: { action: MARKER_ACTION }, orderBy: { createdAt: 'desc' }, select: { after: true },
    })
    if (marker) {
      if (recordedFiles(marker.after) === 0) return { done: false }
      const row = await tx.nucleiTemplate.findFirst({ select: { id: true } })
      if (row) return { done: false }
    }

    const { count } = files.length
      ? await tx.nucleiTemplate.createMany({
        data: files.map((f) => ({ ...f, ownerUserId: null })),
        skipDuplicates: true,
      })
      : { count: 0 }

    await tx.auditLog.create({
      data: {
        action: MARKER_ACTION, targetType: 'system', source: 'system',
        after: { files: files.length, rowsCreated: count },
      },
    })
    return { done: true, files: files.length, rowsCreated: count }
  }, { timeout: 120_000, maxWait: 30_000 })
}

/** The entrypoint's call: logs the outcome, never throws. */
export async function run(prisma, root = templatesRoot()) {
  try {
    const r = await backfillNucleiTemplateOwners(prisma, root)
    if (r.done) {
      console.log(`[rbac] nuclei template owners recorded: ${r.files} file(s) present at the upgrade are instance templates (${r.rowsCreated} row(s) written).`)
    }
  } catch (err) {
    console.error('[rbac] could not record the nuclei template owners (retried next boot):', err?.code || err?.message || err)
  }
}

async function main() {
  const prisma = new PrismaClient()
  try {
    await run(prisma)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}

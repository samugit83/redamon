/**
 * Keep JS Recon's TruffleHog engine OFF for the projects that existed before it.
 *
 * `jsReconTrufflehogEnabled` defaults to true, and that default is meant for NEW
 * projects only. Left to `prisma db push`, the column would arrive as
 * `ADD COLUMN ... NOT NULL DEFAULT true`, and Postgres fills every existing row
 * with the default: an update would switch the engine on in every project
 * that runs JS Recon. Adding the column here first, with DEFAULT false, leaves
 * the existing rows off; the push then only changes the default to true.
 *
 * Runs from the webapp entrypoint IMMEDIATELY BEFORE `db push`. Raw SQL only:
 * the database still has the old schema while the generated client has the new.
 *
 * Idempotent and safe on every path:
 *   - fresh install (no `projects` table yet) -> no-op, the push creates it all
 *   - column already present                  -> no-op, nothing is rewritten
 *
 * Fails CLOSED: if it cannot add the column, it exits non-zero so the push never
 * adds it with DEFAULT true; the container restarts and tries again.
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

// The @map of jsReconTrufflehogEnabled in prisma/schema.prisma; a test holds them equal.
export const COLUMN = 'js_recon_trufflehog_enabled'

/** Returns 'fresh', 'present' or 'added', and how many projects it left off. */
export async function addJsReconTrufflehogColumn(prisma) {
  const table = await prisma.$queryRawUnsafe(
    `SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='projects' LIMIT 1`,
  )
  if (table.length === 0) return { status: 'fresh', keptOff: 0 }

  const column = await prisma.$queryRawUnsafe(
    `SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='projects' AND column_name=$1 LIMIT 1`,
    COLUMN,
  )
  if (column.length > 0) return { status: 'present', keptOff: 0 }

  await prisma.$executeRawUnsafe(
    `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ${COLUMN} boolean NOT NULL DEFAULT false`,
  )
  const [{ n }] = await prisma.$queryRawUnsafe(`SELECT count(*)::int AS n FROM projects`)
  return { status: 'added', keptOff: n }
}

async function main() {
  const prisma = new PrismaClient()
  try {
    const { status, keptOff } = await addJsReconTrufflehogColumn(prisma)
    if (status === 'added') {
      console.log(`[js-recon] TruffleHog stays off in ${keptOff} existing project(s); new projects get it on.`)
    }
  } catch (err) {
    console.error('[js-recon] FAILED to add the TruffleHog column, refusing to continue to db push:',
      err?.message || err)
    process.exitCode = 1
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}

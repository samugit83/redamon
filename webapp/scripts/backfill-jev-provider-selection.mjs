/**
 * One-time backfill for the change that made each project select its Jev provider.
 *
 * Before it, every /jev/* call used the project owner's Jev token, and a user could
 * hold at most one (`jev`, TypeSafe). After it, a project with no `jevProviderId` runs
 * every Jev hook on its static fallback. So each project that existed when the new
 * code FIRST started gets its owner's TypeSafe row selected: what ran before keeps
 * running, and a selection alone turns no hook on.
 *
 * Only rows from before that moment count: projects and providers created later were
 * created under the explicit rule. The moment is its own AuditLog row (CUTOFF_ACTION),
 * written before the backfill and kept when the backfill fails, so a retry on a later
 * boot never selects a row for a project created meanwhile. An owner with no TypeSafe
 * row from before the cutoff gets nothing, and so does one with several (impossible
 * under the old one-per-user rule): the choice would be a guess.
 *
 * Run once: the marker is an AuditLog row (MARKER_ACTION), written in the same
 * transaction as the selections, under an advisory lock so two webapp copies booting
 * together do it once. Rows are written with `update`, so `updatedAt` moves and a
 * form opened before the upgrade gets a stale-save refusal instead of saving its
 * empty selection back over this one.
 *
 * Runs from the webapp entrypoint AFTER `db push` (the column must exist), and from
 * the dev container's command. Never fatal: a failure is logged and the next boot
 * tries again (no marker was written).
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const MARKER_ACTION = 'system.jev_provider_selection_backfill'
export const CUTOFF_ACTION = 'system.jev_provider_selection_cutoff'
/** The only Jev provider type that existed before per-project selection. */
export const LEGACY_PROVIDER_TYPE = 'jev'

/**
 * When the code that requires an explicit selection first started: the database time
 * of the cutoff row, written by the first call and read by every later one.
 */
export async function recordCutoff(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${CUTOFF_ACTION}))`
    const existing = await tx.auditLog.findFirst({ where: { action: CUTOFF_ACTION }, orderBy: { createdAt: 'asc' } })
    if (existing) return existing.createdAt
    const row = await tx.auditLog.create({ data: { action: CUTOFF_ACTION, targetType: 'system', source: 'system' } })
    return row.createdAt
  })
}

/** Returns {done: false} when the marker existed, else what it wrote. */
export async function backfillJevProviderSelection(prisma) {
  const cutoff = await recordCutoff(prisma)
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${MARKER_ACTION}))`
    const marker = await tx.auditLog.findFirst({ where: { action: MARKER_ACTION }, select: { id: true } })
    if (marker) return { done: false }

    const legacyRows = (await tx.userLlmProvider.findMany({
      where: { providerType: LEGACY_PROVIDER_TYPE },
      select: { id: true, userId: true, createdAt: true },
    })).filter((row) => !(row.createdAt > cutoff))
    const rowsByOwner = new Map()
    for (const row of legacyRows) rowsByOwner.set(row.userId, [...(rowsByOwner.get(row.userId) ?? []), row.id])
    const selectionByOwner = new Map(
      [...rowsByOwner].filter(([, ids]) => ids.length === 1).map(([owner, ids]) => [owner, ids[0]]),
    )
    const ambiguousOwners = [...rowsByOwner.values()].filter((ids) => ids.length > 1).length

    const projects = selectionByOwner.size === 0 ? [] : (await tx.project.findMany({
      where: { userId: { in: [...selectionByOwner.keys()] } },
      select: { id: true, userId: true, jevProviderId: true, createdAt: true },
    })).filter((p) => p.jevProviderId == null && !(p.createdAt > cutoff))
    for (const project of projects) {
      await tx.project.update({
        where: { id: project.id },
        data: { jevProviderId: selectionByOwner.get(project.userId) },
      })
    }

    const result = { projects: projects.length, owners: selectionByOwner.size, ambiguousOwners }
    await tx.auditLog.create({
      data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after: result },
    })
    return { done: true, ...result }
  }, { timeout: 300_000, maxWait: 30_000 })
}

async function main() {
  const prisma = new PrismaClient()
  try {
    const result = await backfillJevProviderSelection(prisma)
    if (result.done) {
      console.log(`[jev] selected the owner's TypeSafe row in ${result.projects} existing project(s) ` +
        `for ${result.owners} owner(s); ${result.ambiguousOwners} owner(s) with several rows left unselected.`)
    }
  } catch (err) {
    console.error('[jev] could not backfill Jev provider selections (retried next boot):', err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}

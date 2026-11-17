/**
 * One-time move of the Tradecraft row of the tool phase map to its new default.
 *
 * The owner's decision of 2026-11-17: `tradecraft_lookup` (whose row `tradecraft_search` and
 * `tradecraft_ask` follow) is allowed in all three phases by default, because the three read only
 * the run owner's library and its resources' own sites, never the target. A Prisma @default reaches
 * new projects only, and the agent reads a project's stored map as it is, never merged with the
 * defaults. So every project whose row still EQUALS the old default (exploitation and
 * post-exploitation, in any order) gets all three phases; its other tools stay as they are. Any
 * other row is a person's choice and is kept: another set of phases, a value that is not a plain
 * list of phases, no row at all (the tools then run in no phase, as before), a map that is not an
 * object.
 *
 * Run once: the marker is an AuditLog row (`system.tradecraft_phases_backfill`, carrying the count
 * and nothing else), written in the same transaction as the update, under an advisory lock so two
 * webapp copies booting together do it once. Running it again would undo a person who puts the old
 * phases back after the upgrade. Only projects that existed when the new code FIRST started move:
 * that moment is its own AuditLog row (`system.tradecraft_phases_cutoff`), kept when the update
 * fails, so a later retry never touches a project created meanwhile with the new default and
 * narrowed by its person. Every `system.*` row is kept by audit retention (auditRetention.ts).
 *
 * One SQL statement, so each row is judged and changed under its own row lock; it sets
 * `updated_at` itself (Prisma's @updatedAt is applied by the client), so a form opened before the
 * upgrade gets a stale-save refusal instead of writing the old row back.
 *
 * Runs from the webapp entrypoint AFTER `db push`, and from the dev container's command. Never
 * fatal: a failure is logged with its error code only and the next boot tries again (no marker).
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const CUTOFF_ACTION = 'system.tradecraft_phases_cutoff'
export const MARKER_ACTION = 'system.tradecraft_phases_backfill'
export const OLD_PHASES = ['exploitation', 'post_exploitation']
export const NEW_PHASES = ['informational', 'exploitation', 'post_exploitation']

/** When the new default first started: the database time of the cutoff row, written once. */
export async function recordCutoff(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${CUTOFF_ACTION}))`
    const existing = await tx.auditLog.findFirst({ where: { action: CUTOFF_ACTION }, orderBy: { createdAt: 'asc' } })
    if (existing) return existing.createdAt
    const row = await tx.auditLog.create({ data: { action: CUTOFF_ACTION, targetType: 'system', source: 'system' } })
    return row.createdAt
  })
}

/** Returns {done: false} when the marker existed, else how many projects it moved. */
export async function backfillTradecraftPhases(prisma) {
  await recordCutoff(prisma)
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${MARKER_ACTION}))`
    const marker = await tx.auditLog.findFirst({ where: { action: MARKER_ACTION }, select: { id: true } })
    if (marker) return { done: false }

    const oldPhases = JSON.stringify(OLD_PHASES)
    // jsonb containment both ways is set equality on a list of strings: order and repeats aside,
    // nothing missing and nothing else (a nested list or another value is contained in no string).
    const projects = await tx.$executeRaw`
      UPDATE projects
         SET agent_tool_phase_map = jsonb_set(agent_tool_phase_map, '{tradecraft_lookup}', ${JSON.stringify(NEW_PHASES)}::jsonb),
             updated_at = now()
       WHERE jsonb_typeof(agent_tool_phase_map) = 'object'
         AND jsonb_typeof(agent_tool_phase_map -> 'tradecraft_lookup') = 'array'
         AND (agent_tool_phase_map -> 'tradecraft_lookup') @> ${oldPhases}::jsonb
         AND (agent_tool_phase_map -> 'tradecraft_lookup') <@ ${oldPhases}::jsonb
         AND created_at <= (SELECT min(created_at) FROM audit_log WHERE action = ${CUTOFF_ACTION})`

    await tx.auditLog.create({
      data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after: { projects } },
    })
    return { done: true, projects }
  }, { timeout: 120_000, maxWait: 30_000 })
}

export async function main(prisma = new PrismaClient()) {
  try {
    const result = await backfillTradecraftPhases(prisma)
    if (result.done) {
      console.log(`[tradecraft] phases_default_moved projects=${result.projects} (Tradecraft tools now in every phase where the old default was kept)`)
    }
  } catch (err) {
    // The code only: a database message can quote row values.
    console.error(`[tradecraft] phases_default_failed code=${err?.code || err?.name || 'unknown'} (retried next boot)`)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}

/**
 * One-time backfill of the RBAC hardening: the shared tools an existing member keeps.
 *
 * Before the hardening every signed-in account reached the instance-wide tools: the Kali
 * terminal, every shell session, the tunnel settings. The hardening restricts them to
 * admins, so each member who could use them on the day of the upgrade keeps them as
 * legacy grants (`User.legacyGrants`) that an admin reviews: `kali_terminal` and
 * `shell_sessions` for every non-admin account with a password, and `tunnels` for one
 * whose settings configure a tunnel (an ngrok token or a chisel URL: the rule
 * GET /api/global/tunnel-config uses; chisel runs without auth). Admins need none; a
 * passwordless account never signed in, so it gets none.
 *
 * Only accounts that existed when the new code FIRST started are granted. That moment is
 * its own AuditLog row (`system.rbac_legacy_grants_cutoff`), written once before the
 * backfill and kept when the backfill fails; the escape hatch REDAMON_SHARED_TOOLS_COMPAT
 * (src/lib/authz/sharedTools.ts) reads the same row.
 *
 * Run once: the marker (`system.rbac_legacy_grants_backfill`, with how many accounts hold
 * each grant) is written in the same transaction as the grants, under an advisory lock, so
 * webapp copies booting together grant once. It skips only when the marker exists AND the
 * grants are there: a downgrade's `db push` drops the column while the AuditLog marker
 * survives, so a re-upgrade grants again, minus every grant an admin removed.
 *
 * The grants are written through Prisma with the row's own `updatedAt`, so `updated_at`
 * does not move: a grant is not an edit of the account.
 *
 * Runs from the webapp entrypoint AFTER `db push`, and from the dev container's command.
 * Never fatal: a failure is logged and the next boot tries again (no marker was written).
 */
import { PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const LOCK_KEY = 'system.rbac_legacy_grants'
export const CUTOFF_ACTION = 'system.rbac_legacy_grants_cutoff'
export const MARKER_ACTION = 'system.rbac_legacy_grants_backfill'
// The admin review's removal of a grant: one row per account and grant, `targetId` the
// account and `after.grant` the grant. A re-derivation never gives a removed grant back.
export const REMOVE_ACTION = 'rbac.legacy_grant.remove'
export const LEGACY_GRANTS = ['kali_terminal', 'shell_sessions', 'tunnels']

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

/**
 * When the code that restricts the shared tools first started: the database time of the
 * cutoff row, written by the first call and read by every later one.
 */
export async function recordCutoff(prisma) {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    const existing = await tx.auditLog.findFirst({ where: { action: CUTOFF_ACTION }, orderBy: { createdAt: 'asc' } })
    if (existing) return existing.createdAt
    const row = await tx.auditLog.create({ data: { action: CUTOFF_ACTION, targetType: 'system', source: 'system' } })
    return row.createdAt
  })
}

/** How many grants a marker says the accounts held; a marker without counts held none. */
function recordedGrants(after) {
  if (!isPlainObject(after)) return 0
  return LEGACY_GRANTS.reduce((n, g) => n + (Number.isFinite(after[g]) ? after[g] : 0), 0)
}

/**
 * Returns {done: false} when the marker and the grants were already there, else how many
 * accounts hold each grant after the run and how many rows it wrote.
 */
export async function backfillRbacLegacyGrants(prisma) {
  const cutoff = await recordCutoff(prisma)
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    const marker = await tx.auditLog.findFirst({
      where: { action: MARKER_ACTION }, orderBy: { createdAt: 'desc' }, select: { after: true },
    })
    if (marker) {
      if (recordedGrants(marker.after) === 0) return { done: false }
      const holder = await tx.user.findFirst({ where: { legacyGrants: { hasSome: LEGACY_GRANTS } }, select: { id: true } })
      if (holder) return { done: false }
    }

    const members = (await tx.user.findMany({
      where: { role: { not: 'admin' }, password: { not: '' } },
      select: { id: true, legacyGrants: true, createdAt: true, updatedAt: true },
      orderBy: { id: 'asc' },
    })).filter((u) => !(u.createdAt > cutoff))
    const ids = members.map((u) => u.id)

    // At most one settings row per account; the members are picked below.
    const tunnelHolders = new Set((await tx.userSettings.findMany({
      where: { OR: [{ ngrokAuthtoken: { not: '' } }, { chiselServerUrl: { not: '' } }] },
      select: { userId: true },
    })).map((s) => s.userId))

    const removed = new Set()
    for (const r of await tx.auditLog.findMany({
      where: { action: REMOVE_ACTION, targetId: { in: ids } },
      select: { targetId: true, after: true },
    })) {
      if (isPlainObject(r.after) && typeof r.after.grant === 'string') removed.add(`${r.targetId}\u0000${r.after.grant}`)
    }

    const holders = Object.fromEntries(LEGACY_GRANTS.map((g) => [g, 0]))
    let usersChanged = 0
    for (const member of members) {
      const held = Array.isArray(member.legacyGrants) ? member.legacyGrants : []
      const due = ['kali_terminal', 'shell_sessions', ...(tunnelHolders.has(member.id) ? ['tunnels'] : [])]
        .filter((g) => !removed.has(`${member.id}\u0000${g}`))
      // Known grants in a fixed order, then anything else the row already held, untouched.
      const next = [
        ...LEGACY_GRANTS.filter((g) => due.includes(g) || held.includes(g)),
        ...held.filter((g) => !LEGACY_GRANTS.includes(g)),
      ]
      for (const g of LEGACY_GRANTS) if (next.includes(g)) holders[g]++
      if (next.length === held.length && next.every((g, i) => g === held[i])) continue
      await tx.user.update({ where: { id: member.id }, data: { legacyGrants: next, updatedAt: member.updatedAt } })
      usersChanged++
    }

    await tx.auditLog.create({
      data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after: holders },
    })
    return { done: true, ...holders, usersChanged }
  }, { timeout: 300_000, maxWait: 30_000 })
}

async function main() {
  const prisma = new PrismaClient()
  try {
    const r = await backfillRbacLegacyGrants(prisma)
    if (r.done) {
      console.log(`[rbac] legacy grants recorded: ${r.kali_terminal} member(s) keep the Kali terminal, ${r.shell_sessions} the shell sessions, ${r.tunnels} the tunnels (${r.usersChanged} account(s) written).`)
    }
  } catch (err) {
    console.error('[rbac] could not backfill legacy grants (retried next boot):', err?.message || err)
  } finally {
    await prisma.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main()
}

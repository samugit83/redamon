/**
 * Fills the instance settings (`instance_settings`, one row) with the tunnel and the
 * TrafficMind capture policy in force in the user rows (step 2.4, ID-34, §14.6).
 *
 * Before the identity switch (RBAC_IDENTITY_ENABLED) these settings live in each account's
 * `user_settings` row, and the readers pick one row: the tunnel from the rows that hold an
 * ngrok token or a chisel URL, enabled first, then the most recent save, then the lowest id
 * (GET /api/global/tunnel-config, TUNNEL_ROW_ORDER); the capture, egress and SCA settings
 * from the admin row saved last (GET /api/internal/capture-config). This copies exactly
 * those values, records which row each group came from (`tunnelSourceUserId`,
 * `captureSourceUserId`) and never writes a user row.
 *
 * While the switch is off the user rows stay the truth, so every boot copies them again
 * (only when something differs, and without a new marker): the row is ready, and current,
 * the day the switch goes on. The first boot with the switch on copies them one last time
 * and records it (`identity: true` in the marker); from then on the row is the truth and
 * only the admin route writes it (it sets `updatedById`, and the backfill never overwrites
 * a row an admin wrote). A boot with the switch off again resets that, since the user rows
 * are the truth again.
 *
 * The marker (`system.rbac_instance_settings_backfill`, with both sources and the candidate
 * ids) is written in the same transaction as the row, under an advisory lock, so webapp
 * copies booting together fill it once. It is skipped only when the marker exists AND the
 * row is there: a downgrade's `db push` drops the table while the AuditLog marker survives,
 * so a re-upgrade fills it again. The host commands (set-root, create-admin) may create the
 * row first (ensureInstanceSettingsRow: these same values, no marker): the backfill fills
 * that row again and records it, never touching its Root columns. No cutoff row: a user
 * row saved after the first boot holds the values in force then, so it is copied too.
 *
 * Runs from the webapp entrypoint AFTER `db push`, and from the dev container's command.
 * Never fatal: a failure is logged and the next boot tries again (no marker was written).
 */
import { Prisma, PrismaClient } from '@prisma/client'
import { pathToFileURL } from 'node:url'

export const LOCK_KEY = 'system.rbac_instance_settings'
export const MARKER_ACTION = 'system.rbac_instance_settings_backfill'
export const SINGLETON_ID = 'instance'

export const TUNNEL_FIELDS = ['tunnelsEnabled', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']

// The UserSettings columns the instance row copies (schema.prisma, InstanceSettings).
export const CAPTURE_FIELDS = [
  'captureProxyEnabled', 'captureProxyPort', 'captureProxyScope', 'captureProxyStoreBodies',
  'captureProxyMaxBodyKb', 'captureProxyRetentionDays', 'captureProxyRedactSecrets',
  'captureProxyPassiveDetect', 'captureProxyStoreReqBodies', 'captureProxyStoreRespBodies',
  'captureProxyMaxStoreMb', 'captureProxyBodyRules',
  'captureEgressBlockEmptyHost', 'captureEgressBlockHardGuardrail', 'captureEgressFailClosed',
  'captureEgressBlockUnresolvable', 'captureEgressBlockPrivate', 'captureEgressBlockLoopback',
  'captureEgressBlockLinkLocal', 'captureEgressBlockCgnat', 'captureEgressBlockReserved',
  'captureEgressBlockMulticast', 'captureEgressBlockUnspecified',
  'scaIntelIgnoreSuffixes',
]

// The schema's defaults: what the row holds when no user row configures a group.
export const TUNNEL_DEFAULTS = { tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }
export const CAPTURE_DEFAULTS = {
  captureProxyEnabled: true, captureProxyPort: 8888, captureProxyScope: 'both', captureProxyStoreBodies: true,
  captureProxyMaxBodyKb: 64, captureProxyRetentionDays: 14, captureProxyRedactSecrets: true,
  captureProxyPassiveDetect: true, captureProxyStoreReqBodies: true, captureProxyStoreRespBodies: true,
  captureProxyMaxStoreMb: 5, captureProxyBodyRules: {},
  captureEgressBlockEmptyHost: true, captureEgressBlockHardGuardrail: true, captureEgressFailClosed: true,
  captureEgressBlockUnresolvable: true, captureEgressBlockPrivate: true, captureEgressBlockLoopback: true,
  captureEgressBlockLinkLocal: true, captureEgressBlockCgnat: true, captureEgressBlockReserved: true,
  captureEgressBlockMulticast: true, captureEgressBlockUnspecified: true,
  scaIntelIgnoreSuffixes: 'oastify.com,oast.fun,mburpcollab.com,canarytokens.com,pipedream.net',
}

// The readers' rules, repeated (src/lib/sharedInstanceSettings.ts holds the same; a test
// holds them equal). The id breaks a tie of two saves in the same instant.
export const TUNNEL_CANDIDATE_WHERE = { OR: [{ ngrokAuthtoken: { not: '' } }, { chiselServerUrl: { not: '' } }] }
export const TUNNEL_ROW_ORDER = [{ tunnelsEnabled: 'desc' }, { updatedAt: 'desc' }, { id: 'asc' }]
export const CAPTURE_ROW_ORDER = [{ updatedAt: 'desc' }, { id: 'asc' }]

/** RBAC_IDENTITY_ENABLED as src/lib/authz/flags.ts reads it: true, 1 or yes (any case). */
export function identitySwitchOn(env = process.env) {
  return ['true', '1', 'yes'].includes(String(env.RBAC_IDENTITY_ENABLED ?? '').trim().toLowerCase())
}

const pick = (row, fields) => Object.fromEntries(fields.map((f) => [f, row[f]]))
const select = (fields) => Object.fromEntries(['userId', ...fields].map((f) => [f, true]))
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

/** The values in force in the user rows, where each group came from, and the candidates. */
export async function deriveInstanceValues(tx) {
  const tunnelRows = await tx.userSettings.findMany({
    where: TUNNEL_CANDIDATE_WHERE, orderBy: TUNNEL_ROW_ORDER, select: select(TUNNEL_FIELDS),
  })
  const adminIds = (await tx.user.findMany({ where: { role: 'admin' }, select: { id: true } })).map((a) => a.id)
  const captureRows = adminIds.length
    ? await tx.userSettings.findMany({
      where: { userId: { in: adminIds } }, orderBy: CAPTURE_ROW_ORDER, select: select(CAPTURE_FIELDS),
    })
    : []
  const tunnel = tunnelRows[0]
  const capture = captureRows[0]
  return {
    data: {
      ...(tunnel ? pick(tunnel, TUNNEL_FIELDS) : TUNNEL_DEFAULTS),
      tunnelSourceUserId: tunnel?.userId ?? null,
      ...(capture ? pick(capture, CAPTURE_FIELDS) : CAPTURE_DEFAULTS),
      captureSourceUserId: capture?.userId ?? null,
    },
    tunnelCandidates: tunnelRows.map((r) => r.userId),
    captureCandidates: captureRows.map((r) => r.userId),
  }
}

// The copied fields the schema types Json: sent as text and cast.
export const JSON_FIELDS = ['captureProxyBodyRules']

/** The instance_settings column of a copied field: its @map (a test holds them equal). */
export const columnOf = (field) => field.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)

/**
 * Creates the row, when missing, with the values this backfill copies, for the host
 * commands (create-admin, set-root): they record Root in it and can run before any boot
 * filled it (an upgrade's first `update`, or a boot whose backfill failed). A row of
 * schema defaults would be the readers' truth once the switch is on: the tunnel would read
 * empty and capture would run with the defaults. No marker: the next boot still fills the
 * row and records it. Raw SQL, as the host commands write the identity columns: they also
 * run from a checkout on an older image's client (tests/rbac_scripts_db_test.sh).
 * Returns whether it created the row.
 */
export async function ensureInstanceSettingsRow(tx) {
  const [present] = await tx.$queryRaw`SELECT 1 FROM instance_settings WHERE id = ${SINGLETON_ID}`
  if (present) return false
  const { data } = await deriveInstanceValues(tx)
  const fields = Object.keys(data)
  const values = fields.map((f) => (JSON_FIELDS.includes(f)
    ? Prisma.sql`${JSON.stringify(data[f])}::jsonb`
    : Prisma.sql`${data[f]}`))
  return (await tx.$executeRaw`
    INSERT INTO instance_settings (id, updated_at, ${Prisma.raw(fields.map(columnOf).join(', '))})
    VALUES (${SINGLETON_ID}, now(), ${Prisma.join(values)})
    ON CONFLICT (id) DO NOTHING`) > 0
}

const same = (a, b) => (isPlainObject(a) || isPlainObject(b) ? JSON.stringify(a) === JSON.stringify(b) : a === b)

/** Whether the row already holds these values and no admin wrote it since. */
export function rowHolds(row, data) {
  return row.updatedById == null && Object.entries(data).every(([k, v]) => same(row[k] ?? null, v ?? null))
}

/**
 * What to do with the row (`write`: 'upsert' | 'none') and whether to write a marker, from
 * the latest marker's `after`, the row, the switch and the values in force.
 */
export function planInstanceSettings({ marker, row, switchOn, data }) {
  const adminWrote = !!row && row.updatedById != null
  if (!row) return { write: 'upsert', marker: true }
  if (!marker) return { write: adminWrote ? 'none' : 'upsert', marker: true }
  if (!switchOn) return { write: rowHolds(row, data) ? 'none' : 'upsert', marker: false }
  const filledWithSwitchOn = isPlainObject(marker.after) && marker.after.identity === true
  if (filledWithSwitchOn) return { write: 'none', marker: false }
  return { write: adminWrote ? 'none' : 'upsert', marker: true }
}

/**
 * Returns {marker: false} when nothing was recorded, else the sources and candidates of the
 * values in force and whether the row was written.
 */
export async function backfillRbacInstanceSettings(prisma, env = process.env) {
  const switchOn = identitySwitchOn(env)
  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${LOCK_KEY}))`
    const marker = await tx.auditLog.findFirst({
      where: { action: MARKER_ACTION }, orderBy: { createdAt: 'desc' }, select: { after: true },
    })
    const row = await tx.instanceSettings.findUnique({ where: { id: SINGLETON_ID } })
    const derived = await deriveInstanceValues(tx)
    const plan = planInstanceSettings({ marker, row, switchOn, data: derived.data })
    if (plan.write === 'upsert') {
      await tx.instanceSettings.upsert({
        where: { id: SINGLETON_ID },
        create: { id: SINGLETON_ID, ...derived.data },
        update: { ...derived.data, updatedById: null },
      })
    }
    const kept = plan.write === 'none' ? row : null
    const result = {
      wrote: plan.write === 'upsert',
      identity: switchOn,
      tunnelSourceUserId: kept ? kept.tunnelSourceUserId ?? null : derived.data.tunnelSourceUserId,
      captureSourceUserId: kept ? kept.captureSourceUserId ?? null : derived.data.captureSourceUserId,
      tunnelCandidates: derived.tunnelCandidates,
      captureCandidates: derived.captureCandidates,
    }
    if (plan.marker) {
      await tx.auditLog.create({
        data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after: result },
      })
    }
    return { marker: plan.marker, ...result }
  }, { timeout: 120_000, maxWait: 30_000 })
}

export async function run(prisma, env = process.env) {
  try {
    const r = await backfillRbacInstanceSettings(prisma, env)
    if (r.marker) {
      console.log(`[rbac] instance settings ${r.wrote ? 'filled from' : 'kept; recorded against'} the user rows: tunnel from ${r.tunnelSourceUserId ?? 'none'} (${r.tunnelCandidates.length} candidate(s)), capture from ${r.captureSourceUserId ?? 'none'} (${r.captureCandidates.length} admin row(s)).`)
    } else if (r.wrote) {
      console.log('[rbac] instance settings refreshed from the user rows (the identity switch is off).')
    }
  } catch (err) {
    console.error('[rbac] could not fill the instance settings (retried next boot):', failureReason(err))
  }
}

/**
 * One line naming the failure. A validation error quotes the call's arguments, which hold
 * the tunnel credentials, so only its name is logged; a database error quotes no values.
 */
export function failureReason(err) {
  if (err?.name === 'PrismaClientValidationError') return err.name
  return String(err?.message || err).replace(/\s+/g, ' ').trim()
}

// Imported by the tests without running; executed by the entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const prisma = new PrismaClient()
  run(prisma).finally(() => prisma.$disconnect().catch(() => {}))
}

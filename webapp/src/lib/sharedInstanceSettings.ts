/**
 * The settings every account shares because the instance runs one of each: the tunnel
 * (one ngrok/chisel listener) and the TrafficMind capture proxy with its egress guard and
 * SCA ignore list. Before the identity switch they live in the `user_settings` rows and a
 * reader picks one row; with RBAC_IDENTITY_ENABLED on they live in the instance settings
 * row, which scripts/backfill-rbac-instance-settings.mjs fills with the values these rules
 * pick (a test holds its copies of the rules equal to these).
 */
import type { InstanceSettings, Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { rbacFlags } from '@/lib/authz/flags'
import { writeAuditTx } from '@/lib/audit'
import { actorFields, type AuditActor } from '@/lib/auditActor'

/** The user rows that configure a tunnel: an ngrok token or a chisel URL (chisel runs without auth). */
export const TUNNEL_CANDIDATE_WHERE = {
  OR: [
    { ngrokAuthtoken: { not: '' } },
    { chiselServerUrl: { not: '' } },
  ],
}

/**
 * The tunnel row in force: the enabled one first (the last enable pushed it to the
 * sandbox), then the most recent save, then the lowest id, so every call names the same
 * tunnel.
 */
export const TUNNEL_ROW_ORDER = [
  { tunnelsEnabled: 'desc' as const },
  { updatedAt: 'desc' as const },
  { id: 'asc' as const },
]

export const TUNNEL_FIELDS = ['tunnelsEnabled', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

/** The capture proxy, egress guard and SCA ignore list columns, the same in both tables. */
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
] as const

/** The schema's defaults of the capture columns: what a missing settings row reads as. */
export const CAPTURE_DEFAULTS: Readonly<Record<(typeof CAPTURE_FIELDS)[number], unknown>> = {
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

/** The one instance settings row (InstanceSettings, `@default("instance")`). */
export const INSTANCE_SETTINGS_ID = 'instance'

/**
 * The instance settings row when the identity switch is on and the row exists, else null:
 * the readers then pick a user row as before the switch. Off, nothing is read here. The row
 * is missing only until the boot backfill first fills it (a failure is retried each boot).
 */
export async function instanceSettingsInForce() {
  if (!rbacFlags().identity) return null
  return prisma.instanceSettings.findUnique({ where: { id: INSTANCE_SETTINGS_ID } })
}

type Values = Record<string, unknown>

/** A stored secret shown to a browser: its last 4 characters, as the settings routes show keys. */
export function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

/**
 * The tunnel settings a write would change. A masked secret keeps the stored value and
 * an unchanged value is no change, so the Global Settings page's full-form save, which
 * sends all four every time, changes nothing.
 */
export function changedTunnelFields(existing: Values | null, body: Values): string[] {
  const changed: string[] = (['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const).filter((f) => {
    if (!(f in body)) return false
    const stored = (existing?.[f] as string | undefined) ?? ''
    const sent = body[f]
    const next = typeof sent === 'string' && sent.startsWith('••••') && existing ? stored : sent
    return next !== stored
  })
  const storedEnabled = (existing?.tunnelsEnabled as boolean | undefined) ?? false
  if ('tunnelsEnabled' in body && Boolean(body.tunnelsEnabled) !== storedEnabled) changed.push('tunnelsEnabled')
  return changed
}

export type CapturePatch = Record<string, boolean | number | string | Record<string, string>>

const CAPTURE_BOOL_FIELDS = ['captureProxyStoreBodies', 'captureProxyRedactSecrets', 'captureProxyPassiveDetect',
  // Granular body-storage direction toggles (Body storage sub-panel).
  'captureProxyStoreReqBodies', 'captureProxyStoreRespBodies',
  // Egress-guard toggles (Global Settings > TrafficMind). All default true (block).
  'captureEgressBlockEmptyHost', 'captureEgressBlockHardGuardrail', 'captureEgressFailClosed',
  'captureEgressBlockUnresolvable', 'captureEgressBlockPrivate', 'captureEgressBlockLoopback',
  'captureEgressBlockLinkLocal', 'captureEgressBlockCgnat', 'captureEgressBlockReserved',
  'captureEgressBlockMulticast', 'captureEgressBlockUnspecified'] as const
const CAPTURE_INT_FIELDS = ['captureProxyPort', 'captureProxyMaxBodyKb', 'captureProxyRetentionDays',
  'captureProxyMaxStoreMb'] as const
// Sane lower bounds - a retentionDays <= 0 would make maintenance delete ALL traffic;
// port/maxBodyKb must be positive. maxStoreMb may be 0 (= unlimited).
const CAPTURE_INT_MIN: Record<string, number> = {
  captureProxyPort: 1, captureProxyMaxBodyKb: 1, captureProxyRetentionDays: 1, captureProxyMaxStoreMb: 0,
}

/**
 * The capture, egress and SCA fields of a write, validated (the master switch,
 * `captureProxyEnabled`, is handled by each writer). Booleans and ints cannot ride a
 * string loop; out-of-range ints are clamped; unknown values are dropped.
 */
export function parseCapturePatch(body: Values, sanitize: (rules: unknown) => Record<string, string>): CapturePatch {
  const captureData: CapturePatch = {}
  for (const f of CAPTURE_BOOL_FIELDS) if (f in body) captureData[f] = Boolean(body[f])
  for (const f of CAPTURE_INT_FIELDS) if (f in body) {
    const n = parseInt(String(body[f]), 10)
    if (Number.isFinite(n)) captureData[f] = Math.max(CAPTURE_INT_MIN[f] ?? 0, n)
  }
  if ('captureProxyScope' in body && ['recon', 'agent', 'both'].includes(body.captureProxyScope as string)) {
    captureData.captureProxyScope = body.captureProxyScope as string
  }
  // Body-storage policy map (family -> policy). Sanitized against allowlists so a
  // bad key/value can never reach the proxy env; unknown pairs are dropped.
  if ('captureProxyBodyRules' in body) {
    captureData.captureProxyBodyRules = sanitize(body.captureProxyBodyRules)
  }
  // Incident-match ignore list (A1). Sanitized to hostname-ish tokens because
  // it is forwarded to a spawned container as env: a comma-separated list is
  // the only shape either matcher understands, and anything else is dropped
  // rather than passed through.
  if ('scaIntelIgnoreSuffixes' in body) {
    captureData.scaIntelIgnoreSuffixes = String(body.scaIntelIgnoreSuffixes ?? '')
      .split(/[,\s]+/)
      .map(s => s.trim().toLowerCase().replace(/^\.+/, ''))
      .filter(s => s && s.length <= 253 && /^[a-z0-9.-]+$/.test(s))
      .slice(0, 50)
      .join(',')
  }
  return captureData
}

const sameValue = (a: unknown, b: unknown) =>
  (a !== null && typeof a === 'object') || (b !== null && typeof b === 'object')
    ? JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
    : a === b

/**
 * The capture fields a write would change: the validated patch against the stored values,
 * and the master switch when the body names it (a missing row reads as the defaults: on).
 */
export function changedCaptureFields(existing: Values | null, patch: CapturePatch, body: Values): string[] {
  const stored: Values = existing ?? CAPTURE_DEFAULTS
  const changed = Object.keys(patch).filter((k) => !sameValue(patch[k], stored[k]))
  const storedEnabled = (stored.captureProxyEnabled as boolean | undefined) ?? true
  if ('captureProxyEnabled' in body && Boolean(body.captureProxyEnabled) !== storedEnabled) changed.push('captureProxyEnabled')
  return changed
}

type Tx = Prisma.TransactionClient

/**
 * The account whose user row receives a group's mirror: the group's source while that
 * account exists, else the confirmed Root, else the oldest admin; null when there is none.
 */
async function mirrorTarget(tx: Tx, sourceUserId: string | null, row: InstanceSettings): Promise<string | null> {
  const exists = async (id: string | null) =>
    !!id && !!(await tx.user.findUnique({ where: { id }, select: { id: true } }))
  if (await exists(sourceUserId)) return sourceUserId
  if (row.rootConfirmedAt && await exists(row.rootUserId)) return row.rootUserId
  const admin = await tx.user.findFirst({
    where: { role: 'admin' }, orderBy: [{ createdAt: 'asc' }, { id: 'asc' }], select: { id: true },
  })
  return admin?.id ?? null
}

const GROUPS = [
  { name: 'tunnel', fields: TUNNEL_FIELDS, source: 'tunnelSourceUserId' },
  { name: 'capture', fields: CAPTURE_FIELDS, source: 'captureSourceUserId' },
] as const

export interface InstanceSettingsWrite {
  /** The changed columns with their new values (tunnel and capture columns only). */
  data: Record<string, unknown>
  actor: AuditActor
  /** How the actor may change the tunnel, when the write changes it: admin, legacy, compat. */
  tunnelVia?: string | null
}

/**
 * Writes the changed tunnel and capture columns of the instance settings row, then, for each
 * changed group, the group's whole value set into one user row (the mirror a downgrade, or
 * the switch turned off, reads; the `*SourceUserId` column follows it when the source account
 * is gone), and the `instance.settings_changed` audit row naming the fields, never their
 * values: all in one transaction, which a failed audit write rolls back (AU-05).
 */
export async function writeInstanceSettings({ data, actor, tunnelVia }: InstanceSettingsWrite): Promise<InstanceSettings> {
  const fields = Object.keys(data)
  return prisma.$transaction(async (tx) => {
    let row = await tx.instanceSettings.update({
      where: { id: INSTANCE_SETTINGS_ID },
      data: { ...(data as Prisma.InstanceSettingsUpdateInput), updatedById: actor.actorId },
    })
    const mirror: Record<string, string | null> = {}
    const sources: Record<string, string | null> = {}
    for (const group of GROUPS) {
      if (!group.fields.some((f) => fields.includes(f))) continue
      const current = row[group.source]
      const target = await mirrorTarget(tx, current, row)
      if (target) {
        const values = Object.fromEntries(group.fields.map((f) => [f, row[f]])) as Prisma.UserSettingsUncheckedUpdateInput
        await tx.userSettings.upsert({
          where: { userId: target },
          update: values,
          create: { ...(values as Prisma.UserSettingsUncheckedCreateInput), userId: target },
        })
      }
      mirror[group.name] = target
      if (target !== current) sources[group.source] = target
    }
    if (Object.keys(sources).length) {
      row = await tx.instanceSettings.update({ where: { id: INSTANCE_SETTINGS_ID }, data: sources })
    }
    await writeAuditTx(tx, {
      ...actorFields(actor),
      action: 'instance.settings_changed',
      targetType: 'instance',
      targetId: INSTANCE_SETTINGS_ID,
      after: { fields, ...(tunnelVia ? { tunnelVia } : {}), mirroredTo: mirror },
    })
    return row
  })
}

/**
 * The settings every account shares because the instance runs one of each: the tunnel
 * (one ngrok/chisel listener) and the TrafficMind capture proxy with its egress guard and
 * SCA ignore list. Before the identity switch they live in the `user_settings` rows and a
 * reader picks one row; with RBAC_IDENTITY_ENABLED on they live in the instance settings
 * row, which scripts/backfill-rbac-instance-settings.mjs fills with the values these rules
 * pick (a test holds its copies of the rules equal to these).
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from '@/lib/authz/flags'

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

import { NextRequest, NextResponse } from 'next/server'
import type { InstanceSettings } from '@prisma/client'
import { getSession, type Session } from '@/lib/session'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal, type Principal } from '@/lib/authz/principal'
import { sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { secretReentryResponse, settingsEndpointChange, settingsSecretReentry } from '@/lib/authz/secretEndpointRebind'
import { requireStepUp } from '@/lib/authz/stepUp'
import { sessionHolds } from '@/lib/authz/adminPermission'
import { rootOnlyRefusal, rootStanding, type RootStanding } from '@/lib/authz/rootPowers'
import { accountTypeOf } from '@/lib/authz/root'
import {
  changedSecurityPolicyFields, parseSecurityPolicyPatch, securityPolicyView,
} from '@/lib/instanceSecurityPolicy'
import {
  changedSharingPolicyFields, invalidateSharingPolicy, parseSharingPolicy, parseSharingPolicyPatch, sharingPolicyToStore,
  type SharingPolicyPatch,
} from '@/lib/authz/sharingPolicy'
import { auditActorOf, sessionActor } from '@/lib/auditActor'
import { sanitizeBodyRules } from '@/lib/captureBodyRules'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import {
  CAPTURE_FIELDS, changedCaptureFields, changedTunnelFields, instanceSettingsInForce, maskSecret,
  parseCapturePatch, writeInstanceSettings,
} from '@/lib/sharedInstanceSettings'
import { CAPTURE_RECREATE_FIELDS, pushTunnelConfig, reconcileCaptureProxy } from '@/lib/sharedSettingsEffects'
import type { SaveWarning } from '@/app/api/users/[id]/settings/saveWarnings'
import {
  applyQuotaPatch, changedQuotaKeys, parseQuotaPatch, parseQuotaStore, quotasInForce, quotaStoreToJson,
  quotaTargetsView, unknownQuotaTargets, type QuotaPatch,
} from '@/lib/authz/quotas'
import { now } from '@/lib/authz/clock'
import { changeRetention, parseRetentionDays, retentionChangeOf, retentionState, retentionView } from '@/lib/authz/auditRetention'

/**
 * The settings the instance shares because it runs one of each (step 2.4, ID-32): the
 * tunnel, and the TrafficMind capture proxy with its egress guard and SCA ignore list. They
 * live in the instance settings row with RBAC_IDENTITY_ENABLED on; off, this route answers
 * 404, as before it existed, and the user settings route keeps them.
 *
 * The person is the one signed in, read fresh for a write (T3), never the account an admin
 * acts as (F-15): an admin acting as a member saves here under their own name. Each group is
 * its permission's, whoever holds it (step 3.9): the tunnel platform:tunnels, through
 * sharedToolAccess so the member holding the `tunnels` legacy grant (until step 3.15's
 * conversion, then its override) and a pre-upgrade account under REDAMON_SHARED_TOOLS_COMPAT
 * keep it (HD-06, T27; owner question OQ-R3, default (a)); the capture, egress and SCA fields
 * platform:traffic_capture (this is the only TrafficMind write with the identity switch on).
 * With RBAC_PERMISSIONS_ENABLED off every admin holds both. A person sees only the groups they
 * hold; anyone holding none, and no administrator account, is refused. Secrets are answered
 * masked.
 *
 * A PUT changes only what differs from the stored values (a masked secret keeps the stored
 * one), keeps the user settings route's rules for the tunnel (a new chisel URL needs its auth
 * typed again, HD-24, and the person's password, ID-25), mirrors each changed group into a
 * user row, audits `instance.settings_changed` with the field names, then applies the change:
 * the capture proxy follows its switch and spawn-time knobs, the sandbox takes the tunnel.
 *
 * The security policy (password policy, session and link lifetimes, impersonation settings,
 * public base URL; step 2.6) is the confirmed Root's: every administrator account reads it
 * (it is not a platform tool), a change by anyone else is 403 `root_only`, and Root changes it
 * with its password. A value sent unchanged needs neither.
 *
 * The sharing policy (step 4.2, SH-21) follows the same rule, with RBAC_SHARING_ENABLED on only:
 * admins read it as it is in force (lib/authz/sharingPolicy.ts), only the confirmed Root changes
 * it, with its password, and the whole policy is stored (no user-row mirror: 7.7.x has no home for
 * it). With the switch off the route is the one before: the policy is neither shown nor read from
 * a body.
 *
 * The quotas (step 6.8, GV-09..GV-13) are the `instance:quotas` holder's (Full admin holds it; no
 * password asked), with RBAC_GOVERNANCE_ENABLED on only: `quotas` is the stored
 * `{defaults, perSet, perUser}` (lib/authz/quotas.ts), answered with the sets the editor names and,
 * to a users:read holder, the accounts its per-user entries name. A PUT's `quotas` is a patch:
 * `defaults` replaces the defaults, each named set or account entry is replaced (or removed by null);
 * a value out of bounds is 400 `invalid_field`, a new entry for a set or account that does not exist
 * 400 `unknown_quota_target`. The audit row names the changed keys (`defaults.maxProjects`,
 * `perUser.<id>`), never the values. With the switch off nothing is shown or read from a body.
 *
 * The audit retention (step 6.6, AU-04, OQ-40) is the confirmed Root's, with RBAC_GOVERNANCE_ENABLED on
 * only: every administrator account reads `auditRetention` (the days in force, a change waiting with
 * its date, the floor and the delay); a PUT's `auditRetentionDays` (null = keep every row, else whole
 * days from the floor up, 400 `invalid_field` otherwise) by anyone else is 403 `root_only`, and Root's
 * takes its password. It never applies at once: it waits its delay as a pending change (audited
 * `instance.audit_retention_requested`), and sending the value in force while one waits cancels it
 * (`instance.audit_retention_cancelled`); lib/authz/auditRetention.ts, in its own transaction after
 * the other groups. With the switch off nothing is shown or read from a body.
 */

const TUNNEL_STRINGS = ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

const notFound = () => NextResponse.json({ error: 'Not found' }, { status: 404 })

const forbidden = (error: string, permission: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code: 'forbidden', permission, ...extra }, { status: 403 })

/** The row is missing only while the boot backfill has not filled it (it logs why each boot). */
function notReady(): NextResponse {
  console.warn('[rbac] instance settings row missing: the boot backfill has not filled it')
  return NextResponse.json(
    {
      error: 'The instance settings are not ready: the webapp fills them when it starts. Restart it, then check its log for "[rbac] could not fill the instance settings".',
      code: 'instance_settings_unavailable',
    },
    { status: 503 },
  )
}

interface Access {
  session: Session
  principal: Principal
  /** An administrator account (Root is one): reads the security policy. */
  admin: boolean
  /** platform:traffic_capture: the capture, egress and SCA fields. */
  capture: boolean
  /** platform:tunnels, or the escape hatch: the tunnel fields. */
  tunnels: SharedToolAccess
  /** instance:quotas, with RBAC_GOVERNANCE_ENABLED on: the quotas. */
  quotas: boolean
}

async function access(fresh: boolean): Promise<Access | NextResponse> {
  const session = await getSession({ fresh })
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const principal = await loadPrincipal(session.userId, { fresh })
  if (!principal) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const tunnels = await sharedToolAccess(principal, 'tunnels', { record: false })
  const capture = await sessionHolds(session, 'platform:traffic_capture', { fresh })
  const admin = accountTypeOf(principal, null) === 'admin'
  if (!admin && !capture && !tunnels.allowed) {
    return forbidden('Only whoever holds the instance tunnel or the traffic capture opens the instance settings.', 'platform:tunnels')
  }
  const quotas = quotasInForce() && (await sessionHolds(session, 'instance:quotas', { fresh }))
  return { session, principal, admin, capture, tunnels, quotas }
}

const ROOT_ONLY_POLICY = 'Only Root can change the instance security policy.'
const ROOT_ONLY_SHARING = 'Only Root can change the instance sharing policy.'
const ROOT_ONLY_RETENTION = 'Only Root can change the audit retention.'

/** What a browser sees: the secrets masked, each group only for whoever holds it, the security policy for an admin. */
function view(row: InstanceSettings, a: Access, standing: RootStanding, warnings: SaveWarning[] = []) {
  return {
    ...(a.tunnels.allowed
      ? {
          tunnelsEnabled: row.tunnelsEnabled,
          ngrokAuthtoken: maskSecret(row.ngrokAuthtoken),
          chiselServerUrl: row.chiselServerUrl,
          chiselAuth: maskSecret(row.chiselAuth),
        }
      : {}),
    ...(a.capture ? Object.fromEntries(CAPTURE_FIELDS.map((f) => [f, row[f]])) : {}),
    canManageTunnels: a.tunnels.allowed,
    canManageCapture: a.capture,
    ...(a.admin
      ? { securityPolicy: securityPolicyView(row as unknown as Record<string, unknown>), canManageSecurityPolicy: standing === 'confirmed' }
      : {}),
    ...(a.admin && rbacFlags().sharing
      ? { sharingPolicy: parseSharingPolicy(row.sharingPolicy), canManageSharingPolicy: standing === 'confirmed' }
      : {}),
    ...(a.admin && rbacFlags().governance
      ? { auditRetention: retentionView(row, now()), canManageAuditRetention: standing === 'confirmed' }
      : {}),
    ...(warnings.length ? { warnings } : {}),
  }
}

/** The answer: the view, plus the quotas with the names their editor shows for an instance:quotas holder. */
async function answer(row: InstanceSettings, a: Access, standing: RootStanding, warnings: SaveWarning[] = []) {
  if (!a.quotas) return NextResponse.json(view(row, a, standing, warnings))
  const quotas = parseQuotaStore(row.quotas)
  const targets = await quotaTargetsView(quotas, { withUsers: await sessionHolds(a.session, 'users:read') })
  return NextResponse.json({ ...view(row, a, standing, warnings), quotas, canManageQuotas: true, ...targets })
}

export const GET = withRouteErrors('Could not read the instance settings', async (_request: NextRequest) => {
  if (!rbacFlags().identity) return notFound()
  const a = await access(false)
  if (a instanceof NextResponse) return a
  const row = await instanceSettingsInForce()
  if (!row) return notReady()
  return answer(row, a, a.admin ? await rootStanding(a.session.userId) : 'none')
})

export const PUT = withRouteErrors('Could not save the instance settings', async (request: NextRequest) => {
  if (!rbacFlags().identity) return notFound()
  const a = await access(true)
  if (a instanceof NextResponse) return a
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const body = parsed.body

  for (const f of TUNNEL_STRINGS) {
    if (f in body && typeof body[f] !== 'string') {
      return NextResponse.json({ error: `${f} must be text`, code: 'invalid_field', field: f }, { status: 400 })
    }
  }
  const policy = parseSecurityPolicyPatch(body)
  if ('error' in policy) {
    return NextResponse.json({ error: policy.error.message, code: 'invalid_field', field: policy.error.field }, { status: 400 })
  }
  const sharing: { patch: SharingPolicyPatch } | { error: { field: string; message: string } } =
    rbacFlags().sharing && 'sharingPolicy' in body ? parseSharingPolicyPatch(body.sharingPolicy) : { patch: {} }
  if ('error' in sharing) {
    return NextResponse.json({ error: sharing.error.message, code: 'invalid_field', field: sharing.error.field }, { status: 400 })
  }
  const quotaPatch: { patch: QuotaPatch } | { error: { field: string; message: string } } =
    quotasInForce() && 'quotas' in body ? parseQuotaPatch(body.quotas) : { patch: {} }
  if ('error' in quotaPatch) {
    return NextResponse.json({ error: quotaPatch.error.message, code: 'invalid_field', field: quotaPatch.error.field }, { status: 400 })
  }
  const retentionAsk = rbacFlags().governance && 'auditRetentionDays' in body ? parseRetentionDays(body.auditRetentionDays) : null
  if (retentionAsk && 'error' in retentionAsk) {
    return NextResponse.json({ error: retentionAsk.error, code: 'invalid_field', field: 'auditRetentionDays' }, { status: 400 })
  }

  const row = await instanceSettingsInForce()
  if (!row) return notReady()
  const stored = row as unknown as Record<string, unknown>

  const tunnelChanges = changedTunnelFields(stored, body)
  const capturePatch = parseCapturePatch(body, sanitizeBodyRules)
  const captureChanges = changedCaptureFields(stored, capturePatch, body)
  if (tunnelChanges.length && !a.tunnels.allowed) {
    return forbidden('Only whoever holds platform:tunnels changes the instance tunnel.', 'platform:tunnels', { fields: tunnelChanges })
  }
  if (captureChanges.length && !a.capture) {
    return forbidden('Only whoever holds platform:traffic_capture changes the TrafficMind settings.', 'platform:traffic_capture', {
      fields: captureChanges,
    })
  }
  const policyChanges = changedSecurityPolicyFields(stored, policy.patch)
  const sharingChanges = changedSharingPolicyFields(parseSharingPolicy(row.sharingPolicy), sharing.patch)
  const retentionChange = retentionAsk ? retentionChangeOf(retentionState(row, now()), retentionAsk.days) : null
  const standing = a.admin || policyChanges.length || sharingChanges.length || retentionChange
    ? await rootStanding(a.session.userId) : 'none'
  if (policyChanges.length && standing !== 'confirmed') return rootOnlyRefusal(standing, ROOT_ONLY_POLICY)
  if (sharingChanges.length && standing !== 'confirmed') return rootOnlyRefusal(standing, ROOT_ONLY_SHARING)
  if (retentionChange && standing !== 'confirmed') return rootOnlyRefusal(standing, ROOT_ONLY_RETENTION)
  const storedQuotas = parseQuotaStore(row.quotas)
  const nextQuotas = applyQuotaPatch(storedQuotas, quotaPatch.patch)
  const quotaChanges = changedQuotaKeys(storedQuotas, nextQuotas)
  if (quotaChanges.length && !a.quotas) {
    return forbidden('Only whoever holds instance:quotas changes the quotas.', 'instance:quotas', { fields: quotaChanges })
  }
  if (quotaChanges.length) {
    const unknown = await unknownQuotaTargets(quotaPatch.patch)
    if (unknown.sets.length || unknown.users.length) {
      return NextResponse.json(
        { error: 'A quota names a permission set or an account that does not exist.', code: 'unknown_quota_target', ...unknown },
        { status: 400 },
      )
    }
  }

  // A new chisel URL must come with its auth typed again (HD-24), and re-pointing a
  // configured tunnel takes the person's password (ID-25); before anything is written.
  const reentry = settingsSecretReentry(stored, body)
  if (reentry) return secretReentryResponse(reentry)
  if (settingsEndpointChange(stored, body) || policyChanges.length || sharingChanges.length || retentionChange) {
    const refused = await requireStepUp(request, body.stepUpPassword)
    if (refused) return refused
  }

  const otherChanges = tunnelChanges.length || captureChanges.length || policyChanges.length || sharingChanges.length || quotaChanges.length
  if (!otherChanges && !retentionChange) return answer(row, a, standing)
  if (!otherChanges) {
    await changeRetention(retentionAsk!.days, auditActorOf(sessionActor(a.session)), now())
    return answer((await instanceSettingsInForce()) ?? row, a, standing)
  }

  const data: Record<string, unknown> = {}
  for (const f of tunnelChanges) {
    data[f] = f === 'tunnelsEnabled' ? Boolean(body.tunnelsEnabled) : body[f]
  }
  for (const f of captureChanges) {
    data[f] = f === 'captureProxyEnabled' ? Boolean(body.captureProxyEnabled) : capturePatch[f]
  }
  for (const f of policyChanges) data[f] = policy.patch[f]
  if (sharingChanges.length) data.sharingPolicy = sharingPolicyToStore(row.sharingPolicy, sharing.patch)
  if (quotaChanges.length) data.quotas = quotaStoreToJson(nextQuotas)
  const changedKeys = {
    ...(sharingChanges.length ? { sharingPolicy: sharingChanges } : {}),
    ...(quotaChanges.length ? { quotas: quotaChanges } : {}),
  }
  // A use of the escape hatch is recorded only when it changes something.
  if (tunnelChanges.length && a.tunnels.via === 'compat') {
    await sharedToolAccess(a.principal, 'tunnels')
  }

  const saved = await writeInstanceSettings({
    data,
    actor: auditActorOf(sessionActor(a.session)),
    tunnelVia: tunnelChanges.length ? a.tunnels.via : null,
    ...(Object.keys(changedKeys).length ? { changedKeys } : {}),
  })
  if (sharingChanges.length) invalidateSharingPolicy()

  const warnings: SaveWarning[] = []
  const captureWarning = await reconcileCaptureProxy(saved, {
    enabledChanged: captureChanges.includes('captureProxyEnabled'),
    recreateFieldChanged: CAPTURE_RECREATE_FIELDS.some((f) => captureChanges.includes(f)),
  })
  if (captureWarning) warnings.push(captureWarning)
  if (tunnelChanges.length) {
    const tunnelWarning = await pushTunnelConfig(saved)
    if (tunnelWarning) warnings.push(tunnelWarning)
  }
  if (retentionChange) {
    await changeRetention(retentionAsk!.days, auditActorOf(sessionActor(a.session)), now())
    return answer((await instanceSettingsInForce()) ?? saved, a, standing, warnings)
  }
  return answer(saved, a, standing, warnings)
})

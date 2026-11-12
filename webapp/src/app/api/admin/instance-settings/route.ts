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
import {
  changedSecurityPolicyFields, parseSecurityPolicyPatch, securityPolicyView,
} from '@/lib/instanceSecurityPolicy'
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

/**
 * The settings the instance shares because it runs one of each (step 2.4, ID-32): the
 * tunnel, and the TrafficMind capture proxy with its egress guard and SCA ignore list. They
 * live in the instance settings row with RBAC_IDENTITY_ENABLED on; off, this route answers
 * 404, as before it existed, and the user settings route keeps them.
 *
 * The person is the one signed in, read fresh for a write (T3), never the account an admin
 * acts as (F-15): an admin acting as a member saves here under their own name. An admin
 * changes everything, the capture fields only holding platform:traffic_capture (every admin
 * with RBAC_PERMISSIONS_ENABLED off; this is the only TrafficMind write with the identity
 * switch on); the tunnel also the member holding the `tunnels` legacy grant, or a
 * pre-upgrade account under REDAMON_SHARED_TOOLS_COMPAT (HD-06, T27; owner question OQ-R3,
 * default (a)), who sees and changes only the tunnel. Secrets are answered masked.
 *
 * A PUT changes only what differs from the stored values (a masked secret keeps the stored
 * one), keeps the user settings route's rules for the tunnel (a new chisel URL needs its auth
 * typed again, HD-24, and the person's password, ID-25), mirrors each changed group into a
 * user row, audits `instance.settings_changed` with the field names, then applies the change:
 * the capture proxy follows its switch and spawn-time knobs, the sandbox takes the tunnel.
 *
 * The security policy (password policy, session and link lifetimes, impersonation settings,
 * public base URL; step 2.6) is the confirmed Root's: admins read it, a change by anyone else is
 * 403 `root_only`, and Root changes it with its password. A value sent unchanged needs neither.
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
  principal: Principal | null
  capture: boolean
  tunnels: SharedToolAccess
}

async function access(fresh: boolean): Promise<Access | NextResponse> {
  const session = await getSession({ fresh })
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  // getSession read the role from the database: an admin needs no second read.
  if (session.role === 'admin') {
    return { session, principal: null, capture: true, tunnels: { allowed: true, via: 'admin' } }
  }
  const principal = await loadPrincipal(session.userId, { fresh })
  const tunnels = principal
    ? await sharedToolAccess(principal, 'tunnels', { record: false })
    : { allowed: false, via: null }
  if (!tunnels.allowed) {
    return forbidden('Only an administrator changes the instance settings.', 'instance:settings')
  }
  return { session, principal, capture: false, tunnels }
}

const ROOT_ONLY_POLICY = 'Only Root can change the instance security policy.'

/** What a browser sees: the secrets masked, the capture part and the security policy only for an admin. */
function view(row: InstanceSettings, a: Access, standing: RootStanding, warnings: SaveWarning[] = []) {
  return {
    tunnelsEnabled: row.tunnelsEnabled,
    ngrokAuthtoken: maskSecret(row.ngrokAuthtoken),
    chiselServerUrl: row.chiselServerUrl,
    chiselAuth: maskSecret(row.chiselAuth),
    ...(a.capture ? Object.fromEntries(CAPTURE_FIELDS.map((f) => [f, row[f]])) : {}),
    canManageTunnels: true,
    canManageCapture: a.capture,
    ...(a.capture
      ? { securityPolicy: securityPolicyView(row as unknown as Record<string, unknown>), canManageSecurityPolicy: standing === 'confirmed' }
      : {}),
    ...(warnings.length ? { warnings } : {}),
  }
}

export const GET = withRouteErrors('Could not read the instance settings', async (_request: NextRequest) => {
  if (!rbacFlags().identity) return notFound()
  const a = await access(false)
  if (a instanceof NextResponse) return a
  const row = await instanceSettingsInForce()
  if (!row) return notReady()
  return NextResponse.json(view(row, a, a.capture ? await rootStanding(a.session.userId) : 'none'))
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

  const row = await instanceSettingsInForce()
  if (!row) return notReady()
  const stored = row as unknown as Record<string, unknown>

  const tunnelChanges = changedTunnelFields(stored, body)
  const capturePatch = parseCapturePatch(body, sanitizeBodyRules)
  const captureChanges = changedCaptureFields(stored, capturePatch, body)
  if (captureChanges.length && !(a.capture && await sessionHolds(a.session, 'platform:traffic_capture', { fresh: true }))) {
    return forbidden('Only an administrator changes the TrafficMind settings.', 'platform:traffic_capture', {
      fields: captureChanges,
    })
  }
  const policyChanges = changedSecurityPolicyFields(stored, policy.patch)
  const standing = a.capture || policyChanges.length ? await rootStanding(a.session.userId) : 'none'
  if (policyChanges.length && standing !== 'confirmed') return rootOnlyRefusal(standing, ROOT_ONLY_POLICY)

  // A new chisel URL must come with its auth typed again (HD-24), and re-pointing a
  // configured tunnel takes the person's password (ID-25); before anything is written.
  const reentry = settingsSecretReentry(stored, body)
  if (reentry) return secretReentryResponse(reentry)
  if (settingsEndpointChange(stored, body) || policyChanges.length) {
    const refused = await requireStepUp(request, body.stepUpPassword)
    if (refused) return refused
  }

  if (!tunnelChanges.length && !captureChanges.length && !policyChanges.length) return NextResponse.json(view(row, a, standing))

  const data: Record<string, unknown> = {}
  for (const f of tunnelChanges) {
    data[f] = f === 'tunnelsEnabled' ? Boolean(body.tunnelsEnabled) : body[f]
  }
  for (const f of captureChanges) {
    data[f] = f === 'captureProxyEnabled' ? Boolean(body.captureProxyEnabled) : capturePatch[f]
  }
  for (const f of policyChanges) data[f] = policy.patch[f]
  // A use of the escape hatch is recorded only when it changes something.
  if (tunnelChanges.length && a.tunnels.via === 'compat' && a.principal) {
    await sharedToolAccess(a.principal, 'tunnels')
  }

  const saved = await writeInstanceSettings({
    data,
    actor: auditActorOf(sessionActor(a.session)),
    tunnelVia: tunnelChanges.length ? a.tunnels.via : null,
  })

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
  return NextResponse.json(view(saved, a, standing, warnings))
})

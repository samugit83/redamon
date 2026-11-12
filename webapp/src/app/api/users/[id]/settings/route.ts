import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest, isScannerRequest, requireUserAccess } from '@/lib/session'
import { orchestratorFetch } from '@/lib/orchestrator'
import { sanitizeBodyRules } from '@/lib/captureBodyRules'
import { isValidGithubHost } from '@/lib/github/ownerTarget'
import { ROTATION_TOOL_NAMES } from '@/lib/rotationTools'
import { requireEffectiveUser } from '@/lib/access'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, sessionActor, type AuditActor } from '@/lib/auditActor'
import { featureModelsMap, parseFeatureModelsPatch, type FeatureModelsPatch } from '@/lib/featureModels'
import { listPluginLlmFeatures } from '@/lib/plugins/pluginLlmFeatures'
import { maskMcpServersForApi } from '@/lib/mcp/mask'
import type { MCPServer } from '@/lib/mcp/schema'
import { internalError, safeErrorCode } from '@/lib/routeErrors'
import { normalizeGithubHost, secretReentryResponse, settingsEndpointChange, settingsSecretReentry } from '@/lib/authz/secretEndpointRebind'
import { requireStepUp } from '@/lib/authz/stepUp'
import { loadPrincipal } from '@/lib/authz/principal'
import { scannerJobRefusalForLiveProject } from '@/lib/authz/jobCredential'
import { sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { followUpWarning, type SaveWarning } from './saveWarnings'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Mask a secret string to show only the last 4 characters. */
function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

const TUNNEL_FIELDS = ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

const TUNNELS_ADMIN_ONLY =
  'The tunnel is shared by the whole instance: only an administrator, or the member who configured it, can change it.'

/**
 * The tunnel settings this PUT would change. A masked secret keeps the stored value and
 * an unchanged value is no change, so the Global Settings page's full-form save, which
 * sends all four every time, changes nothing.
 */
function changedTunnelFields(existing: Record<string, unknown> | null, body: Record<string, unknown>): string[] {
  const changed: string[] = TUNNEL_FIELDS.filter((f) => {
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

/**
 * Whether the signed-in account may change the instance tunnel (HD-06, F-05): an admin,
 * the member who kept the `tunnels` legacy grant, or a pre-upgrade account under the
 * escape hatch. `record: false` asks without counting a use of that hatch. The PUT decides on
 * a `fresh` read, so a demoted admin or a removed grant never changes the instance's tunnel.
 */
async function tunnelAccess(record: boolean, { fresh = false }: { fresh?: boolean } = {}): Promise<{ access: SharedToolAccess; actor: AuditActor }> {
  const session = await getSession({ fresh })
  if (!session) return { access: { allowed: false, via: null }, actor: auditActorOf(null) }
  const actor = auditActorOf(sessionActor(session))
  // getSession read the role from the database: an admin needs no second read.
  if (session.role === 'admin') return { access: { allowed: true, via: 'admin' }, actor }
  const principal = await loadPrincipal(session.userId, { fresh })
  if (!principal) return { access: { allowed: false, via: null }, actor: auditActorOf(null) }
  return { access: await sharedToolAccess(principal, 'tunnels', { record }), actor }
}

/**
 * Tells a browser whether to offer the tunnel controls. Only a hint: a failed read leaves
 * it out, the page then keeps the controls, and the PUT still decides.
 */
async function tunnelControlsHint(): Promise<{ canManageTunnels?: boolean }> {
  try {
    return { canManageTunnels: (await tunnelAccess(false)).access.allowed }
  } catch (err) {
    console.warn(`[rbac] tunnel access hint unavailable code=${safeErrorCode(err)}`)
    return {}
  }
}

/**
 * Every secret column, masked to its last 4 characters for any caller that is
 * not the internal/scanner principal. The GET and the PUT response share this
 * list: a column missing here is returned in cleartext. githubEnterpriseHost
 * and chiselServerUrl are configuration, not secrets, and stay readable.
 */
const SECRET_FIELDS = [
  'githubAccessToken',
  'supplyChainGithubToken',
  'githubEnterpriseToken',
  'tavilyApiKey',
  'shodanApiKey',
  'serpApiKey',
  'nvdApiKey',
  'vulnersApiKey',
  'urlscanApiKey',
  'censysApiToken',
  'censysOrgId',
  'fofaApiKey',
  'otxApiKey',
  'netlasApiKey',
  'virusTotalApiKey',
  'zoomEyeApiKey',
  'criminalIpApiKey',
  'securitytrailsApiKey',
  'viewdnsApiKey',
  'quakeApiKey',
  'hunterApiKey',
  'publicWwwApiKey',
  'hunterHowApiKey',
  'googleApiKey',
  'googleApiCx',
  'onypheApiKey',
  'driftnetApiKey',
  'wpscanApiToken',
  'pdcpApiKey',
  'ngrokAuthtoken',
  'chiselAuth',
  'trufflehogGithubToken',
  'trufflehogGitlabToken',
  'trufflehogDockerToken',
  'trufflehogHuggingfaceToken',
  'trufflehogAwsAccessKeyId',
  'trufflehogAwsSecretKey',
  'trufflehogAwsSessionToken',
  'trufflehogGcpServiceAccount',
  'trufflehogPostmanToken',
  'trufflehogJenkinsUsername',
  'trufflehogJenkinsPassword',
  'trufflehogElasticUsername',
  'trufflehogElasticPassword',
  'trufflehogElasticApiKey',
  'trufflehogElasticServiceToken',
  'trufflehogCircleciToken',
  'trufflehogTravisciToken',
  'trufflehogGitUsername',
  'trufflehogGitToken',
] as const

function maskSecrets<T extends Record<string, unknown>>(row: T): T {
  const out: Record<string, unknown> = { ...row }
  for (const f of SECRET_FIELDS) {
    if (typeof out[f] === 'string') out[f] = maskSecret(out[f] as string)
  }
  // The row also holds the MCP servers: their bearer tokens, header values and stdio
  // env values are masked as /api/users/[id]/mcp masks them (HD-23). A value that is
  // not a list of servers cannot be masked field by field, so it is not returned.
  if ('mcpServers' in out) {
    const servers = Array.isArray(out.mcpServers) ? out.mcpServers : []
    out.mcpServers = maskMcpServersForApi(
      servers.filter((s): s is MCPServer => !!s && typeof s === 'object' && !Array.isArray(s)),
    )
  }
  return out as T
}

/**
 * Merge a validated featureModels patch in one statement. A Prisma
 * read-modify-write would let two tabs saving different features drop each
 * other's key. The raw UPDATE skips Prisma's @updatedAt, hence updated_at here.
 * Only called for the effective user (the PUT's gate), so the target is also
 * the effective user the audit row records.
 */
async function applyFeatureModels(userId: string, patch: FeatureModelsPatch, actorId: string | null): Promise<void> {
  if (Object.keys(patch.set).length === 0 && patch.removed.length === 0) return
  const beforeRow = await prisma.userSettings.findUnique({ where: { userId }, select: { featureModels: true } })
  if (!beforeRow) {
    await prisma.userSettings.upsert({ where: { userId }, update: {}, create: { userId } })
  }
  await prisma.$executeRaw`
    UPDATE user_settings
    SET feature_models = (feature_models || ${JSON.stringify(patch.set)}::jsonb) - ${patch.removed}::text[],
        updated_at = now()
    WHERE user_id = ${userId}`
  const afterRow = await prisma.userSettings.findUnique({ where: { userId }, select: { featureModels: true } })
  await writeAudit({
    actorId,
    action: 'user_settings.feature_models',
    targetType: 'user',
    targetId: userId,
    before: { featureModels: featureModelsMap(beforeRow?.featureModels) },
    after: { featureModels: featureModelsMap(afterRow?.featureModels), effectiveUserId: userId },
  })
}

// GET /api/users/[id]/settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership + secret-unmask gate (STRIDE I1). Browser callers must own the
    // account (or be admin) and NEVER receive unmasked secrets; unmasking is
    // gated on a valid X-Internal-Key header (the agent/scanners), not the
    // client-supplied ?internal=true query param.
    // S3/E6: a scan reads its owner's OSINT settings here (recon needs the
    // Shodan/URLScan keys) with the scoped scanner token, on THIS route only
    // (middleware enforces the route scope), unmasked. The bare key reads nothing:
    // it needs the scan's job credential naming this account (step 1.16, HD-20),
    // for a project that still exists and is still this account's.
    const scanner = isScannerRequest(request) && !isInternalRequest(request)
    if (scanner) {
      const refused = await scannerJobRefusalForLiveProject(request, { tenant: id })
      if (refused) return refused
    }
    const denied = scanner ? null : await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const service = isInternalRequest(request) || scanner
    const internal = service && request.nextUrl.searchParams.get('internal') === 'true'

    let settings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })
    const tunnelHint = service ? {} : await tunnelControlsHint()

    // Fetch rotation configs
    const rotationRows = await prisma.apiKeyRotationConfig.findMany({
      where: { userId: id },
    })

    // Build rotationConfigs object
    const rotationConfigs: Record<string, { extraKeys?: string[]; extraKeyCount: number; rotateEveryN: number }> = {}
    for (const row of rotationRows) {
      const keys = row.extraKeys ? row.extraKeys.split('\n').filter(k => k.trim()) : []
      if (internal) {
        rotationConfigs[row.toolName] = { extraKeys: keys, extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      } else {
        rotationConfigs[row.toolName] = { extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      }
    }

    if (!settings) {
      return NextResponse.json({
        githubAccessToken: '',
        supplyChainGithubToken: '',
        githubEnterpriseHost: '',
        githubEnterpriseToken: '',
        tavilyApiKey: '',
        shodanApiKey: '',
        serpApiKey: '',
        nvdApiKey: '',
        vulnersApiKey: '',
        urlscanApiKey: '',
        censysApiToken: '',
        censysOrgId: '',
        fofaApiKey: '',
        otxApiKey: '',
        netlasApiKey: '',
        virusTotalApiKey: '',
        zoomEyeApiKey: '',
        criminalIpApiKey: '',
        securitytrailsApiKey: '',
        viewdnsApiKey: '',
        quakeApiKey: '',
        hunterApiKey: '',
        publicWwwApiKey: '',
        hunterHowApiKey: '',
        googleApiKey: '',
        googleApiCx: '',
        onypheApiKey: '',
        driftnetApiKey: '',
        wpscanApiToken: '',
        pdcpApiKey: '',
        ngrokAuthtoken: '',
        chiselServerUrl: '',
        chiselAuth: '',
        captureProxyEnabled: true,
        captureProxyPort: 8888,
        captureProxyScope: 'both',
        captureProxyStoreBodies: true,
        captureProxyMaxBodyKb: 64,
        captureProxyRetentionDays: 14,
        captureProxyRedactSecrets: true,
        captureProxyPassiveDetect: true,
        captureProxyStoreReqBodies: true,
        captureProxyStoreRespBodies: true,
        captureProxyMaxStoreMb: 5,
        captureProxyBodyRules: {},
        captureEgressBlockEmptyHost: true,
        captureEgressBlockHardGuardrail: true,
        captureEgressFailClosed: true,
        captureEgressBlockUnresolvable: true,
        captureEgressBlockPrivate: true,
        captureEgressBlockLoopback: true,
        captureEgressBlockLinkLocal: true,
        captureEgressBlockCgnat: true,
        captureEgressBlockReserved: true,
        captureEgressBlockMulticast: true,
        captureEgressBlockUnspecified: true,
        // Must match the Prisma @default and DEFAULT_CAPTURE, or a user who has
        // never saved settings sees a different list from the one both matchers
        // actually apply.
        scaIntelIgnoreSuffixes: 'oastify.com,oast.fun,mburpcollab.com,canarytokens.com,pipedream.net',
        featureModels: {},
        rotationConfigs,
        ...tunnelHint,
      })
    }

    if (!internal) {
      settings = maskSecrets(settings)
    }

    return NextResponse.json({ ...settings, rotationConfigs, ...tunnelHint })
  } catch (error) {
    return internalError(error, 'Failed to fetch user settings')
  }
}

// PUT /api/users/[id]/settings - Upsert user settings
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Settings hold tunnel credentials and OSINT keys: only the account's own
    // session (or an admin acting as a passwordless managed account), or a trusted
    // internal caller, may write them (HD-23).
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied

    const body = await request.json()

    // A feature's model decides whose provider keys that feature spends, so it
    // is the person's own choice: no service key extends to it. Refused or
    // invalid, the whole PUT stops here, before anything else in it is written.
    let featureModelsPatch: FeatureModelsPatch | null = null
    let featureModelsActor: string | null = null
    if ('featureModels' in body) {
      const refused = NextResponse.json(
        { error: 'Models by feature can only be changed by the signed-in user, for their own account' },
        { status: 403 },
      )
      if (isInternalRequest(request) || isScannerRequest(request)) return refused
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      if (eff.userId !== id) return refused
      // Plugin keys qualify only for the plugins installed, enabled and holding llm:invoke.
      const pluginFeatureIds = new Set((await listPluginLlmFeatures()).map((f) => f.featureId))
      const parsed = parseFeatureModelsPatch(body.featureModels, { pluginFeatureIds })
      if ('error' in parsed) return NextResponse.json({ error: parsed.error }, { status: 400 })
      featureModelsPatch = parsed
      featureModelsActor = (await getSession())?.userId ?? null
    }

    // TrafficMind capture-proxy config (incl. the egress guard) is a GLOBAL,
    // admin-only control: there is a single shared proxy serving every user and
    // project, so these settings propagate to all of them. The UI hides the card
    // from non-admins; enforce it server-side too (defense in depth) by stripping
    // every capture*/captureEgress* field from a write that is neither an admin
    // (UI) nor the internal key. A non-admin can still save their own non-capture
    // settings; the capture fields are simply ignored, so the shared guard cannot be
    // changed by a direct API call. The scanner key grants nothing on a write: sent
    // beside a member's cookie it made that member a capture admin (NF-02).
    const captureAdminOK = isInternalRequest(request) || (await getSession())?.role === 'admin'
    // Named in the answer, so a non-admin's TrafficMind save does not read as applied.
    const ignoredFields: string[] = []
    if (!captureAdminOK) {
      for (const k of Object.keys(body)) {
        if (k.startsWith('captureProxy') || k.startsWith('captureEgress')) {
          delete body[k]
          ignoredFields.push(k)
        }
      }
    }

    // If a masked value is sent back, preserve the existing value
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    // The tunnel is one listener for the whole instance (HD-06): changing it is refused
    // here, before any check of the request's values and before anything is written.
    const tunnelChanges = changedTunnelFields(existing as Record<string, unknown> | null, body)
    let tunnelActor = auditActorOf(null)
    let tunnelVia = 'internal'
    if (tunnelChanges.length && !isInternalRequest(request)) {
      const { access, actor } = await tunnelAccess(true, { fresh: true })
      if (!access.allowed || !access.via) {
        return NextResponse.json(
          { error: TUNNELS_ADMIN_ONLY, code: 'tunnels_admin_only', fields: tunnelChanges },
          { status: 403 },
        )
      }
      tunnelActor = actor
      tunnelVia = access.via
    }

    // The GHE host is the ALLOWLIST every supply-chain host check is made
    // against, so it is normalized and validated on the way in rather than at
    // each use: a pasted URL becomes a bare hostname, and anything that is not a
    // dotted DNS name (IP literal, localhost, host:port) is refused outright.
    if ('githubEnterpriseHost' in body) {
      const stripped = normalizeGithubHost(body.githubEnterpriseHost)
      if (stripped && !isValidGithubHost(stripped)) {
        return NextResponse.json(
          { error: 'GitHub Enterprise Host must be a hostname such as ghe.example.com (no scheme, port or path)' },
          { status: 400 },
        )
      }
      body.githubEnterpriseHost = stripped
    }

    // A new GitHub Enterprise host or chisel URL must come with its secret typed
    // again (HD-24): a kept, masked secret would follow the endpoint to the new
    // address. Before anything in this PUT is written.
    const reentry = settingsSecretReentry(existing as Record<string, unknown> | null, body)
    if (reentry) return secretReentryResponse(reentry)
    // Re-pointing a configured host or tunnel server also takes the signed-in person's
    // password (ID-25): with a secret typed again the rule above passes, yet the scans'
    // requests or the tunnel follow the endpoint. The internal key has no password.
    if (!isInternalRequest(request) && settingsEndpointChange(existing as Record<string, unknown> | null, body)) {
      const refused = await requireStepUp(request, body.stepUpPassword)
      if (refused) return refused
    }

    const data: Record<string, string> = {}
    const fields = ['githubAccessToken', 'supplyChainGithubToken', 'githubEnterpriseHost', 'githubEnterpriseToken', 'tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey', 'vulnersApiKey', 'urlscanApiKey', 'censysApiToken', 'censysOrgId', 'fofaApiKey', 'otxApiKey', 'netlasApiKey', 'virusTotalApiKey', 'zoomEyeApiKey', 'criminalIpApiKey', 'securitytrailsApiKey', 'viewdnsApiKey', 'quakeApiKey', 'hunterApiKey', 'publicWwwApiKey', 'hunterHowApiKey', 'googleApiKey', 'googleApiCx', 'onypheApiKey', 'driftnetApiKey', 'wpscanApiToken', 'pdcpApiKey', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth',
      // TruffleHog per-source credentials. Absent from this list, a key is
      // accepted by the form and silently never persisted.
      'trufflehogGithubToken', 'trufflehogGitlabToken', 'trufflehogDockerToken', 'trufflehogHuggingfaceToken', 'trufflehogAwsAccessKeyId', 'trufflehogAwsSecretKey', 'trufflehogAwsSessionToken', 'trufflehogGcpServiceAccount', 'trufflehogPostmanToken', 'trufflehogJenkinsUsername', 'trufflehogJenkinsPassword', 'trufflehogElasticUsername', 'trufflehogElasticPassword', 'trufflehogElasticApiKey', 'trufflehogElasticServiceToken', 'trufflehogCircleciToken', 'trufflehogTravisciToken', 'trufflehogGitUsername', 'trufflehogGitToken'] as const

    for (const field of fields) {
      if (field in body) {
        const val = body[field] as string
        // If the value starts with '••••', keep existing
        if (val.startsWith('••••') && existing) {
          data[field] = existing[field]
        } else {
          data[field] = val
        }
      }
    }

    // STRIDE I19: tunnelsEnabled is a Boolean, so it can't ride the string
    // `data`/`fields` loop above - handle it separately.
    const enabledProvided = 'tunnelsEnabled' in body
    const desiredEnabled = enabledProvided
      ? Boolean(body.tunnelsEnabled)
      : (existing?.tunnelsEnabled ?? false)

    // HTTP Traffic Capture (Phase 1) global config. Booleans/ints, so - like
    // tunnelsEnabled - they cannot ride the string `data` loop above.
    const captureBoolFields = ['captureProxyStoreBodies', 'captureProxyRedactSecrets', 'captureProxyPassiveDetect',
      // Granular body-storage direction toggles (Body storage sub-panel).
      'captureProxyStoreReqBodies', 'captureProxyStoreRespBodies',
      // Egress-guard toggles (Global Settings > TrafficMind). All default true (block).
      'captureEgressBlockEmptyHost', 'captureEgressBlockHardGuardrail', 'captureEgressFailClosed',
      'captureEgressBlockUnresolvable', 'captureEgressBlockPrivate', 'captureEgressBlockLoopback',
      'captureEgressBlockLinkLocal', 'captureEgressBlockCgnat', 'captureEgressBlockReserved',
      'captureEgressBlockMulticast', 'captureEgressBlockUnspecified'] as const
    const captureIntFields = ['captureProxyPort', 'captureProxyMaxBodyKb', 'captureProxyRetentionDays',
      'captureProxyMaxStoreMb'] as const
    const captureData: Record<string, boolean | number | string | Record<string, string>> = {}
    for (const f of captureBoolFields) if (f in body) captureData[f] = Boolean(body[f])
    // Sane lower bounds - a retentionDays <= 0 would make maintenance delete ALL
    // traffic; port/maxBodyKb must be positive. maxStoreMb may be 0 (= unlimited).
    const captureIntMin: Record<string, number> = {
      captureProxyPort: 1, captureProxyMaxBodyKb: 1, captureProxyRetentionDays: 1,
      captureProxyMaxStoreMb: 0,
    }
    for (const f of captureIntFields) if (f in body) {
      const n = parseInt(String(body[f]), 10)
      if (Number.isFinite(n)) captureData[f] = Math.max(captureIntMin[f] ?? 0, n)
    }
    if ('captureProxyScope' in body && ['recon', 'agent', 'both'].includes(body.captureProxyScope)) {
      captureData.captureProxyScope = body.captureProxyScope
    }
    // Body-storage policy map (family -> policy). Sanitized against allowlists so a
    // bad key/value can never reach the proxy env; unknown pairs are dropped.
    if ('captureProxyBodyRules' in body) {
      captureData.captureProxyBodyRules = sanitizeBodyRules(body.captureProxyBodyRules)
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
    const captureEnabledProvided = 'captureProxyEnabled' in body
    const captureDesiredEnabled = captureEnabledProvided
      ? Boolean(body.captureProxyEnabled)
      : (existing?.captureProxyEnabled ?? true)

    // Before the upsert below, so the row it returns carries the merged map.
    if (featureModelsPatch) await applyFeatureModels(id, featureModelsPatch, featureModelsActor)

    const settings = await prisma.userSettings.upsert({
      where: { userId: id },
      update: {
        ...data, ...captureData,
        ...(enabledProvided ? { tunnelsEnabled: desiredEnabled } : {}),
        ...(captureEnabledProvided ? { captureProxyEnabled: captureDesiredEnabled } : {}),
      },
      create: {
        userId: id, ...data, ...captureData,
        tunnelsEnabled: desiredEnabled,
        captureProxyEnabled: captureDesiredEnabled,
      },
    })

    // Reconcile the capture proxy container with the desired state (plan §8.4):
    // flipping the master toggle, or changing a runtime knob while enabled, drives
    // the orchestrator capture-proxy/{start,stop}. Best-effort: a save must not
    // fail because the orchestrator is briefly unreachable, but it says so in
    // `warnings` rather than reading as applied.
    const warnings: SaveWarning[] = []
    const captureEnabledChanged = captureEnabledProvided && captureDesiredEnabled !== (existing?.captureProxyEnabled ?? true)
    // Egress toggles + body-storage policy are applied LIVE by the proxy's config-file
    // hot-reload (DB -> /spool/.capture-config.json -> proxy, within seconds), so a
    // save that touches ONLY those must NOT restart the proxy. A container recreate is
    // required solely for knobs baked in at spawn time: the listen port (proxy command)
    // and redact-secrets (the ingest container's env). Everything else is either
    // hot-reloaded or enforced outside the container (scope routing, retention cron).
    const RECREATE_FIELDS = ['captureProxyPort', 'captureProxyRedactSecrets'] as const
    const existingRow = existing as Record<string, unknown> | null
    const changedRecreateField = RECREATE_FIELDS.some(
      (k) => k in captureData && captureData[k] !== existingRow?.[k],
    )
    if (captureEnabledChanged || (settings.captureProxyEnabled && changedRecreateField)) {
      const orchUrl = process.env.RECON_ORCHESTRATOR_URL || 'http://recon-orchestrator:8010'
      const warning = settings.captureProxyEnabled
        ? await followUpWarning('orchestrator', 'The capture proxy was not started', () =>
          orchestratorFetch(`${orchUrl}/capture-proxy/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              port: settings.captureProxyPort,
              maxBodyKb: settings.captureProxyMaxBodyKb,
              storeBodies: settings.captureProxyStoreBodies,
              redactSecrets: settings.captureProxyRedactSecrets,
              scope: settings.captureProxyScope,
              // Granular body-storage policy -> CAPTURE_* env at proxy spawn.
              storeReqBodies: settings.captureProxyStoreReqBodies,
              storeRespBodies: settings.captureProxyStoreRespBodies,
              maxStoreMb: settings.captureProxyMaxStoreMb,
              bodyRules: JSON.stringify(settings.captureProxyBodyRules ?? {}),
              // Egress-guard toggles -> CAPTURE_EGRESS_* env at proxy spawn.
              egressBlockEmptyHost: settings.captureEgressBlockEmptyHost,
              egressBlockHardGuardrail: settings.captureEgressBlockHardGuardrail,
              egressFailClosed: settings.captureEgressFailClosed,
              egressBlockUnresolvable: settings.captureEgressBlockUnresolvable,
              egressBlockPrivate: settings.captureEgressBlockPrivate,
              egressBlockLoopback: settings.captureEgressBlockLoopback,
              egressBlockLinkLocal: settings.captureEgressBlockLinkLocal,
              egressBlockCgnat: settings.captureEgressBlockCgnat,
              egressBlockReserved: settings.captureEgressBlockReserved,
              egressBlockMulticast: settings.captureEgressBlockMulticast,
              egressBlockUnspecified: settings.captureEgressBlockUnspecified,
            }),
          }))
        : await followUpWarning('orchestrator', 'The capture proxy was not stopped', () =>
          orchestratorFetch(`${orchUrl}/capture-proxy/stop`, { method: 'POST' }))
      if (warning) warnings.push(warning)
    }

    // Push tunnel config to kali-sandbox when the enabled state OR a tunnel
    // credential changed. STRIDE I19: tunnels activate ONLY when the operator has
    // explicitly enabled them; otherwise we push an empty (stop) config so a
    // credential edit alone can never bring a tunnel up. The request carries the
    // TUNNEL_AUTH_TOKEN so a rogue container can't drive :8015 (S14).
    if (tunnelChanges.length) {
      // Which fields changed and through what right, never their values.
      await writeAudit({
        ...actorFields(tunnelActor),
        action: 'settings.tunnel_changed',
        targetType: 'user',
        targetId: id,
        after: { fields: tunnelChanges, via: tunnelVia },
      })
      const config = settings.tunnelsEnabled
        ? {
            ngrokAuthtoken: settings.ngrokAuthtoken,
            chiselServerUrl: settings.chiselServerUrl,
            chiselAuth: settings.chiselAuth,
          }
        : { ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      const token = process.env.TUNNEL_AUTH_TOKEN
      if (token) headers['Authorization'] = `Bearer ${token}`
      const warning = await followUpWarning('kali_sandbox', 'The tunnel configuration was not applied', () =>
        fetch('http://kali-sandbox:8015/tunnel/configure', {
          method: 'POST',
          headers,
          body: JSON.stringify(config),
        }))
      if (warning) warnings.push(warning)
    }

    // Handle rotation configs if provided
    const rotationConfigs: Record<string, { extraKeys?: string[]; extraKeyCount: number; rotateEveryN: number }> = {}
    if (body.rotationConfigs && typeof body.rotationConfigs === 'object') {
      for (const toolName of ROTATION_TOOL_NAMES) {
        const cfg = body.rotationConfigs[toolName]
        if (!cfg) continue

        const extraKeysRaw = (cfg.extraKeys || '') as string
        const rotateEveryN = Math.max(1, parseInt(cfg.rotateEveryN, 10) || 10)

        // If extraKeys is a masked marker, preserve existing
        if (extraKeysRaw.startsWith('••••')) {
          const existing = await prisma.apiKeyRotationConfig.findUnique({
            where: { userId_toolName: { userId: id, toolName } },
          })
          if (existing) {
            const keys = existing.extraKeys.split('\n').filter(k => k.trim())
            rotationConfigs[toolName] = { extraKeyCount: keys.length, rotateEveryN: existing.rotateEveryN }
            // Update only rotateEveryN if it changed
            if (rotateEveryN !== existing.rotateEveryN) {
              await prisma.apiKeyRotationConfig.update({
                where: { userId_toolName: { userId: id, toolName } },
                data: { rotateEveryN },
              })
              rotationConfigs[toolName].rotateEveryN = rotateEveryN
            }
          }
          continue
        }

        const keys = extraKeysRaw.split('\n').filter((k: string) => k.trim())
        if (keys.length === 0) {
          // No extra keys - delete rotation config if exists
          await prisma.apiKeyRotationConfig.deleteMany({
            where: { userId: id, toolName },
          })
        } else {
          await prisma.apiKeyRotationConfig.upsert({
            where: { userId_toolName: { userId: id, toolName } },
            update: { extraKeys: keys.join('\n'), rotateEveryN },
            create: { userId: id, toolName, extraKeys: keys.join('\n'), rotateEveryN },
          })
          rotationConfigs[toolName] = { extraKeyCount: keys.length, rotateEveryN }
        }
      }
    }

    // Also fetch any rotation configs not in the request (to return full state)
    const allRotationRows = await prisma.apiKeyRotationConfig.findMany({
      where: { userId: id },
    })
    for (const row of allRotationRows) {
      if (!rotationConfigs[row.toolName]) {
        const keys = row.extraKeys.split('\n').filter(k => k.trim())
        rotationConfigs[row.toolName] = { extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      }
    }

    // Masked on the way out, like the GET: the browser never gets a secret back.
    return NextResponse.json({
      ...maskSecrets(settings), rotationConfigs,
      ...(warnings.length ? { warnings } : {}),
      ...(ignoredFields.length ? { ignoredFields } : {}),
    })
  } catch (error) {
    return internalError(error, 'Failed to update user settings')
  }
}

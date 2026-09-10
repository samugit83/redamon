import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest, isScannerRequest, requireUserAccess } from '@/lib/session'
import { orchestratorFetch } from '@/lib/orchestrator'
import { sanitizeBodyRules } from '@/lib/captureBodyRules'
import { isValidGithubHost } from '@/lib/github/ownerTarget'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Mask a secret string to show only the last 4 characters. */
function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

const TUNNEL_FIELDS = ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const
const TOOL_NAMES = ['tavily', 'shodan', 'serp', 'nvd', 'vulners', 'urlscan', 'censys', 'fofa', 'otx', 'netlas', 'virustotal', 'zoomeye', 'criminalip', 'quake', 'hunter', 'publicwww', 'hunterhow', 'onyphe', 'driftnet', 'pdcp'] as const

// GET /api/users/[id]/settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership + secret-unmask gate (STRIDE I1). Browser callers must own the
    // account (or be admin) and NEVER receive unmasked secrets; unmasking is
    // gated on a valid X-Internal-Key header (the agent/scanners), not the
    // client-supplied ?internal=true query param.
    // S3/E6: the scoped scanner token reads its OSINT settings here (recon needs
    // Shodan/URLScan keys). It is accepted like the internal principal on THIS
    // route only (middleware enforces the route scope) and gets unmasked values.
    const scanner = isScannerRequest(request)
    const denied = scanner ? null : await requireUserAccess(request, id)
    if (denied) return denied
    const internal = (isInternalRequest(request) || scanner) && request.nextUrl.searchParams.get('internal') === 'true'

    let settings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

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
        rotationConfigs,
      })
    }

    if (!internal) {
      settings = {
        ...settings,
        githubAccessToken: maskSecret(settings.githubAccessToken),
        supplyChainGithubToken: maskSecret(settings.supplyChainGithubToken),
        // The host is not a secret (the operator has to read it back to confirm
        // what is allowlisted); its token is.
        githubEnterpriseToken: maskSecret(settings.githubEnterpriseToken),
        tavilyApiKey: maskSecret(settings.tavilyApiKey),
        shodanApiKey: maskSecret(settings.shodanApiKey),
        serpApiKey: maskSecret(settings.serpApiKey),
        nvdApiKey: maskSecret(settings.nvdApiKey),
        vulnersApiKey: maskSecret(settings.vulnersApiKey),
        urlscanApiKey: maskSecret(settings.urlscanApiKey),
        censysApiToken: maskSecret(settings.censysApiToken),
        censysOrgId: maskSecret(settings.censysOrgId),
        fofaApiKey: maskSecret(settings.fofaApiKey),
        otxApiKey: maskSecret(settings.otxApiKey),
        netlasApiKey: maskSecret(settings.netlasApiKey),
        virusTotalApiKey: maskSecret(settings.virusTotalApiKey),
        zoomEyeApiKey: maskSecret(settings.zoomEyeApiKey),
        criminalIpApiKey: maskSecret(settings.criminalIpApiKey),
        securitytrailsApiKey: maskSecret(settings.securitytrailsApiKey),
        viewdnsApiKey: maskSecret(settings.viewdnsApiKey),
        quakeApiKey: maskSecret(settings.quakeApiKey),
        hunterApiKey: maskSecret(settings.hunterApiKey),
        publicWwwApiKey: maskSecret(settings.publicWwwApiKey),
        hunterHowApiKey: maskSecret(settings.hunterHowApiKey),
        googleApiKey: maskSecret(settings.googleApiKey),
        googleApiCx: maskSecret(settings.googleApiCx),
        onypheApiKey: maskSecret(settings.onypheApiKey),
        driftnetApiKey: maskSecret(settings.driftnetApiKey),
        wpscanApiToken: maskSecret(settings.wpscanApiToken),
        pdcpApiKey: maskSecret(settings.pdcpApiKey),
        ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
        chiselAuth: maskSecret(settings.chiselAuth),
        // TruffleHog per-source credentials. Unmasked they would be readable by
        // anyone who can open the settings page.
        trufflehogGithubToken: maskSecret(settings.trufflehogGithubToken),
        trufflehogGitlabToken: maskSecret(settings.trufflehogGitlabToken),
        trufflehogDockerToken: maskSecret(settings.trufflehogDockerToken),
        trufflehogHuggingfaceToken: maskSecret(settings.trufflehogHuggingfaceToken),
        trufflehogAwsAccessKeyId: maskSecret(settings.trufflehogAwsAccessKeyId),
        trufflehogAwsSecretKey: maskSecret(settings.trufflehogAwsSecretKey),
        trufflehogAwsSessionToken: maskSecret(settings.trufflehogAwsSessionToken),
        trufflehogGcpServiceAccount: maskSecret(settings.trufflehogGcpServiceAccount),
        trufflehogPostmanToken: maskSecret(settings.trufflehogPostmanToken),
        trufflehogJenkinsUsername: maskSecret(settings.trufflehogJenkinsUsername),
        trufflehogJenkinsPassword: maskSecret(settings.trufflehogJenkinsPassword),
        trufflehogElasticUsername: maskSecret(settings.trufflehogElasticUsername),
        trufflehogElasticPassword: maskSecret(settings.trufflehogElasticPassword),
        trufflehogElasticApiKey: maskSecret(settings.trufflehogElasticApiKey),
        trufflehogElasticServiceToken: maskSecret(settings.trufflehogElasticServiceToken),
        trufflehogCircleciToken: maskSecret(settings.trufflehogCircleciToken),
        trufflehogTravisciToken: maskSecret(settings.trufflehogTravisciToken),
        trufflehogGitUsername: maskSecret(settings.trufflehogGitUsername),
        trufflehogGitToken: maskSecret(settings.trufflehogGitToken),
      }
    }

    return NextResponse.json({ ...settings, rotationConfigs })
  } catch (error) {
    console.error('Failed to fetch user settings:', error)
    return NextResponse.json(
      { error: 'Failed to fetch user settings' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/settings - Upsert user settings
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Only the account owner (or admin), or a trusted internal caller, may write
    // another user's settings (which include tunnel credentials + OSINT keys).
    const denied = await requireUserAccess(request, id)
    if (denied) return denied

    const body = await request.json()

    // TrafficMind capture-proxy config (incl. the egress guard) is a GLOBAL,
    // admin-only control: there is a single shared proxy serving every user and
    // project, so these settings propagate to all of them. The UI hides the card
    // from non-admins; enforce it server-side too (defense in depth) by stripping
    // every capture*/captureEgress* field from a write that is neither an admin
    // (UI) nor a trusted service (internal/scanner) request. A non-admin can still
    // save their own non-capture settings; the capture fields are simply ignored,
    // so the shared guard cannot be changed by a direct API call.
    const isServiceReq = isInternalRequest(request) || isScannerRequest(request)
    const captureAdminOK = isServiceReq || (await getSession())?.role === 'admin'
    if (!captureAdminOK) {
      for (const k of Object.keys(body)) {
        if (k.startsWith('captureProxy') || k.startsWith('captureEgress')) delete body[k]
      }
    }

    // If a masked value is sent back, preserve the existing value
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    // The GHE host is the ALLOWLIST every supply-chain host check is made
    // against, so it is normalized and validated on the way in rather than at
    // each use: a pasted URL becomes a bare hostname, and anything that is not a
    // dotted DNS name (IP literal, localhost, host:port) is refused outright.
    if ('githubEnterpriseHost' in body) {
      const raw = String(body.githubEnterpriseHost ?? '').trim()
      const stripped = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '').toLowerCase()
      if (stripped && !isValidGithubHost(stripped)) {
        return NextResponse.json(
          { error: 'GitHub Enterprise Host must be a hostname such as ghe.example.com (no scheme, port or path)' },
          { status: 400 },
        )
      }
      body.githubEnterpriseHost = stripped
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
    // fail because the orchestrator is briefly unreachable.
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
      try {
        if (settings.captureProxyEnabled) {
          await orchestratorFetch(`${orchUrl}/capture-proxy/start`, {
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
          })
        } else {
          await orchestratorFetch(`${orchUrl}/capture-proxy/stop`, { method: 'POST' })
        }
      } catch (e) {
        console.warn('Failed to reconcile capture proxy with orchestrator:', e)
      }
    }

    // Push tunnel config to kali-sandbox when the enabled state OR a tunnel
    // credential changed. STRIDE I19: tunnels activate ONLY when the operator has
    // explicitly enabled them; otherwise we push an empty (stop) config so a
    // credential edit alone can never bring a tunnel up. The request carries the
    // TUNNEL_AUTH_TOKEN so a rogue container can't drive :8015 (S14).
    const credChanged = TUNNEL_FIELDS.some(f => f in body && data[f] !== (existing?.[f] ?? ''))
    const enabledChanged = enabledProvided && desiredEnabled !== (existing?.tunnelsEnabled ?? false)
    if (credChanged || enabledChanged) {
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
      try {
        await fetch('http://kali-sandbox:8015/tunnel/configure', {
          method: 'POST',
          headers,
          body: JSON.stringify(config),
        })
      } catch (e) {
        console.warn('Failed to push tunnel config to kali-sandbox:', e)
      }
    }

    // Handle rotation configs if provided
    const rotationConfigs: Record<string, { extraKeys?: string[]; extraKeyCount: number; rotateEveryN: number }> = {}
    if (body.rotationConfigs && typeof body.rotationConfigs === 'object') {
      for (const toolName of TOOL_NAMES) {
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

    // Return masked (chiselServerUrl is not a secret)
    return NextResponse.json({
      ...settings,
      githubAccessToken: maskSecret(settings.githubAccessToken),
      supplyChainGithubToken: maskSecret(settings.supplyChainGithubToken),
      githubEnterpriseToken: maskSecret(settings.githubEnterpriseToken),
      tavilyApiKey: maskSecret(settings.tavilyApiKey),
      shodanApiKey: maskSecret(settings.shodanApiKey),
      serpApiKey: maskSecret(settings.serpApiKey),
      nvdApiKey: maskSecret(settings.nvdApiKey),
      vulnersApiKey: maskSecret(settings.vulnersApiKey),
      urlscanApiKey: maskSecret(settings.urlscanApiKey),
      censysApiToken: maskSecret(settings.censysApiToken),
      censysOrgId: maskSecret(settings.censysOrgId),
      fofaApiKey: maskSecret(settings.fofaApiKey),
      otxApiKey: maskSecret(settings.otxApiKey),
      netlasApiKey: maskSecret(settings.netlasApiKey),
      virusTotalApiKey: maskSecret(settings.virusTotalApiKey),
      zoomEyeApiKey: maskSecret(settings.zoomEyeApiKey),
      criminalIpApiKey: maskSecret(settings.criminalIpApiKey),
      securitytrailsApiKey: maskSecret(settings.securitytrailsApiKey),
      viewdnsApiKey: maskSecret(settings.viewdnsApiKey),
      quakeApiKey: maskSecret(settings.quakeApiKey),
      hunterApiKey: maskSecret(settings.hunterApiKey),
      publicWwwApiKey: maskSecret(settings.publicWwwApiKey),
      hunterHowApiKey: maskSecret(settings.hunterHowApiKey),
      googleApiKey: maskSecret(settings.googleApiKey),
      googleApiCx: maskSecret(settings.googleApiCx),
      onypheApiKey: maskSecret(settings.onypheApiKey),
      driftnetApiKey: maskSecret(settings.driftnetApiKey),
      wpscanApiToken: maskSecret(settings.wpscanApiToken),
      pdcpApiKey: maskSecret(settings.pdcpApiKey),
      ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
      chiselAuth: maskSecret(settings.chiselAuth),
      rotationConfigs,
    })
  } catch (error) {
    console.error('Failed to update user settings:', error)
    return NextResponse.json(
      { error: 'Failed to update user settings' },
      { status: 500 }
    )
  }
}

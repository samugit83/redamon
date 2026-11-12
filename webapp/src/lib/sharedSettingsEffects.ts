/**
 * What a saved tunnel or capture change does outside the database, the same for the
 * user settings PUT (identity switch off) and PUT /api/admin/instance-settings (on):
 * the capture proxy container follows its master switch and the knobs baked in at spawn,
 * and the kali-sandbox's tunnel manager takes the tunnel config. Best effort: a save must
 * not fail because the orchestrator or the sandbox is briefly unreachable, but it says so
 * in a warning rather than reading as applied.
 */
import { orchestratorFetch } from '@/lib/orchestrator'
import { followUpWarning, type SaveWarning } from '@/app/api/users/[id]/settings/saveWarnings'

/**
 * Egress toggles + body-storage policy are applied LIVE by the proxy's config-file
 * hot-reload (DB -> /spool/.capture-config.json -> proxy, within seconds), so a
 * save that touches ONLY those must NOT restart the proxy. A container recreate is
 * required solely for knobs baked in at spawn time: the listen port (proxy command)
 * and redact-secrets (the ingest container's env). Everything else is either
 * hot-reloaded or enforced outside the container (scope routing, retention cron).
 */
export const CAPTURE_RECREATE_FIELDS = ['captureProxyPort', 'captureProxyRedactSecrets'] as const

export interface CaptureValues {
  captureProxyEnabled: boolean
  captureProxyPort: number
  captureProxyMaxBodyKb: number
  captureProxyStoreBodies: boolean
  captureProxyRedactSecrets: boolean
  captureProxyScope: string
  captureProxyStoreReqBodies: boolean
  captureProxyStoreRespBodies: boolean
  captureProxyMaxStoreMb: number
  captureProxyBodyRules: unknown
  captureEgressBlockEmptyHost: boolean
  captureEgressBlockHardGuardrail: boolean
  captureEgressFailClosed: boolean
  captureEgressBlockUnresolvable: boolean
  captureEgressBlockPrivate: boolean
  captureEgressBlockLoopback: boolean
  captureEgressBlockLinkLocal: boolean
  captureEgressBlockCgnat: boolean
  captureEgressBlockReserved: boolean
  captureEgressBlockMulticast: boolean
  captureEgressBlockUnspecified: boolean
}

/**
 * Reconcile the capture proxy container with the saved state (plan §8.4): flipping the
 * master toggle, or changing a spawn-time knob while enabled, drives the orchestrator's
 * capture-proxy/{start,stop}. Null when nothing was due or the call succeeded.
 */
export async function reconcileCaptureProxy(
  settings: CaptureValues,
  { enabledChanged, recreateFieldChanged }: { enabledChanged: boolean; recreateFieldChanged: boolean },
): Promise<SaveWarning | null> {
  if (!enabledChanged && !(settings.captureProxyEnabled && recreateFieldChanged)) return null
  const orchUrl = process.env.RECON_ORCHESTRATOR_URL || 'http://recon-orchestrator:8010'
  return settings.captureProxyEnabled
    ? followUpWarning('orchestrator', 'The capture proxy was not started', () =>
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
    : followUpWarning('orchestrator', 'The capture proxy was not stopped', () =>
      orchestratorFetch(`${orchUrl}/capture-proxy/stop`, { method: 'POST' }))
}

/**
 * Push the tunnel config to the kali-sandbox. STRIDE I19: tunnels activate ONLY when the
 * operator has explicitly enabled them; otherwise an empty (stop) config goes, so a
 * credential edit alone can never bring a tunnel up. The request carries the
 * TUNNEL_AUTH_TOKEN so a rogue container can't drive :8015 (S14).
 */
export async function pushTunnelConfig(settings: {
  tunnelsEnabled: boolean; ngrokAuthtoken: string; chiselServerUrl: string; chiselAuth: string
}): Promise<SaveWarning | null> {
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
  return followUpWarning('kali_sandbox', 'The tunnel configuration was not applied', () =>
    fetch('http://kali-sandbox:8015/tunnel/configure', {
      method: 'POST',
      headers,
      body: JSON.stringify(config),
    }))
}

'use client'

/**
 * TrafficMind global settings, as a self-contained admin modal opened from the
 * TrafficMind (/traffic) page toolbar. It owns its own fetch + save against
 * /api/users/[userId]/settings (capture fields only), so it does not share state
 * with the System settings page and cannot be clobbered by a stale save there. With
 * the identity switch on that GET answers `sharedSettingsAt: 'instance'` and the modal
 * reads and saves /api/admin/instance-settings instead, as the signed-in admin even
 * while acting as a member (step 2.4, F-15).
 *
 * There is a single shared capture proxy, so these are GLOBAL settings: a change
 * applies to every user and project and the last save wins. Needs
 * platform:traffic_capture (the /traffic page mounts it only then; the settings
 * route also strips capture writes from anyone without it).
 *
 * Save model: the whole global config is batched behind ONE Apply button. Every
 * control mutates local state only; Apply PUTs the changed fields in a single
 * request, so the orchestrator respawns the proxy AT MOST ONCE per Apply (never
 * once-per-click). The per-project routing matrix at the bottom is the exception
 * - it is per-project, does not respawn the proxy, and keeps applying immediately.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { Info } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { Toggle, Tooltip, WikiInfoButton, useToast, useAlertModal } from '@/components/ui'
import { TrafficMindProjectMatrix } from '@/components/traffic/TrafficMindProjectMatrix'
import { BODY_POLICIES, type BodyPolicy, type BodyFamily } from '@/lib/captureBodyRules'
import {
  type CaptureSettings, DEFAULT_CAPTURE, pickCapture, diffCapture, isCaptureDirty,
  effectiveBodyPolicy, adoptCanonical,
} from '@/components/traffic/captureSettingsForm'
import styles from '@/components/settings/Settings.module.css'
import { failureText, saveWarningLines } from '@/components/settings/failureText'
import { readApiError, toApiError } from '@/lib/apiError'

// ── Egress-guard toggles (mirror scanners/capture_proxy/egress.py). All default true (block).
type EgressToggleKey =
  | 'captureEgressBlockEmptyHost' | 'captureEgressBlockHardGuardrail' | 'captureEgressFailClosed'
  | 'captureEgressBlockUnresolvable' | 'captureEgressBlockPrivate' | 'captureEgressBlockLoopback'
  | 'captureEgressBlockLinkLocal' | 'captureEgressBlockCgnat' | 'captureEgressBlockReserved'
  | 'captureEgressBlockMulticast' | 'captureEgressBlockUnspecified'

const EGRESS_TOGGLES: { key: EgressToggleKey; title: string; tip: string; danger?: boolean }[] = [
  { key: 'captureEgressBlockPrivate', title: 'Private IPs (RFC1918)', danger: true,
    tip: 'Refuse 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 ULA (fc00::/7). Turn OFF to let the proxy reach internal / lab targets on a private network (e.g. Docker 172.x). WARNING: this also exposes RedAmon’s own services on those ranges; keep their IPs in the always-on blocked-IPs denylist (CAPTURE_BLOCKED_IPS) so they stay refused.' },
  { key: 'captureEgressBlockLinkLocal', title: 'Link-local IPs',
    tip: 'Refuse 169.254.0.0/16 and fe80::/10. Includes the cloud metadata endpoint 169.254.169.254, a classic SSRF credential-theft target. Leave on unless you specifically need it.' },
  { key: 'captureEgressBlockLoopback', title: 'Loopback IPs',
    tip: 'Refuse 127.0.0.0/8 and ::1 (the proxy host itself). Prevents the proxy being used to reach services bound to localhost inside its own container.' },
  { key: 'captureEgressBlockCgnat', title: 'CGNAT (100.64/10)',
    tip: 'Refuse 100.64.0.0/10, the carrier-grade NAT shared address space.' },
  { key: 'captureEgressBlockReserved', title: 'Reserved ranges',
    tip: 'Refuse IANA-reserved address ranges (e.g. 240.0.0.0/4 and other non-routable reserved blocks).' },
  { key: 'captureEgressBlockMulticast', title: 'Multicast',
    tip: 'Refuse 224.0.0.0/4 and ff00::/8 multicast destinations.' },
  { key: 'captureEgressBlockUnspecified', title: 'Unspecified (0.0.0.0 / ::)',
    tip: 'Refuse the unspecified addresses 0.0.0.0 and :: .' },
  { key: 'captureEgressBlockHardGuardrail', title: 'Sensitive hostnames',
    tip: 'Refuse .gov / .mil / .edu / .int domains and the built-in hard-guardrail denylist. Stops the proxy reaching protected / government hosts.' },
  { key: 'captureEgressBlockUnresolvable', title: 'Unresolvable hosts',
    tip: 'Refuse hosts that do not resolve in DNS or have an invalid IDNA label. Structural: with no IP there is nothing to connect to, so these are never forwarded regardless of this toggle.' },
  { key: 'captureEgressBlockEmptyHost', title: 'Empty host',
    tip: 'Refuse requests with no Host. Structural: there is no target to forward to, so these are never sent regardless of this toggle.' },
  { key: 'captureEgressFailClosed', title: 'Fail closed on guard error', danger: true,
    tip: 'If the egress guard itself throws an error, refuse the request (fail closed, safe). Turning this OFF makes it FAIL-OPEN: the request is forwarded WITHOUT vetting or IP pinning. Dangerous; leave on.' },
]

// ── Body-storage policy matrix (mirror capture_lib.DEFAULT_BODY_RULES).
const BODY_FAMILIES: { key: BodyFamily; title: string; tip: string }[] = [
  { key: 'text', title: 'HTML / CSS / text', tip: 'text/html, text/css, text/plain, xml, csv.' },
  { key: 'json', title: 'JSON / API data', tip: 'application/json, form-urlencoded, graphql - the highest-value bodies.' },
  { key: 'script', title: 'Scripts (JS)', tip: 'application/javascript, ecmascript.' },
  { key: 'image', title: 'Images', tip: 'image/* - usually render noise.' },
  { key: 'font', title: 'Fonts', tip: 'font/*, woff/woff2/ttf/otf (incl. octet-stream mislabeled by extension).' },
  { key: 'video', title: 'Video', tip: 'video/* - large render noise.' },
  { key: 'audio', title: 'Audio', tip: 'audio/*.' },
  { key: 'document', title: 'Documents', tip: 'pdf / office / rtf - often leak evidence; agent cannot read, human can.' },
  { key: 'archive', title: 'Archives', tip: 'zip / gzip / tar / 7z - source or backup disclosure.' },
  { key: 'binary', title: 'Binary / downloads', tip: 'octet-stream / wasm / serialized blobs - deserialization & file downloads.' },
]
const BODY_RULES_MINIMAL: Record<string, BodyPolicy> = {
  text: 'auto', json: 'auto', script: 'meta', image: 'meta', font: 'meta',
  video: 'meta', audio: 'meta', document: 'meta', archive: 'meta', binary: 'meta',
}
const BODY_RULES_RECOMMENDED_UI: Record<string, BodyPolicy> = {
  text: 'auto', json: 'auto', script: 'auto', image: 'meta', font: 'meta',
  video: 'meta', audio: 'meta', document: 'disk', archive: 'disk', binary: 'disk',
}
const BODY_RULES_EVERYTHING: Record<string, BodyPolicy> = {
  text: 'auto', json: 'auto', script: 'auto', image: 'disk', font: 'disk',
  video: 'disk', audio: 'disk', document: 'disk', archive: 'disk', binary: 'disk',
}
const BODY_PRESETS: { name: string; rules: Record<string, BodyPolicy> }[] = [
  { name: 'Minimal', rules: BODY_RULES_MINIMAL },
  { name: 'Recommended', rules: BODY_RULES_RECOMMENDED_UI },
  { name: 'Everything', rules: BODY_RULES_EVERYTHING },
]
const BODY_POLICY_TABLE: { policy: BodyPolicy; kept: string; bytes: string }[] = [
  { policy: 'auto', kept: 'size-based: small text → DB, else disk', bytes: 'kept' },
  { policy: 'inline', kept: 'forced into the database column', bytes: 'kept' },
  { policy: 'disk', kept: 'full bytes offloaded to /bodies/<sha>', bytes: 'kept' },
  { policy: 'meta', kept: 'only size + sha256', bytes: 'dropped' },
]
function activeBodyPreset(rules: Record<string, string> | undefined): string | null {
  const hit = BODY_PRESETS.find((p) =>
    BODY_FAMILIES.every((f) => effectiveBodyPolicy(rules, f.key) === p.rules[f.key]))
  return hit ? hit.name : null
}

const LOAD_FAILED = "Couldn't load the TrafficMind settings"
const INSTANCE_SETTINGS_URL = '/api/admin/instance-settings'

const label13 = { display: 'flex', flexDirection: 'column' as const, gap: 4, color: 'var(--text-secondary)', fontSize: 13 }
const row13 = { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, color: 'var(--text-secondary)', fontSize: 13 }

export function TrafficMindSettingsModal({ isOpen, onClose, userId }: {
  isOpen: boolean; onClose: () => void; userId: string | null
}) {
  const toast = useToast()
  const alerts = useAlertModal()
  const [s, setS] = useState<CaptureSettings>(DEFAULT_CAPTURE)
  const [saving, setSaving] = useState(false)
  // Apply stays off until a load succeeds: diffing edits against the defaults
  // would send fields the person never touched and overwrite the saved values.
  const [loaded, setLoaded] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  // Last server-synced truth. Edits diff against this; Apply reconciles to it.
  const saved = useRef<CaptureSettings>({ ...DEFAULT_CAPTURE })
  // Where the settings live: this account's row, or the instance settings.
  const endpoint = useRef<string | null>(null)

  const dirty = isCaptureDirty(saved.current, s)

  const load = useCallback(async () => {
    if (!userId) return
    try {
      const userUrl = `/api/users/${userId}/settings`
      let resp = await fetch(userUrl)
      if (!resp.ok) throw await readApiError(resp, LOAD_FAILED)
      let body = await resp.json()
      endpoint.current = userUrl
      if (body?.sharedSettingsAt === 'instance') {
        endpoint.current = INSTANCE_SETTINGS_URL
        resp = await fetch(INSTANCE_SETTINGS_URL)
        if (!resp.ok) throw await readApiError(resp, LOAD_FAILED)
        body = await resp.json()
      }
      const c = pickCapture(body)
      saved.current = c
      setS(c)
      setLoaded(true)
      setLoadError(null)
    } catch (e) {
      setLoadError(failureText(LOAD_FAILED, e))
    }
  }, [userId])

  // Re-sync from the server every time the dialog opens, discarding any stale
  // unsaved edits from a previous open.
  useEffect(() => { if (isOpen) load() }, [isOpen, load])

  // Every control funnels through here: mutate local state ONLY. Nothing hits the
  // network until Apply, so a proxy respawn happens once per Apply, not per edit.
  const setField = useCallback(<K extends keyof CaptureSettings>(field: K, value: CaptureSettings[K]) => {
    setS((prev) => ({ ...prev, [field]: value }))
  }, [])

  // Apply: PUT exactly the changed fields in one request → at most one respawn.
  // On success adopt the server's canonical values (reflecting any clamping) for
  // the submitted fields, preserving any field the user re-edited mid-save.
  const applyChanges = useCallback(async () => {
    if (!userId || !loaded || !endpoint.current) return
    const patch = diffCapture(saved.current, s)
    const keys = Object.keys(patch) as (keyof CaptureSettings)[]
    if (keys.length === 0) return
    const submitted = s
    setSaving(true)
    try {
      const resp = await fetch(endpoint.current, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch),
      })
      if (!resp.ok) throw await readApiError(resp, 'the server gave no reason')
      const body = await resp.json()
      const canonical = pickCapture(body)
      saved.current = canonical
      setS((prev) => adoptCanonical(prev, submitted, canonical, keys))
      // A non-admin's capture fields are dropped by the route with a 200.
      if (Array.isArray(body.ignoredFields) && body.ignoredFields.length > 0) {
        toast.error('Not saved - TrafficMind settings are admin-only')
        return
      }
      toast.success('TrafficMind settings applied')
      const warnings = saveWarningLines(body)
      if (warnings.length) toast.warning(warnings.join('\n'), 'Saved, but not applied')
    } catch (e) {
      toast.error(`Not saved - ${toApiError(e, 'the request failed').message}`)
    } finally {
      setSaving(false)
    }
  }, [userId, loaded, s, toast])

  // Revert every pending edit back to server truth.
  const revert = useCallback(() => setS(saved.current), [])

  // Guard the dialog close: warn before discarding unsaved edits.
  const requestClose = useCallback(async () => {
    if (isCaptureDirty(saved.current, s)) {
      const ok = await alerts.confirm(
        'You have unsaved TrafficMind changes. Discard them and close?', 'Discard changes?')
      if (!ok) return
    }
    onClose()
  }, [s, alerts, onClose])

  return (
    <Modal isOpen={isOpen} onClose={requestClose} size="large" title="TrafficMind settings">
      <div style={{ display: 'flex', flexDirection: 'column', maxHeight: '75vh' }}>
        <div style={{ overflowY: 'auto', paddingRight: 6, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div>
              <p style={{ margin: '0 0 6px', color: 'var(--text-tertiary)', fontSize: 'var(--text-sm, 13px)' }}>
                Master switch for the TrafficMind capture proxy. Enabling starts the proxy + ingest containers;
                disabling stops them - the change takes effect when you click <strong>Apply</strong>. Turn capture
                on/off per project in the matrix below, or from the toggle on the TrafficMind page.{' '}
                <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/TrafficMind" title="Open TrafficMind wiki page" />
              </p>
              <p style={{ margin: '0', color: 'var(--text-tertiary)', fontSize: 'var(--text-sm, 13px)' }}>
                There is a single
                shared capture proxy, so the master switch, container config, and egress guard apply to{' '}
                <strong>every user and every project</strong>. A change here is propagated to all of them, and the
                last save wins. Only administrators can edit them. (The one exception is the per-project routing
                matrix at the bottom, which is per-project.)
              </p>
            </div>
            <Toggle checked={s.captureProxyEnabled}
              onChange={(v) => setField('captureProxyEnabled', v)} aria-label="Enable TrafficMind capture" />
          </div>

          {s.captureProxyEnabled && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginTop: 18 }}>
              <label style={label13}>
                Listen port
                <input type="number" className="textInput" value={s.captureProxyPort}
                  onChange={(e) => setField('captureProxyPort', parseInt(e.target.value) || 8888)} />
              </label>
              <label style={label13}>
                Scope
                <select className="select" value={s.captureProxyScope} onChange={(e) => setField('captureProxyScope', e.target.value)}>
                  <option value="both">Recon + Agent</option>
                  <option value="recon">Recon only</option>
                  <option value="agent">Agent only</option>
                </select>
              </label>
              <label style={label13}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  Inline body cap (KB)
                  <Tooltip content="Text bodies at or under this size are stored INLINE in the database (fast, shown directly in the UI). Larger text and all binary go to disk. This is a DB-vs-disk routing threshold, not a size limit - nothing is dropped by it." position="top" maxWidth={460}>
                    <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                  </Tooltip>
                </span>
                <input type="number" className="textInput" value={s.captureProxyMaxBodyKb}
                  onChange={(e) => setField('captureProxyMaxBodyKb', parseInt(e.target.value) || 64)} />
              </label>
              <label style={label13}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  Max store (MB)
                  <Tooltip content="Hard ceiling: any body larger than this is NOT stored (only its size + sha256 are kept), regardless of family policy. 0 = unlimited. This is the real size cap that keeps multi-MB blobs off disk." position="top" maxWidth={460}>
                    <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                  </Tooltip>
                </span>
                <input type="number" className="textInput" value={s.captureProxyMaxStoreMb}
                  onChange={(e) => setField('captureProxyMaxStoreMb', Math.max(0, parseInt(e.target.value) || 0))} />
              </label>
              <label style={label13}>
                Retention (days)
                <input type="number" className="textInput" value={s.captureProxyRetentionDays}
                  onChange={(e) => setField('captureProxyRetentionDays', parseInt(e.target.value) || 14)} />
              </label>
              <label style={label13}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  Hosts to ignore for incident matching
                  <Tooltip
                    content="Captured requests are compared against a catalog of published supply-chain incidents. That catalog legitimately lists OAST / interaction-server providers as indicators, so without this list your own Burp Collaborator callbacks would be flagged on every engagement. Comma-separated; clearing it restores the shipped defaults."
                    position="top" maxWidth={460}>
                    <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                  </Tooltip>
                </span>
                <input type="text" className="textInput" value={s.scaIntelIgnoreSuffixes}
                  placeholder="oastify.com,oast.fun,..."
                  onChange={(e) => setField('scaIntelIgnoreSuffixes', e.target.value)} />
              </label>
              <div style={row13}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  Store bodies
                  <Tooltip content="Master switch. Off = keep only metadata (size + sha256) for every body. On = keep bodies per the direction toggles and family policy below." position="top" maxWidth={420}>
                    <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                  </Tooltip>
                </span>
                <Toggle checked={s.captureProxyStoreBodies} onChange={(v) => setField('captureProxyStoreBodies', v)} aria-label="Store bodies" />
              </div>
              <div style={row13}>
                <span>Store request bodies</span>
                <Toggle checked={s.captureProxyStoreReqBodies} onChange={(v) => setField('captureProxyStoreReqBodies', v)} aria-label="Store request bodies" />
              </div>
              <div style={row13}>
                <span>Store response bodies</span>
                <Toggle checked={s.captureProxyStoreRespBodies} onChange={(v) => setField('captureProxyStoreRespBodies', v)} aria-label="Store response bodies" />
              </div>
              <div style={row13}>
                <span>Redact secrets</span>
                <Toggle checked={s.captureProxyRedactSecrets} onChange={(v) => setField('captureProxyRedactSecrets', v)} aria-label="Redact secrets" />
              </div>
              <div style={row13}>
                <span>Passive detections</span>
                <Toggle checked={s.captureProxyPassiveDetect} onChange={(v) => setField('captureProxyPassiveDetect', v)} aria-label="Passive detections" />
              </div>
            </div>
          )}

          {s.captureProxyEnabled && (
            <div style={{ marginTop: 18, borderTop: '1px solid var(--border-default)', paddingTop: 16 }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--text-primary)', fontSize: 'var(--text-md, 14px)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                Body storage
                <Tooltip position="top" maxWidth={460} content={
                  <div style={{ fontSize: 12, lineHeight: 1.45, textAlign: 'left' }}>
                    <div style={{ marginBottom: 6 }}>Per content-type family, choose where each captured body goes:</div>
                    <table style={{ borderCollapse: 'collapse', width: '100%' }}>
                      <thead>
                        <tr>
                          <th style={{ textAlign: 'left', padding: '2px 8px 4px 0', borderBottom: '1px solid var(--border-default)' }}>Policy</th>
                          <th style={{ textAlign: 'left', padding: '2px 8px 4px 0', borderBottom: '1px solid var(--border-default)' }}>What&apos;s kept</th>
                          <th style={{ textAlign: 'left', padding: '2px 0 4px 0', borderBottom: '1px solid var(--border-default)' }}>Bytes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {BODY_POLICY_TABLE.map((r) => (
                          <tr key={r.policy}>
                            <td style={{ padding: '3px 8px 3px 0', verticalAlign: 'top' }}><code>{r.policy}</code></td>
                            <td style={{ padding: '3px 8px 3px 0', verticalAlign: 'top' }}>{r.kept}</td>
                            <td style={{ padding: '3px 0', verticalAlign: 'top', color: r.bytes === 'dropped' ? 'var(--danger, #e5484d)' : 'var(--text-secondary)' }}>{r.bytes}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <div style={{ marginTop: 6 }}>The <strong>Max store (MB)</strong> ceiling overrides disk/inline for oversized bodies.</div>
                  </div>
                }>
                  <Info size={14} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                </Tooltip>
              </h4>
              <p style={{ margin: '0 0 12px', color: 'var(--text-tertiary)', fontSize: 'var(--text-sm, 13px)' }}>
                Where each body is kept. <strong>Recommended</strong> keeps text/JSON, drops media noise (images, fonts, video), and offloads leak-worthy downloads (documents, archives, binaries) to disk.
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
                <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>Preset</span>
                <div className={styles.segmentedControl} role="tablist" aria-label="Body storage preset">
                  {BODY_PRESETS.map((preset) => {
                    const active = activeBodyPreset(s.captureProxyBodyRules) === preset.name
                    return (
                      <button key={preset.name} type="button" role="tab" aria-selected={active}
                        className={`${styles.segmentedOption} ${active ? styles.segmentedOptionActive : ''}`}
                        onClick={() => { if (activeBodyPreset(s.captureProxyBodyRules) !== preset.name) setField('captureProxyBodyRules', { ...preset.rules }) }}>
                        {preset.name}
                      </button>
                    )
                  })}
                </div>
                {activeBodyPreset(s.captureProxyBodyRules) === null && (
                  <span style={{ color: 'var(--text-tertiary)', fontSize: 12, fontStyle: 'italic' }}>Custom</span>
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12 }}>
                {BODY_FAMILIES.map((fam) => {
                  const current = effectiveBodyPolicy(s.captureProxyBodyRules, fam.key)
                  return (
                    <div key={fam.key} style={row13}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <span>{fam.title}</span>
                        <Tooltip content={fam.tip} position="top" maxWidth={420}>
                          <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                        </Tooltip>
                      </span>
                      <select className="select" style={{ maxWidth: 110 }} value={current}
                        onChange={(e) => setField('captureProxyBodyRules', { ...s.captureProxyBodyRules, [fam.key]: e.target.value })}
                        aria-label={`${fam.title} storage policy`}>
                        {BODY_POLICIES.map((p) => <option key={p} value={p}>{p}</option>)}
                      </select>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {s.captureProxyEnabled && (
            <div style={{ marginTop: 18, borderTop: '1px solid var(--border-default)', paddingTop: 16 }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--text-primary)', fontSize: 'var(--text-md, 14px)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                Egress guard
                <Tooltip content="The egress guard stops the capture proxy becoming an SSRF pivot into RedAmon's internal network. Each condition below is REFUSED (returns 403, nothing forwarded). All default to block; relaxing one lets the proxy reach that class of destination. RedAmon's own service IPs stay blocked via the separate blocked-IPs denylist regardless." position="top" maxWidth={520}>
                  <Info size={14} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                </Tooltip>
              </h4>
              <p style={{ margin: '0 0 12px', color: 'var(--text-tertiary)', fontSize: 'var(--text-sm, 13px)' }}>
                Which destinations the proxy refuses. Every toggle is <strong>block</strong> by default; turn one off only to deliberately allow that class (e.g. private IPs to reach an internal / lab target on a private Docker network).
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12 }}>
                {EGRESS_TOGGLES.map((t) => (
                  <div key={t.key} style={row13}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span>{t.title}</span>
                      {t.danger && <span title="Relaxing this has a real security cost" style={{ color: 'var(--danger, #e5484d)', fontSize: 12, lineHeight: 1 }}>⚠</span>}
                      <Tooltip content={t.tip} position="top" maxWidth={480}>
                        <Info size={13} style={{ color: 'var(--text-tertiary)', cursor: 'help' }} />
                      </Tooltip>
                    </span>
                    <Toggle checked={s[t.key]} onChange={(v) => setField(t.key, v)} aria-label={t.title} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {s.captureProxyEnabled && <TrafficMindProjectMatrix />}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 12, borderTop: '1px solid var(--border-default)', paddingTop: 14, marginTop: 6 }}>
          {loadError ? (
            <span role="alert" style={{ marginRight: 'auto', fontSize: 12, color: 'var(--status-error-text)' }}>
              {loadError}. Apply is off until they load.{' '}
              <button className="textButton" onClick={load} type="button">Retry</button>
            </span>
          ) : (
            <span style={{ marginRight: 'auto', fontSize: 12, color: dirty ? 'var(--warning, #e5a54d)' : 'var(--text-tertiary)' }}>
              {dirty ? '● Unsaved changes' : 'All changes saved'}
            </span>
          )}
          {dirty && (
            <button className="secondaryButton" onClick={revert} type="button" disabled={saving}>Revert</button>
          )}
          <button className="secondaryButton" onClick={requestClose} type="button">Close</button>
          <button className="primaryButton" onClick={applyChanges} type="button" disabled={!loaded || !dirty || saving}>
            {saving ? 'Applying…' : 'Apply'}
          </button>
        </div>
      </div>
    </Modal>
  )
}

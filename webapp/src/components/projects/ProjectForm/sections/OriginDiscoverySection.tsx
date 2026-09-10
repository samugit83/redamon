'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, Globe, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface OriginDiscoverySectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

// Scanner sources this module reuses (each needs its own key) + the two net-new
// passive-DNS keys. null = still checking (F6/G6 loading state).
interface KeyStatus {
  shodan: boolean
  censys: boolean
  fofa: boolean
  zoomEye: boolean
  otx: boolean
  virusTotal: boolean
  securitytrails: boolean
  viewdns: boolean
}

export function OriginDiscoverySection({ data, updateField, onRun }: OriginDiscoverySectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()
  const [keyStatus, setKeyStatus] = useState<KeyStatus | null>(null) // null = loading

  const checkApiKeys = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) {
          setKeyStatus({
            shodan:         !!settings.shodanApiKey,
            censys:         !!(settings.censysApiToken && settings.censysOrgId),
            fofa:           !!settings.fofaApiKey,
            zoomEye:        !!settings.zoomEyeApiKey,
            otx:            !!settings.otxApiKey,
            virusTotal:     !!settings.virusTotalApiKey,
            securitytrails: !!settings.securitytrailsApiKey,
            viewdns:        !!settings.viewdnsApiKey,
          })
        }
      })
      // Fail to "no keys" rather than flicker — the keyless group still works.
      .catch(() => setKeyStatus({
        shodan: false, censys: false, fofa: false, zoomEye: false,
        otx: false, virusTotal: false, securitytrails: false, viewdns: false,
      }))
  }, [userId])

  useEffect(() => { checkApiKeys() }, [checkApiKeys])

  // OTX is intentionally NOT here: its passive-DNS endpoint works without a key
  // (a key only raises the rate limit), so it is never "skipped for want of a key".
  const keyRequiredScanners: Array<[keyof KeyStatus, string]> = [
    ['shodan', 'Shodan'], ['censys', 'Censys'], ['fofa', 'FOFA'],
    ['zoomEye', 'ZoomEye'], ['virusTotal', 'VirusTotal'],
  ]
  const liveScanners = keyStatus ? keyRequiredScanners.filter(([k]) => keyStatus[k]).map(([, n]) => n) : []
  const missingScanners = keyStatus ? keyRequiredScanners.filter(([k]) => !keyStatus[k]).map(([, n]) => n) : []

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Globe size={16} />
          Origin Discovery
          <NodeInfoTooltip section="OriginDiscovery" />
          <WikiInfoButton target="OriginDiscovery" />
          <span className={styles.badgePassive}>Passive</span>
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.originDiscoveryEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run Origin Discovery"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.originDiscoveryEnabled}
              onChange={(checked) => updateField('originDiscoveryEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Finds the real origin server hiding behind a CDN/WAF (Cloudflare, Akamai, Fastly, ...).
            It gathers candidate origin IPs from many fingerprint sources - non-CDN subdomains,
            SPF/MX email records, certificate transparency, the favicon hash, internet-wide scanners,
            and DNS history - then confirms each by fetching it directly and comparing the page, TLS
            certificate and headers against the fronted site. A confirmed origin is added to the graph
            with a HAS_ORIGIN link and reported as a WAF-bypass exposure. Every candidate is dropped if
            it points anywhere private/internal before it is ever probed.
          </p>

          {data.originDiscoveryEnabled && (
          <>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Source Groups</h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Keyless sources</span>
                <p className={styles.toggleDescription}>
                  Non-CDN subdomain probing, SPF/MX email-record IPs, and crt.sh certificate search. No API key required - this group always runs.
                </p>
              </div>
              <Toggle
                checked={data.originDiscoveryKeyless}
                onChange={(checked) => updateField('originDiscoveryKeyless', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Internet-wide scanners</span>
                <p className={styles.toggleDescription}>
                  Favicon-hash and certificate pivots via Shodan, Censys, FOFA, ZoomEye and VirusTotal (each uses the key you store; a source with no key is skipped), plus OTX (works without a key).
                </p>
                {data.originDiscoveryScanners && (
                  <p className={styles.fieldHint} style={{ marginTop: '4px' }}>
                    {keyStatus === null ? 'Checking configured keys...' : (
                      <>Live now (key set): {liveScanners.length ? liveScanners.join(', ') : 'none'}; OTX runs without a key.
                      {missingScanners.length ? ` No key, skipped: ${missingScanners.join(', ')}. Add keys in Global Settings to widen coverage.` : ''}</>
                    )}
                  </p>
                )}
              </div>
              <Toggle
                checked={data.originDiscoveryScanners}
                onChange={(checked) => updateField('originDiscoveryScanners', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Passive DNS history</span>
                <p className={styles.toggleDescription}>
                  Historical A records from SecurityTrails and ViewDNS that often reveal the pre-CDN origin.
                </p>
                {data.originDiscoveryPassiveDns && (
                  <p className={styles.fieldHint} style={{ marginTop: '4px' }}>
                    {keyStatus === null ? 'Checking configured keys...' : (
                      <>SecurityTrails {keyStatus.securitytrails ? 'live (key set)' : 'no key, skipped'}, ViewDNS {keyStatus.viewdns ? 'live (key set)' : 'no key, skipped'}.
                      {(!keyStatus.securitytrails || !keyStatus.viewdns) ? ' Add keys in Global Settings.' : ''}</>
                    )}
                  </p>
                )}
              </div>
              <Toggle
                checked={data.originDiscoveryPassiveDns}
                onChange={(checked) => updateField('originDiscoveryPassiveDns', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Tuning</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Confidence threshold (%)</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.originDiscoveryThreshold ?? 60}
                  onChange={(e) => updateField('originDiscoveryThreshold', parseInt(e.target.value) || 60)}
                  min={0}
                  max={100}
                />
                <span className={styles.fieldHint}>Weighted HTML+cert+header score needed to confirm an origin</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Max candidates</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.originDiscoveryMaxCandidates ?? 25}
                  onChange={(e) => updateField('originDiscoveryMaxCandidates', parseInt(e.target.value) || 25)}
                  min={1}
                  max={200}
                />
                <span className={styles.fieldHint}>Cap on candidate IPs probed per fronted host</span>
              </div>
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Max search calls</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.originDiscoveryMaxSearchCalls ?? 50}
                  onChange={(e) => updateField('originDiscoveryMaxSearchCalls', parseInt(e.target.value) || 50)}
                  min={0}
                  max={500}
                />
                <span className={styles.fieldHint}>Per-scan budget of keyed scanner-search calls (protects query credits)</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Workers</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.originDiscoveryWorkers ?? 10}
                  onChange={(e) => updateField('originDiscoveryWorkers', parseInt(e.target.value) || 10)}
                  min={1}
                  max={30}
                />
                <span className={styles.fieldHint}>Parallel source + validation workers</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Timeout (s)</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.originDiscoveryTimeout ?? 10}
                  onChange={(e) => updateField('originDiscoveryTimeout', parseInt(e.target.value) || 10)}
                  min={1}
                  max={60}
                />
                <span className={styles.fieldHint}>Per-probe HTTP timeout</span>
              </div>
            </div>
          </div>
          </>
          )}
        </div>
      )}
    </div>
  )
}

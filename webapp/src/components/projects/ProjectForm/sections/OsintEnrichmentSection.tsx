'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, ShieldCheck, Info, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface OsintEnrichmentSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
  onRunUncover?: () => void
}

interface KeyStatus {
  censys: boolean
  fofa: boolean
  otx: boolean
  netlas: boolean
  virusTotal: boolean
  zoomEye: boolean
  criminalIp: boolean
}

export function OsintEnrichmentSection({ data, updateField, onRun, onRunUncover }: OsintEnrichmentSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()
  const [keyStatus, setKeyStatus] = useState<KeyStatus | null>(null)

  const checkApiKeys = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) {
          setKeyStatus({
            censys:     !!(settings.censysApiToken && settings.censysOrgId),
            fofa:       !!settings.fofaApiKey,
            otx:        !!settings.otxApiKey,
            netlas:     !!settings.netlasApiKey,
            virusTotal: !!settings.virusTotalApiKey,
            zoomEye:    !!settings.zoomEyeApiKey,
            criminalIp: !!settings.criminalIpApiKey,
          })
        }
      })
      .catch(() => setKeyStatus({ censys: false, fofa: false, otx: false, netlas: false, virusTotal: false, zoomEye: false, criminalIp: false }))
  }, [userId])

  useEffect(() => { checkApiKeys() }, [checkApiKeys])

  const noKey = (tool: keyof KeyStatus) => !keyStatus || !keyStatus[tool]

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <ShieldCheck size={16} />
          OSINT &amp; Threat Intelligence Enrichment
          <NodeInfoTooltip section="OsintEnrichment" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.osintEnrichmentEnabled && (
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
              title="Run OSINT Enrichment"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.osintEnrichmentEnabled}
              onChange={(checked) => updateField('osintEnrichmentEnabled', checked)}
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
            Passive OSINT enrichment using external threat intelligence APIs. All tools run in
            parallel after domain discovery, without sending any traffic to your targets. Each tool
            requires an API key configured in Global Settings. Enable or disable each source
            independently per project.
          </p>

          {data.osintEnrichmentEnabled && (
          <>
          {/* Censys */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Censys</span>
                <p className={styles.toggleDescription}>
                  Query Censys Search API v2 for host records: services, geolocation, ASN, and OS
                  metadata for discovered IPs. Requires API ID + Secret pair.
                </p>
                {noKey('censys') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Censys API credentials — add API Token &amp; Organization ID in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.censysEnabled}
                onChange={(checked) => updateField('censysEnabled', checked)}
                disabled={noKey('censys')}
              />
            </div>
            {data.censysEnabled && !noKey('censys') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.censysWorkers ?? 5}
                    onChange={(e) => updateField('censysWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel Censys IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* FOFA */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>FOFA</span>
                <p className={styles.toggleDescription}>
                  Query FOFA (Chinese internet intelligence) for hosts matching the target domain
                  or discovered IPs. Returns banners, ports, technologies, and TLS certificates.
                </p>
                {noKey('fofa') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No FOFA API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.fofaEnabled}
                onChange={(checked) => updateField('fofaEnabled', checked)}
                disabled={noKey('fofa')}
              />
            </div>
            {data.fofaEnabled && !noKey('fofa') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.fofaMaxResults}
                    onChange={(e) => updateField('fofaMaxResults', parseInt(e.target.value) || 1000)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum results to fetch from FOFA API (1-10 000)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.fofaWorkers ?? 5}
                    onChange={(e) => updateField('fofaWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel FOFA IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* AlienVault OTX */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>AlienVault OTX</span>
                <p className={styles.toggleDescription}>
                  Retrieve threat intelligence pulses, passive DNS records, and reputation data for
                  discovered IPs and the target domain from AlienVault OTX.
                  {noKey('otx') && <em> Works with limited public data without a key; add one in Global Settings for full pulse data.</em>}
                </p>
              </div>
              <Toggle
                checked={data.otxEnabled}
                onChange={(checked) => updateField('otxEnabled', checked)}
              />
            </div>
            {data.otxEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.otxWorkers ?? 5}
                    onChange={(e) => updateField('otxWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel OTX IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* Netlas */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Netlas</span>
                <p className={styles.toggleDescription}>
                  Query Netlas internet intelligence platform for host data, open ports, and
                  service banners on discovered IPs and the target domain.
                </p>
                {noKey('netlas') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Netlas API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.netlasEnabled}
                onChange={(checked) => updateField('netlasEnabled', checked)}
                disabled={noKey('netlas')}
              />
            </div>
            {data.netlasEnabled && !noKey('netlas') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.netlasWorkers ?? 5}
                    onChange={(e) => updateField('netlasWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel Netlas IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* VirusTotal */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>VirusTotal</span>
                <p className={styles.toggleDescription}>
                  Fetch multi-engine reputation scores, malicious detection counts, and category
                  labels for the target domain and discovered IPs. Free tier: 4 req/min. Add an API key in Global Settings to enable.
                </p>
                {noKey('virusTotal') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No VirusTotal API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.virusTotalEnabled}
                onChange={(checked) => updateField('virusTotalEnabled', checked)}
                disabled={noKey('virusTotal')}
              />
            </div>
            {data.virusTotalEnabled && !noKey('virusTotal') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.virusTotalWorkers ?? 3}
                    onChange={(e) => updateField('virusTotalWorkers', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                  <span className={styles.fieldHint}>Parallel VirusTotal IP enrichment workers (1-10)</span>
                </div>
              </div>
            )}
          </div>

          {/* ZoomEye */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>ZoomEye</span>
                <p className={styles.toggleDescription}>
                  Query ZoomEye cyberspace search engine for open ports, service banners, and
                  technologies associated with discovered IPs and the target domain.
                </p>
                {noKey('zoomEye') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No ZoomEye API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.zoomEyeEnabled}
                onChange={(checked) => updateField('zoomEyeEnabled', checked)}
                disabled={noKey('zoomEye')}
              />
            </div>
            {data.zoomEyeEnabled && !noKey('zoomEye') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zoomEyeMaxResults}
                    onChange={(e) => updateField('zoomEyeMaxResults', parseInt(e.target.value) || 1000)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum results to fetch from ZoomEye API (1-10 000)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.zoomEyeWorkers ?? 5}
                    onChange={(e) => updateField('zoomEyeWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel ZoomEye IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* Criminal IP */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Criminal IP</span>
                <p className={styles.toggleDescription}>
                  Retrieve inbound/outbound risk scores and VPN/proxy/Tor flags for discovered IPs
                  from Criminal IP threat intelligence platform.
                </p>
                {noKey('criminalIp') && (
                  <div className={styles.shodanWarning}>
                    <Info size={13} />
                    No Criminal IP API key — add it in Global Settings to enable.
                  </div>
                )}
              </div>
              <Toggle
                checked={data.criminalIpEnabled}
                onChange={(checked) => updateField('criminalIpEnabled', checked)}
                disabled={noKey('criminalIp')}
              />
            </div>
            {data.criminalIpEnabled && !noKey('criminalIp') && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.criminalIpWorkers ?? 5}
                    onChange={(e) => updateField('criminalIpWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                    max={20}
                  />
                  <span className={styles.fieldHint}>Parallel CriminalIP IP enrichment workers (1-20)</span>
                </div>
              </div>
            )}
          </div>

          {/* Uncover */}
          <div className={styles.subSection}>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Uncover (Multi-Engine Search)</span>
                <p className={styles.toggleDescription}>
                  ProjectDiscovery Uncover — searches Shodan, Censys, FOFA, ZoomEye, Netlas,
                  CriminalIP, Quake, Hunter, and more simultaneously for target expansion.
                  Discovers additional IPs, subdomains, and open ports before port scanning.
                  Configure API keys for each engine in Global Settings.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {onRunUncover && data.uncoverEnabled && (
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); onRunUncover() }}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '4px',
                      padding: '3px 8px', borderRadius: '4px',
                      border: '1px solid rgba(34, 197, 94, 0.3)',
                      backgroundColor: 'rgba(34, 197, 94, 0.1)',
                      color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
                    }}
                    title="Run Uncover"
                  >
                    <Play size={10} /> Run partial recon
                  </button>
                )}
                <Toggle
                  checked={data.uncoverEnabled}
                  onChange={(checked) => updateField('uncoverEnabled', checked)}
                />
              </div>
            </div>
            {data.uncoverEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.uncoverMaxResults}
                    onChange={(e) => updateField('uncoverMaxResults', parseInt(e.target.value) || 500)}
                    min={1}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Maximum total results across all engines (1–10 000)</span>
                </div>
              </div>
            )}
          </div>


          </>
          )}
        </div>
      )}
    </div>
  )
}

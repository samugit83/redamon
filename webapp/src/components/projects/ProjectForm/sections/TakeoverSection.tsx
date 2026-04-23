'use client'

import { useState, type CSSProperties } from 'react'
import { ChevronDown, ShieldAlert, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TakeoverSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

// Inline code-snippet style — keeps monospace snippets smaller than surrounding text
const codeStyle: CSSProperties = {
  fontSize: '0.85em',
  padding: '1px 4px',
  backgroundColor: 'rgba(255,255,255,0.06)',
  borderRadius: '3px',
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e53e3e',
  high: '#dd6b20',
  medium: '#d69e2e',
  low: '#38a169',
  info: '#3182ce',
}

// Must match recon/helpers/takeover_helpers.py::BADDNS_MODULES.
// Upstream ships 11 modules; only 10 are CLI-addressable (MTA-STS fails the
// baddns 2.1.0 validate_modules regex). Excluded here deliberately.
const BADDNS_MODULE_OPTIONS = [
  'cname',
  'ns',
  'mx',
  'txt',
  'spf',
  'dmarc',
  'wildcard',
  'nsec',
  'references',
  'zonetransfer',
] as const

const BADDNS_MODULE_DESCRIPTIONS: Record<string, string> = {
  cname: 'Dangling CNAME records + takeover potential',
  ns: 'Dangling NS records (expired nameservers, cloud DNS delegations)',
  mx: 'Dangling MX records + base-domain availability',
  txt: 'TXT record takeover opportunities',
  spf: 'SPF include/redirect chain to dangling domains',
  dmarc: 'Missing or misconfigured DMARC',
  wildcard: 'Wildcard DNS enabling broad takeovers',
  nsec: 'Subdomain enumeration via NSEC-walking (slow)',
  references: 'HTML links pointing to hijackable domains',
  zonetransfer: 'DNS zone-transfer attempts (AXFR, slow)',
}

export function TakeoverSection({ data, updateField, onRun }: TakeoverSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const toggleSeverity = (severity: string) => {
    const current = data.takeoverSeverity ?? []
    if (current.includes(severity)) {
      updateField('takeoverSeverity', current.filter(s => s !== severity))
    } else {
      updateField('takeoverSeverity', [...current, severity])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <ShieldAlert size={16} />
          Subdomain Takeover
          <NodeInfoTooltip section="SubdomainTakeover" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.subdomainTakeoverEnabled && (
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
              title="Run Subdomain Takeover"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.subdomainTakeoverEnabled}
              onChange={(checked) => updateField('subdomainTakeoverEnabled', checked)}
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
            Layered subdomain takeover detection. <strong>Subjack</strong> (DNS-first, high precision)
            validates candidates by resolving CNAME/NS/MX records; <strong>Nuclei takeover templates</strong>
            (<code style={codeStyle}>http/takeovers/</code> + <code style={codeStyle}>dns/</code>) add HTTP fingerprint coverage against alive URLs.
            Findings are deduplicated across tools, scored, and written as <code style={codeStyle}>Vulnerability</code> nodes
            with <code style={codeStyle}>source=&quot;takeover_scan&quot;</code>.
          </p>

          {data.subdomainTakeoverEnabled && (
            <>
              {/* Scanner toggles */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Scanners</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Subjack (DNS-first)</div>
                    <div className={styles.toggleDescription}>
                      Resolves CNAME chains, checks service fingerprints. Apache-2.0 Go binary baked into the recon image.
                    </div>
                  </div>
                  <Toggle
                    checked={data.subjackEnabled}
                    onChange={(checked) => updateField('subjackEnabled', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Nuclei takeover templates</div>
                    <div className={styles.toggleDescription}>
                      Runs <code style={codeStyle}>-t http/takeovers/ -t dns/</code> against alive URLs from httpx. Reuses the existing Nuclei Docker image.
                    </div>
                  </div>
                  <Toggle
                    checked={data.nucleiTakeoversEnabled}
                    onChange={(checked) => updateField('nucleiTakeoversEnabled', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>BadDNS</div>
                    <div className={styles.toggleDescription}>
                      Deep DNS analysis across CNAME / NS / MX / TXT / SPF / DMARC / wildcard / NSEC / zone-transfer modules. Runs in its own isolated Docker image (<code style={codeStyle}>redamon-baddns:latest</code>). Build once with <code style={codeStyle}>docker compose --profile tools build baddns-scanner</code>.
                    </div>
                  </div>
                  <Toggle
                    checked={data.baddnsEnabled}
                    onChange={(checked) => updateField('baddnsEnabled', checked)}
                  />
                </div>
              </div>

              {data.baddnsEnabled && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>BadDNS modules</label>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {BADDNS_MODULE_OPTIONS.map(mod => {
                      const active = (data.baddnsModules ?? []).includes(mod)
                      return (
                        <button
                          key={mod}
                          type="button"
                          onClick={() => {
                            const current = data.baddnsModules ?? []
                            updateField(
                              'baddnsModules',
                              active ? current.filter(m => m !== mod) : [...current, mod],
                            )
                          }}
                          style={{
                            padding: '4px 10px',
                            borderRadius: '4px',
                            border: `1px solid ${active ? '#6366f1' : 'rgba(255,255,255,0.15)'}`,
                            backgroundColor: active ? 'rgba(99,102,241,0.15)' : 'transparent',
                            color: active ? '#a5b4fc' : '#a0aec0',
                            cursor: 'pointer',
                            fontSize: '12px',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                          }}
                          title={BADDNS_MODULE_DESCRIPTIONS[mod]}
                        >
                          {mod}
                        </button>
                      )
                    })}
                  </div>
                  <div className={styles.fieldHint}>
                    Module list is passed to <code style={codeStyle}>baddns -m</code>. Hover each for its purpose. Heavy modules like <code style={codeStyle}>nsec</code> and <code style={codeStyle}>zonetransfer</code> can be slow on large targets.
                  </div>
                </div>
              )}

              {/* Subjack extras */}
              {data.subjackEnabled && (
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Subjack checks</label>

                  <div className={styles.toggleRow}>
                    <div>
                      <div className={styles.toggleLabel}>Force HTTPS (-ssl)</div>
                      <div className={styles.toggleDescription}>Probe targets over HTTPS -- improves accuracy.</div>
                    </div>
                    <Toggle checked={data.subjackSsl} onChange={(c) => updateField('subjackSsl', c)} />
                  </div>

                  <div className={styles.toggleRow}>
                    <div>
                      <div className={styles.toggleLabel}>Test every URL (-a)</div>
                      <div className={styles.toggleDescription}>Probe subdomains without an obvious CNAME. Slower but more thorough.</div>
                    </div>
                    <Toggle checked={data.subjackAll} onChange={(c) => updateField('subjackAll', c)} />
                  </div>

                  <div className={styles.toggleRow}>
                    <div>
                      <div className={styles.toggleLabel}>Check NS takeovers (-ns)</div>
                      <div className={styles.toggleDescription}>Detect expired nameserver delegations and dangling cloud DNS zones.</div>
                    </div>
                    <Toggle checked={data.subjackCheckNs} onChange={(c) => updateField('subjackCheckNs', c)} />
                  </div>

                  <div className={styles.toggleRow}>
                    <div>
                      <div className={styles.toggleLabel}>Check stale A records (-ar)</div>
                      <div className={styles.toggleDescription}>Flag A records pointing to dead cloud IPs (candidates for IP reuse -- human verification required).</div>
                    </div>
                    <Toggle checked={data.subjackCheckAr} onChange={(c) => updateField('subjackCheckAr', c)} />
                  </div>

                  <div className={styles.toggleRow}>
                    <div>
                      <div className={styles.toggleLabel}>Check SPF / MX takeovers (-mail)</div>
                      <div className={styles.toggleDescription}>Audit SPF includes and MX records for references to dead infrastructure.</div>
                    </div>
                    <Toggle checked={data.subjackCheckMail} onChange={(c) => updateField('subjackCheckMail', c)} />
                  </div>
                </div>
              )}

              {/* Severity + scoring */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Severity filter (Nuclei takeover templates)</label>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {SEVERITY_OPTIONS.map(sev => {
                    const active = (data.takeoverSeverity ?? []).includes(sev)
                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => toggleSeverity(sev)}
                        style={{
                          padding: '4px 10px',
                          borderRadius: '4px',
                          border: `1px solid ${active ? SEVERITY_COLORS[sev] : 'rgba(255,255,255,0.15)'}`,
                          backgroundColor: active ? SEVERITY_COLORS[sev] + '33' : 'transparent',
                          color: active ? SEVERITY_COLORS[sev] : '#a0aec0',
                          cursor: 'pointer',
                          fontSize: '12px',
                          textTransform: 'capitalize',
                        }}
                      >
                        {sev}
                      </button>
                    )
                  })}
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>
                  Confidence threshold ({data.takeoverConfidenceThreshold ?? 60})
                </label>
                <input
                  type="range"
                  min={0}
                  max={100}
                  step={5}
                  value={data.takeoverConfidenceThreshold ?? 60}
                  onChange={(e) =>
                    updateField('takeoverConfidenceThreshold', parseInt(e.target.value, 10) || 60)
                  }
                  style={{ width: '100%' }}
                />
                <div className={styles.fieldHint}>
                  Findings at or above this score become <strong>confirmed</strong>. 10 points below become <strong>likely</strong>. Lower scores go to <strong>manual_review</strong>.
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Nuclei rate limit (req/s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.takeoverRateLimit ?? 50}
                    onChange={(e) => updateField('takeoverRateLimit', parseInt(e.target.value, 10) || 50)}
                    min={1}
                    max={500}
                  />
                  <span className={styles.fieldHint}>Cap for Nuclei takeover pass. Actual peak can burst ~15% above (token-bucket).</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Subjack threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.subjackThreads ?? 10}
                    onChange={(e) => updateField('subjackThreads', parseInt(e.target.value, 10) || 10)}
                    min={1}
                    max={100}
                  />
                  <span className={styles.fieldHint}>Parallel DNS probes. Safe to raise — no target-facing HTTP load.</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <div className={styles.toggleLabel}>Auto-publish manual-review findings</div>
                  <div className={styles.toggleDescription}>
                    Publish <code style={codeStyle}>manual_review</code> findings to the main findings table (default: kept in a separate review queue with <code style={codeStyle}>severity=&quot;info&quot;</code>).
                  </div>
                </div>
                <Toggle
                  checked={data.takeoverManualReviewAutoPublish}
                  onChange={(c) => updateField('takeoverManualReviewAutoPublish', c)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

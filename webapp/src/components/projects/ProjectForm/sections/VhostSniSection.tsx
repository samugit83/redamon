'use client'

import { useState } from 'react'
import { ChevronDown, Network, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { ipHostnameOverrides } from '@/lib/ipHostnameOverrides'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '../ipHostnameModes'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface VhostSniSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function VhostSniSection({ data, updateField, onRun }: VhostSniSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  // "IP only" sends no discovered name anywhere, so recon turns graph candidates
  // off whatever is stored (D-09: the custom wordlist is the only source then).
  const graphCandidatesForced = ipHostnameOverrides(data).find(o => o.key === 'vhostSniUseGraphCandidates')

  const customWordlistLines = (data.vhostSniCustomWordlist || '')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#')).length

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Network size={16} />
          VHost & SNI Enumeration
          <NodeInfoTooltip section="VhostSni" />
          <WikiInfoButton target="VhostSni" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.vhostSniEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run VHost & SNI Enumeration"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.vhostSniEnabled}
              onChange={(checked) => updateField('vhostSniEnabled', checked)}
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
            Discovers <strong>hidden virtual hosts</strong> on every target IP by probing each candidate
            hostname with two crafted curl requests: an <strong>L7 test</strong> (overrides the HTTP <code>Host:</code> header)
            and an <strong>L4 test</strong> (forces the TLS SNI via <code>--resolve</code>).
            Anomalies versus the bare-IP baseline are emitted as <code>Vulnerability</code> nodes
            with <code>source=&quot;vhost_sni_enum&quot;</code>. L7 catches classic Apache/Nginx vhosts.
            L4 catches modern reverse proxies (k8s ingress, Traefik, Cloudflare) that route at the TLS layer.
          </p>

          {data.vhostSniEnabled && (
            <>
              {/* Layer toggles */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Test layers</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>L7 test (HTTP Host header)</div>
                    <div className={styles.toggleDescription}>
                      Sends <code>curl -H &quot;Host: candidate&quot; https://IP</code>. Catches classic vhost routing.
                    </div>
                  </div>
                  <Toggle
                    checked={data.vhostSniTestL7}
                    onChange={(checked) => updateField('vhostSniTestL7', checked)}
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>L4 test (TLS SNI)</div>
                    <div className={styles.toggleDescription}>
                      Sends <code>curl --resolve candidate:port:IP https://candidate</code>. Catches ingress/CDN routing.
                    </div>
                  </div>
                  <Toggle
                    checked={data.vhostSniTestL4}
                    onChange={(checked) => updateField('vhostSniTestL4', checked)}
                  />
                </div>
              </div>

              {/* Candidate sources */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Candidate sources</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Use graph candidates (recommended)</div>
                    <div className={styles.toggleDescription}>
                      Pulls the hostnames already known on each target IP: Subdomain, ExternalDomain, TLS SAN list and CNAME targets. Highest signal source.
                      {data.ipMode === true && !graphCandidatesForced && (
                        <> In this IP project they are the hostnames {IP_HOSTNAME_SECTION_LABEL} recorded on that IP (reverse DNS, certificates, passive DNS), tried on that IP only and never on a shared CDN edge.</>
                      )}
                      {graphCandidatesForced && (
                        <> Off: forced by {IP_HOSTNAME_SECTION_LABEL} ({ipHostnameModeLabel(data.ipHostnameMode)}).</>
                      )}
                    </div>
                  </div>
                  <Toggle
                    checked={graphCandidatesForced ? graphCandidatesForced.value : data.vhostSniUseGraphCandidates}
                    onChange={(checked) => updateField('vhostSniUseGraphCandidates', checked)}
                    disabled={!!graphCandidatesForced}
                    aria-label="Use graph candidates"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Use default wordlist</div>
                    <div className={styles.toggleDescription}>
                      ~2,300 curated admin / dev / staging / internal / modern-stack prefixes from <code>recon/wordlists/vhost-common.txt</code>. Each prefix expands as <code>{`{prefix}.{scan_root}`}</code> under an enumerated scope group; a listed group is tested only against its own hosts.
                    </div>
                  </div>
                  <Toggle
                    checked={data.vhostSniUseDefaultWordlist}
                    onChange={(checked) => updateField('vhostSniUseDefaultWordlist', checked)}
                  />
                </div>
              </div>

              {/* Custom wordlist upload */}
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>
                  Custom wordlist (one entry per line, {customWordlistLines} entries)
                </label>
                <textarea
                  className="textInput"
                  rows={8}
                  placeholder={'# One prefix or full hostname per line.\n# Lines starting with # are ignored.\nadmin\nstaging\nhidden.acme.com'}
                  value={data.vhostSniCustomWordlist || ''}
                  onChange={(e) => updateField('vhostSniCustomWordlist', e.target.value)}
                  style={{ width: '100%', minHeight: '160px', fontFamily: 'monospace', fontSize: '12px' }}
                />
                <div className={styles.fieldHint}>
                  Bare prefixes (<code>admin</code>) are expanded as <code>{`admin.{scan_root}`}</code>. Full hostnames (containing a dot) are used as-is. Combined with graph candidates and the default wordlist, then deduped.
                </div>
              </div>

              {/* Performance / behavior */}
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Per-request timeout (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.vhostSniTimeout ?? 3}
                    onChange={(e) => updateField('vhostSniTimeout', parseInt(e.target.value, 10) || 3)}
                    min={1}
                    max={30}
                  />
                  <span className={styles.fieldHint}>curl <code>--connect-timeout</code>. Total per-request budget is 3x this.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Concurrency</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.vhostSniConcurrency ?? 20}
                    onChange={(e) => updateField('vhostSniConcurrency', parseInt(e.target.value, 10) || 20)}
                    min={1}
                    max={100}
                  />
                  <span className={styles.fieldHint}>Parallel curl probes per IP/port. Higher = faster, but louder for the target.</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Baseline size tolerance (bytes)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.vhostSniBaselineSizeTolerance ?? 50}
                    onChange={(e) => updateField('vhostSniBaselineSizeTolerance', parseInt(e.target.value, 10) || 50)}
                    min={0}
                    max={10000}
                  />
                  <span className={styles.fieldHint}>Body size deltas within this many bytes are not flagged (suppresses Set-Cookie / timestamp jitter).</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max candidates per IP</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.vhostSniMaxCandidatesPerIp ?? 2000}
                    onChange={(e) => updateField('vhostSniMaxCandidatesPerIp', parseInt(e.target.value, 10) || 2000)}
                    min={10}
                    max={50000}
                  />
                  <span className={styles.fieldHint}>Hard cap to bound run time. Default wordlist + graph candidates rarely exceed 2,500 per IP.</span>
                </div>
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <div className={styles.toggleLabel}>Inject discovered hidden vhosts as BaseURLs</div>
                  <div className={styles.toggleDescription}>
                    When a hidden vhost is confirmed, create a <code>BaseURL</code> node so a follow-up partial recon (Katana, Nuclei) can scan it. Recommended.
                  </div>
                </div>
                <Toggle
                  checked={data.vhostSniInjectDiscovered}
                  onChange={(c) => updateField('vhostSniInjectDiscovered', c)}
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

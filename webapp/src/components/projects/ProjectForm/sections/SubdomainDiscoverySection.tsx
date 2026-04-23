'use client'

import { useState } from 'react'
import { ChevronDown, Play, Search } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SubdomainDiscoverySectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function SubdomainDiscoverySection({ data, updateField, onRun }: SubdomainDiscoverySectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          Subdomain Discovery
          <NodeInfoTooltip section="SubdomainDiscovery" />
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.subdomainDiscoveryEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                padding: '3px 8px',
                borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e',
                cursor: 'pointer',
                fontSize: '11px',
                fontWeight: 500,
              }}
              title="Run Subdomain Discovery"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.subdomainDiscoveryEnabled}
              onChange={(checked) => updateField('subdomainDiscoveryEnabled', checked)}
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
            Configure which subdomain discovery sources to use. Passive sources query external
            databases without touching the target. Active discovery sends DNS queries directly.
          </p>

          {data.subdomainDiscoveryEnabled && (
          <>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Sources <span className={styles.badgePassive}>Passive</span></h3>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>crt.sh</span>
                <p className={styles.toggleDescription}>
                  Certificate transparency logs — discovers subdomains from SSL/TLS certificates
                </p>
              </div>
              {data.crtshEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.crtshMaxResults}
                    onChange={(e) => updateField('crtshMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.crtshEnabled}
                onChange={(checked) => updateField('crtshEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>HackerTarget</span>
                <p className={styles.toggleDescription}>
                  DNS lookup database — discovers subdomains from HackerTarget&apos;s host search API
                </p>
              </div>
              {data.hackerTargetEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.hackerTargetMaxResults}
                    onChange={(e) => updateField('hackerTargetMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.hackerTargetEnabled}
                onChange={(checked) => updateField('hackerTargetEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Subfinder</span>
                <p className={styles.toggleDescription}>
                  Passive subdomain enumeration using 50+ online sources (certificate logs, DNS databases, web archives)
                </p>
              </div>
              {data.subfinderEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.subfinderMaxResults}
                    onChange={(e) => updateField('subfinderMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.subfinderEnabled}
                onChange={(checked) => updateField('subfinderEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Knockpy Recon</span>
                <p className={styles.toggleDescription}>
                  Passive wordlist-based subdomain enumeration using Knockpy&apos;s recon mode
                </p>
              </div>
              {data.knockpyReconEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.knockpyReconMaxResults}
                    onChange={(e) => updateField('knockpyReconMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.knockpyReconEnabled}
                onChange={(checked) => updateField('knockpyReconEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>Amass</span>
                <p className={styles.toggleDescription}>
                  OWASP Amass — subdomain enumeration using 50+ data sources (certificate logs, DNS databases, web archives, WHOIS)
                </p>
              </div>
              {data.amassEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Max</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.amassMaxResults}
                    onChange={(e) => updateField('amassMaxResults', parseInt(e.target.value) || 5000)}
                    min={1}
                    max={50000}
                  />
                </>
              )}
              <Toggle
                checked={data.amassEnabled}
                onChange={(checked) => updateField('amassEnabled', checked)}
              />
            </div>
          </div>

          {data.amassEnabled && (
            <div className={styles.subSection}>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Amass Timeout (minutes)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.amassTimeout}
                    onChange={(e) => updateField('amassTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                    max={120}
                  />
                </div>
              </div>
            </div>
          )}

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Discovery <span className={styles.badgeActive}>Active</span></h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Knockpy Bruteforce Mode</span>
                <p className={styles.toggleDescription}>
                  Use wordlist-based subdomain bruteforcing — sends thousands of DNS queries
                </p>
                <TimeEstimate estimate="+5-30 min depending on wordlist size" />
              </div>
              <Toggle
                checked={data.useBruteforceForSubdomains}
                onChange={(checked) => updateField('useBruteforceForSubdomains', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Amass Active Mode</span>
                <p className={styles.toggleDescription}>
                  Enable zone transfers and certificate name grabs — sends DNS queries directly to target
                </p>
              </div>
              <Toggle
                checked={data.amassActive}
                onChange={(checked) => updateField('amassActive', checked)}
                disabled={!data.amassEnabled}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Amass Bruteforce</span>
                <p className={styles.toggleDescription}>
                  DNS brute forcing after passive enumeration — significantly increases scan time
                </p>
                <TimeEstimate estimate="+10-60 min depending on target size" />
              </div>
              <Toggle
                checked={data.amassBrute}
                onChange={(checked) => updateField('amassBrute', checked)}
                disabled={!data.amassEnabled}
              />
            </div>

            {data.amassBrute && data.amassEnabled && (
              <div style={{ marginLeft: 'var(--space-6)', marginTop: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
                <span className={styles.toggleLabel}>Brute Force Wordlists</span>
                <p className={styles.toggleDescription}>
                  Select which wordlists to use. Amass Default is always active.
                </p>

                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)', opacity: 0.6 }}>
                  <input type="checkbox" checked disabled />
                  <span>Amass Default (~8K entries)</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>always active</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
                  <input
                    type="checkbox"
                    checked={(Array.isArray(data.amassBruteWordlists) ? data.amassBruteWordlists as string[] : ['default']).includes('jhaddix-all')}
                    onChange={(e) => {
                      const current = (Array.isArray(data.amassBruteWordlists) ? data.amassBruteWordlists as string[] : ['default']).filter((w: string) => w !== 'jhaddix-all')
                      if (e.target.checked) current.push('jhaddix-all')
                      if (!current.includes('default')) current.unshift('default')
                      updateField('amassBruteWordlists', current as any)
                    }}
                  />
                  <span>jhaddix all.txt (~2.18M entries)</span>
                </label>
                <TimeEstimate estimate="+30-60 min extra scan time" />
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Wildcard Filtering <span className={styles.badgeActive}>Active</span></h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Puredns Wildcard Filtering</span>
                <p className={styles.toggleDescription}>
                  Validates discovered subdomains against public DNS resolvers and removes wildcard
                  entries and DNS-poisoned results &mdash; runs after all discovery tools complete
                </p>
              </div>
              <Toggle
                checked={data.purednsEnabled}
                onChange={(checked) => updateField('purednsEnabled', checked)}
              />
            </div>

            {data.purednsEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads (0 = auto)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.purednsThreads}
                    onChange={(e) => updateField('purednsThreads', parseInt(e.target.value) || 0)}
                    min={0}
                    max={1000}
                  />
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit (0 = unlimited)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.purednsRateLimit}
                    onChange={(e) => updateField('purednsRateLimit', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                </div>
              </div>
            )}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>DNS Performance</h3>

            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>DNS Max Workers</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.dnsMaxWorkers ?? 50}
                  onChange={(e) => updateField('dnsMaxWorkers', parseInt(e.target.value) || 50)}
                  min={1}
                  max={200}
                />
                <span className={styles.fieldHint}>Parallel DNS resolution workers</span>
              </div>
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>DNS Record Parallelism</span>
                <p className={styles.toggleDescription}>Query all DNS record types in parallel per hostname</p>
              </div>
              <Toggle
                checked={data.dnsRecordParallelism ?? true}
                onChange={(checked) => updateField('dnsRecordParallelism', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>DNS &amp; WHOIS <span className={styles.badgePassive}>Passive</span></h3>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>WHOIS Lookup</span>
                <p className={styles.toggleDescription}>
                  Query public WHOIS databases for domain registration info (registrar, dates, contacts)
                </p>
              </div>
              {data.whoisEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Retries</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.whoisMaxRetries}
                    onChange={(e) => updateField('whoisMaxRetries', parseInt(e.target.value) || 6)}
                    min={1}
                    max={20}
                  />
                </>
              )}
              <Toggle
                checked={data.whoisEnabled}
                onChange={(checked) => updateField('whoisEnabled', checked)}
              />
            </div>

            <div className={styles.toggleRowCompact}>
              <div className={styles.toggleRowCompactInfo}>
                <span className={styles.toggleLabelLg}>DNS Resolution</span>
                <p className={styles.toggleDescription}>
                  Resolve DNS records (A, AAAA, MX, NS, TXT) and reverse DNS for discovered hosts
                </p>
              </div>
              {data.dnsEnabled && (
                <>
                  <span className={styles.toggleRowCompactLabel}>Retries</span>
                  <input
                    type="number"
                    className={`textInput ${styles.toggleRowCompactInput}`}
                    value={data.dnsMaxRetries}
                    onChange={(e) => updateField('dnsMaxRetries', parseInt(e.target.value) || 3)}
                    min={1}
                    max={10}
                  />
                </>
              )}
              <Toggle
                checked={data.dnsEnabled}
                onChange={(checked) => updateField('dnsEnabled', checked)}
              />
            </div>
          </div>
          </>
          )}
        </div>
      )}
    </div>
  )
}

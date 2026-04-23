'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, Radar, AlertTriangle, Info, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ShodanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function ShodanSection({ data, updateField, onRun }: ShodanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()
  const [hasApiKey, setHasApiKey] = useState<boolean | null>(null) // null = loading

  const checkApiKey = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) {
          setHasApiKey(!!settings.shodanApiKey)
        }
      })
      .catch(() => setHasApiKey(false))
  }, [userId])

  useEffect(() => { checkApiKey() }, [checkApiKey])

  const noKey = hasApiKey === false || hasApiKey === null

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Radar size={16} />
          Shodan Enrichment
          <NodeInfoTooltip section="Shodan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.shodanEnabled && (
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
              title="Run Shodan Enrichment"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.shodanEnabled}
              onChange={(checked) => updateField('shodanEnabled', checked)}
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
            Passive internet-wide OSINT enrichment using the Shodan API. Runs after domain discovery,
            before port scanning. Enriches IP nodes with geolocation, services, and known vulnerabilities
            without sending any traffic to your targets. If no API key is configured or the key is on the
            free tier, Host Lookup, Reverse DNS, and Passive CVEs automatically fall back to
            Shodan&apos;s InternetDB (free, no key required) which provides ports, hostnames, CPEs, CVEs, and tags.
          </p>

          {data.shodanEnabled && (
          <>
          {noKey && (
            <div className={styles.shodanWarning}>
              <Info size={14} />
              No Shodan API key configured — Host Lookup, Reverse DNS, and Passive CVEs will use InternetDB (free fallback: ports, hostnames, CPEs, CVEs, tags). For full data (geolocation, banners, services) and Domain DNS, add your key in Global Settings.
            </div>
          )}

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Workers</label>
              <input
                type="number"
                className="textInput"
                value={data.shodanWorkers ?? 5}
                onChange={(e) => updateField('shodanWorkers', parseInt(e.target.value) || 5)}
                min={1}
                max={20}
              />
              <span className={styles.fieldHint}>Parallel IP lookup workers</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Pipeline Features</h3>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Host Lookup</span>
                <p className={styles.toggleDescription}>
                  Query each discovered IP for OS, ISP, organization, geolocation, open ports, service banners, and known vulnerabilities.
                  {noKey && <em> (InternetDB fallback: ports, hostnames, CPEs, CVEs, tags — no geo/banners)</em>}
                </p>
              </div>
              <Toggle
                checked={data.shodanHostLookup}
                onChange={(checked) => updateField('shodanHostLookup', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Reverse DNS</span>
                <p className={styles.toggleDescription}>
                  Discover hostnames that resolve to known IPs. Can reveal additional subdomains not found by standard enumeration.
                  {noKey && <em> (InternetDB fallback)</em>}
                </p>
              </div>
              <Toggle
                checked={data.shodanReverseDns}
                onChange={(checked) => updateField('shodanReverseDns', checked)}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Domain DNS</span>
                <p className={styles.toggleDescription}>
                  Enumerate subdomains and DNS records via Shodan&apos;s DNS database. <em>(Requires paid Shodan plan + API key)</em>
                </p>
              </div>
              <Toggle
                checked={data.shodanDomainDns}
                onChange={(checked) => updateField('shodanDomainDns', checked)}
                disabled={noKey}
              />
            </div>

            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Passive CVEs</span>
                <p className={styles.toggleDescription}>
                  Extract known CVEs associated with discovered IPs from Shodan&apos;s vulnerability database. No active scanning required.
                  {noKey && <em> (InternetDB fallback)</em>}
                </p>
              </div>
              <Toggle
                checked={data.shodanPassiveCves}
                onChange={(checked) => updateField('shodanPassiveCves', checked)}
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

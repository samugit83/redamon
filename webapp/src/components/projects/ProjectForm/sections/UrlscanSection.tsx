'use client'

import { useState, useEffect, useCallback } from 'react'
import { ChevronDown, Globe, Info, Play, ShieldCheck } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface UrlscanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

// Each use site keeps its literal `updateField('<column>', …)` call: the
// registry parity test finds a field's form input by that call.
function UrlscanToggle({ checked, onChange, label, description, hint }: {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
  description: string
  hint?: string
}) {
  return (
    <div className={styles.toggleRow}>
      <div>
        <span className={styles.toggleLabel}>{label}</span>
        <p className={styles.toggleDescription}>{description}</p>
        {hint && <p className={styles.toggleDescription}><Info size={12} /> {hint}</p>}
      </div>
      <Toggle checked={checked} onChange={onChange} />
    </div>
  )
}

export function UrlscanSection({ data, updateField, onRun }: UrlscanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()
  const [hasApiKey, setHasApiKey] = useState<boolean | null>(null)

  const checkApiKey = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) {
          setHasApiKey(!!settings.urlscanApiKey)
        }
      })
      .catch(() => setHasApiKey(false))
  }, [userId])

  useEffect(() => { checkApiKey() }, [checkApiKey])

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Globe size={16} />
          URLScan.io Enrichment
          <NodeInfoTooltip section="Urlscan" />
          <WikiInfoButton target="Urlscan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.urlscanEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run URLScan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.urlscanEnabled}
              onChange={(checked) => updateField('urlscanEnabled', checked)}
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
            Passive OSINT enrichment using URLScan.io historical scan data. Discovers subdomains,
            IPs, ASN info, TLS certificates, server technologies and screenshots, and checks the
            visits it downloads for leaks, exposed files and problem pages - all without touching
            the target directly.
          </p>

          <div className={`${styles.callout} ${styles.calloutInfo}`}>
            <Info size={16} />
            {hasApiKey
              ? 'URLScan API key configured. How far back you can see depends on your urlscan plan.'
              : "No API key: urlscan returns only the last 30 days of visits, 100 per search, without urlscan's verdicts; RedAmon reads at most 1,000. Add a key in Global Settings to reach older visits, where the rare leaks are."}
          </div>

          {data.urlscanEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Results</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.urlscanMaxResults}
                    onChange={(e) => updateField('urlscanMaxResults', parseInt(e.target.value) || 10000)}
                    min={1}
                    max={50000}
                  />
                  <span className={styles.fieldHint}>
                    Maximum scan results to fetch from URLScan API. Values above 10,000 are capped;
                    without a key RedAmon reads at most 1,000.
                  </span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max urlscan searches per scan</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.urlscanMaxSearches ?? 60}
                    onChange={(e) => updateField('urlscanMaxSearches', parseInt(e.target.value) || 60)}
                    min={1}
                    max={1000}
                  />
                  <span className={styles.fieldHint}>
                    The most searches one scan may send to urlscan, across every domain of the
                    project. Without a key urlscan allows 30 a minute; the free plan allows 1,000 a
                    day, shared by every scan, scheduled ones included.
                  </span>
                </div>
              </div>

              <UrlscanToggle
                checked={data.urlscanRedirectSearch ?? false}
                onChange={(checked) => updateField('urlscanRedirectSearch', checked)}
                label="Outbound Redirects"
                description="One extra urlscan search per domain. Finds visits that started on the target and were redirected to another site: open redirects, leaked reset or invite links, and sign-in flows on the target's own URLs. The other sites are only recorded as External Domains, never scanned."
                hint="+1 urlscan search per domain"
              />

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Leak Detection</h3>
                <div className={`${styles.callout} ${styles.calloutInfo}`}>
                  <ShieldCheck size={16} />
                  Links containing tokens or passwords are never opened by RedAmon.
                </div>
                <UrlscanToggle
                  checked={data.urlscanLeakedLinks ?? true}
                  onChange={(checked) => updateField('urlscanLeakedLinks', checked)}
                  label="Leaked One-Time Links"
                  description="Checks the URLs urlscan already returned for the target's password-reset, account-setup, invitation, payment and login links. Each one becomes a finding. RedAmon never opens them. No extra searches."
                />
                <UrlscanToggle
                  checked={data.urlscanSecretsInUrls ?? true}
                  onChange={(checked) => updateField('urlscanSecretsInUrls', checked)}
                  label="Secrets in URLs"
                  description="Checks the URLs urlscan already returned for passwords, API keys, tokens and JWTs written in the address. Each one becomes a Secret, stored masked. No extra searches."
                />
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Exposed Files</h3>
                <UrlscanToggle
                  checked={data.urlscanSensitiveFiles ?? true}
                  onChange={(checked) => updateField('urlscanSensitiveFiles', checked)}
                  label="Sensitive Files and Pages"
                  description={'Checks the URLs urlscan already returned for files and pages that should never be public: .env, .git, database dumps, backups, private keys, logs, phpinfo, debug pages, leftover installers, web shells, file managers, debug consoles and memory dumps. Each one becomes a finding marked "seen on urlscan". Turn on Route Exposure to check whether they are still online. No extra searches.'}
                  hint={data.routeExposureEnabled
                    ? 'Route Exposure will check whether they are still online.'
                    : 'Turn on Route Exposure to check whether they are still online.'}
                />
                <UrlscanToggle
                  checked={data.urlscanDocumentLinks ?? true}
                  onChange={(checked) => updateField('urlscanDocumentLinks', checked)}
                  label="Documents Opened by Direct Link"
                  description="Marks the URLs urlscan already returned that are documents or data rather than web pages: PDF, Word, Excel, CSV, ZIP, JSON and raw text. They are listed for review on their endpoints, not reported as findings. No extra searches."
                />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

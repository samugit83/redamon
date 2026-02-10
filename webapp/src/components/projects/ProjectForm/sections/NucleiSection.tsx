'use client'

import { useState } from 'react'
import { ChevronDown, Shield } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface NucleiSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']

export function NucleiSection({ data, updateField }: NucleiSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const toggleSeverity = (severity: string) => {
    const current = data.nucleiSeverity
    if (current.includes(severity)) {
      updateField('nucleiSeverity', current.filter(s => s !== severity))
    } else {
      updateField('nucleiSeverity', [...current, severity])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Nuclei Vulnerability Scanner
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Template-based vulnerability scanning using ProjectDiscovery's Nuclei. Runs thousands of security checks against discovered endpoints to identify CVEs, misconfigurations, exposed panels, and other security issues.
          </p>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Severity Levels</h3>
            <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Filter vulnerabilities by severity. Exclude &ldquo;info&rdquo; for production scans</p>
            <TimeEstimate estimate="Critical only: ~70% faster than all severities" />
            <div className={styles.checkboxGroup}>
              {SEVERITY_OPTIONS.map(severity => (
                <label key={severity} className="checkboxLabel">
                  <input
                    type="checkbox"
                    className="checkbox"
                    checked={data.nucleiSeverity.includes(severity)}
                    onChange={() => toggleSeverity(severity)}
                  />
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </label>
              ))}
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Rate Limit</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiRateLimit}
                onChange={(e) => updateField('nucleiRateLimit', parseInt(e.target.value) || 100)}
                min={1}
              />
              <span className={styles.fieldHint}>Requests/sec. 100-150 for most targets, lower for sensitive systems</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Bulk Size</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiBulkSize}
                onChange={(e) => updateField('nucleiBulkSize', parseInt(e.target.value) || 25)}
                min={1}
              />
              <span className={styles.fieldHint}>Number of hosts to process in parallel</span>
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Concurrency</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiConcurrency}
                onChange={(e) => updateField('nucleiConcurrency', parseInt(e.target.value) || 25)}
                min={1}
              />
              <span className={styles.fieldHint}>Templates to execute in parallel</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Timeout (seconds)</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiTimeout}
                onChange={(e) => updateField('nucleiTimeout', parseInt(e.target.value) || 10)}
                min={1}
              />
              <span className={styles.fieldHint}>Request timeout per template check</span>
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Retries</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiRetries}
                onChange={(e) => updateField('nucleiRetries', parseInt(e.target.value) || 1)}
                min={0}
                max={10}
              />
              <span className={styles.fieldHint}>Retry attempts for failed requests</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Max Redirects</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiMaxRedirects}
                onChange={(e) => updateField('nucleiMaxRedirects', parseInt(e.target.value) || 10)}
                min={0}
                max={50}
              />
              <span className={styles.fieldHint}>Maximum redirect chain to follow</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Template Configuration</h3>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Template Folders</label>
              <input
                type="text"
                className="textInput"
                value={data.nucleiTemplates.join(', ')}
                onChange={(e) => updateField('nucleiTemplates', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                placeholder="cves, vulnerabilities, misconfig (empty = all)"
              />
              <span className={styles.fieldHint}>cves, vulnerabilities, misconfiguration, exposures, technologies, default-logins, takeovers</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Exclude Template Paths</label>
              <input
                type="text"
                className="textInput"
                value={data.nucleiExcludeTemplates.join(', ')}
                onChange={(e) => updateField('nucleiExcludeTemplates', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                placeholder="http/vulnerabilities/generic/"
              />
              <span className={styles.fieldHint}>Exclude specific directories or template files by path</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Custom Template Paths</label>
              <textarea
                className="textarea"
                value={data.nucleiCustomTemplates.join('\n')}
                onChange={(e) => updateField('nucleiCustomTemplates', e.target.value.split('\n').filter(Boolean))}
                placeholder="/path/to/custom-templates&#10;~/my-nuclei-templates"
                rows={2}
              />
              <span className={styles.fieldHint}>Add your own templates in addition to the official repository</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Template Tags</h3>
            <p className={styles.fieldHint} style={{ marginBottom: '0.5rem' }}>Filter templates by functionality tags</p>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Include Tags</label>
                <input
                  type="text"
                  className="textInput"
                  value={data.nucleiTags.join(', ')}
                  onChange={(e) => updateField('nucleiTags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  placeholder="cve, xss, sqli, rce (empty = all)"
                />
                <span className={styles.fieldHint}>Popular: cve, xss, sqli, rce, lfi, ssrf, xxe, ssti</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Exclude Tags</label>
                <input
                  type="text"
                  className="textInput"
                  value={data.nucleiExcludeTags.join(', ')}
                  onChange={(e) => updateField('nucleiExcludeTags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  placeholder="dos, fuzz"
                />
                <span className={styles.fieldHint}>Exclude dos, fuzz for production</span>
              </div>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Template Options</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Auto Update Templates</span>
                <p className={styles.toggleDescription}>Download latest templates before scan. Adds ~10-30 seconds</p>
              </div>
              <Toggle
                checked={data.nucleiAutoUpdateTemplates}
                onChange={(checked) => updateField('nucleiAutoUpdateTemplates', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>New Templates Only</span>
                <p className={styles.toggleDescription}>Only run templates added since last update. Good for daily scans</p>
              </div>
              <Toggle
                checked={data.nucleiNewTemplatesOnly}
                onChange={(checked) => updateField('nucleiNewTemplatesOnly', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>DAST Mode</span>
                <p className={styles.toggleDescription}>Active fuzzing for XSS, SQLi, RCE. More aggressive, may trigger alerts. Requires URLs with parameters</p>
                <TimeEstimate estimate="+50-100% scan time (active fuzzing)" />
              </div>
              <Toggle
                checked={data.nucleiDastMode}
                onChange={(checked) => updateField('nucleiDastMode', checked)}
              />
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Advanced Options</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Headless Mode</span>
                <p className={styles.toggleDescription}>Use headless browser for JavaScript-rendered pages. Requires Chrome installed</p>
                <TimeEstimate estimate="+100-200% scan time (browser rendering)" />
              </div>
              <Toggle
                checked={data.nucleiHeadless}
                onChange={(checked) => updateField('nucleiHeadless', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>System DNS Resolvers</span>
                <p className={styles.toggleDescription}>Use OS DNS instead of nuclei defaults. Better for internal networks</p>
              </div>
              <Toggle
                checked={data.nucleiSystemResolvers}
                onChange={(checked) => updateField('nucleiSystemResolvers', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Interactsh</span>
                <p className={styles.toggleDescription}>Detect blind vulns (SSRF, XXE, RCE) via out-of-band callbacks. Requires internet</p>
              </div>
              <Toggle
                checked={data.nucleiInteractsh}
                onChange={(checked) => updateField('nucleiInteractsh', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Follow Redirects</span>
                <p className={styles.toggleDescription}>Follow HTTP redirects during template execution</p>
              </div>
              <Toggle
                checked={data.nucleiFollowRedirects}
                onChange={(checked) => updateField('nucleiFollowRedirects', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Scan All IPs</span>
                <p className={styles.toggleDescription}>Scan all resolved IPs, not just hostnames. May find duplicate vulns</p>
              </div>
              <Toggle
                checked={data.nucleiScanAllIps}
                onChange={(checked) => updateField('nucleiScanAllIps', checked)}
              />
            </div>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Docker Image</label>
            <input
              type="text"
              className="textInput"
              value={data.nucleiDockerImage}
              disabled
            />
          </div>
        </div>
      )}
    </div>
  )
}

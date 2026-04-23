'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { ChevronDown, Shield, Upload, Trash2, Loader2, FileText, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface NucleiSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

interface CustomTemplate {
  id: string
  name: string
  severity: string
  file: string
  path: string
  size: number
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e53e3e',
  high: '#dd6b20',
  medium: '#d69e2e',
  low: '#38a169',
  info: '#3182ce',
  unknown: '#718096',
}

export function NucleiSection({ data, updateField, onRun }: NucleiSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [customTemplates, setCustomTemplates] = useState<CustomTemplate[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const templateFileRef = useRef<HTMLInputElement>(null)

  const fetchTemplates = useCallback(async () => {
    try {
      const res = await fetch('/api/nuclei-templates')
      if (res.ok) {
        const json = await res.json()
        setCustomTemplates(json.templates || [])
      }
    } catch {
      // Silently fail
    }
  }, [])

  useEffect(() => {
    fetchTemplates()
  }, [fetchTemplates])

  const handleTemplateUpload = async (file: File) => {
    setIsUploading(true)
    setUploadError(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch('/api/nuclei-templates', {
        method: 'POST',
        body: formData,
      })

      const result = await res.json()
      if (!res.ok) {
        setUploadError(result.error || 'Upload failed')
        return
      }

      setCustomTemplates(result.templates || [])
    } catch {
      setUploadError('Upload failed. Please try again.')
    } finally {
      setIsUploading(false)
      if (templateFileRef.current) templateFileRef.current.value = ''
    }
  }

  const handleTemplateDelete = async (templatePath: string) => {
    try {
      const res = await fetch(
        `/api/nuclei-templates?path=${encodeURIComponent(templatePath)}`,
        { method: 'DELETE' }
      )

      if (res.ok) {
        const result = await res.json()
        setCustomTemplates(result.templates || [])
      }
    } catch {
      // Silently fail
    }
  }

  const toggleSeverity = (severity: string) => {
    const current = data.nucleiSeverity ?? []
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
          <NodeInfoTooltip section="Nuclei" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.nucleiEnabled && (
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
              title="Run Nuclei"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.nucleiEnabled}
              onChange={(checked) => updateField('nucleiEnabled', checked)}
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
            Template-based vulnerability scanning using ProjectDiscovery's Nuclei. Runs thousands of security checks against discovered endpoints to identify CVEs, misconfigurations, exposed panels, and other security issues.
          </p>
          {data.nucleiEnabled && (
          <>
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
                    checked={(data.nucleiSeverity ?? []).includes(severity)}
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
                value={(data.nucleiTemplates ?? []).join(', ')}
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
                value={(data.nucleiExcludeTemplates ?? []).join(', ')}
                onChange={(e) => updateField('nucleiExcludeTemplates', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                placeholder="http/vulnerabilities/generic/"
              />
              <span className={styles.fieldHint}>Exclude specific directories or template files by path</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Custom Template Paths</label>
              <textarea
                className="textarea"
                value={(data.nucleiCustomTemplates ?? []).join('\n')}
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
                  value={(data.nucleiTags ?? []).join(', ')}
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
                  value={(data.nucleiExcludeTags ?? []).join(', ')}
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
            {/* Custom Templates Manager */}
            <div style={{ marginTop: '12px', padding: '12px', background: 'var(--bg-secondary, #1a1a2e)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div>
                  <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-primary)' }}>Custom Templates</span>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', margin: '2px 0 0' }}>
                    Upload is global. Check templates to include in this project's scans.
                  </p>
                </div>
                <div>
                  <input
                    ref={templateFileRef}
                    type="file"
                    accept=".yaml,.yml"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) handleTemplateUpload(file)
                    }}
                  />
                  <button
                    type="button"
                    className="secondaryButton"
                    style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.8rem', padding: '4px 10px' }}
                    onClick={() => templateFileRef.current?.click()}
                    disabled={isUploading}
                  >
                    {isUploading ? <Loader2 size={13} className={styles.spin} /> : <Upload size={13} />}
                    {isUploading ? 'Uploading...' : 'Upload .yaml'}
                  </button>
                </div>
              </div>

              {uploadError && (
                <p style={{ fontSize: '0.75rem', color: '#e53e3e', margin: '4px 0 8px' }}>{uploadError}</p>
              )}

              {customTemplates.length === 0 ? (
                <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontStyle: 'italic', margin: '8px 0 0' }}>
                  No custom templates uploaded yet.
                </p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
                  {customTemplates.map((t) => {
                    const selected = data.nucleiSelectedCustomTemplates ?? []
                    const isChecked = selected.includes(t.path)
                    return (
                      <div
                        key={t.path}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '6px 8px',
                          borderRadius: '6px',
                          background: isChecked ? 'var(--bg-tertiary, #16162a)' : 'transparent',
                          fontSize: '0.78rem',
                          border: isChecked ? '1px solid var(--color-primary, #e53e3e33)' : '1px solid transparent',
                        }}
                      >
                        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1, cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => {
                              const current = data.nucleiSelectedCustomTemplates ?? []
                              if (isChecked) {
                                updateField('nucleiSelectedCustomTemplates', current.filter(p => p !== t.path))
                              } else {
                                updateField('nucleiSelectedCustomTemplates', [...current, t.path])
                              }
                            }}
                            style={{ accentColor: 'var(--color-primary, #e53e3e)', cursor: 'pointer', flexShrink: 0 }}
                          />
                          <span
                            style={{
                              display: 'inline-block',
                              padding: '1px 6px',
                              borderRadius: '3px',
                              fontSize: '0.7rem',
                              fontWeight: 600,
                              color: '#fff',
                              background: SEVERITY_COLORS[t.severity] || SEVERITY_COLORS.unknown,
                              flexShrink: 0,
                            }}
                          >
                            {t.severity}
                          </span>
                          <span style={{ color: 'var(--text-primary)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {t.id}
                          </span>
                          {t.name && (
                            <span style={{ color: 'var(--text-tertiary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              — {t.name}
                            </span>
                          )}
                        </label>
                        <button
                          type="button"
                          onClick={() => handleTemplateDelete(t.path)}
                          style={{
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--text-tertiary)',
                            padding: '2px',
                            flexShrink: 0,
                            marginLeft: '8px',
                          }}
                          title={`Delete ${t.file}`}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    )
                  })}
                </div>
              )}
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
          </>
          )}
        </div>
      )}
    </div>
  )
}

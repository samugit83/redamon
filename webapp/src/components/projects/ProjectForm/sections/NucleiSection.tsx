'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { ChevronDown, Shield, Upload, Trash2, Loader2, FileText, Play, Info } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { TimeEstimate } from '../TimeEstimate'
import { FileImportButton } from '../FileImportButton'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'
import { RegistryFields } from '../RegistryFields'
import { readApiError, toApiError } from '@/lib/apiError'

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

export function NucleiSection({ data, updateField, onRun }: NucleiSectionProps) {
  const jevStatus = useHasJevProvider()
  const [isOpen, setIsOpen] = useState(true)
  const [customTemplates, setCustomTemplates] = useState<CustomTemplate[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
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

      if (!res.ok) {
        setUploadError((await readApiError(res, 'Upload failed')).message)
        return
      }

      const result = await res.json()
      setCustomTemplates(result.templates || [])
    } catch (err) {
      setUploadError(toApiError(err, 'Upload failed. Please try again.').message)
    } finally {
      setIsUploading(false)
      if (templateFileRef.current) templateFileRef.current.value = ''
    }
  }

  const handleTemplateDelete = async (templatePath: string) => {
    setDeleteError(null)
    try {
      const res = await fetch(
        `/api/nuclei-templates?path=${encodeURIComponent(templatePath)}`,
        { method: 'DELETE' }
      )

      if (!res.ok) {
        setDeleteError((await readApiError(res, `Could not delete ${templatePath}`)).message)
        return
      }
      const result = await res.json()
      setCustomTemplates(result.templates || [])
    } catch (err) {
      setDeleteError(toApiError(err, `Could not delete ${templatePath}`).message)
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
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Nuclei Vulnerability Scanner
          <NodeInfoTooltip section="Nuclei" />
          <WikiInfoButton target="Nuclei" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.nucleiEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
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
            Template-based vulnerability scanning using ProjectDiscovery&apos;s Nuclei. Runs thousands of security checks against discovered endpoints to identify CVEs, misconfigurations, exposed panels, and other security issues.
          </p>
          {data.nucleiEnabled && (
          <>
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Severity Levels</h3>
            <p className={styles.fieldHint}>Filter vulnerabilities by severity. Exclude &ldquo;info&rdquo; for production scans</p>
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
              <label className={styles.fieldLabel}>Max runtime (seconds)</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiMaxRuntime}
                onChange={(e) => updateField('nucleiMaxRuntime', parseInt(e.target.value) || 86400)}
                min={600}
                max={604800}
              />
              <span className={styles.fieldHint}>Wall-clock cap per pass; partial findings are kept (default 24h)</span>
            </div>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Max errors per host</label>
              <input
                type="number"
                className="textInput"
                value={data.nucleiMaxHostError}
                onChange={(e) => updateField('nucleiMaxHostError', parseInt(e.target.value) || 30)}
                min={1}
                max={10000}
              />
              <span className={styles.fieldHint}>Stop probing a host after this many errors (-mhe)</span>
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
              <div className={styles.fileImportWrap}>
                <input
                  type="text"
                  className="textInput"
                  value={(data.nucleiTemplates ?? []).join(', ')}
                  onChange={(e) => updateField('nucleiTemplates', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  placeholder="cves, vulnerabilities, misconfig (empty = all)"
                />
                <FileImportButton
                  fieldName="template folders"
                  onImport={(values) => updateField('nucleiTemplates', values)}
                />
              </div>
              <span className={styles.fieldHint}>cves, vulnerabilities, misconfiguration, exposures, technologies, default-logins, takeovers</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Exclude Template Paths</label>
              <div className={styles.fileImportWrap}>
                <input
                  type="text"
                  className="textInput"
                  value={(data.nucleiExcludeTemplates ?? []).join(', ')}
                  onChange={(e) => updateField('nucleiExcludeTemplates', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                  placeholder="http/vulnerabilities/generic/"
                />
                <FileImportButton
                  fieldName="template paths"
                  onImport={(values) => updateField('nucleiExcludeTemplates', values)}
                />
              </div>
              <span className={styles.fieldHint}>Exclude specific directories or template files by path</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Custom Template Paths</label>
              <div className={styles.fileImportWrap}>
                <textarea
                  className="textarea"
                  value={(data.nucleiCustomTemplates ?? []).join('\n')}
                  onChange={(e) => updateField('nucleiCustomTemplates', e.target.value.split('\n').filter(Boolean))}
                  placeholder="/path/to/custom-templates&#10;~/my-nuclei-templates"
                  rows={2}
                />
                <FileImportButton
                  variant="textarea"
                  fieldName="template paths"
                  onImport={(values) => updateField('nucleiCustomTemplates', values)}
                />
              </div>
              <span className={styles.fieldHint}>Add your own templates in addition to the official repository</span>
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Template Tags</h3>
            <p className={styles.fieldHint}>Filter templates by functionality tags</p>
            <div className={styles.toggleRow} style={{ marginBottom: 'var(--space-2)', alignItems: 'center' }}>
              <AiToggleLabel
                label="Use AI for Tag Selection"
                tooltip={
                  'AI prunes the include-tags list per scan based on detected tech stack ' +
                  '(drops irrelevant tags like wordpress on Node sites, adds tech-specific ' +
                  'tags like apache when detected). When on, the static Include Tags list ' +
                  'below is ignored. Same toggle as in the Target tab AI panel: flipping it ' +
                  'here flips it there. Candidate tag pool is built from the live ' +
                  'nuclei-templates volume (count >= 50, ~125 broad-category tags). ' +
                  (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                }
              />
              <Toggle
                checked={data.nucleiAiTags}
                disabled={!data.aiInPipeline}
                onChange={(checked) => updateField('nucleiAiTags', checked)}
              />
            </div>
            {data.nucleiAiTags && (
              <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
                <span className={styles.fieldLabel}>Engine</span>
                <JevEngineControl
                  value={data.nucleiTagsAiUseJev}
                  enabled={data.aiInPipeline && data.nucleiAiTags}
                  jevStatus={jevStatus}
                  onSelect={(useJev) => updateField('nucleiTagsAiUseJev', useJev)}
                />
              </div>
            )}
            <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-4)', marginBottom: 'var(--space-2)' }}>
              <AiToggleLabel
                label="Use AI to Filter False-Positive Block Pages"
                tooltip={
                  "Augments Nuclei's keyword-based WAF/rate-limit detection. " +
                  "When a finding's response carries a suspicious status code " +
                  '(403/406/418/429/503) but no keyword matched, the LLM classifies ' +
                  'the body as a block page or real hit. Catches rebranded WAF ' +
                  'blocks (AWS WAF JSON, custom Imperva, Fortinet) that the static ' +
                  'list misses, and avoids false positives where legitimate pages ' +
                  'contain words like "WAF" or "Access Denied". ' +
                  (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                }
              />
              <Toggle
                checked={data.nucleiAiResponseFilter}
                disabled={!data.aiInPipeline}
                onChange={(checked) => updateField('nucleiAiResponseFilter', checked)}
              />
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Include Tags</label>
                <div className={styles.fileImportWrap}>
                  <input
                    type="text"
                    className="textInput"
                    value={(data.nucleiTags ?? []).join(', ')}
                    onChange={(e) => updateField('nucleiTags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    placeholder="cve, xss, sqli, rce (empty = custom templates only)"
                    disabled={data.nucleiAiTags}
                    style={data.nucleiAiTags ? { opacity: 0.5 } : undefined}
                  />
                  <FileImportButton
                    fieldName="tags"
                    onImport={(values) => updateField('nucleiTags', values)}
                  />
                </div>
                <span className={styles.fieldHint}>
                  {data.nucleiAiTags ? (
                    <>Tags chosen by AI per scan based on tech fingerprint. The static list above is ignored.</>
                  ) : (
                    <>
                      Popular: cve, xss, sqli, rce, lfi, ssrf, xxe, ssti.
                      <strong> Empty</strong> means the built-in 8000-template pool will <em>not</em> run -
                      only the custom templates you select below. If both are empty, the detection pass is skipped.
                    </>
                  )}
                </span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Exclude Tags</label>
                <div className={styles.fileImportWrap}>
                  <input
                    type="text"
                    className="textInput"
                    value={(data.nucleiExcludeTags ?? []).join(', ')}
                    onChange={(e) => updateField('nucleiExcludeTags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    placeholder="dos, fuzz"
                  />
                  <FileImportButton
                    fieldName="tags"
                    onImport={(values) => updateField('nucleiExcludeTags', values)}
                  />
                </div>
                <span className={styles.fieldHint}>Excluding dos, fuzz is recommended for production scans</span>
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
            <div className={styles.fieldGroup}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--space-3)' }}>
                <div>
                  <span className={styles.fieldLabel}>Custom Templates</span>
                  <p className={styles.fieldHint}>
                    Upload is global. Check templates to include in this project's scans.
                  </p>
                </div>
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
                  onClick={() => templateFileRef.current?.click()}
                  disabled={isUploading}
                >
                  {isUploading ? <Loader2 size={13} className={styles.spin} /> : <Upload size={13} />}
                  {isUploading ? 'Uploading...' : 'Upload .yaml'}
                </button>
              </div>

              {uploadError && <p className={styles.inlineError}>{uploadError}</p>}
              {deleteError && <p className={styles.inlineError}>{deleteError}</p>}

              {customTemplates.length === 0 ? (
                <p className={styles.itemEmpty}>No custom templates uploaded yet.</p>
              ) : (
                <div className={styles.itemList}>
                  {customTemplates.map((t) => {
                    const selected = data.nucleiSelectedCustomTemplates ?? []
                    const isChecked = selected.includes(t.path)
                    return (
                      <div key={t.path} className={`${styles.itemRow} ${isChecked ? styles.itemRowOn : ''}`}>
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
                          />
                          <span className={`${styles.sevBadge} ${styles.sev}`} data-sev={t.severity}>
                            {t.severity}
                          </span>
                          <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {t.id}
                          </span>
                          {t.name && (
                            <span className={styles.itemMeta} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              - {t.name}
                            </span>
                          )}
                        </label>
                        <button
                          type="button"
                          className={styles.removeButton}
                          onClick={() => handleTemplateDelete(t.path)}
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
                <span className={styles.toggleLabel}>Add DAST Pass</span>
                <p className={styles.toggleDescription}>Runs a second nuclei pass with <code>-dast</code> on URLs with parameters (XSS, SQLi, SSTI, RCE fuzzing). Additive: your detection pass (CVEs, exposures, custom templates, tags) still runs first.</p>
                <TimeEstimate estimate="+50-100% scan time (extra DAST pass)" />
              </div>
              <Toggle
                checked={data.nucleiDastMode}
                onChange={(checked) => updateField('nucleiDastMode', checked)}
              />
            </div>
            {data.nucleiDastMode && (
              <div className={`${styles.callout} ${styles.calloutInfo}`}>
                <Info size={16} />
                <div>
                  <strong>How the two passes work.</strong> Pass 1 (detection) runs your full configuration: severities, tags, custom templates, the whole ~8000-template corpus minus what you exclude. Pass 2 (DAST) runs only the ~250 templates under <code>dast/</code> with <code>-dast</code> forced on, and ignores tag/template filters because those filters would empty-intersect with the DAST set and fatal with <em>&ldquo;no templates provided for scan.&rdquo;</em>
                  <br /><br />
                  <strong>DAST pass needs parameterized URLs.</strong> Built-in DAST templates fuzz query parameters (path/header/cookie/body fuzzing exists since v3.2 but is rare in stock templates). If <code>resource_enum</code> hasn&rsquo;t produced any URLs containing <code>?param=value</code>, the DAST pass is skipped automatically and only the detection pass runs. Run Katana / Hakrawler first if you want DAST coverage.
                  <br /><br />
                  <strong>Tag and template filters apply to the detection pass only.</strong> Want to bias the detection pass toward GraphQL? Set Include Tags <code>graphql,apollo,hasura</code> as usual: it filters pass 1 only, the DAST pass still runs unfiltered against your parameterized URLs.
                  <br /><br />
                  <strong>Cost:</strong> roughly 2x scan time when DAST is on (the two passes can&rsquo;t share work). Findings from both passes are merged into a single report.
                </div>
              </div>
            )}
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
          </>
          )}

          <RegistryFields
            keys={['nucleiTakeoverRunTimeout']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
    </div>
  )
}

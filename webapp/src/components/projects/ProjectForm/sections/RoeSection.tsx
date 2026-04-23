'use client'

import { useState, useRef } from 'react'
import { ChevronDown, Shield, Upload, Loader2, Plus, Minus, CheckCircle } from 'lucide-react'
import { Toggle } from '@/components/ui'
import { Modal } from '@/components/ui/Modal/Modal'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RoeSectionProps {
  data: ProjectFormData
  updateField: <K extends keyof ProjectFormData>(field: K, value: ProjectFormData[K]) => void
  updateMultipleFields: (fields: Partial<ProjectFormData>) => void
  mode: 'create' | 'edit'
  onFileSelected: (file: File | null) => void
}

const ENGAGEMENT_TYPES = [
  { value: 'external', label: 'External Penetration Test' },
  { value: 'internal', label: 'Internal Penetration Test' },
  { value: 'web_app', label: 'Web Application Test' },
  { value: 'api', label: 'API Security Test' },
  { value: 'mobile', label: 'Mobile Application Test' },
  { value: 'physical', label: 'Physical Security Test' },
  { value: 'social_engineering', label: 'Social Engineering' },
  { value: 'red_team', label: 'Red Team Engagement' },
]

const FORBIDDEN_CATEGORIES = [
  { value: 'brute_force', label: 'Credential Testing' },
  { value: 'dos', label: 'Availability Testing' },
  { value: 'social_engineering', label: 'Social Engineering' },
  { value: 'physical', label: 'Physical Access' },
]

const DATA_HANDLING_OPTIONS = [
  { value: 'no_access', label: 'No access to sensitive data' },
  { value: 'prove_access_only', label: 'Prove access only (no collection)' },
  { value: 'limited_collection', label: 'Limited collection' },
  { value: 'full_access', label: 'Full access' },
]

const COMPLIANCE_OPTIONS = ['PCI-DSS', 'HIPAA', 'SOC2', 'GDPR', 'ISO27001']

const WEEKDAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']

export function RoeSection({ data, updateField, updateMultipleFields, mode, onFileSelected }: RoeSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [isParsing, setIsParsing] = useState(false)
  const [parseError, setParseError] = useState<string | null>(null)
  const [showParseSuccess, setShowParseSuccess] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const readOnly = mode === 'edit'

  const handleFileUpload = async (file: File) => {
    setIsParsing(true)
    setParseError(null)
    onFileSelected(file)

    try {
      const formData = new FormData()
      formData.append('file', file)
      // Pass the currently selected LLM model so the agent uses it for parsing
      if (data.agentOpenaiModel) {
        formData.append('model', data.agentOpenaiModel as string)
      }

      const response = await fetch('/api/roe/parse', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const err = await response.json().catch(() => ({}))
        throw new Error(err.error || `Parse failed (${response.status})`)
      }

      const parsed = await response.json()

      // Build update object from parsed fields, only setting non-null values
      const updates: Partial<ProjectFormData> = {}
      const fieldMap: Record<string, keyof ProjectFormData> = {
        name: 'name',
        description: 'description',
        targetDomain: 'targetDomain',
        targetIps: 'targetIps',
        ipMode: 'ipMode',
        subdomainList: 'subdomainList',
        stealthMode: 'stealthMode',
        roeEnabled: 'roeEnabled',
        roeRawText: 'roeRawText',
        roeClientName: 'roeClientName',
        roeClientContactName: 'roeClientContactName',
        roeClientContactEmail: 'roeClientContactEmail',
        roeClientContactPhone: 'roeClientContactPhone',
        roeEmergencyContact: 'roeEmergencyContact',
        roeEngagementStartDate: 'roeEngagementStartDate',
        roeEngagementEndDate: 'roeEngagementEndDate',
        roeEngagementType: 'roeEngagementType',
        roeExcludedHosts: 'roeExcludedHosts',
        roeExcludedHostReasons: 'roeExcludedHostReasons',
        roeTimeWindowEnabled: 'roeTimeWindowEnabled',
        roeTimeWindowTimezone: 'roeTimeWindowTimezone',
        roeTimeWindowDays: 'roeTimeWindowDays',
        roeTimeWindowStartTime: 'roeTimeWindowStartTime',
        roeTimeWindowEndTime: 'roeTimeWindowEndTime',
        roeForbiddenCategories: 'roeForbiddenCategories',
        agentToolPhaseMap: 'agentToolPhaseMap',
        roeMaxSeverityPhase: 'roeMaxSeverityPhase',
        roeAllowDos: 'roeAllowDos',
        roeAllowSocialEngineering: 'roeAllowSocialEngineering',
        roeAllowPhysicalAccess: 'roeAllowPhysicalAccess',
        roeAllowDataExfiltration: 'roeAllowDataExfiltration',
        roeAllowAccountLockout: 'roeAllowAccountLockout',
        roeAllowProductionTesting: 'roeAllowProductionTesting',
        roeGlobalMaxRps: 'roeGlobalMaxRps',
        roeSensitiveDataHandling: 'roeSensitiveDataHandling',
        roeDataRetentionDays: 'roeDataRetentionDays',
        roeRequireDataEncryption: 'roeRequireDataEncryption',
        roeStatusUpdateFrequency: 'roeStatusUpdateFrequency',
        roeCriticalFindingNotify: 'roeCriticalFindingNotify',
        roeIncidentProcedure: 'roeIncidentProcedure',
        roeThirdPartyProviders: 'roeThirdPartyProviders',
        roeComplianceFrameworks: 'roeComplianceFrameworks',
        roeNotes: 'roeNotes',
        naabuRateLimit: 'naabuRateLimit',
        nucleiRateLimit: 'nucleiRateLimit',
        katanaRateLimit: 'katanaRateLimit',
        httpxRateLimit: 'httpxRateLimit',
        nucleiSeverity: 'nucleiSeverity',
        scanModules: 'scanModules',
      }

      for (const [key, formKey] of Object.entries(fieldMap)) {
        if (parsed[key] !== null && parsed[key] !== undefined) {
          // agentToolPhaseMap: LLM returns only disabled tools (e.g. {"execute_hydra": []}).
          // Merge into existing map so we don't wipe out all other tools' phases.
          if (key === 'agentToolPhaseMap' && typeof parsed[key] === 'object') {
            const currentMap = (typeof data.agentToolPhaseMap === 'string'
              ? JSON.parse(data.agentToolPhaseMap)
              : data.agentToolPhaseMap ?? {}) as Record<string, string[]>
            const disabledTools = parsed[key] as Record<string, string[]>
            const merged = { ...currentMap }
            for (const [tool, phases] of Object.entries(disabledTools)) {
              merged[tool] = phases // override only the tools the LLM wants to disable
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (updates as any)[formKey] = merged
            continue
          }
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (updates as any)[formKey] = parsed[key]
        }
      }

      // Store parsed JSON for viewer
      updates.roeParsedJson = parsed
      updates.roeEnabled = true

      updateMultipleFields(updates)
      setShowParseSuccess(true)
    } catch (err) {
      setParseError(err instanceof Error ? err.message : 'Failed to parse document')
    } finally {
      setIsParsing(false)
    }
  }

  const addExcludedHost = () => {
    updateField('roeExcludedHosts', [...(data.roeExcludedHosts || []), ''])
    updateField('roeExcludedHostReasons', [...(data.roeExcludedHostReasons || []), ''])
  }

  const removeExcludedHost = (index: number) => {
    const hosts = [...(data.roeExcludedHosts || [])]
    const reasons = [...(data.roeExcludedHostReasons || [])]
    hosts.splice(index, 1)
    reasons.splice(index, 1)
    updateField('roeExcludedHosts', hosts)
    updateField('roeExcludedHostReasons', reasons)
  }

  const updateExcludedHost = (index: number, value: string) => {
    const hosts = [...(data.roeExcludedHosts || [])]
    hosts[index] = value
    updateField('roeExcludedHosts', hosts)
  }

  const updateExcludedReason = (index: number, value: string) => {
    const reasons = [...(data.roeExcludedHostReasons || [])]
    reasons[index] = value
    updateField('roeExcludedHostReasons', reasons)
  }

  const toggleDay = (day: string) => {
    const days = data.roeTimeWindowDays || []
    if (days.includes(day)) {
      updateField('roeTimeWindowDays', days.filter(d => d !== day))
    } else {
      updateField('roeTimeWindowDays', [...days, day])
    }
  }

  const toggleForbiddenCategory = (cat: string) => {
    const cats = data.roeForbiddenCategories || []
    if (cats.includes(cat)) {
      updateField('roeForbiddenCategories', cats.filter(c => c !== cat))
    } else {
      updateField('roeForbiddenCategories', [...cats, cat])
    }
  }

  const toggleCompliance = (fw: string) => {
    const current = data.roeComplianceFrameworks || []
    if (current.includes(fw)) {
      updateField('roeComplianceFrameworks', current.filter(c => c !== fw))
    } else {
      updateField('roeComplianceFrameworks', [...current, fw])
    }
  }

  return (
    <>
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          Rules of Engagement
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          {/* Document Upload (create mode only) */}
          {mode === 'create' && (
            <div className={styles.subSection}>
              <h3 className={styles.subSectionTitle}>Upload RoE Document</h3>
              <p className={styles.sectionDescription}>
                Upload a Rules of Engagement document (.pdf, .txt, .md, .docx) to auto-populate project settings.
                The parsed rules will enforce guardrails on both the <strong>recon pipeline</strong> (excluded hosts, rate limits, time windows) and <strong>agentic AI activities</strong> (tool restrictions, severity phase cap, prompt-level instructions).
              </p>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pdf,.txt,.md,.docx"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) handleFileUpload(file)
                    }}
                  />
                  <button
                    type="button"
                    className="secondaryButton"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isParsing}
                    style={{ width: 'fit-content' }}
                  >
                    {isParsing ? (
                      <>
                        <Loader2 size={14} className={styles.spinner} />
                        Parsing RoE document...
                      </>
                    ) : (
                      <>
                        <Upload size={14} />
                        Upload & Parse Document
                      </>
                    )}
                  </button>
                  {parseError && (
                    <span style={{ color: 'var(--color-error)', fontSize: '0.8rem', marginTop: 4 }}>
                      {parseError}
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Master Switch */}
          <div className={styles.subSection}>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Enable Rules of Engagement</label>
                <Toggle
                  checked={data.roeEnabled}
                  onChange={(v) => updateField('roeEnabled', v)}
                  disabled={readOnly}
                />
                <span className={styles.fieldHint}>When enabled, RoE constraints are enforced on both the agent and recon pipeline.</span>
              </div>
            </div>
          </div>

          {data.roeEnabled && (
            <>
              {/* Client & Engagement */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Client & Engagement</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Client Name</label>
                    <input className="textInput" value={data.roeClientName} readOnly={readOnly}
                      onChange={(e) => updateField('roeClientName', e.target.value)} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Engagement Type</label>
                    <select className="select" value={data.roeEngagementType} disabled={readOnly}
                      onChange={(e) => updateField('roeEngagementType', e.target.value)}>
                      {ENGAGEMENT_TYPES.map(t => (
                        <option key={t.value} value={t.value}>{t.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Contact Name</label>
                    <input className="textInput" value={data.roeClientContactName} readOnly={readOnly}
                      onChange={(e) => updateField('roeClientContactName', e.target.value)} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Contact Email</label>
                    <input className="textInput" type="email" value={data.roeClientContactEmail} readOnly={readOnly}
                      onChange={(e) => updateField('roeClientContactEmail', e.target.value)} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Contact Phone</label>
                    <input className="textInput" value={data.roeClientContactPhone} readOnly={readOnly}
                      onChange={(e) => updateField('roeClientContactPhone', e.target.value)} />
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Emergency Contact</label>
                    <input className="textInput" value={data.roeEmergencyContact} readOnly={readOnly}
                      onChange={(e) => updateField('roeEmergencyContact', e.target.value)} />
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Start Date</label>
                    <input className="textInput" type="date" value={data.roeEngagementStartDate} readOnly={readOnly}
                      onChange={(e) => updateField('roeEngagementStartDate', e.target.value)} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>End Date</label>
                    <input className="textInput" type="date" value={data.roeEngagementEndDate} readOnly={readOnly}
                      onChange={(e) => updateField('roeEngagementEndDate', e.target.value)} />
                  </div>
                </div>
              </div>

              {/* Excluded Hosts */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Excluded Hosts</h3>
                <p className={styles.sectionDescription}>IPs or domains that must NEVER be scanned or tested.</p>
                {(data.roeExcludedHosts || []).map((host, i) => (
                  <div key={i} className={styles.fieldRow} style={{ alignItems: 'flex-end' }}>
                    <div className={styles.fieldGroup} style={{ flex: 1 }}>
                      <label className={styles.fieldLabel}>Host</label>
                      <input className="textInput" value={host} readOnly={readOnly}
                        onChange={(e) => updateExcludedHost(i, e.target.value)} placeholder="IP or domain" />
                    </div>
                    <div className={styles.fieldGroup} style={{ flex: 1 }}>
                      <label className={styles.fieldLabel}>Reason</label>
                      <input className="textInput" value={(data.roeExcludedHostReasons || [])[i] || ''} readOnly={readOnly}
                        onChange={(e) => updateExcludedReason(i, e.target.value)} placeholder="Why excluded" />
                    </div>
                    {!readOnly && (
                      <button type="button" className="secondaryButton" onClick={() => removeExcludedHost(i)}
                        style={{ marginBottom: 4 }}>
                        <Minus size={14} />
                      </button>
                    )}
                  </div>
                ))}
                {!readOnly && (
                  <button type="button" className="secondaryButton" onClick={addExcludedHost}
                    style={{ width: 'fit-content', marginTop: 4 }}>
                    <Plus size={14} /> Add Excluded Host
                  </button>
                )}
              </div>

              {/* Time Window */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Time Window</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Restrict testing to specific time window</label>
                    <Toggle
                      checked={data.roeTimeWindowEnabled}
                      onChange={(v) => updateField('roeTimeWindowEnabled', v)}
                      disabled={readOnly}
                    />
                  </div>
                </div>
                {data.roeTimeWindowEnabled && (
                  <>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Timezone</label>
                        <input className="textInput" value={data.roeTimeWindowTimezone} readOnly={readOnly}
                          onChange={(e) => updateField('roeTimeWindowTimezone', e.target.value)}
                          placeholder="e.g. Europe/Rome, America/New_York" />
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Start Time</label>
                        <input className="textInput" type="time" value={data.roeTimeWindowStartTime} readOnly={readOnly}
                          onChange={(e) => updateField('roeTimeWindowStartTime', e.target.value)} />
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>End Time</label>
                        <input className="textInput" type="time" value={data.roeTimeWindowEndTime} readOnly={readOnly}
                          onChange={(e) => updateField('roeTimeWindowEndTime', e.target.value)} />
                      </div>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Allowed Days</label>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {WEEKDAYS.map(day => (
                            <label key={day} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: readOnly ? 'default' : 'pointer' }}>
                              <input type="checkbox" checked={(data.roeTimeWindowDays || []).includes(day)}
                                disabled={readOnly} onChange={() => toggleDay(day)} />
                              {day.charAt(0).toUpperCase() + day.slice(1, 3)}
                            </label>
                          ))}
                        </div>
                      </div>
                    </div>
                  </>
                )}
              </div>

              {/* Testing Permissions */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Testing Permissions</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Availability Testing</label>
                    <Toggle checked={data.roeAllowDos} onChange={(v) => updateField('roeAllowDos', v)} disabled={readOnly} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Social Engineering</label>
                    <Toggle checked={data.roeAllowSocialEngineering} onChange={(v) => updateField('roeAllowSocialEngineering', v)} disabled={readOnly} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Physical Access</label>
                    <Toggle checked={data.roeAllowPhysicalAccess} onChange={(v) => updateField('roeAllowPhysicalAccess', v)} disabled={readOnly} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Data Exfiltration</label>
                    <Toggle checked={data.roeAllowDataExfiltration} onChange={(v) => updateField('roeAllowDataExfiltration', v)} disabled={readOnly} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Account Lockout</label>
                    <Toggle checked={data.roeAllowAccountLockout} onChange={(v) => updateField('roeAllowAccountLockout', v)} disabled={readOnly} />
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Allow Production Testing</label>
                    <Toggle checked={data.roeAllowProductionTesting} onChange={(v) => updateField('roeAllowProductionTesting', v)} disabled={readOnly} />
                  </div>
                </div>
              </div>

              {/* Forbidden Categories */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Forbidden Techniques</h3>
                <p style={{ fontSize: '0.8rem', color: '#888', margin: '0 0 8px 0' }}>
                  Tool-level restrictions are applied via Tool Phase Restrictions in the Tool Matrix tab.
                </p>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Forbidden Categories</label>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {FORBIDDEN_CATEGORIES.map(cat => (
                        <label key={cat.value} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: readOnly ? 'default' : 'pointer' }}>
                          <input type="checkbox" checked={(data.roeForbiddenCategories || []).includes(cat.value)}
                            disabled={readOnly} onChange={() => toggleForbiddenCategory(cat.value)} />
                          {cat.label}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Severity Cap & Rate Limit */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Constraints</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Max Allowed Phase</label>
                    <select className="select" value={data.roeMaxSeverityPhase} disabled={readOnly}
                      onChange={(e) => updateField('roeMaxSeverityPhase', e.target.value)}>
                      <option value="informational">Informational only (recon/scanning)</option>
                      <option value="exploitation">Up to exploitation</option>
                      <option value="post_exploitation">All phases (no restriction)</option>
                    </select>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Global Max Requests/sec</label>
                    <input className="textInput" type="number" min={0} value={data.roeGlobalMaxRps} readOnly={readOnly}
                      onChange={(e) => updateField('roeGlobalMaxRps', parseInt(e.target.value) || 0)} />
                    <span className={styles.fieldHint}>0 = no cap. Caps all tool rate limits.</span>
                  </div>
                </div>
              </div>

              {/* Data Handling */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Data Handling</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Sensitive Data Policy</label>
                    <select className="select" value={data.roeSensitiveDataHandling} disabled={readOnly}
                      onChange={(e) => updateField('roeSensitiveDataHandling', e.target.value)}>
                      {DATA_HANDLING_OPTIONS.map(opt => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Data Retention (days)</label>
                    <input className="textInput" type="number" min={1} value={data.roeDataRetentionDays} readOnly={readOnly}
                      onChange={(e) => updateField('roeDataRetentionDays', parseInt(e.target.value) || 90)} />
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Require data encryption</label>
                    <Toggle checked={data.roeRequireDataEncryption}
                      onChange={(v) => updateField('roeRequireDataEncryption', v)} disabled={readOnly} />
                  </div>
                </div>
              </div>

              {/* Communication */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Communication</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Status Update Frequency</label>
                    <select className="select" value={data.roeStatusUpdateFrequency} disabled={readOnly}
                      onChange={(e) => updateField('roeStatusUpdateFrequency', e.target.value)}>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="on_finding">On each finding</option>
                      <option value="none">None</option>
                    </select>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Notify client on critical findings</label>
                    <Toggle checked={data.roeCriticalFindingNotify}
                      onChange={(v) => updateField('roeCriticalFindingNotify', v)} disabled={readOnly} />
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Incident Procedure</label>
                    <textarea className="textInput" rows={3} value={data.roeIncidentProcedure} readOnly={readOnly}
                      onChange={(e) => updateField('roeIncidentProcedure', e.target.value)}
                      placeholder="What to do if testing causes an incident..." />
                  </div>
                </div>
              </div>

              {/* Compliance */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Compliance & Authorization</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Compliance Frameworks</label>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {COMPLIANCE_OPTIONS.map(fw => (
                        <label key={fw} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: readOnly ? 'default' : 'pointer' }}>
                          <input type="checkbox" checked={(data.roeComplianceFrameworks || []).includes(fw)}
                            disabled={readOnly} onChange={() => toggleCompliance(fw)} />
                          {fw}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Third-Party Providers */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Third-Party Providers</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Cloud/hosting providers with separate authorization</label>
                    <input className="textInput" type="text" readOnly={readOnly}
                      value={(data.roeThirdPartyProviders || []).join(', ')}
                      onChange={(e) => updateField('roeThirdPartyProviders', e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean))}
                      placeholder="e.g. AWS, Hetzner, Cloudflare" />
                  </div>
                </div>
              </div>

              {/* Notes */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Notes</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <textarea className="textInput" rows={4} value={data.roeNotes} readOnly={readOnly}
                      onChange={(e) => updateField('roeNotes', e.target.value)}
                      placeholder="Additional rules not captured by fields above..." />
                  </div>
                </div>
              </div>

              {/* Raw RoE Text (always read-only) */}
              {data.roeRawText && (
                <div className={styles.subSection}>
                  <h3 className={styles.subSectionTitle}>Extracted Document Text</h3>
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <textarea className="textInput" rows={8} value={data.roeRawText} readOnly
                        style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>

    <Modal
      isOpen={showParseSuccess}
      onClose={() => setShowParseSuccess(false)}
      title="RoE Document Parsed Successfully"
      size="default"
      footer={
        <button
          type="button"
          onClick={() => setShowParseSuccess(false)}
          style={{
            padding: '8px 24px',
            background: 'var(--color-accent, #3b82f6)',
            color: '#fff',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '0.9rem',
            fontWeight: 500,
          }}
        >
          OK
        </button>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '0.9rem', lineHeight: 1.6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-success, #22c55e)' }}>
          <CheckCircle size={20} />
          <strong>Project settings have been updated from your RoE document.</strong>
        </div>

        <p style={{ margin: 0 }}>
          The following tabs may have been modified based on the parsed rules. Please review them before saving:
        </p>

        <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <li><strong>Target &amp; Modules</strong> — target domain, IP addresses, scan modules, rate limits</li>
          <li><strong>Tool Matrix</strong> — Tool Phase Restrictions (forbidden tools are disabled in the matrix)</li>
          <li><strong>Rules of Engagement</strong> — excluded hosts, time windows, testing permissions, compliance</li>
        </ul>

        <p style={{ margin: 0, padding: '10px 12px', background: 'var(--color-surface-alt, rgba(59,130,246,0.08))', borderRadius: '6px', borderLeft: '3px solid var(--color-accent, #3b82f6)' }}>
          The Rules of Engagement will be enforced on both the <strong>recon pipeline</strong> (host exclusions, rate limits, time windows) and the <strong>agentic AI</strong> (tool restrictions, severity phase cap, prompt instructions).
        </p>
      </div>
    </Modal>
    </>
  )
}

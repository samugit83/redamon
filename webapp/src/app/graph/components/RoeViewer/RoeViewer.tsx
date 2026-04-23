'use client'

import { Download, Shield, Clock, Ban, FileText, Users, AlertTriangle, Lock, Globe } from 'lucide-react'
import styles from './RoeViewer.module.css'

interface RoeViewerProps {
  projectId: string
  project: {
    roeEnabled?: boolean
    roeClientName?: string
    roeClientContactName?: string
    roeClientContactEmail?: string
    roeClientContactPhone?: string
    roeEmergencyContact?: string
    roeEngagementStartDate?: string
    roeEngagementEndDate?: string
    roeEngagementType?: string
    roeExcludedHosts?: string[]
    roeExcludedHostReasons?: string[]
    roeTimeWindowEnabled?: boolean
    roeTimeWindowTimezone?: string
    roeTimeWindowDays?: string[]
    roeTimeWindowStartTime?: string
    roeTimeWindowEndTime?: string
    roeForbiddenCategories?: string[]
    roeMaxSeverityPhase?: string
    roeAllowDos?: boolean
    roeAllowSocialEngineering?: boolean
    roeAllowPhysicalAccess?: boolean
    roeAllowDataExfiltration?: boolean
    roeAllowAccountLockout?: boolean
    roeAllowProductionTesting?: boolean
    roeGlobalMaxRps?: number
    roeSensitiveDataHandling?: string
    roeDataRetentionDays?: number
    roeRequireDataEncryption?: boolean
    roeStatusUpdateFrequency?: string
    roeCriticalFindingNotify?: boolean
    roeIncidentProcedure?: string
    roeThirdPartyProviders?: string[]
    roeComplianceFrameworks?: string[]
    roeNotes?: string
    roeDocumentName?: string
    targetDomain?: string
    targetIps?: string[]
    [key: string]: unknown
  }
}

function PermBadge({ allowed, label }: { allowed: boolean; label: string }) {
  return (
    <span className={`${styles.permBadge} ${allowed ? styles.permAllowed : styles.permDenied}`}>
      {allowed ? '\u2713' : '\u2717'} {label}
    </span>
  )
}

function Section({ title, icon, children, fullWidth }: { title: string; icon: React.ReactNode; children: React.ReactNode; fullWidth?: boolean }) {
  return (
    <div className={`${styles.card} ${fullWidth ? styles.fullWidth : ''}`}>
      <div className={styles.cardHeader}>
        {icon}
        <h3>{title}</h3>
      </div>
      <div className={styles.cardBody}>{children}</div>
    </div>
  )
}

const ENGAGEMENT_TYPE_LABELS: Record<string, string> = {
  external: 'External Penetration Test',
  internal: 'Internal Penetration Test',
  web_app: 'Web Application Test',
  api: 'API Security Test',
  mobile: 'Mobile Application Test',
  physical: 'Physical Security Test',
  social_engineering: 'Social Engineering',
  red_team: 'Red Team Engagement',
}

const CATEGORY_LABELS: Record<string, string> = {
  brute_force: 'Credential Testing',
  dos: 'Availability Testing',
  social_engineering: 'Social Engineering',
  physical: 'Physical Access',
}

export function RoeViewer({ projectId, project }: RoeViewerProps) {
  if (!project.roeEnabled) {
    return (
      <div className={styles.container}>
        <div className={styles.inner}>
          <div className={styles.empty}>
            <Shield size={44} strokeWidth={1.5} />
            <h2>No Rules of Engagement</h2>
            <p>No RoE document has been configured for this project.</p>
            <p className={styles.hint}>Upload a RoE document when creating a project to enable engagement constraints.</p>
          </div>
        </div>
      </div>
    )
  }

  const handleDownload = () => {
    window.open(`/api/projects/${projectId}/roe/download`, '_blank')
  }

  // Time window status
  let timeWindowActive = false
  if (project.roeTimeWindowEnabled) {
    try {
      const now = new Date()
      const day = now.toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase()
      timeWindowActive = (project.roeTimeWindowDays || []).includes(day)
      const currentTime = now.toTimeString().slice(0, 5)
      if (timeWindowActive) {
        const start = project.roeTimeWindowStartTime || '00:00'
        const end = project.roeTimeWindowEndTime || '23:59'
        if (start <= end) {
          timeWindowActive = currentTime >= start && currentTime <= end
        } else {
          timeWindowActive = currentTime >= start || currentTime <= end
        }
      }
    } catch {
      // ignore
    }
  }

  const maxPhase = project.roeMaxSeverityPhase || 'post_exploitation'
  const phaseClass = maxPhase === 'informational' ? styles.phaseInfo : maxPhase === 'exploitation' ? styles.phaseExploit : styles.phaseAll
  const phaseLabel = maxPhase === 'informational' ? 'Informational only' : maxPhase === 'exploitation' ? 'Up to Exploitation' : 'All Phases'

  const dataHandlingLabels: Record<string, string> = {
    no_access: 'No access to sensitive data',
    prove_access_only: 'Prove access only (no collection)',
    limited_collection: 'Limited collection allowed',
    full_access: 'Full access permitted',
  }

  const frequencyLabels: Record<string, string> = {
    daily: 'Daily',
    weekly: 'Weekly',
    on_finding: 'On each finding',
    none: 'None',
  }

  const excludedHosts = project.roeExcludedHosts || []
  const forbiddenCategories = project.roeForbiddenCategories || []
  const complianceFrameworks = project.roeComplianceFrameworks || []
  const thirdPartyProviders = project.roeThirdPartyProviders || []

  return (
    <div className={styles.container}>
      <div className={styles.inner}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <Shield size={20} />
          <h2>Rules of Engagement</h2>
        </div>
        {project.roeDocumentName && (
          <button className={styles.downloadBtn} onClick={handleDownload}>
            <Download size={14} />
            {project.roeDocumentName}
          </button>
        )}
      </div>

      <div className={styles.grid}>
        {/* Engagement Info */}
        <Section title="Engagement" icon={<Users size={15} />}>
          {project.roeClientName && <div className={styles.row}><span>Client</span><strong>{project.roeClientName}</strong></div>}
          {project.roeEngagementType && (
            <div className={styles.row}><span>Type</span><strong>{ENGAGEMENT_TYPE_LABELS[project.roeEngagementType] || project.roeEngagementType}</strong></div>
          )}
          {(project.roeEngagementStartDate || project.roeEngagementEndDate) && (
            <div className={styles.row}>
              <span>Period</span>
              <strong>{project.roeEngagementStartDate || '?'} &rarr; {project.roeEngagementEndDate || '?'}</strong>
            </div>
          )}
          {project.roeClientContactName && <div className={styles.row}><span>Contact</span><strong>{project.roeClientContactName}</strong></div>}
          {project.roeClientContactEmail && <div className={styles.row}><span>Email</span><strong>{project.roeClientContactEmail}</strong></div>}
          {project.roeClientContactPhone && <div className={styles.row}><span>Phone</span><strong>{project.roeClientContactPhone}</strong></div>}
          {project.roeEmergencyContact && <div className={styles.row}><span>Emergency</span><strong>{project.roeEmergencyContact}</strong></div>}
        </Section>

        {/* Scope */}
        <Section title="Scope" icon={<Globe size={15} />}>
          {project.targetDomain && <div className={styles.row}><span>Domain</span><strong>{project.targetDomain}</strong></div>}
          {project.targetIps && project.targetIps.length > 0 && (
            <div className={styles.row}><span>IP Ranges</span><strong>{project.targetIps.join(', ')}</strong></div>
          )}
          {excludedHosts.length > 0 && (
            <div className={styles.row}><span>Exclusions</span><strong>{excludedHosts.length} hosts</strong></div>
          )}
        </Section>

        {/* Exclusions — full width */}
        {excludedHosts.length > 0 && (
          <Section title="Excluded Hosts" icon={<Ban size={15} />} fullWidth>
            {excludedHosts.map((host, i) => (
              <div key={i} className={styles.exclusionRow}>
                <span className={styles.exclusionHost}>{host}</span>
                {(project.roeExcludedHostReasons || [])[i] && (
                  <span className={styles.exclusionReason}>&mdash; {(project.roeExcludedHostReasons || [])[i]}</span>
                )}
              </div>
            ))}
          </Section>
        )}

        {/* Time Window */}
        {project.roeTimeWindowEnabled && (
          <Section title="Time Window" icon={<Clock size={15} />}>
            <div className={styles.row}>
              <span>Days</span>
              <strong>{(project.roeTimeWindowDays || []).map(d => d.charAt(0).toUpperCase() + d.slice(1, 3)).join(', ')}</strong>
            </div>
            <div className={styles.row}>
              <span>Hours</span>
              <strong>{project.roeTimeWindowStartTime} &ndash; {project.roeTimeWindowEndTime}</strong>
            </div>
            <div className={styles.row}>
              <span>Timezone</span>
              <strong>{project.roeTimeWindowTimezone || 'UTC'}</strong>
            </div>
            <div className={styles.row}>
              <span>Status</span>
              <span className={timeWindowActive ? styles.statusActive : styles.statusInactive}>
                {timeWindowActive ? '\u25CF ACTIVE' : '\u25CB OUTSIDE WINDOW'}
              </span>
            </div>
          </Section>
        )}

        {/* Testing Permissions */}
        <Section title="Testing Permissions" icon={<Shield size={15} />}>
          <div className={styles.permGrid}>
            <PermBadge allowed={!!project.roeAllowDos} label="Avail." />
            <PermBadge allowed={!!project.roeAllowSocialEngineering} label="Social Eng." />
            <PermBadge allowed={!!project.roeAllowPhysicalAccess} label="Physical" />
            <PermBadge allowed={!!project.roeAllowDataExfiltration} label="Data Exfil." />
            <PermBadge allowed={!!project.roeAllowAccountLockout} label="Lockout" />
            <PermBadge allowed={project.roeAllowProductionTesting !== false} label="Production" />
          </div>
        </Section>

        {/* Constraints */}
        <Section title="Constraints" icon={<AlertTriangle size={15} />}>
          <div className={styles.row}>
            <span>Max Phase</span>
            <span className={`${styles.phaseIndicator} ${phaseClass}`}>{phaseLabel}</span>
          </div>
          {(project.roeGlobalMaxRps || 0) > 0 && (
            <div className={styles.row}><span>Rate Limit</span><strong>{project.roeGlobalMaxRps} rps</strong></div>
          )}
          {forbiddenCategories.length > 0 && (
            <>
              <div className={styles.row}><span>Forbidden</span><span /></div>
              <div className={styles.tagList}>
                {forbiddenCategories.map(cat => (
                  <span key={cat} className={styles.tagDanger}>{CATEGORY_LABELS[cat] || cat}</span>
                ))}
              </div>
            </>
          )}
        </Section>

        {/* Data Handling */}
        <Section title="Data Handling" icon={<Lock size={15} />}>
          <div className={styles.row}>
            <span>Policy</span>
            <span className={styles.dataHandling}>{dataHandlingLabels[project.roeSensitiveDataHandling || 'no_access']}</span>
          </div>
          <div className={styles.row}>
            <span>Retention</span>
            <strong>{project.roeDataRetentionDays || 90} days</strong>
          </div>
          {project.roeRequireDataEncryption !== false && (
            <div className={styles.row}>
              <span>Encryption</span>
              <span className={styles.encryptionBadge}>{'\u2713'} Required (at rest + in transit)</span>
            </div>
          )}
        </Section>

        {/* Communication */}
        <Section title="Communication" icon={<FileText size={15} />}>
          <div className={styles.row}>
            <span>Status Updates</span>
            <strong>{frequencyLabels[project.roeStatusUpdateFrequency || 'daily'] || project.roeStatusUpdateFrequency}</strong>
          </div>
          <div className={styles.row}>
            <span>Critical Notify</span>
            <strong>{project.roeCriticalFindingNotify !== false ? 'Immediately' : 'No'}</strong>
          </div>
          {project.roeIncidentProcedure && (
            <div className={styles.textBlock}>
              <span>Incident Procedure</span>
              <p>{project.roeIncidentProcedure}</p>
            </div>
          )}
        </Section>

        {/* Compliance */}
        {(complianceFrameworks.length > 0 || thirdPartyProviders.length > 0) && (
          <Section title="Compliance & Authorization" icon={<Shield size={15} />}>
            {complianceFrameworks.length > 0 && (
              <>
                <div className={styles.row}><span>Frameworks</span><span /></div>
                <div className={styles.tagList}>
                  {complianceFrameworks.map(fw => (
                    <span key={fw} className={styles.tagInfo}>{fw}</span>
                  ))}
                </div>
              </>
            )}
            {thirdPartyProviders.length > 0 && (
              <>
                <div className={styles.row}><span>Third-Party</span><span /></div>
                <div className={styles.tagList}>
                  {thirdPartyProviders.map(p => (
                    <span key={p} className={styles.tag}>{p}</span>
                  ))}
                </div>
              </>
            )}
          </Section>
        )}

        {/* Notes — full width */}
        {project.roeNotes && (
          <Section title="Additional Notes" icon={<FileText size={15} />} fullWidth>
            <p className={styles.notes}>{project.roeNotes}</p>
          </Section>
        )}
      </div>
      </div>
    </div>
  )
}

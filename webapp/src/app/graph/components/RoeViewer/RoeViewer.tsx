'use client'

import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Download, Shield, Clock, Ban, FileText, Users, AlertTriangle, Lock, Globe, FileCheck, Trash2 } from 'lucide-react'
import { AuthorizationHistory } from './AuthorizationHistory'
import { deriveRoeEnabled } from '@/lib/engagement'
import { agentEnforcementWarning } from '@/lib/roe/agentWarning'
import { announceProjectWrite } from '@/lib/projectVersion'
import { useToast } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import { RoeUploadButton } from '@/components/roe/RoeUploadButton'
import { RoeReviewModal } from '@/components/roe/RoeReviewModal'
import { downloadRoeFile, reviewRemove } from '@/components/roe/roeClient'
import { clearRoeEntry, setRoeEntry, useRoeEntry, useRoeMounted } from '@/components/roe/roeParseStore'
import { roeAppliedSummary } from '@/components/roe/roeAppliedSummary'
import styles from './RoeViewer.module.css'
import { type ScopeGroup, groupLabel } from '@/lib/scopeGroups'
import { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '@/components/projects/ProjectForm/ipHostnameModes'

/**
 * The read-only engagement panel, split the way the model is.
 *
 * ENGAGEMENT LIMITS are live and enforced: the rate ceiling, the never-touch
 * hosts, the scanning window, the agent's denylists. ENGAGEMENT RECORD is the
 * contract: the client, the contacts, the dates, the compliance frameworks.
 * They used to be one undifferentiated list under one heading, which is what
 * made the two concepts easy to confuse in the first place - and what let a
 * checkbox that disabled the rate ceiling sit beside the client's phone number
 * looking like the same kind of thing.
 *
 * Whether the limits are live is DERIVED, never read from a column.
 */
interface RoeViewerProps {
  projectId: string
  project: {
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
    roeForbiddenTools?: string[]
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
    engagementKind?: string
    engagementIdentityHeader?: string
    targetDomain?: string
    targetIps?: string[]
    scopeGroups?: ScopeGroup[]
    ipMode?: boolean
    ipHostnameMode?: string
    ipHostnameInclude?: string[]
    ipHostnameExclude?: string[]
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
  const queryClient = useQueryClient()
  const { currentProject, setCurrentProject } = useProject()
  const toast = useToast()
  useRoeMounted(projectId)
  const entry = useRoeEntry(projectId)
  const [actionError, setActionError] = useState<string | null>(null)
  const [removing, setRemoving] = useState(false)

  // Derived: a ceiling, an exclusion list or a window. Never a stored flag, so
  // this panel cannot report limits as active while nothing applies them, nor
  // hide a limit somebody set.
  const limitsActive = deriveRoeEnabled(project)
  const hasRecord = Boolean(
    project.roeClientName || project.roeDocumentName || project.roeNotes ||
    project.roeEngagementStartDate || project.roeClientContactName
  )
  const hasDocument = Boolean(project.roeDocumentName)
  const stored = (project.roeParsedJson && typeof project.roeParsedJson === 'object' ? project.roeParsedJson : {}) as {
    applied?: Record<string, unknown>; textSha256?: string; appliedAt?: string
  }
  const enforcementWarning = agentEnforcementWarning(Object.keys(stored.applied ?? {}), project)

  const applied = (result: Record<string, unknown>) => {
    const row = (result.project ?? {}) as Record<string, unknown>
    void queryClient.invalidateQueries({ queryKey: ['project', projectId] })
    void queryClient.invalidateQueries({ queryKey: ['projects'] })
    // The toolbar's Limits badge reads the provider, which no query refreshes.
    if (currentProject && currentProject.id === projectId) {
      setCurrentProject({
        ...currentProject,
        roeGlobalMaxRps: row.roeGlobalMaxRps as number,
        roeExcludedHosts: row.roeExcludedHosts as string[],
        roeTimeWindowEnabled: row.roeTimeWindowEnabled as boolean,
        updatedAt: row.updatedAt as never,
      })
    }
    announceProjectWrite(projectId, row.updatedAt)
    clearRoeEntry(projectId)
    toast.success(roeAppliedSummary(result), 'Rules of Engagement saved')
  }

  const startRemove = async () => {
    setActionError(null)
    setRemoving(true)
    const review = await reviewRemove(projectId)
    setRemoving(false)
    if (!review.ok) setActionError(review.error.error)
    else setRoeEntry(projectId, { status: 'review', review: review.value, file: null, error: null })
  }

  const handleDownload = async () => {
    setActionError(await downloadRoeFile(`/api/projects/${projectId}/roe/download`, project.roeDocumentName || 'roe-document'))
  }

  const reviewModal = entry.status === 'review' && entry.review ? (
    <RoeReviewModal
      review={entry.review}
      target="existing"
      projectId={projectId}
      file={entry.file}
      onClose={() => clearRoeEntry(projectId)}
      onApplied={applied}
      onReviewChanged={review => setRoeEntry(projectId, { review })}
    />
  ) : null

  if (!limitsActive && !hasRecord) {
    // The thing worth saying out loud is NOT "no document": it is that this
    // project has no request-rate ceiling, so every tool runs at whatever rate
    // its own setting says. Both defaults land here, so this is where the whole
    // pre-existing estate arrives.
    return (
      <div className={styles.container}>
        <div className={styles.inner}>
          <div className={styles.empty}>
            <Shield size={44} strokeWidth={1.5} />
            <h2>No engagement limits</h2>
            <p className={styles.hint} style={{ color: 'var(--color-warning, #c80)' }}>
              This project has <strong>no request-rate ceiling</strong>, no excluded hosts and
              no scanning window: every tool runs at whatever rate its own setting says, and
              nothing caps the total. If the target is not your own estate, create a project
              with the engagement kind set to third party, which cannot scan without a ceiling
              and a record of what authorized it.
            </p>
            <p className={styles.hint}>
              Set a ceiling, exclude a host or restrict the window in the project&apos;s
              Target &amp; Modules settings, or upload a Rules of Engagement document: it is read
              into a proposed set of changes you review before anything applies.
            </p>
            <div className={styles.emptyUpload}>
              <RoeUploadButton storeKey={projectId} projectId={projectId} hasDocument={false} />
            </div>
            {actionError && <p className={styles.actionError} role="alert">{actionError}</p>}
          </div>
        </div>
        {reviewModal}
      </div>
    )
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
  const forbiddenTools = project.roeForbiddenTools || []
  const complianceFrameworks = project.roeComplianceFrameworks || []
  const thirdPartyProviders = project.roeThirdPartyProviders || []

  return (
    <div className={styles.container}>
      <div className={styles.inner}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <Shield size={20} />
          <h2>Engagement</h2>
          <span className={styles.hint}>
            {limitsActive
              ? 'Limits are ACTIVE and enforced at scan start.'
              : 'No limits are active: nothing below constrains a scan.'}
          </span>
        </div>
        <div className={styles.headerActions}>
          <RoeUploadButton storeKey={projectId} projectId={projectId} hasDocument={hasDocument} showModelLine={false} compact />
          {hasDocument && (
            <button type="button" className="secondaryButton" onClick={startRemove} disabled={removing || entry.status !== 'idle' && entry.status !== 'error'}>
              <Trash2 size={14} />
              {removing ? 'Preparing…' : 'Remove'}
            </button>
          )}
          {hasDocument && (
            <button className={styles.downloadBtn} onClick={handleDownload} title={project.roeDocumentName}>
              <Download size={14} />
              <span className={styles.docName}>{project.roeDocumentName}</span>
            </button>
          )}
        </div>
      </div>
      {actionError && <p className={styles.actionError} role="alert">{actionError}</p>}
      {enforcementWarning && (
        <div className={styles.enforcementBanner} role="status">
          <AlertTriangle size={15} />
          <span>{enforcementWarning}</span>
        </div>
      )}

      <div className={styles.grid}>
        {/* Engagement Info */}
        <Section title="Engagement record" icon={<Users size={15} />}>
          <div className={styles.row}>
            <span>Kind</span>
            <strong>
              {project.engagementKind === 'third_party'
                ? 'Third party - somebody else\u2019s estate'
                : 'Internal - our own estate'}
            </strong>
          </div>
          <div className={styles.row}>
            <span>Rate ceiling</span>
            <strong>
              {/* 0 means NO ceiling rather than a slow one, which is the trap
                  worth spelling out wherever the number is shown. */}
              {project.roeGlobalMaxRps && project.roeGlobalMaxRps > 0
                ? `${project.roeGlobalMaxRps} rps`
                : 'none - every tool runs at its own rate'}
            </strong>
          </div>
          <div className={styles.row}>
            <span>Identity header</span>
            <strong>{project.engagementIdentityHeader || 'none sent'}</strong>
          </div>
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

        {/* What authorized this engagement. Append-only, and deliberately its
            own card rather than a line in Engagement: it is a history, not a
            value, and an incident review reads it as one. */}
        <Section title="Authorization" icon={<FileCheck size={15} />} fullWidth>
          <AuthorizationHistory
            projectId={projectId}
            engagementKind={project.engagementKind}
            currentDocumentSha256={typeof stored.textSha256 === 'string' ? stored.textSha256 : null}
          />
        </Section>

        {/* Scope */}
        <Section title="Scope" icon={<Globe size={15} />}>
          {Array.isArray(project.scopeGroups) && project.scopeGroups.length > 0 ? (
            project.scopeGroups.map(g => (
              <div key={g.scanRoot} className={styles.row}>
                <span>{g.mode === 'enumerate' ? 'Enumerated' : 'Listed'}</span>
                <strong>{groupLabel(g)}{g.orgDomain !== g.scanRoot ? ` · domain ${g.orgDomain}` : ''}</strong>
              </div>
            ))
          ) : project.targetDomain && (
            <div className={styles.row}><span>Domain</span><strong>{project.targetDomain}</strong></div>
          )}
          {project.targetIps && project.targetIps.length > 0 && (
            <div className={styles.row}><span>IP Ranges</span><strong>{project.targetIps.join(', ')}</strong></div>
          )}
          {/* A read without the column says nothing about the policy, and
              guessing "IP only" would misstate what the scan reaches. */}
          {project.ipMode === true && typeof project.ipHostnameMode === 'string' && (
            <div className={styles.row} data-testid="roe-ip-hostname-mode">
              <span>{IP_HOSTNAME_SECTION_LABEL}</span>
              <strong>
                {ipHostnameModeLabel(project.ipHostnameMode)}
                {project.ipHostnameMode === 'record_filter' &&
                  ` · include ${(project.ipHostnameInclude ?? []).length}, exclude ${(project.ipHostnameExclude ?? []).length}`}
              </strong>
            </div>
          )}
          {excludedHosts.length > 0 && (
            <div className={styles.row}><span>Exclusions</span><strong>{excludedHosts.length} hosts</strong></div>
          )}
        </Section>

        {/* Exclusions - full width */}
        {excludedHosts.length > 0 && (
          <Section title="Engagement limit: excluded hosts" icon={<Ban size={15} />} fullWidth>
            {excludedHosts.map((host, i) => (
              <div key={i} className={styles.exclusionRow}>
                <span className={styles.exclusionHost}>{host}</span>
                {(project.roeExcludedHostReasons || [])[i] && (
                  <span className={styles.exclusionReason}>- {(project.roeExcludedHostReasons || [])[i]}</span>
                )}
              </div>
            ))}
          </Section>
        )}

        {/* Time Window */}
        {project.roeTimeWindowEnabled && (
          <Section title="Engagement limit: time window" icon={<Clock size={15} />}>
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
        {/* Only the three nothing checks. The other three moved to the agent
            limits card above, because the split this panel draws is between
            what is ENFORCED and what is merely recorded - and showing an
            enforced flag under "recorded" is the confusion it exists to end. */}
        <Section title="Recorded permissions" icon={<Shield size={15} />}>
          <p className={styles.hint}>Read by the agent as prompt context. No code refuses anything on these.</p>
          <div className={styles.permGrid}>
            <PermBadge allowed={!!project.roeAllowPhysicalAccess} label="Physical" />
            <PermBadge allowed={!!project.roeAllowDataExfiltration} label="Data Exfil." />
            <PermBadge allowed={project.roeAllowProductionTesting !== false} label="Production" />
          </div>
        </Section>

        {/* Constraints */}
        <Section title="Engagement limits: agent" icon={<AlertTriangle size={15} />}>
          <div className={styles.row}>
            <span>Max Phase</span>
            <span className={`${styles.phaseIndicator} ${phaseClass}`}>{phaseLabel}</span>
          </div>
          {(project.roeGlobalMaxRps || 0) > 0 && (
            <div className={styles.row}><span>Rate Limit</span><strong>{project.roeGlobalMaxRps} rps</strong></div>
          )}
          {forbiddenCategories.length > 0 && (
            <>
              <div className={styles.row}><span>Forbidden categories</span><span /></div>
              <div className={styles.tagList}>
                {forbiddenCategories.map(cat => (
                  <span key={cat} className={styles.tagDanger}>{CATEGORY_LABELS[cat] || cat}</span>
                ))}
              </div>
            </>
          )}
          {/* A tool denylist refuses a tool BEFORE it runs, so leaving it off
              this panel hid a live constraint from the one screen that exists
              to show what constrains the engagement. */}
          {forbiddenTools.length > 0 && (
            <>
              <div className={styles.row}><span>Forbidden tools</span><span /></div>
              <div className={styles.tagList}>
                {forbiddenTools.map(tool => (
                  <span key={tool} className={styles.tagDanger}>{tool}</span>
                ))}
              </div>
            </>
          )}
          <div className={styles.row}>
            <span>Availability testing</span>
            <span><PermBadge allowed={!!project.roeAllowDos} label="DoS" /></span>
          </div>
          <div className={styles.row}>
            <span>Account lockout</span>
            <span><PermBadge allowed={!!project.roeAllowAccountLockout} label="Lockout" /></span>
          </div>
          <div className={styles.row}>
            <span>Social engineering</span>
            <span><PermBadge allowed={!!project.roeAllowSocialEngineering} label="Social Eng." /></span>
          </div>
        </Section>

        {/* Data Handling */}
        <Section title="Record: data handling" icon={<Lock size={15} />}>
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
        <Section title="Record: communication" icon={<FileText size={15} />}>
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
          <Section title="Record: compliance" icon={<Shield size={15} />}>
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

        {/* Notes - full width */}
        {project.roeNotes && (
          <Section title="Additional Notes" icon={<FileText size={15} />} fullWidth>
            <p className={styles.notes}>{project.roeNotes}</p>
          </Section>
        )}
      </div>
      </div>
      {reviewModal}
    </div>
  )
}

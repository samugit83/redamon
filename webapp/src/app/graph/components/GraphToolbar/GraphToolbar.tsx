'use client'

import { Bot, Play, Download, Loader2, Terminal, Shield, Github, Target, Zap, MessageSquare, Pause, Square, ShieldAlert, FolderOpen } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { ReconStatus, GvmStatus, GithubHuntStatus, TrufflehogStatus, PartialReconState } from '@/lib/recon-types'
import { PartialReconBadges } from '@/components/PartialReconBadges'
import { VersionSwitch } from '../VersionSwitch'
import { ScanStatusWarning } from '@/components/scans/ScanStatusWarning'
import { GVM_NOT_INSTALLED } from '@/components/scans/scanErrors'
import { usePermissionRefused } from '@/hooks/useCan'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'
import { emergencyPauseTitle, type EmergencyStopScope } from './emergencyStopScope'
import styles from './GraphToolbar.module.css'

interface GraphToolbarProps {
  projectId: string
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  onOpenFileSystem?: () => void
  isFileSystemOpen?: boolean
  // Target info
  /** One line naming the target (projectTargetLabel). */
  targetLabel?: string
  /** One line per scope group, shown on hover. */
  scopeLines?: string[]
  // Recon props
  onStartRecon?: () => void
  onPauseRecon?: () => void
  onResumeRecon?: () => void
  onStopRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: ReconStatus
  hasReconData?: boolean
  /** Set when the data check itself failed, so the disabled download does not claim "no data". */
  reconDataError?: string | null
  isLogsOpen?: boolean
  // GVM props
  gvmAvailable?: boolean
  /** The GVM button's tooltip while unavailable: not installed, or the check itself failed. */
  gvmUnavailableReason?: string
  onStartGvm?: () => void
  onPauseGvm?: () => void
  onResumeGvm?: () => void
  onStopGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  hasGvmData?: boolean
  gvmDataError?: string | null
  isGvmLogsOpen?: boolean
  /** One entry per scan whose status could not be read; the buttons then show the last known state. */
  scanStatusErrors?: Array<string | null | undefined>
  // GitHub Hunt props
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // TruffleHog props
  // The toolbar only reflects whether SOMETHING TruffleHog is running (the Other
  // Scans button's busy state). The per-source controls live in that modal, so
  // the toolbar takes one aggregate flag instead of a project-level status it
  // could no longer represent with several sources in flight.
  isTrufflehogRunning?: boolean
  hasTrufflehogData?: boolean
  // Partial Recon props (multi-run)
  activePartialRecons?: PartialReconState[]
  activePartialReconLogsDrawer?: string | null  // run_id of currently open logs drawer
  onStopPartialRecon?: (runId: string) => void
  onTogglePartialReconLogs?: (runId: string) => void
  // Other Scans modal
  onToggleOtherScansModal?: () => void
  // Stealth mode
  stealthMode?: boolean
  /** Whether the engagement's limits are live. DERIVED by the caller. */
  engagementLimitsActive?: boolean
  // Emergency Pause All
  onEmergencyPauseAll?: () => void
  isAnyPipelineRunning?: boolean
  isEmergencyPausing?: boolean
  /** Whose agent runs a press stops, as the emergency-stop route answered; unknown until it does. */
  emergencyStopScope?: EmergencyStopScope
  // Tunnel status (displayed next to Pause All)
  tunnelStatus?: { ngrok?: { active: boolean; host?: string; port?: number }; chisel?: { active: boolean; host?: string; port?: number; srvPort?: number } }
  // Scan Timeline (version switch)
  scanVersions?: ScanVersionSummary[]
  selectedVersionId?: string | null
  onSelectVersion?: (versionId: string | null) => void
  onManageVersions?: () => void
  isActivatingVersion?: boolean
  /** True while a PAST version is being viewed: live-graph actions are disabled. */
  viewingPastVersion?: boolean
  // Agent status
  agentActiveCount?: number
  agentConversations?: Array<{
    id: string
    title: string
    currentPhase: string
    iterationCount: number
    agentRunning: boolean
    sessionId: string
  }>
}

export function GraphToolbar({
  projectId,
  is3D,
  showLabels,
  onToggle3D,
  onToggleLabels,
  onToggleAI,
  isAIOpen = false,
  onOpenFileSystem,
  isFileSystemOpen = false,
  // Target info
  targetLabel,
  scopeLines = [],
  // Recon props
  onStartRecon,
  onPauseRecon,
  onResumeRecon,
  onStopRecon,
  onDownloadJSON,
  onToggleLogs,
  reconStatus = 'idle',
  hasReconData = false,
  reconDataError = null,
  isLogsOpen = false,
  // GVM props
  gvmAvailable = true,
  gvmUnavailableReason = '',
  onStartGvm,
  onPauseGvm,
  onResumeGvm,
  onStopGvm,
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  hasGvmData = false,
  gvmDataError = null,
  isGvmLogsOpen = false,
  scanStatusErrors = [],
  // GitHub Hunt props
  onStartGithubHunt,
  onPauseGithubHunt,
  onResumeGithubHunt,
  onStopGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  // TruffleHog props
  isTrufflehogRunning = false,
  hasTrufflehogData = false,
  // Partial Recon props (multi-run)
  activePartialRecons = [],
  activePartialReconLogsDrawer = null,
  onStopPartialRecon,
  onTogglePartialReconLogs,
  // Other Scans modal
  onToggleOtherScansModal,
  // Stealth mode
  stealthMode = false,
  engagementLimitsActive = false,
  // Emergency Pause All
  onEmergencyPauseAll,
  isAnyPipelineRunning = false,
  isEmergencyPausing = false,
  emergencyStopScope,
  tunnelStatus,
  // Scan Timeline (version switch)
  scanVersions = [],
  selectedVersionId = null,
  onSelectVersion,
  onManageVersions,
  isActivatingVersion = false,
  viewingPastVersion = false,
  // Agent status
  agentActiveCount = 0,
  agentConversations = [],
}: GraphToolbarProps) {
  const isReconBusy = reconStatus === 'running' || reconStatus === 'starting' || reconStatus === 'pausing'
  const isReconStopping = reconStatus === 'stopping'
  const isReconPausing = reconStatus === 'pausing'
  const isReconRunning = isReconBusy || isReconStopping
  const isReconPaused = reconStatus === 'paused'
  const isReconActive = isReconRunning || isReconPaused
  const isGvmBusy = gvmStatus === 'running' || gvmStatus === 'starting' || gvmStatus === 'pausing'
  const isGvmStopping = gvmStatus === 'stopping'
  const isGvmPausing = gvmStatus === 'pausing'
  const isGvmRunning = isGvmBusy || isGvmStopping
  const isGvmPaused = gvmStatus === 'paused'
  const isGvmActive = isGvmRunning || isGvmPaused
  const isGithubHuntBusy = githubHuntStatus === 'running' || githubHuntStatus === 'starting' || githubHuntStatus === 'pausing'
  const isGithubHuntStopping = githubHuntStatus === 'stopping'
  const isGithubHuntPausing = githubHuntStatus === 'pausing'
  const isGithubHuntRunning = isGithubHuntBusy || isGithubHuntStopping
  const isGithubHuntPaused = githubHuntStatus === 'paused'
  const isGithubHuntActive = isGithubHuntRunning || isGithubHuntPaused
  const isTrufflehogBusy = isTrufflehogRunning
  const isTrufflehogActive = isTrufflehogRunning
  const hasActivePartialRecons = activePartialRecons.length > 0
  // What the start and resume routes ask (route manifest): without it the button says why.
  const reconRefused = usePermissionRefused('recon:scan', projectId)
  const gvmRefused = usePermissionRefused('scan:gvm', projectId)

  // Agent status derived values
  const runningAgent = agentConversations.find(c => c.agentRunning)
  const totalConversations = agentConversations.length

  const PHASE_STYLES: Record<string, { color: string; bg: string; icon: typeof Shield }> = {
    informational: { color: '#059669', bg: 'rgba(5, 150, 105, 0.1)', icon: Shield },
    exploitation: { color: 'var(--status-warning)', bg: 'rgba(245, 158, 11, 0.1)', icon: Target },
    post_exploitation: { color: 'var(--status-error)', bg: 'rgba(239, 68, 68, 0.1)', icon: Zap },
  }

  return (
    <div className={styles.toolbar}>
      <WikiInfoButton target="graph" title="Open Red Zone wiki page" />

      {targetLabel && (
        <>
          <div className={styles.divider} />
          <div className={styles.targetSection}>
            {scopeLines.length > 0 ? (
              <div className={styles.subdomainWrapper}>
                <span className={styles.targetDomain}>{targetLabel}</span>
                <div className={styles.subdomainTooltip}>
                  {scopeLines.map(line => <div key={line}>{line}</div>)}
                </div>
              </div>
            ) : (
              <span className={styles.targetDomain}>{targetLabel}</span>
            )}
          </div>
        </>
      )}

      {stealthMode && (
        <>
          <div className={styles.divider} />
          <div className={styles.stealthBadge} title="Stealth Mode is active - passive/low-noise techniques only">
            <StealthIcon size={12} />
            <span>Stealth</span>
          </div>
        </>
      )}

      {engagementLimitsActive && (
        <>
          <div className={styles.divider} />
          <div
            className={styles.roeBadge}
            title="Engagement limits are active - a rate ceiling, an excluded-host list or a scanning window is set, and each is enforced at scan start"
          >
            <Shield size={12} />
            <span>Limits</span>
          </div>
        </>
      )}

      {onSelectVersion && scanVersions.length > 0 && (
        <>
          <div className={styles.divider} />
          <VersionSwitch
            versions={scanVersions}
            selectedVersionId={selectedVersionId}
            onSelect={onSelectVersion}
            onManage={onManageVersions}
            activating={isActivatingVersion}
          />
        </>
      )}

      <div className={styles.divider} />
      <button
        className={`${styles.emergencyPauseButton} ${isEmergencyPausing ? styles.emergencyPauseButtonActive : ''}`}
        onClick={onEmergencyPauseAll}
        disabled={!isAnyPipelineRunning && !isEmergencyPausing}
        title={emergencyPauseTitle(emergencyStopScope)}
      >
        {isEmergencyPausing ? (
          <Loader2 size={14} className={styles.spinner} />
        ) : (
          <ShieldAlert size={14} />
        )}
        <span>{isEmergencyPausing ? 'PAUSING...' : 'PAUSE ALL'}</span>
      </button>

      {(tunnelStatus?.ngrok?.active || tunnelStatus?.chisel?.active) && (
        <div className={styles.tunnelBadges}>
          {tunnelStatus.ngrok?.active && (
            <span className={styles.tunnelBadge} title={`Tunnel active: ${tunnelStatus.ngrok.host}:${tunnelStatus.ngrok.port}`}>
              <span className={styles.tunnelDot} />
              ngrok
            </span>
          )}
          {tunnelStatus.chisel?.active && (
            <span className={styles.tunnelBadge} title={`Tunnel active: ${tunnelStatus.chisel.host}:${tunnelStatus.chisel.port}`}>
              <span className={styles.tunnelDot} />
              chisel
            </span>
          )}
        </div>
      )}

      <div className={styles.spacer} />

      <div className={styles.actionsRight}>
        {/* Recon Actions */}
        {projectId && (
          <>
            <div className={styles.actionGroup}>
              <button
                className={`${styles.reconButton} ${isReconActive ? styles.reconButtonActive : ''}`}
                onClick={isReconPaused ? onResumeRecon : onStartRecon}
                disabled={reconRefused || isReconRunning || hasActivePartialRecons || viewingPastVersion || isActivatingVersion}
                title={reconRefused ? forbiddenNoticeText('recon:scan') : viewingPastVersion ? 'You are viewing a saved version -- switch back to the active version to scan' : isActivatingVersion ? 'A version activation is in progress' : hasActivePartialRecons ? 'Partial recon is running -- stop it first' : isReconStopping ? 'Stopping...' : isReconRunning ? 'Recon in progress...' : isReconPaused ? 'Resume Recon' : 'Start Reconnaissance'}
              >
                {isReconRunning ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Play size={14} />
                )}
                <span>{isReconStopping ? 'Stopping...' : isReconPausing ? 'Pausing...' : isReconBusy ? 'Running...' : isReconPaused ? 'Resume' : 'Start Recon Pipeline'}</span>
              </button>

              {isReconBusy && (
                <button
                  className={styles.pauseButton}
                  onClick={onPauseRecon}
                  disabled={isReconPausing}
                  title={isReconPausing ? 'Pausing...' : 'Pause Recon'}
                >
                  {isReconPausing ? <Loader2 size={14} className={styles.spinner} /> : <Pause size={14} />}
                </button>
              )}

              {isReconActive && (
                <button
                  className={styles.stopButton}
                  onClick={onStopRecon}
                  disabled={isReconStopping}
                  title="Stop Recon"
                >
                  <Square size={14} />
                </button>
              )}

              {isReconActive && (
                <button
                  className={`${styles.logsButton} ${isLogsOpen ? styles.logsButtonActive : ''}`}
                  onClick={onToggleLogs}
                  title="View Logs"
                >
                  <Terminal size={14} />
                </button>
              )}

              <button
                className={styles.downloadButton}
                onClick={onDownloadJSON}
                disabled={!hasReconData || isReconActive || viewingPastVersion}
                title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasReconData ? 'Download Recon JSON' : reconDataError || 'No data available'}
              >
                <Download size={14} />
              </button>
            </div>

            {/* Partial Recon Badges (multi-run) */}
            {hasActivePartialRecons && (
              <PartialReconBadges
                activePartialRecons={activePartialRecons}
                activeLogsRunId={activePartialReconLogsDrawer}
                onToggleLogs={(runId) => onTogglePartialReconLogs?.(runId)}
                onStop={(runId) => onStopPartialRecon?.(runId)}
              />
            )}

            {/* GVM Scan Actions */}
            <div className={styles.actionGroup}>
              <button
                className={`${styles.gvmButton} ${isGvmActive ? styles.gvmButtonActive : ''}`}
                onClick={isGvmPaused ? onResumeGvm : onStartGvm}
                disabled={gvmRefused || !gvmAvailable || isGvmRunning || (!hasReconData && !isGvmPaused) || (stealthMode && !isGvmPaused) || viewingPastVersion || isActivatingVersion}
                title={
                  gvmRefused
                    ? forbiddenNoticeText('scan:gvm')
                    : viewingPastVersion
                    ? 'Viewing a saved version - switch back to the active version to scan'
                    : isActivatingVersion
                    ? 'A version activation is in progress'
                    : !gvmAvailable
                    ? gvmUnavailableReason || GVM_NOT_INSTALLED
                    : stealthMode && !isGvmPaused
                    ? 'GVM scanning is disabled in Stealth Mode (generates ~50,000 active probes per target)'
                    : !hasReconData && !isGvmPaused
                    ? 'Run recon first'
                    : isGvmStopping
                    ? 'Stopping...'
                    : isGvmRunning
                    ? 'GVM scan in progress...'
                    : isGvmPaused
                    ? 'Resume GVM Scan'
                    : 'Start GVM Vulnerability Scan'
                }
              >
                {isGvmRunning ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Shield size={14} />
                )}
                <span>{isGvmStopping ? 'Stopping...' : isGvmPausing ? 'Pausing...' : isGvmBusy ? 'Scanning...' : isGvmPaused ? 'Resume' : 'GVM Scan'}</span>
              </button>

              {isGvmBusy && (
                <button
                  className={styles.pauseButton}
                  onClick={onPauseGvm}
                  disabled={isGvmPausing}
                  title={isGvmPausing ? 'Pausing...' : 'Pause GVM Scan'}
                >
                  {isGvmPausing ? <Loader2 size={14} className={styles.spinner} /> : <Pause size={14} />}
                </button>
              )}

              {isGvmActive && (
                <button
                  className={styles.stopButton}
                  onClick={onStopGvm}
                  disabled={isGvmStopping}
                  title="Stop GVM Scan"
                >
                  <Square size={14} />
                </button>
              )}

              {isGvmActive && (
                <button
                  className={`${styles.logsButton} ${isGvmLogsOpen ? styles.logsButtonActive : ''}`}
                  onClick={onToggleGvmLogs}
                  title="View GVM Logs"
                >
                  <Terminal size={14} />
                </button>
              )}

              <button
                className={styles.downloadButton}
                onClick={onDownloadGvmJSON}
                disabled={!hasGvmData || isGvmActive || viewingPastVersion}
                title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasGvmData ? 'Download GVM JSON' : gvmDataError || 'No GVM data available'}
              >
                <Download size={14} />
              </button>
            </div>

            {/* Other Scans (GitHub Hunt + Secret Multiscanner + Supply Chain) */}
            <div className={styles.actionGroup}>
              <button
                className={`${styles.githubHuntButton} ${(isGithubHuntActive || isTrufflehogActive) ? styles.githubHuntButtonActive : ''}`}
                onClick={onToggleOtherScansModal}
                title="Other Scans (GitHub Hunt, Secret Multiscanner, Supply Chain)"
              >
                {(isGithubHuntRunning || isTrufflehogRunning) ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Github size={14} />
                )}
                <span>{(isGithubHuntBusy || isTrufflehogBusy) ? 'Scanning...' : 'Other Scans'}</span>
              </button>
            </div>

            <ScanStatusWarning errors={scanStatusErrors} />
          </>
        )}

        {/* Agent Status Indicators */}
        {totalConversations > 0 && (
          <div className={styles.agentStatus}>
            {agentActiveCount > 0 ? (
              <div className={styles.agentActiveBadge}>
                <span className={styles.agentDot} />
                <span>{agentActiveCount} active</span>
              </div>
            ) : (
              <div className={styles.agentIdleBadge}>
                <MessageSquare size={10} />
                <span>{totalConversations} chat{totalConversations !== 1 ? 's' : ''}</span>
              </div>
            )}
            {runningAgent && (() => {
              const phase = PHASE_STYLES[runningAgent.currentPhase] || PHASE_STYLES.informational
              const PhaseIcon = phase.icon
              return (
                <div
                  className={styles.agentPhaseBadge}
                  style={{ color: phase.color, backgroundColor: phase.bg, borderColor: phase.color }}
                >
                  <PhaseIcon size={10} />
                  <span>{runningAgent.currentPhase.replace('_', ' ')}</span>
                  {runningAgent.iterationCount > 0 && (
                    <span className={styles.agentStep}>Step {runningAgent.iterationCount}</span>
                  )}
                </div>
              )
            })()}
          </div>
        )}

        <div className={styles.aiButtonGroup}>
          <button
            className={`${styles.aiButton} ${styles.aiButtonGroupStart} ${isAIOpen ? styles.aiButtonActive : ''}`}
            onClick={onToggleAI}
            aria-label="Toggle AI Agent"
            aria-expanded={isAIOpen}
            title="AI Agent"
          >
            <Bot size={14} />
            <span>AI Agent</span>
          </button>
          {onOpenFileSystem && (
            <button
              className={`${styles.aiButton} ${styles.aiButtonGroupEnd} ${isFileSystemOpen ? styles.aiButtonActive : ''}`}
              onClick={onOpenFileSystem}
              aria-label="Toggle Workspace"
              aria-expanded={isFileSystemOpen}
              title="Workspace files + background jobs"
            >
              <FolderOpen size={14} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

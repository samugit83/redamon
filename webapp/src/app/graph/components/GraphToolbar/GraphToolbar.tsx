'use client'

import { Bot, Play, Download, Loader2, Terminal, Shield, Github, Target, Zap, MessageSquare, Pause, Square, ShieldAlert } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Toggle } from '@/components/ui'
import type { ReconStatus, GvmStatus, GithubHuntStatus, TrufflehogStatus, PartialReconState } from '@/lib/recon-types'
import { PartialReconBadges } from '@/components/PartialReconBadges'
import styles from './GraphToolbar.module.css'

interface GraphToolbarProps {
  projectId: string
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  // Target info
  targetDomain?: string
  subdomainList?: string[]
  // Recon props
  onStartRecon?: () => void
  onPauseRecon?: () => void
  onResumeRecon?: () => void
  onStopRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: ReconStatus
  hasReconData?: boolean
  isLogsOpen?: boolean
  // GVM props
  gvmAvailable?: boolean
  onStartGvm?: () => void
  onPauseGvm?: () => void
  onResumeGvm?: () => void
  onStopGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
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
  onStartTrufflehog?: () => void
  onPauseTrufflehog?: () => void
  onResumeTrufflehog?: () => void
  onStopTrufflehog?: () => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: () => void
  trufflehogStatus?: TrufflehogStatus
  hasTrufflehogData?: boolean
  isTrufflehogLogsOpen?: boolean
  // Partial Recon props (multi-run)
  activePartialRecons?: PartialReconState[]
  activePartialReconLogsDrawer?: string | null  // run_id of currently open logs drawer
  onStopPartialRecon?: (runId: string) => void
  onTogglePartialReconLogs?: (runId: string) => void
  // Other Scans modal
  onToggleOtherScansModal?: () => void
  // Stealth mode
  stealthMode?: boolean
  // RoE
  roeEnabled?: boolean
  // Emergency Pause All
  onEmergencyPauseAll?: () => void
  isAnyPipelineRunning?: boolean
  isEmergencyPausing?: boolean
  // Tunnel status (displayed next to Pause All)
  tunnelStatus?: { ngrok?: { active: boolean; host?: string; port?: number }; chisel?: { active: boolean; host?: string; port?: number; srvPort?: number } }
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
  // Target info
  targetDomain,
  subdomainList = [],
  // Recon props
  onStartRecon,
  onPauseRecon,
  onResumeRecon,
  onStopRecon,
  onDownloadJSON,
  onToggleLogs,
  reconStatus = 'idle',
  hasReconData = false,
  isLogsOpen = false,
  // GVM props
  gvmAvailable = true,
  onStartGvm,
  onPauseGvm,
  onResumeGvm,
  onStopGvm,
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  hasGvmData = false,
  isGvmLogsOpen = false,
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
  onStartTrufflehog,
  onPauseTrufflehog,
  onResumeTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogStatus = 'idle',
  hasTrufflehogData = false,
  isTrufflehogLogsOpen = false,
  // Partial Recon props (multi-run)
  activePartialRecons = [],
  activePartialReconLogsDrawer = null,
  onStopPartialRecon,
  onTogglePartialReconLogs,
  // Other Scans modal
  onToggleOtherScansModal,
  // Stealth mode
  stealthMode = false,
  // RoE
  roeEnabled = false,
  // Emergency Pause All
  onEmergencyPauseAll,
  isAnyPipelineRunning = false,
  isEmergencyPausing = false,
  tunnelStatus,
  // Agent status
  agentActiveCount = 0,
  agentConversations = [],
}: GraphToolbarProps) {
  const isReconBusy = reconStatus === 'running' || reconStatus === 'starting'
  const isReconStopping = reconStatus === 'stopping'
  const isReconRunning = isReconBusy || isReconStopping
  const isReconPaused = reconStatus === 'paused'
  const isReconActive = isReconRunning || isReconPaused
  const isGvmBusy = gvmStatus === 'running' || gvmStatus === 'starting'
  const isGvmStopping = gvmStatus === 'stopping'
  const isGvmRunning = isGvmBusy || isGvmStopping
  const isGvmPaused = gvmStatus === 'paused'
  const isGvmActive = isGvmRunning || isGvmPaused
  const isGithubHuntBusy = githubHuntStatus === 'running' || githubHuntStatus === 'starting'
  const isGithubHuntStopping = githubHuntStatus === 'stopping'
  const isGithubHuntRunning = isGithubHuntBusy || isGithubHuntStopping
  const isGithubHuntPaused = githubHuntStatus === 'paused'
  const isGithubHuntActive = isGithubHuntRunning || isGithubHuntPaused
  const isTrufflehogBusy = trufflehogStatus === 'running' || trufflehogStatus === 'starting'
  const isTrufflehogStopping = trufflehogStatus === 'stopping'
  const isTrufflehogRunning = isTrufflehogBusy || isTrufflehogStopping
  const isTrufflehogPaused = trufflehogStatus === 'paused'
  const isTrufflehogActive = isTrufflehogRunning || isTrufflehogPaused
  const hasActivePartialRecons = activePartialRecons.length > 0

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
      {targetDomain && (
        <>
          <div className={styles.divider} />
          <div className={styles.targetSection}>
            {subdomainList.length > 0 && (
              <div className={styles.subdomainWrapper}>
                <span className={styles.subdomainList}>
                  {subdomainList.join(', ')}
                </span>
                <div className={styles.subdomainTooltip}>
                  {subdomainList.join(', ')}
                </div>
              </div>
            )}
            <span className={styles.targetDomain}>{targetDomain}</span>
          </div>
        </>
      )}

      {stealthMode && (
        <>
          <div className={styles.divider} />
          <div className={styles.stealthBadge} title="Stealth Mode is active — passive/low-noise techniques only">
            <StealthIcon size={12} />
            <span>Stealth</span>
          </div>
        </>
      )}

      {roeEnabled && (
        <>
          <div className={styles.divider} />
          <div className={styles.roeBadge} title="Rules of Engagement are active — guardrails enforced on recon and agent">
            <Shield size={12} />
            <span>RoE</span>
          </div>
        </>
      )}

      <div className={styles.divider} />
      <button
        className={`${styles.emergencyPauseButton} ${isEmergencyPausing ? styles.emergencyPauseButtonActive : ''}`}
        onClick={onEmergencyPauseAll}
        disabled={!isAnyPipelineRunning && !isEmergencyPausing}
        title="EMERGENCY PAUSE — Freeze all running containers immediately. Use if scanning or exploiting unwanted targets."
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
                disabled={isReconRunning || hasActivePartialRecons}
                title={hasActivePartialRecons ? 'Partial recon is running -- stop it first' : isReconStopping ? 'Stopping...' : isReconRunning ? 'Recon in progress...' : isReconPaused ? 'Resume Recon' : 'Start Reconnaissance'}
              >
                {isReconRunning ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Play size={14} />
                )}
                <span>{isReconStopping ? 'Stopping...' : isReconBusy ? 'Running...' : isReconPaused ? 'Resume' : 'Start Recon Pipeline'}</span>
              </button>

              {isReconBusy && (
                <button
                  className={styles.pauseButton}
                  onClick={onPauseRecon}
                  title="Pause Recon"
                >
                  <Pause size={14} />
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
                disabled={!hasReconData || isReconActive}
                title={hasReconData ? 'Download Recon JSON' : 'No data available'}
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
                disabled={!gvmAvailable || isGvmRunning || (!hasReconData && !isGvmPaused) || (stealthMode && !isGvmPaused)}
                title={
                  !gvmAvailable
                    ? 'GVM is not installed. Run ./redamon.sh install --gvm to enable vulnerability scanning'
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
                <span>{isGvmStopping ? 'Stopping...' : isGvmBusy ? 'Scanning...' : isGvmPaused ? 'Resume' : 'GVM Scan'}</span>
              </button>

              {isGvmBusy && (
                <button
                  className={styles.pauseButton}
                  onClick={onPauseGvm}
                  title="Pause GVM Scan"
                >
                  <Pause size={14} />
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
                disabled={!hasGvmData || isGvmActive}
                title={hasGvmData ? 'Download GVM JSON' : 'No GVM data available'}
              >
                <Download size={14} />
              </button>
            </div>

            {/* Other Scans (GitHub Hunt + TruffleHog) */}
            <div className={styles.actionGroup}>
              <button
                className={`${styles.githubHuntButton} ${(isGithubHuntActive || isTrufflehogActive) ? styles.githubHuntButtonActive : ''}`}
                onClick={onToggleOtherScansModal}
                title="Other Scans (GitHub Hunt, TruffleHog)"
              >
                {(isGithubHuntRunning || isTrufflehogRunning) ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Github size={14} />
                )}
                <span>{(isGithubHuntBusy || isTrufflehogBusy) ? 'Scanning...' : 'Other Scans'}</span>
              </button>
            </div>
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

        <button
          className={`${styles.aiButton} ${isAIOpen ? styles.aiButtonActive : ''}`}
          onClick={onToggleAI}
          aria-label="Toggle AI Agent"
          aria-expanded={isAIOpen}
          title="AI Agent"
        >
          <Bot size={14} />
          <span>AI Agent</span>
        </button>
      </div>
    </div>
  )
}

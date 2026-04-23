'use client'

import { Play, Pause, Square, Terminal, Download, Loader2, Github, Search, AlertTriangle } from 'lucide-react'
import Link from 'next/link'
import { Modal } from '@/components/ui'
import type { GithubHuntStatus, TrufflehogStatus } from '@/lib/recon-types'
import styles from './OtherScansModal.module.css'

interface OtherScansModalProps {
  isOpen: boolean
  onClose: () => void
  hasReconData: boolean
  hasGithubToken: boolean
  // GitHub Hunt
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // TruffleHog
  onStartTrufflehog?: () => void
  onPauseTrufflehog?: () => void
  onResumeTrufflehog?: () => void
  onStopTrufflehog?: () => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: () => void
  trufflehogStatus?: TrufflehogStatus
  hasTrufflehogData?: boolean
  isTrufflehogLogsOpen?: boolean
}

function StatusBadge({ status }: { status: string }) {
  const styleMap: Record<string, string> = {
    idle: styles.statusIdle,
    starting: styles.statusRunning,
    running: styles.statusRunning,
    paused: styles.statusPaused,
    stopping: styles.statusRunning,
    completed: styles.statusCompleted,
    error: styles.statusError,
  }
  return (
    <span className={`${styles.statusBadge} ${styleMap[status] || styles.statusIdle}`}>
      {status}
    </span>
  )
}

export function OtherScansModal({
  isOpen,
  onClose,
  hasReconData,
  hasGithubToken,
  // GitHub Hunt
  onStartGithubHunt,
  onPauseGithubHunt,
  onResumeGithubHunt,
  onStopGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  // TruffleHog
  onStartTrufflehog,
  onPauseTrufflehog,
  onResumeTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogStatus = 'idle',
  hasTrufflehogData = false,
  isTrufflehogLogsOpen = false,
}: OtherScansModalProps) {
  // GitHub Hunt derived state
  const isGHBusy = githubHuntStatus === 'running' || githubHuntStatus === 'starting'
  const isGHStopping = githubHuntStatus === 'stopping'
  const isGHRunning = isGHBusy || isGHStopping
  const isGHPaused = githubHuntStatus === 'paused'
  const isGHActive = isGHRunning || isGHPaused

  // TruffleHog derived state
  const isTHBusy = trufflehogStatus === 'running' || trufflehogStatus === 'starting'
  const isTHStopping = trufflehogStatus === 'stopping'
  const isTHRunning = isTHBusy || isTHStopping
  const isTHPaused = trufflehogStatus === 'paused'
  const isTHActive = isTHRunning || isTHPaused

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Other Scans"
      size="large"
    >
      <div className={styles.content}>
        {/* GitHub Secret Hunt Card */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Github size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>GitHub Secret Hunt</h3>
            <StatusBadge status={githubHuntStatus} />
          </div>
          <p className={styles.cardDescription}>
            Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain.
          </p>
          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '6px',
            }}>
              <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href="/settings" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Global Settings
                </Link>
              </span>
            </div>
          )}
          <div className={styles.cardActions}>
            {isGHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeGithubHunt}
                disabled={!hasGithubToken}
                title={!hasGithubToken ? 'GitHub token required' : 'Resume GitHub Hunt'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartGithubHunt}
                disabled={!hasGithubToken || isGHRunning || (!hasReconData && !isGHPaused)}
                title={!hasGithubToken ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isGHRunning ? 'In progress...' : 'Start GitHub Hunt'}
              >
                {isGHRunning ? (
                  <Loader2 size={12} className={styles.spinner} />
                ) : (
                  <Play size={12} />
                )}
                <span>{isGHBusy ? 'Running...' : isGHStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}

            {isGHBusy && (
              <button
                className={styles.pauseButton}
                onClick={onPauseGithubHunt}
                title="Pause"
              >
                <Pause size={12} />
                <span>Pause</span>
              </button>
            )}

            {isGHActive && (
              <button
                className={styles.stopButton}
                onClick={onStopGithubHunt}
                disabled={isGHStopping}
                title="Stop"
              >
                <Square size={12} />
                <span>Stop</span>
              </button>
            )}

            <button
              className={`${styles.logsButton} ${isGithubHuntLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleGithubHuntLogs}
              disabled={!isGHActive}
              title="View Logs"
            >
              <Terminal size={12} />
              <span>Logs</span>
            </button>

            <button
              className={styles.downloadButton}
              onClick={onDownloadGithubHuntJSON}
              disabled={!hasGithubHuntData || isGHActive}
              title={hasGithubHuntData ? 'Download JSON' : 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>
          </div>
        </div>

        {/* TruffleHog Scanner Card */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Search size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>TruffleHog Scanner</h3>
            <StatusBadge status={trufflehogStatus} />
          </div>
          <p className={styles.cardDescription}>
            Deep secret scanning with 700+ detectors and optional verification against live APIs.
          </p>
          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '6px',
            }}>
              <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href="/settings" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Global Settings
                </Link>
              </span>
            </div>
          )}
          <div className={styles.cardActions}>
            {isTHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeTrufflehog}
                disabled={!hasGithubToken}
                title={!hasGithubToken ? 'GitHub token required' : 'Resume TruffleHog'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartTrufflehog}
                disabled={!hasGithubToken || isTHRunning || (!hasReconData && !isTHPaused)}
                title={!hasGithubToken ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isTHRunning ? 'In progress...' : 'Start TruffleHog'}
              >
                {isTHRunning ? (
                  <Loader2 size={12} className={styles.spinner} />
                ) : (
                  <Play size={12} />
                )}
                <span>{isTHBusy ? 'Running...' : isTHStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}

            {isTHBusy && (
              <button
                className={styles.pauseButton}
                onClick={onPauseTrufflehog}
                title="Pause"
              >
                <Pause size={12} />
                <span>Pause</span>
              </button>
            )}

            {isTHActive && (
              <button
                className={styles.stopButton}
                onClick={onStopTrufflehog}
                disabled={isTHStopping}
                title="Stop"
              >
                <Square size={12} />
                <span>Stop</span>
              </button>
            )}

            <button
              className={`${styles.logsButton} ${isTrufflehogLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleTrufflehogLogs}
              disabled={!isTHActive}
              title="View Logs"
            >
              <Terminal size={12} />
              <span>Logs</span>
            </button>

            <button
              className={styles.downloadButton}
              onClick={onDownloadTrufflehogJSON}
              disabled={!hasTrufflehogData || isTHActive}
              title={hasTrufflehogData ? 'Download JSON' : 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>
          </div>
        </div>
      </div>
    </Modal>
  )
}

export default OtherScansModal

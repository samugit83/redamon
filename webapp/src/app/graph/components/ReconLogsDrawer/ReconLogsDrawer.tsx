'use client'

import { useEffect, useRef, useState } from 'react'
import { X, Terminal, CheckCircle, AlertCircle, Pause, Play, Trash2, Square, Loader2, Download } from 'lucide-react'
import { RECON_PHASES } from '@/lib/recon-types'
import type { ReconLogEvent, ReconStatus } from '@/lib/recon-types'
import styles from './ReconLogsDrawer.module.css'

interface ReconLogsDrawerProps {
  isOpen: boolean
  onClose: () => void
  logs: ReconLogEvent[]
  currentPhase: string | null
  currentPhaseNumber: number | null
  status: ReconStatus
  onClearLogs: () => void
  onPause?: () => void
  onResume?: () => void
  onStop?: () => void
  title?: string
  phases?: readonly string[]
  totalPhases?: number
  errorMessage?: string | null
  hidePhaseProgress?: boolean
}

export function ReconLogsDrawer({
  isOpen,
  onClose,
  logs,
  currentPhase,
  currentPhaseNumber,
  status,
  onClearLogs,
  onPause,
  onResume,
  onStop,
  title = 'Reconnaissance Logs',
  phases = RECON_PHASES,
  totalPhases = 7,
  errorMessage,
  hidePhaseProgress = false,
}: ReconLogsDrawerProps) {
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  // Detect manual scroll to disable auto-scroll
  const handleScroll = () => {
    if (!logsContainerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logsContainerRef.current
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50
    setAutoScroll(isAtBottom)
  }

  const getStatusIcon = () => {
    switch (status) {
      case 'running':
      case 'starting':
        return <div className={styles.runningIndicator} />
      case 'paused':
        return <Pause size={14} className={styles.pausedIcon} />
      case 'stopping':
        return <Loader2 size={14} className={styles.spinner} />
      case 'completed':
        return <CheckCircle size={14} className={styles.successIcon} />
      case 'error':
        return <AlertCircle size={14} className={styles.errorIcon} />
      default:
        return <Terminal size={14} />
    }
  }

  const getStatusText = () => {
    switch (status) {
      case 'starting':
        return 'Starting...'
      case 'running':
        if (!currentPhase) return 'Running...'
        return hidePhaseProgress
          ? `Scanning: ${currentPhase}`
          : `Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'paused':
        if (!currentPhase) return 'Paused'
        return hidePhaseProgress
          ? `Paused: ${currentPhase}`
          : `Paused — Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'completed':
        return 'Completed'
      case 'error':
        return errorMessage ? `Error: ${errorMessage}` : 'Error'
      case 'stopping':
        return 'Stopping...'
      default:
        return 'Idle'
    }
  }

  const handleDownloadLogs = () => {
    if (logs.length === 0) return

    const lines = logs.map(log => {
      const ts = new Date(log.timestamp).toISOString()
      const level = log.level.toUpperCase().padEnd(7)
      const phase = log.phase ? ` [${log.phase}]` : ''
      return `${ts}  ${level}${phase}  ${log.log}`
    })

    // Add header
    const header = [
      `# ${title}`,
      `# Status: ${status}`,
      `# Phase: ${currentPhase || 'N/A'} (${currentPhaseNumber || 0}/${totalPhases})`,
      `# Exported: ${new Date().toISOString()}`,
      `# Total lines: ${logs.length}`,
      '',
    ]

    const content = [...header, ...lines].join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    // Sanitize title for filename
    const safeName = title.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/_+$/, '')
    a.download = `${safeName}_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.log`
    a.click()
    URL.revokeObjectURL(url)
  }

  const getLogClassName = (level: string) => {
    switch (level) {
      case 'error':
        return styles.logError
      case 'warning':
        return styles.logWarning
      case 'success':
        return styles.logSuccess
      case 'action':
        return styles.logAction
      default:
        return styles.logInfo
    }
  }

  return (
    <div className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.titleContainer}>
          <Terminal size={16} />
          <span>{title}</span>
        </div>
        <button
          className={styles.closeButton}
          onClick={onClose}
          aria-label="Close drawer"
        >
          <X size={16} />
        </button>
      </div>

      {/* Status bar */}
      <div className={styles.statusBar}>
        <div className={styles.statusLeft}>
          {getStatusIcon()}
          <span className={styles.statusText} title={getStatusText()}>{getStatusText()}</span>
        </div>
        <div className={styles.statusActions}>
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${status === 'paused' ? styles.iconButtonPaused : ''}`}
              onClick={status === 'paused' ? onResume : onPause}
              title={status === 'paused' ? 'Resume pipeline' : 'Pause pipeline'}
            >
              {status === 'paused' ? <Play size={14} /> : <Pause size={14} />}
            </button>
          )}
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${styles.iconButtonStop}`}
              onClick={onStop}
              title="Stop pipeline"
            >
              <Square size={14} />
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={handleDownloadLogs}
            disabled={logs.length === 0}
            title="Download logs"
          >
            <Download size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={onClearLogs}
            title="Clear logs"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Phase progress (hidden for single-phase partial recon) */}
      {!hidePhaseProgress && (
        <div className={styles.phaseProgress}>
          {phases.map((phase, index) => {
            const phaseNum = index + 1
            const isActive = currentPhaseNumber === phaseNum
            const isCompleted = currentPhaseNumber !== null && phaseNum < currentPhaseNumber
            const isPending = currentPhaseNumber === null || phaseNum > currentPhaseNumber

            return (
              <div
                key={phase}
                className={`${styles.phaseItem} ${isActive ? styles.phaseActive : ''} ${isCompleted ? styles.phaseCompleted : ''} ${isPending ? styles.phasePending : ''}`}
                title={phase}
              >
                <span className={styles.phaseNumber}>{phaseNum}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Logs container */}
      <div
        ref={logsContainerRef}
        className={styles.logsContainer}
        onScroll={handleScroll}
      >
        {logs.length === 0 ? (
          <div className={styles.emptyLogs}>
            <Terminal size={24} />
            <p>Waiting for logs...</p>
          </div>
        ) : (
          <>
            {logs.map((log, index) => (
              <div
                key={index}
                className={`${styles.logLine} ${getLogClassName(log.level)}`}
              >
                <span className={styles.logTimestamp}>
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={styles.logMessage}>{log.log}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </>
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && (
        <button
          className={styles.scrollToBottom}
          onClick={() => {
            setAutoScroll(true)
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
          }}
        >
          Scroll to bottom
        </button>
      )}
    </div>
  )
}

export default ReconLogsDrawer

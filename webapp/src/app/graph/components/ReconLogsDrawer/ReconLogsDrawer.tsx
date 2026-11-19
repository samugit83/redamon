'use client'

import { useEffect, useRef, useState } from 'react'
import { useNavigatorObstacle } from '@/components/navigator/obstacles'
import { X, Terminal, CheckCircle, AlertCircle, Pause, Play, Trash2, Square, Loader2, Download } from 'lucide-react'
import { RECON_TOTAL_PHASES, type ReconLogEvent, type ReconStatus } from '@/lib/recon-types'
import styles from './ReconLogsDrawer.module.css'
import { nodeFilterLineKind } from './nodeFilterLog'

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
  totalPhases?: number
  errorMessage?: string | null
  /** The log stream's own failure (lost, or refused with a status); shown while the run is live. */
  streamError?: string | null
  /**
   * The status hook's last failure, shown as is: its text already names what
   * failed ("GVM status unavailable (…)", "Failed to stop recon (…)"). The
   * status shown is then the last known one.
   */
  statusError?: string | null
  hidePhaseProgress?: boolean
  /** Domain batch: the OUTER progress. Phases restart at 1 for every group, so
   *  "Phase 3/6" alone reads as the scan going backwards when group 2 starts. */
  currentGroup?: string | null
  groupNumber?: number | null
  totalGroups?: number | null
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
  totalPhases = RECON_TOTAL_PHASES,
  errorMessage,
  streamError = null,
  statusError = null,
  hidePhaseProgress = false,
  currentGroup = null,
  groupNumber = null,
  totalGroups = null,
}: ReconLogsDrawerProps) {
  // Prefix every status line with the batch's scope group, so a phase counter
  // restarting reads as "next scan root" rather than "the scan went backwards".
  // The orchestrator's marker carries the group's scan root (one token).
  const groupPrefix = groupNumber && totalGroups
    ? `Scope group ${groupNumber}/${totalGroups}${currentGroup ? ` (scan root ${currentGroup})` : ''} - `
    : ''
  const isLive = status === 'running' || status === 'starting' || status === 'paused'
    || status === 'pausing' || status === 'stopping'
  // A finished run closes its stream on purpose; only a live one has lost something.
  const notices = [
    statusError || null,
    streamError && isLive ? `Log stream: ${streamError}` : null,
  ].filter((n): n is string => !!n)
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  const navigatorObstacleRef = useRef<HTMLDivElement>(null)
  useNavigatorObstacle(navigatorObstacleRef, isOpen)
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
      case 'pausing':
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
        if (!currentPhase) return `${groupPrefix}Running...`
        return hidePhaseProgress
          ? `${groupPrefix}Scanning: ${currentPhase}`
          : `${groupPrefix}Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'paused':
        if (!currentPhase) return `${groupPrefix}Paused`
        return hidePhaseProgress
          ? `${groupPrefix}Paused: ${currentPhase}`
          : `${groupPrefix}Paused - Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'completed':
        return 'Completed'
      case 'error':
        return errorMessage ? `Error: ${errorMessage}` : 'Error'
      case 'pausing':
        return 'Pausing...'
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

  // Highlight the union target-list breakdown emitted by build_target_urls
  // (e.g. "[*][Targets] Merged 50 URLs: 2 additional httpx URLs + 48 unprobed
  // subdomains"). Easy to spot when scrolling through verbose scan logs.
  const isTargetsLine = (logText: string) =>
    logText.includes('[Targets]') &&
    (logText.includes('Merged ') || logText.includes('No targets'))

  // Memory governor (Part 5): the pipeline emits "[RESOURCE-CAP] <tool> <PARAM>
  // <env> -> <eff> ..." whenever it throttles a parameter to fit available RAM.
  // Render those red so the user plainly sees when/what was capped.
  const isResourceCapLine = (logText: string) => logText.includes('[RESOURCE-CAP]')

  // Circuit breakers: the pipeline emits "[!][DEGRADED]..." when it could not
  // fully re-check a source or host (a breaker opened, a host went unreachable).
  // Render those amber so a partial run is plain in the log.
  const isDegradedLine = (logText: string) => logText.includes('[!][DEGRADED]')

  const nodeFilterClass = (logText: string) => {
    const kind = nodeFilterLineKind(logText)
    if (kind === 'summary') return ` ${styles.logNodeFilter}`
    if (kind === 'problem') return ` ${styles.logNodeFilter} ${styles.logNodeFilterProblem}`
    return ''
  }

  return (
    <div ref={navigatorObstacleRef} className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}>
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
          {(status === 'running' || status === 'paused' || status === 'pausing') && (
            <button
              className={`${styles.iconButton} ${status === 'paused' ? styles.iconButtonPaused : ''}`}
              onClick={status === 'paused' ? onResume : onPause}
              disabled={status === 'pausing'}
              title={status === 'pausing' ? 'Pausing...' : status === 'paused' ? 'Resume pipeline' : 'Pause pipeline'}
            >
              {status === 'pausing'
                ? <Loader2 size={14} className={styles.spinner} />
                : status === 'paused' ? <Play size={14} /> : <Pause size={14} />}
            </button>
          )}
          {(status === 'running' || status === 'paused' || status === 'pausing') && (
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

      {notices.map(notice => (
        <div key={notice} className={styles.streamNotice} role="alert">
          <AlertCircle size={12} />
          <span>{notice}</span>
        </div>
      ))}

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
                className={`${styles.logLine} ${getLogClassName(log.level)}${
                  isTargetsLine(log.log) ? ` ${styles.logTargets}` : ''
                }${isResourceCapLine(log.log) ? ` ${styles.logResourceCap}` : ''}${
                  isDegradedLine(log.log) ? ` ${styles.logDegraded}` : ''
                }${nodeFilterClass(log.log)}`}
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

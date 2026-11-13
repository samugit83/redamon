'use client'

import { Download, Loader2, Shield, Github, Pause, Square } from 'lucide-react'
import type { ScanControls } from '@/hooks/useScanControls'
import { useToast } from '@/components/ui'
import { ScanStatusWarning } from './ScanStatusWarning'
import { useRefusal } from '@/hooks/useRefusal'
import styles from '@/app/graph/components/GraphToolbar/GraphToolbar.module.css'

/**
 * The graph toolbar's scan cluster, usable outside the graph page.
 *
 * It imports GraphToolbar.module.css on purpose rather than restyling: these
 * are meant to be the SAME buttons, and a second stylesheet would drift from
 * the original the first time either is touched.
 *
 * State comes from useScanControls, which owns the polling. This component is
 * presentational.
 */
export function ScanActions({
  scans,
  showReconDownload = true,
  disabledReason = '',
  stealthMode = false,
}: {
  scans: ScanControls
  /** The recon download; off where the surface already has its own. */
  showReconDownload?: boolean
  /** Non-empty disables every action and explains why (e.g. a past version). */
  disabledReason?: string
  /** The project's Stealth Mode, which bars GVM the same way the graph does. */
  stealthMode?: boolean
}) {
  const { gvm, githubHunt, trufflehog } = scans
  const toast = useToast()
  const blocked = Boolean(disabledReason)
  // GVM's start, resume, pause and stop ask scan:gvm on the open project, as on the graph toolbar.
  const gvmRefusal = useRefusal('scan:gvm')?.text ?? ''

  // The graph toolbar's GVM preconditions, kept in the same order so the two
  // surfaces agree on WHY the button is off, not just that it is.
  const gvmBlockedReason =
    disabledReason ? disabledReason
    : gvmRefusal ? gvmRefusal
    : !gvm.isAvailable ? gvm.unavailableReason
    : stealthMode && !gvm.isPaused ? 'GVM scanning is disabled in Stealth Mode (generates ~50,000 active probes per target)'
    : !scans.hasReconData && !gvm.isPaused ? 'Run recon first'
    : ''

  return (
    <>
      {showReconDownload && (
        <button
          type="button"
          className={styles.downloadButton}
          onClick={() => void scans.downloadReconJSON().then(error => { if (error) toast.error(error) })}
          disabled={!scans.hasReconData || blocked}
          title={disabledReason || (scans.hasReconData ? 'Download Recon JSON' : scans.reconDataError || 'No data available')}
        >
          <Download size={14} />
        </button>
      )}

      <div className={styles.actionGroup}>
        <button
          type="button"
          className={`${styles.gvmButton} ${gvm.isActive ? styles.gvmButtonActive : ''}`}
          onClick={() => void (gvm.isPaused ? gvm.resumeGvm() : gvm.start())}
          disabled={Boolean(gvmBlockedReason) || gvm.isRunning}
          title={
            gvmBlockedReason ||
            (gvm.isStopping ? 'Stopping...'
              : gvm.isRunning ? 'GVM scan in progress...'
              : gvm.isPaused ? 'Resume GVM Scan'
              : 'Start GVM Vulnerability Scan')
          }
        >
          {gvm.isRunning ? <Loader2 size={14} className={styles.spinner} /> : <Shield size={14} />}
          <span>
            {gvm.isStopping ? 'Stopping...'
              : gvm.isPausing ? 'Pausing...'
              : gvm.isBusy ? 'Scanning...'
              : gvm.isPaused ? 'Resume'
              : 'GVM Scan'}
          </span>
        </button>

        {gvm.isBusy && (
          <button
            type="button"
            className={styles.pauseButton}
            onClick={() => void gvm.pauseGvm()}
            disabled={gvm.isPausing || !!gvmRefusal}
            title={gvmRefusal || (gvm.isPausing ? 'Pausing...' : 'Pause GVM Scan')}
          >
            <Pause size={14} />
          </button>
        )}

        {gvm.isActive && (
          <button
            type="button"
            className={styles.stopButton}
            onClick={() => void gvm.stopGvm()}
            disabled={gvm.isStopping || !!gvmRefusal}
            title={gvmRefusal || 'Stop GVM Scan'}
          >
            <Square size={14} />
          </button>
        )}

        <button
          type="button"
          className={styles.downloadButton}
          onClick={gvm.download}
          disabled={!gvm.hasData || gvm.isRunning || blocked}
          title={disabledReason || (gvm.hasData ? 'Download GVM JSON' : gvm.dataError || 'No data available')}
        >
          <Download size={14} />
        </button>
      </div>

      <div className={styles.actionGroup}>
        <button
          type="button"
          className={`${styles.githubHuntButton} ${(githubHunt.isActive || trufflehog.isActive) ? styles.githubHuntButtonActive : ''}`}
          onClick={scans.toggleOtherScans}
          title="Other Scans (GitHub Hunt, Secret Multiscanner, Supply Chain)"
        >
          {(githubHunt.isRunning || trufflehog.isRunning)
            ? <Loader2 size={14} className={styles.spinner} />
            : <Github size={14} />}
          <span>{(githubHunt.isBusy || trufflehog.isRunning) ? 'Scanning...' : 'Other Scans'}</span>
        </button>
      </div>

      <ScanStatusWarning errors={scans.statusErrors} />
    </>
  )
}

'use client'

import { Play, Pause, Square, Terminal, Download, Loader2, Github, Search, AlertTriangle, PackageSearch, Settings } from 'lucide-react'
import Link from 'next/link'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys } from '@/hooks/useCredentialKeys'
import { TRUFFLEHOG_SOURCES } from '@/lib/trufflehogSources'
import type { TrufflehogProfileSummary } from '@/hooks/useTrufflehogRuns'
import { projectSettingsHref, type ProjectSectionAnchor } from '@/lib/projectSettingsLinks'
import { Modal, WikiInfoButton } from '@/components/ui'
import type { GithubHuntStatus, TrufflehogStatus, SupplyChainStatus } from '@/lib/recon-types'
import { ScanStatusWarning } from '@/components/scans/ScanStatusWarning'
import { usePermissionRefused } from '@/hooks/useCan'
import { ForbiddenNotice, forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import { useSupplyChainConfig } from './useSupplyChainConfig'
import { SupplyChainOrgBatchButton } from './SupplyChainOrgBatchButton'
import styles from './OtherScansModal.module.css'

interface OtherScansModalProps {
  isOpen: boolean
  onClose: () => void
  hasReconData: boolean
  hasGithubToken: boolean
  /** True while a PAST version is being viewed: these scans write the LIVE graph,
   *  and the downloadable JSON is always the latest scan, so both are disabled. */
  viewingPastVersion?: boolean
  /** True while a version activation (graph swap) is in flight. */
  isActivatingVersion?: boolean
  // GitHub Hunt
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  /** The run's own failure reason (state.error), shown on the badge of a failed run. */
  githubHuntError?: string | null
  /** Why the status could not be read; the badge then shows the last known one. */
  githubHuntStatusError?: string | null
  hasGithubHuntData?: boolean
  /** Set when the data check itself failed, so the disabled download does not claim "no data". */
  githubHuntDataError?: string | null
  isGithubHuntLogsOpen?: boolean
  // TruffleHog — run-keyed: one row per configured SOURCE, each with its own
  // status, Start, Stop and Logs. A single project-level set of controls could
  // only ever drive one of N parallel runs.
  onStartTrufflehog?: (source: string) => void
  onStopTrufflehog?: (source: string) => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: (source: string) => void
  /** One entry per configured source, from /api/trufflehog/{id}/profiles. */
  trufflehogProfiles?: TrufflehogProfileSummary[]
  /** Why the source list could not be read: then "no sources" would be a false answer. */
  trufflehogProfilesError?: string | null
  /** Live run state keyed by source, from /api/trufflehog/{id}/all. */
  trufflehogRunsBySource?: Record<string, { status: TrufflehogStatus; target?: string; error?: string | null } | undefined>
  trufflehogStatusError?: string | null
  hasTrufflehogData?: boolean
  trufflehogDataError?: string | null
  /** Which source's log drawer is open, if any. */
  openTrufflehogLogsSource?: string | null

  // Supply Chain (L1)
  onStartSupplyChain?: () => void
  onPauseSupplyChain?: () => void
  onResumeSupplyChain?: () => void
  onStopSupplyChain?: () => void
  onDownloadSupplyChainJSON?: () => void
  onToggleSupplyChainLogs?: () => void
  supplyChainStatus?: SupplyChainStatus
  supplyChainError?: string | null
  supplyChainStatusError?: string | null
  hasSupplyChainData?: boolean
  supplyChainDataError?: string | null
  isSupplyChainLogsOpen?: boolean
  /** Needed to read the configured scan input and to link into project settings.
   *  Without it every card renders read-only. */
  projectId?: string
  /** Set by a host that IS the project settings page: an href to that same page
   *  only swaps the hash, which fires no navigation, so the modal would stay
   *  open on top of a form that never moved. The host opens the section itself. */
  onOpenProjectSettings?: (anchor: ProjectSectionAnchor) => void
}

function StatusBadge({ status, error }: { status: string; error?: string | null }) {
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
    <span
      className={`${styles.statusBadge} ${styleMap[status] || styles.statusIdle}`}
      title={status === 'error' && error ? error : undefined}
    >
      {status}
    </span>
  )
}

/** What the Supply-Chain card says it would read, per configured source. */
const SUPPLY_CHAIN_INPUT_LABEL = {
  upload: 'SBOM / lockfile',
  github: 'Repository',
  org: 'Organization',
} as const

export function OtherScansModal({
  isOpen,
  onClose,
  hasReconData,
  hasGithubToken,
  viewingPastVersion = false,
  isActivatingVersion = false,
  // GitHub Hunt
  onStartGithubHunt,
  onPauseGithubHunt,
  onResumeGithubHunt,
  onStopGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  githubHuntError = null,
  githubHuntStatusError = null,
  hasGithubHuntData = false,
  githubHuntDataError = null,
  isGithubHuntLogsOpen = false,
  // TruffleHog
  onStartTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogProfiles = [],
  trufflehogProfilesError = null,
  trufflehogRunsBySource = {},
  trufflehogStatusError = null,
  hasTrufflehogData = false,
  trufflehogDataError = null,
  openTrufflehogLogsSource = null,

  // Supply Chain (L1)
  onStartSupplyChain,
  onPauseSupplyChain,
  onResumeSupplyChain,
  onStopSupplyChain,
  onDownloadSupplyChainJSON,
  onToggleSupplyChainLogs,
  supplyChainStatus = 'idle',
  supplyChainError = null,
  supplyChainStatusError = null,
  hasSupplyChainData = false,
  supplyChainDataError = null,
  isSupplyChainLogsOpen = false,
  projectId,
  onOpenProjectSettings,
}: OtherScansModalProps) {
  // GitHub Hunt derived state
  const isGHBusy = githubHuntStatus === 'running' || githubHuntStatus === 'starting' || githubHuntStatus === 'pausing'
  const isGHStopping = githubHuntStatus === 'stopping'
  const isGHPausing = githubHuntStatus === 'pausing'
  const isGHRunning = isGHBusy || isGHStopping
  const isGHPaused = githubHuntStatus === 'paused'
  const isGHActive = isGHRunning || isGHPaused

  // TruffleHog derived state: aggregated across every source, used only for the
  // card-level badge and the Download button (the JSON download is per project).
  const trufflehogStatuses = trufflehogProfiles
    .map(p => trufflehogRunsBySource[p.source]?.status ?? 'idle')
  const isTHActive = trufflehogStatuses.some(
    st => st === 'running' || st === 'starting' || st === 'stopping')
  const trufflehogCardStatus: TrufflehogStatus =
    trufflehogStatuses.find(st => st === 'running' || st === 'starting') ??
    (trufflehogStatuses.includes('error') ? 'error'
      : trufflehogStatuses.includes('completed') ? 'completed' : 'idle')

  // WHAT the supply-chain scan reads is configured in project settings, so the
  // card reads the saved project to know whether Start can be enabled at all.
  // Re-read every time the modal opens: the settings may have changed since.
  const supplyChain = useSupplyChainConfig(projectId, isOpen)

  // The keys the scan cards below can set in place. `hasGithubToken` is resolved
  // by the page that owns this modal and does not change when a key is saved
  // here, so the live value is OR-ed in to release the Start button at once.
  const credentialKeys = useCredentialKeys()
  const githubTokenSet = hasGithubToken || credentialKeys.isSet('githubAccessToken')

  // Supply Chain derived state
  const isSCBusy = supplyChainStatus === 'running' || supplyChainStatus === 'starting' || supplyChainStatus === 'pausing'
  const isSCStopping = supplyChainStatus === 'stopping'
  const isSCPausing = supplyChainStatus === 'pausing'
  const isSCRunning = isSCBusy || isSCStopping
  const isSCPaused = supplyChainStatus === 'paused'
  const isSCActive = isSCRunning || isSCPaused

  // Read-only past version (or an in-flight swap): no scan may start/resume, and the
  // JSON download is disabled because it would return the latest scan, not this view.
  const scanBlocked = viewingPastVersion || isActivatingVersion
  // What each card's start and resume routes ask (route manifest); a refused card says why (UI-12).
  const secretsRefused = usePermissionRefused('scan:secrets', projectId)
  const supplyChainRefused = usePermissionRefused('scan:supply_chain', projectId)
  const blockedTitle = viewingPastVersion
    ? 'Viewing a saved version - switch back to the active version to run scans'
    : 'A version activation is in progress'

  // A settings href that points at the page ALREADY under the modal only swaps
  // the hash: no navigation, no unmount, so the click would look dead. The host
  // opens the section (and closes the modal) itself in that case.
  const settingsLinkProps = (section: ProjectSectionAnchor) =>
    onOpenProjectSettings
      ? {
          onClick: (e: React.MouseEvent) => {
            e.preventDefault()
            onOpenProjectSettings(section)
          },
        }
      : {}

  const supplyChainSettingsLink = projectId && (
    <Link
      href={projectSettingsHref(projectId, 'supply-chain-scanner')}
      {...settingsLinkProps('supply-chain-scanner')}
      style={{ color: 'var(--accent-primary)', fontWeight: 500 }}
    >
      Set it in project settings
    </Link>
  )

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Other Scans"
      size="large"
      className={styles.wideModal}
    >
      <div className={styles.content}>
        {/* Two columns: the two half-height cards on the left, and the Secret
            Multiscanner on the right spanning both rows - it lists one row per
            configured source, so it is the card that actually grows. */}
        <div className={styles.grid}>
        {/* GitHub Secret Hunt Card */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <Github size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>GitHub Secret Hunt</h3>
            <WikiInfoButton target="Github" title="GitHub Secret Hunting wiki" />
            <StatusBadge status={githubHuntStatus} error={githubHuntError} />
            <ScanStatusWarning errors={[githubHuntStatusError]} />
          </div>
          <p className={styles.cardDescription}>
            Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain.
          </p>
          {secretsRefused && <ForbiddenNotice permission="scan:secrets" />}
          {!githubTokenSet && (
            <CredentialShortcut settingsKey="githubAccessToken" keys={credentialKeys} compact />
          )}
          <div className={styles.cardActions}>
            {isGHPaused ? (
              <button
                className={styles.resumeButton}
                onClick={onResumeGithubHunt}
                disabled={secretsRefused || !githubTokenSet || scanBlocked}
                title={secretsRefused ? forbiddenNoticeText('scan:secrets') : scanBlocked ? blockedTitle : !githubTokenSet ? 'GitHub token required' : 'Resume GitHub Hunt'}
              >
                <Play size={12} />
                <span>Resume</span>
              </button>
            ) : (
              <button
                className={styles.startButton}
                onClick={onStartGithubHunt}
                disabled={secretsRefused || !githubTokenSet || isGHRunning || (!hasReconData && !isGHPaused) || scanBlocked}
                title={secretsRefused ? forbiddenNoticeText('scan:secrets') : scanBlocked ? blockedTitle : !githubTokenSet ? 'GitHub token required' : !hasReconData ? 'Run recon first' : isGHRunning ? 'In progress...' : 'Start GitHub Hunt'}
              >
                {isGHRunning ? (
                  <Loader2 size={12} className={styles.spinner} />
                ) : (
                  <Play size={12} />
                )}
                <span>{isGHPausing ? 'Pausing...' : isGHBusy ? 'Running...' : isGHStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}

            {isGHBusy && (
              <button
                className={styles.pauseButton}
                onClick={onPauseGithubHunt}
                disabled={isGHPausing}
                title="Pause"
              >
                {isGHPausing ? <Loader2 size={12} className={styles.spinner} /> : <Pause size={12} />}
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
              disabled={!hasGithubHuntData || isGHActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasGithubHuntData ? 'Download JSON' : githubHuntDataError || 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>

            {projectId && (
              <Link
                href={projectSettingsHref(projectId, 'github-secret-hunting')}
                {...settingsLinkProps('github-secret-hunting')}
                className={styles.settingsButton}
                title="Configure the target org, repos and scan options in project settings"
                aria-label="Configure GitHub Secret Hunt in project settings"
              >
                <Settings size={13} />
              </Link>
            )}
          </div>
        </div>

        {/* Secret Multiscanner Card — one row per configured source, full height */}
        <div className={`${styles.card} ${styles.cardTall}`}>
          <div className={styles.cardHeader}>
            <Search size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>Secret Multiscanner</h3>
            <WikiInfoButton target="Trufflehog" title="Secret Multiscanner wiki" />
            <StatusBadge status={trufflehogCardStatus} />
            <ScanStatusWarning errors={[trufflehogStatusError]} />
          </div>
          <p className={styles.cardDescription}>
            Deep secret scanning with 700+ detectors across git hosts, container registries,
            Hugging Face, object storage and CI systems. Sources run independently and in parallel.
          </p>
          {secretsRefused && <ForbiddenNotice permission="scan:secrets" />}

          {/* Scrolls on its own: any number of sources can be added, and the
              card must not push the modal past the viewport. */}
          <div className={styles.sourceList}>
          {trufflehogProfilesError && (
            <p className={styles.cardDescription} role="alert" style={{ color: 'var(--status-error)' }}>
              {trufflehogProfilesError}
            </p>
          )}
          {trufflehogProfiles.length === 0 ? (
            trufflehogProfilesError ? null : <p className={styles.cardDescription} style={{ opacity: 0.75 }}>
              No sources configured.{' '}
              {projectId && (
                <Link
                  href={projectSettingsHref(projectId, 'trufflehog-scanner')}
                  {...settingsLinkProps('trufflehog-scanner')}
                  style={{ color: 'var(--accent-primary)', fontWeight: 500 }}
                >
                  Add one in project settings
                </Link>
              )}
              {' '}to make it startable here.
            </p>
          ) : (
            trufflehogProfiles.map(profile => {
              const run = trufflehogRunsBySource[profile.source]
              const status = run?.status ?? 'idle'
              const busy = status === 'running' || status === 'starting'
              const stopping = status === 'stopping'
              const active = busy || stopping
              const missing = (profile.missingCredentials ?? [])
                .filter(m => !credentialKeys.isSet(m.settingsKey))
              const invalid = (profile.validationErrors ?? []).length > 0
              // Fails closed in the UI too, and the start route re-checks: a key
              // cleared after this rendered must not produce an opaque failure.
              const blockedReason = secretsRefused ? forbiddenNoticeText('scan:secrets')
                : missing.length
                ? `Set ${missing.map(m => m.label).join(', ')} in Global Settings > API Keys`
                : invalid ? 'This source is not fully configured'
                : scanBlocked ? blockedTitle : ''

              return (
                <div key={profile.id}>
                {/* Status, Start and Logs stay on ONE line with the source name;
                    the name is what gives way when the card is narrow. */}
                <div className={styles.sourceRow}>
                  <span className={styles.sourceName}>
                    <span className={styles.sourceLabel}>
                      {TRUFFLEHOG_SOURCES[profile.source]?.label ?? profile.source}
                    </span>
                    {run?.target && (
                      <span className={styles.sourceTarget} title={run.target}>{run.target}</span>
                    )}
                  </span>
                  <StatusBadge status={status} error={run?.error} />

                  <button
                    className={styles.startButton}
                    onClick={() => onStartTrufflehog?.(profile.source)}
                    disabled={active || Boolean(blockedReason)}
                    title={blockedReason || (active ? 'In progress...' : `Start ${profile.source}`)}
                  >
                    {busy ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                    <span>{busy ? 'Running...' : stopping ? 'Stopping...' : 'Start'}</span>
                  </button>

                  {active && (
                    <button
                      className={styles.stopButton}
                      onClick={() => onStopTrufflehog?.(profile.source)}
                      disabled={stopping}
                      title="Stop this source"
                    >
                      <Square size={12} />
                      <span>Stop</span>
                    </button>
                  )}

                  <button
                    className={`${styles.logsButton} ${openTrufflehogLogsSource === profile.source ? styles.logsButtonActive : ''}`}
                    onClick={() => onToggleTrufflehogLogs?.(profile.source)}
                    disabled={!active}
                    title="View Logs"
                  >
                    <Terminal size={12} />
                    <span>Logs</span>
                  </button>
                </div>

                {missing.length > 0 && (
                  <span className={styles.missingKeyNote}>
                    <AlertTriangle size={12} />
                    <Link href={`${SETTINGS_KEYS_HREF}#trufflehog-keys`} style={{ color: 'inherit' }}>
                      {missing.map(m => m.label).join(', ')} required
                    </Link>
                  </span>
                )}

                {/* Only the keys that actually block THIS source, so a row that
                    can start stays a single line. */}
                {missing.length > 0 && (
                  <div className={styles.credentialStack}>
                    {missing.map(m => (
                      <CredentialShortcut
                        key={m.settingsKey}
                        settingsKey={m.settingsKey}
                        keys={credentialKeys}
                        compact
                      />
                    ))}
                  </div>
                )}
                </div>
              )
            })
          )}
          </div>

          <div className={styles.cardActions}>
            <button
              className={styles.downloadButton}
              onClick={onDownloadTrufflehogJSON}
              disabled={!hasTrufflehogData || isTHActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasTrufflehogData ? 'Download JSON' : trufflehogDataError || 'No data available'}
            >
              <Download size={12} />
              <span>Download</span>
            </button>

            {projectId && (
              <Link
                href={projectSettingsHref(projectId, 'trufflehog-scanner')}
                {...settingsLinkProps('trufflehog-scanner')}
                className={styles.settingsButton}
                title="Configure which sources to scan and their options in project settings"
                aria-label="Configure Secret Multiscanner in project settings"
              >
                <Settings size={13} />
              </Link>
            )}
          </div>
        </div>

        {/* Supply Chain Scanner (L1). Like the two hunters above it, this card
            owns the run controls only: its input (uploaded SBOM / lockfile,
            repository, or an organization to batch) is configured in project
            settings, which is what the gear links to. */}
        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <PackageSearch size={18} className={styles.cardIcon} />
            <h3 className={styles.cardTitle}>Supply Chain Scanner</h3>
            <WikiInfoButton target="SupplyChainScan" title="Supply-Chain Scanning wiki" />
            <StatusBadge status={supplyChainStatus} error={supplyChainError} />
            <ScanStatusWarning errors={[supplyChainStatusError]} />
          </div>
          <p className={styles.cardDescription}>
            Audit an SBOM / lockfile, or a GitHub repository, against the offline OSV database for
            known-malicious (MAL) and known-vulnerable packages. The OSV verdict is fully offline.
          </p>
          {supplyChainRefused && <ForbiddenNotice permission="scan:supply_chain" />}

          {supplyChain.ready ? (
            <p className={styles.targetLine}>
              <span className={styles.targetKind}>{SUPPLY_CHAIN_INPUT_LABEL[supplyChain.source]}</span>
              <span className={styles.targetValue} title={supplyChain.target}>{supplyChain.target}</span>
            </p>
          ) : (
            <p className={styles.cardDescription} style={{ opacity: 0.75 }}>
              {supplyChain.loading ? 'Loading the configured input...'
                : supplyChain.error ? <span role="alert">{supplyChain.error}</span>
                : <>No input configured.{' '}
                {supplyChainSettingsLink} to make it startable here.</>}
            </p>
          )}

          <div className={styles.cardActions}>
            {isSCPaused ? (
              <button className={styles.resumeButton} onClick={onResumeSupplyChain} disabled={supplyChainRefused || scanBlocked}
                title={supplyChainRefused ? forbiddenNoticeText('scan:supply_chain') : scanBlocked ? blockedTitle : 'Resume Supply-Chain scan'}>
                <Play size={12} /><span>Resume</span>
              </button>
            ) : supplyChain.source === 'org' && projectId ? (
              // The org mode queues N scans instead of running this project's
              // single input, so it replaces Start rather than sitting next to a
              // button that can never be enabled.
              <SupplyChainOrgBatchButton
                projectId={projectId}
                org={supplyChain.org}
                disabled={supplyChainRefused || isSCActive || scanBlocked}
                blockedReason={supplyChainRefused ? forbiddenNoticeText('scan:supply_chain') : scanBlocked ? blockedTitle : ''}
              />
            ) : (
              <button className={styles.startButton} onClick={onStartSupplyChain}
                disabled={supplyChainRefused || !supplyChain.ready || isSCRunning || scanBlocked}
                title={supplyChainRefused ? forbiddenNoticeText('scan:supply_chain') : scanBlocked ? blockedTitle : !supplyChain.ready ? 'Configure the scan input in project settings first' : isSCRunning ? 'In progress...' : 'Start Supply-Chain scan'}>
                {isSCRunning ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                <span>{isSCPausing ? 'Pausing...' : isSCBusy ? 'Running...' : isSCStopping ? 'Stopping...' : 'Start'}</span>
              </button>
            )}
            {isSCBusy && (
              <button className={styles.pauseButton} onClick={onPauseSupplyChain} disabled={isSCPausing} title="Pause">
                {isSCPausing ? <Loader2 size={12} className={styles.spinner} /> : <Pause size={12} />}<span>Pause</span>
              </button>
            )}
            {isSCActive && (
              <button className={styles.stopButton} onClick={onStopSupplyChain} disabled={isSCStopping} title="Stop">
                <Square size={12} /><span>Stop</span>
              </button>
            )}
            <button className={`${styles.logsButton} ${isSupplyChainLogsOpen ? styles.logsButtonActive : ''}`}
              onClick={onToggleSupplyChainLogs} disabled={!isSCActive} title="View Logs">
              <Terminal size={12} /><span>Logs</span>
            </button>
            <button className={styles.downloadButton} onClick={onDownloadSupplyChainJSON}
              disabled={!hasSupplyChainData || isSCActive || viewingPastVersion}
              title={viewingPastVersion ? 'Download reflects the active version, not this saved view' : hasSupplyChainData ? 'Download JSON' : supplyChainDataError || 'No data available'}>
              <Download size={12} /><span>Download</span>
            </button>

            {projectId && (
              <Link
                href={projectSettingsHref(projectId, 'supply-chain-scanner')}
                {...settingsLinkProps('supply-chain-scanner')}
                className={styles.settingsButton}
                title="Configure the SBOM / lockfile, repository or organization to scan in project settings"
                aria-label="Configure Supply Chain Scanner in project settings"
              >
                <Settings size={13} />
              </Link>
            )}
          </div>
        </div>
        </div>
      </div>
    </Modal>
  )
}

export default OtherScansModal

'use client'

import { RefreshCw, Globe, Server } from 'lucide-react'
import { WikiInfoButton } from '@/components/ui'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '@/components/projects/ProjectForm/ipHostnameModes'
import styles from './DashboardHeader.module.css'

interface DashboardHeaderProps {
  projectName: string | null
  targetDomain: string | null
  ipMode: boolean
  isLoading: boolean
  onRefresh: () => void
  /** IP mode: the hostname mode; read from the current project when not passed. */
  ipHostnameMode?: string | null
}

export function DashboardHeader({ projectName, targetDomain, ipMode, isLoading, onRefresh, ipHostnameMode }: DashboardHeaderProps) {
  const contextMode = useOptionalProject()?.currentProject?.ipHostnameMode
  // A read without the field says nothing: absent is not "IP only".
  const hostnameMode = ipHostnameMode !== undefined ? ipHostnameMode : contextMode
  const modeLabel = ipMode && typeof hostnameMode === 'string' ? ipHostnameModeLabel(hostnameMode) : null
  // The project summary's target label already ends in " · <mode label>"; the
  // chip says it once, next to the icon.
  const target = modeLabel && targetDomain?.endsWith(` · ${modeLabel}`)
    ? targetDomain.slice(0, -(modeLabel.length + 3))
    : targetDomain
  return (
    <div className={styles.header}>
      <div className={styles.info}>
        <h1 className={styles.title}>
          Insights
          <WikiInfoButton target="insights" title="Open Insights Dashboard wiki page" />
        </h1>
        {projectName && (
          <div className={styles.project}>
            {ipMode ? <Server size={14} /> : <Globe size={14} />}
            {modeLabel && (
              <span className={styles.hostnameMode} data-testid="insights-hostname-mode" title={IP_HOSTNAME_SECTION_LABEL}>
                <span className={styles.hiddenLabel}>{IP_HOSTNAME_SECTION_LABEL}: </span>
                {modeLabel}
              </span>
            )}
            <span className={styles.projectName}>{projectName}</span>
            {target && (
              <>
                <span className={styles.separator}>/</span>
                <span className={styles.target}>{target}</span>
              </>
            )}
          </div>
        )}
      </div>
      <button
        className={`iconButton ${styles.refreshBtn}`}
        onClick={onRefresh}
        disabled={isLoading}
        title="Refresh data"
      >
        <RefreshCw size={14} className={isLoading ? styles.spinning : ''} />
      </button>
    </div>
  )
}

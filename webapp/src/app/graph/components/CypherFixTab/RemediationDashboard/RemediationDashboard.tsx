'use client'

import { Fragment, useCallback, useMemo, useState } from 'react'
import { RefreshCw, Trash2, XCircle, ChevronRight } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import { cveToUrl } from '@/lib/url-utils'
import { SeverityBadge } from './SeverityBadge'
import { StatusBadge } from './StatusBadge'
import { RemediationTypeIcon } from './RemediationTypeIcon'
import { RemediationFilters } from './RemediationFilters'
import { TriageRunButton } from '@/components/triage/TriageRunButton'
import type {
  Remediation,
  RemediationSeverity,
  RemediationStatus,
} from '@/lib/cypherfix-types'
import { SEVERITY_ORDER } from '@/lib/cypherfix-types'
import styles from './RemediationDashboard.module.css'
import { UpdatedAtCell, UpdatedAtTh, sortByUpdatedAt, useUpdatedAtSortDir } from '@/app/graph/components/RedZoneTables/updatedAt'

interface RemediationDashboardProps {
  remediations: Remediation[]
  isLoading: boolean
  error: Error | null
  severityFilter?: RemediationSeverity
  statusFilter?: RemediationStatus
  onSeverityFilterChange: (severity: RemediationSeverity | undefined) => void
  onStatusFilterChange: (status: RemediationStatus | undefined) => void
  onSelectRemediation: (remediation: Remediation) => void
  onDismiss: (id: string) => void
  onDelete: (id: string) => void
  onRefresh: () => void
  onStartTriage: () => void
  projectId: string
  userId: string
}

export function RemediationDashboard({
  remediations,
  isLoading,
  error,
  severityFilter,
  statusFilter,
  onSeverityFilterChange,
  onStatusFilterChange,
  onSelectRemediation,
  onDismiss,
  onDelete,
  onRefresh,
  onStartTriage,
  projectId,
  userId,
}: RemediationDashboardProps) {
  // Summary stats
  const stats = useMemo(() => {
    const bySeverity: Record<string, number> = {}
    const byStatus: Record<string, number> = {}
    for (const r of remediations) {
      bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1
      byStatus[r.status] = (byStatus[r.status] || 0) + 1
    }
    return { total: remediations.length, bySeverity, byStatus }
  }, [remediations])

  // THE RANK IS THE DEFAULT ORDER, and `priority` ascending IS the rank: 1 is
  // most urgent. It comes from the same triage run that ordered the Priority
  // Board, so the two pages agree unless the operator asks for something else.
  // Re-sorting by updatedAt by default silently disagreed with the board.
  const { sortDir, toggleSort } = useUpdatedAtSortDir()
  // `Updated` is an OPT-IN column sort, not the default: the hook always has a
  // direction, so without this flag every list silently came back in updatedAt
  // order and disagreed with the board.
  const [sortByUpdated, setSortByUpdated] = useState(false)
  const toggleUpdatedSort = useCallback(() => {
    if (!sortByUpdated) setSortByUpdated(true)
    else toggleSort()
  }, [sortByUpdated, toggleSort])

  const sorted = useMemo(() => {
    const byPriority = [...remediations].sort((a, b) => {
      if (a.priority !== b.priority) return a.priority - b.priority
      // `??`, not `||`: SEVERITY_ORDER.critical is 0, and `||` turned the most
      // severe value into the least, so critical sorted last among ties.
      return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
    })
    return sortByUpdated ? sortByUpdatedAt(byPriority, sortDir) : byPriority
  }, [remediations, sortDir, sortByUpdated])

  if (error) {
    return (
      <div className={styles.errorState}>
        <p>Failed to load remediations: {error.message}</p>
        <button className={styles.retryBtn} onClick={onRefresh}>Retry</button>
      </div>
    )
  }

  return (
    <div className={styles.dashboard}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <h3 className={styles.title}>
            Remediations
            <span className={styles.count}>{stats.total}</span>
          </h3>
          {stats.bySeverity.critical && (
            <span className={styles.criticalBadge}>
              {stats.bySeverity.critical} critical
            </span>
          )}
        </div>
        <div className={styles.headerRight}>
          <button className={styles.iconBtn} onClick={onRefresh} title="Refresh">
            <RefreshCw size={14} className={isLoading ? styles.spinning : ''} />
          </button>
          <TriageRunButton
            projectId={projectId ?? null}
            onConfirm={onStartTriage}
            // This dashboard only renders when fix items exist, and fix items
            // are only ever produced by a triage run.
            hasPreviousRun={remediations.length > 0}
          />
        </div>
      </div>

      {/* Filters */}
      <RemediationFilters
        severityFilter={severityFilter}
        statusFilter={statusFilter}
        onSeverityChange={onSeverityFilterChange}
        onStatusChange={onStatusFilterChange}
      />

      {/* Table */}
      <div className={styles.tableWrapper}>
        {isLoading && remediations.length === 0 ? (
          <div className={styles.loading}>Loading remediations...</div>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.thPriority}>#</th>
                <th className={styles.thSeverity}>Severity</th>
                <th className={styles.thTitle}>Title</th>
                <th className={styles.thType}>Type</th>
                <th className={styles.thStatus}>Status</th>
                <th className={styles.thCve}>CVEs</th>
                <UpdatedAtTh dir={sortDir} onToggle={toggleUpdatedSort} />
                <th className={styles.thActions}></th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((rem, idx) => (
                <tr
                  key={rem.id}
                  className={styles.row}
                  onClick={() => onSelectRemediation(rem)}
                >
                  <td className={styles.tdPriority}>{idx + 1}</td>
                  <td className={styles.tdSeverity}>
                    <SeverityBadge severity={rem.severity} />
                  </td>
                  <td className={styles.tdTitle}>
                    <span className={styles.remTitle}>{rem.title}</span>
                    {rem.exploitAvailable && (
                      <span className={styles.exploitTag}>exploit</span>
                    )}
                    {rem.cisaKev && (
                      <span className={styles.kevTag}>KEV</span>
                    )}
                  </td>
                  <td className={styles.tdType}>
                    <RemediationTypeIcon type={rem.remediationType} />
                  </td>
                  <td className={styles.tdStatus}>
                    <StatusBadge status={rem.status} />
                  </td>
                  <td className={styles.tdCve}>
                    {rem.cveIds.length > 0 ? (
                      <span className={styles.cveList} onClick={e => e.stopPropagation()}>
                        {rem.cveIds.slice(0, 2).map((cve, j) => (
                          <Fragment key={cve}>
                            {j > 0 && ', '}
                            <ExternalLink href={cveToUrl(cve)}>{cve}</ExternalLink>
                          </Fragment>
                        ))}
                        {rem.cveIds.length > 2 && ` +${rem.cveIds.length - 2}`}
                      </span>
                    ) : (
                      <span className={styles.noCve}>-</span>
                    )}
                  </td>
                  <td><UpdatedAtCell value={rem.updatedAt} /></td>
                  <td className={styles.tdActions}>
                    <div className={styles.actions} onClick={e => e.stopPropagation()}>
                      {rem.status === 'pending' && (
                        <button
                          className={styles.actionBtn}
                          title="Dismiss"
                          onClick={() => onDismiss(rem.id)}
                        >
                          <XCircle size={14} />
                        </button>
                      )}
                      <button
                        className={styles.actionBtn}
                        title="Delete"
                        onClick={() => onDelete(rem.id)}
                      >
                        <Trash2 size={14} />
                      </button>
                      <ChevronRight size={14} className={styles.chevron} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

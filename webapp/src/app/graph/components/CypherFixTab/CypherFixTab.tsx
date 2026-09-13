'use client'

import { useState, useCallback, useMemo } from 'react'
import { useRemediations } from '@/hooks'
import { useProjectById } from '@/hooks/useProjects'
import type { UseCypherFixTriageWSReturn } from '@/hooks/useCypherFixTriageWS'
import { EmptyState } from './EmptyState/EmptyState'
import { RemediationDashboard } from './RemediationDashboard/RemediationDashboard'
import { RemediationDetail } from './RemediationDetail/RemediationDetail'
import { DiffViewer } from './DiffViewer/DiffViewer'
import { TriageProgress } from './TriageProgress/TriageProgress'
import type { Remediation, RemediationSeverity, RemediationStatus } from '@/lib/cypherfix-types'
import styles from './CypherFixTab.module.css'

type SubView = 'dashboard' | 'detail' | 'diffviewer'

interface CypherFixTabProps {
  projectId: string
  userId: string
  triage: UseCypherFixTriageWSReturn
  showTriageProgress: boolean
  onStartTriage: () => void
  onCloseTriageProgress: () => void
}

export function CypherFixTab({
  projectId,
  userId,
  triage,
  showTriageProgress,
  onStartTriage,
  onCloseTriageProgress,
}: CypherFixTabProps) {
  const [subView, setSubView] = useState<SubView>('dashboard')
  const [selectedRemediation, setSelectedRemediation] = useState<Remediation | null>(null)
  const [severityFilter, setSeverityFilter] = useState<RemediationSeverity | undefined>()
  const [statusFilter, setStatusFilter] = useState<RemediationStatus | undefined>()

  const {
    remediations,
    isLoading,
    error,
    refetch,
    updateRemediation,
    deleteRemediation,
  } = useRemediations({
    projectId,
    severity: severityFilter,
    status: statusFilter,
  })

  const { data: project } = useProjectById(projectId || null)

  const missingSettings = useMemo(() => {
    if (!project) return []
    const missing: string[] = []
    if (!project.cypherfixGithubToken) missing.push('GitHub Token (CypherFix)')
    if (!project.cypherfixDefaultRepo) missing.push('Default Repository')
    if (!project.cypherfixDefaultBranch) missing.push('Default Branch')
    if (!project.cypherfixBranchPrefix) missing.push('Branch Prefix')
    return missing
  }, [project])

  const handleSelectRemediation = useCallback((remediation: Remediation) => {
    setSelectedRemediation(remediation)
    setSubView('detail')
  }, [])

  const handleBackToDashboard = useCallback(() => {
    setSubView('dashboard')
    setSelectedRemediation(null)
  }, [])

  const handleStartCodeFix = useCallback((remediationId: string) => {
    const rem = remediations.find(r => r.id === remediationId) || selectedRemediation
    if (rem) {
      setSelectedRemediation(rem)
      setSubView('diffviewer')
    }
  }, [remediations, selectedRemediation])

  const handleBackToDetail = useCallback(() => {
    setSubView('detail')
  }, [])

  const handleDismiss = useCallback((id: string) => {
    updateRemediation({ id, data: { status: 'dismissed' } })
  }, [updateRemediation])

  const handleDelete = useCallback((id: string) => {
    deleteRemediation(id)
    if (selectedRemediation?.id === id) {
      handleBackToDashboard()
    }
  }, [deleteRemediation, selectedRemediation, handleBackToDashboard])

  const showEmpty = !isLoading && remediations.length === 0 && !severityFilter && !statusFilter

  const renderContent = () => {
    if (showEmpty) {
      return <EmptyState onStartTriage={onStartTriage} projectId={projectId || null} />
    }
    if (subView === 'diffviewer' && selectedRemediation) {
      return (
        <DiffViewer
          remediation={selectedRemediation}
          projectId={projectId}
          userId={userId}
          onBack={handleBackToDetail}
          onRefresh={refetch}
        />
      )
    }
    if (subView === 'detail' && selectedRemediation) {
      return (
        <RemediationDetail
          remediation={selectedRemediation}
          projectId={projectId}
          userId={userId}
          onBack={handleBackToDashboard}
          onDismiss={handleDismiss}
          onDelete={handleDelete}
          onRefresh={refetch}
          onStartCodeFix={handleStartCodeFix}
          missingSettings={missingSettings}
        />
      )
    }
    return (
      <RemediationDashboard
        remediations={remediations}
        isLoading={isLoading}
        error={error}
        severityFilter={severityFilter}
        statusFilter={statusFilter}
        onSeverityFilterChange={setSeverityFilter}
        onStatusFilterChange={setStatusFilter}
        onSelectRemediation={handleSelectRemediation}
        onDismiss={handleDismiss}
        onDelete={handleDelete}
        onRefresh={refetch}
        onStartTriage={onStartTriage}
        projectId={projectId}
        userId={userId}
      />
    )
  }

  return (
    <div className={styles.container}>
      {renderContent()}
      <TriageProgress
        isVisible={showTriageProgress}
        phase={triage.currentPhase}
        progress={triage.progress}
        findings={triage.findings}
        thinking={triage.thinking}
        error={triage.error}
        status={triage.status}
        onClose={onCloseTriageProgress}
        onStop={triage.stopTriage}
      />
    </div>
  )
}

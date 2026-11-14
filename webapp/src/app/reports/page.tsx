'use client'

import { useState, useCallback, useMemo } from 'react'
import { FileText, Download, ExternalLink, Trash2, Loader2, AlertCircle, Sparkles, ChevronDown } from 'lucide-react'
import { useAllReports, type ReportMeta } from '@/hooks/useReports'
import { useProjects } from '@/hooks/useProjects'
import { useProject } from '@/providers/ProjectProvider'
import { projectTargetLabel } from '@/lib/projectSummary'
import { useToast, WikiInfoButton } from '@/components/ui'
import { errorMessage, readApiError, toApiError } from '@/lib/apiError'
import { FeatureModelLine } from '@/components/shared/FeatureModelGate'
import { useRefusalCheck } from '@/hooks/useRefusal'
import { readsOwnerCatalog } from '@/hooks/useProjectOwnerCatalog'
import type { MyAccess } from '@/lib/authz/projectAccess'
import styles from './page.module.css'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

/** Why a report has no narratives, from the route's `narrativesSkipped` code. */
function skippedReason(code: string): string {
  if (code === 'use_agent_required') return "AI narratives need Use AI agent on this project and the owner's consent to spend their credentials"
  if (code === 'owner_model_required') return "the project's owner has not chosen a Report narratives model"
  if (code.startsWith('agent_')) return 'the agent could not be reached'
  if (code.startsWith('unreadable_answer')) return "the model's answer could not be read"
  return 'the model call failed'
}

function riskClass(label?: string): string {
  switch (label?.toLowerCase()) {
    case 'critical': return styles.riskCritical
    case 'high': return styles.riskHigh
    case 'medium': return styles.riskMedium
    case 'low': return styles.riskLow
    default: return ''
  }
}

export default function ReportsPage() {
  const { userId } = useProject()
  const toast = useToast()
  const {
    reports, isLoading, error: listError, generate, isGenerating, generateError,
    deleteReportAsync, isDeleting,
  } = useAllReports()

  const { data: projects } = useProjects(userId || undefined)
  const [selectedProjectId, setSelectedProjectId] = useState<string>('')
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  // Reports span projects, so each action reads its own project's access from the list rows
  // (`myAccess`, RBAC_SHARING_ENABLED on): a read share downloads and opens, and neither generates
  // nor deletes (step 4.11). Without `myAccess` nothing is refused here.
  const refusalCheck = useRefusalCheck()
  const accessOf = useMemo(() => {
    const byId = new Map<string, MyAccess>()
    for (const p of projects ?? []) if (p.myAccess) byId.set(p.id, p.myAccess)
    return (projectId: string) => byId.get(projectId) ?? null
  }, [projects])
  const generateRefusal = selectedProjectId
    ? refusalCheck('reports:generate', accessOf(selectedProjectId))?.text ?? null
    : null
  // A project the person does not own runs its narratives on the OWNER's model, or none (P5-06),
  // by the rule the project form and the graph page read the owner's catalog with.
  const ownerModel = selectedProjectId ? readsOwnerCatalog(accessOf(selectedProjectId)) : false

  const handleGenerate = useCallback(async () => {
    if (!selectedProjectId) return
    try {
      // null: the user cancelled the model prompt, so nothing started.
      const report = await generate(selectedProjectId, { ownerModel })
      if (!report) return
      if (report.narrativesSkipped) {
        toast.warning(`Report generated without AI narratives: ${skippedReason(report.narrativesSkipped)} (${report.narrativesSkipped}).`)
      } else {
        toast.info('Report generation started')
      }
    } catch (e) {
      // The same text stays on the page as generateError.
      toast.error(errorMessage(e, 'Failed to generate report'))
    }
  }, [generate, selectedProjectId, ownerModel, toast])

  const handleDelete = useCallback(async (projectId: string, reportId: string) => {
    try {
      await deleteReportAsync({ projectId, reportId })
      toast.success('Report deleted')
    } catch (e) {
      toast.error(errorMessage(e, 'Failed to delete report'))
    }
    setDeleteConfirm(null)
  }, [deleteReportAsync, toast])

  const handleDownload = useCallback(async (report: ReportMeta) => {
    try {
      const url = `/api/projects/${report.projectId}/reports/${report.id}`
      const res = await fetch(url)
      if (!res.ok) throw await readApiError(res, 'Failed to download report')
      const blob = await res.blob()
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `${report.title || 'report'}.html`
      a.click()
      URL.revokeObjectURL(a.href)
      toast.success('Report downloaded')
    } catch (e) {
      toast.error(toApiError(e, 'Failed to download report').message)
    }
  }, [toast])

  const handleOpen = useCallback((report: ReportMeta) => {
    window.open(`/api/projects/${report.projectId}/reports/${report.id}`, '_blank')
  }, [])

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <FileText size={18} />
          <h2 className={styles.title}>Pentest Reports</h2>
          <span className={styles.count}>{reports.length}</span>
          <WikiInfoButton target="reports" title="Open Pentest Reports wiki page" />
        </div>

        <div className={styles.generateSection}>
          <div className={styles.pickerWrapper}>
            <select
              className={styles.projectPicker}
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              disabled={isGenerating}
            >
              <option value="">Select project...</option>
              {projects?.map(p => {
                const target = projectTargetLabel(p)
                return (
                  <option key={p.id} value={p.id}>
                    {p.name}{target ? ` (${target})` : ''}
                  </option>
                )
              })}
            </select>
            <ChevronDown size={12} className={styles.pickerChevron} />
          </div>
          <button
            className={styles.generateBtn}
            onClick={handleGenerate}
            disabled={isGenerating || !selectedProjectId || !!generateRefusal}
            title={generateRefusal ?? undefined}
          >
            {isGenerating ? (
              <>
                <Loader2 size={13} className={styles.spin} />
                <span>Generating...</span>
              </>
            ) : (
              <>
                <FileText size={13} />
                <span>Generate Report</span>
              </>
            )}
          </button>
          {ownerModel ? (
            <span
              className={styles.ownerModelLine}
              data-feature-model="report_narratives"
              title="The narratives run on the project owner's Report narratives model, which only the owner changes, in their Global Settings"
            >
              Narratives model: the project owner&apos;s
            </span>
          ) : (
            <FeatureModelLine featureId="report_narratives" label="Narratives model" />
          )}
        </div>
      </div>

      {generateRefusal && (
        <p className={styles.readOnlyNote} role="note">
          {generateRefusal}: you can download and open this project&apos;s reports, not generate them.
        </p>
      )}

      {generateError && (
        <div className={styles.error}>
          <AlertCircle size={13} />
          <span>{generateError.message}</span>
        </div>
      )}

      {isLoading ? (
        <div className={styles.empty}>
          <Loader2 size={20} className={styles.spin} />
          <span>Loading reports...</span>
        </div>
      ) : listError && reports.length === 0 ? (
        // A failed list is not an empty one: "No reports generated yet" hid it.
        <div className={styles.error} role="alert">
          <AlertCircle size={13} />
          <span>Failed to load reports: {errorMessage(listError, 'Failed to fetch reports')}</span>
        </div>
      ) : reports.length === 0 ? (
        <div className={styles.empty}>
          <FileText size={32} className={styles.emptyIcon} />
          <p className={styles.emptyTitle}>No reports generated yet</p>
          <p className={styles.emptyHint}>
            Select a project above and generate a professional pentest report from your graph data, vulnerability findings, and remediations.
          </p>
        </div>
      ) : (
        <div className={styles.list}>
          {reports.map(report => {
            const deleteRefusal = refusalCheck('reports:delete', accessOf(report.projectId))?.text ?? null
            return (
            <div key={report.id} className={styles.row}>
              <div className={styles.rowMain}>
                <div className={styles.rowTitle}>
                  <span className={styles.reportTitle}>{report.title}</span>
                  {report.hasNarratives && (
                    <span className={styles.narrativeBadge} title="Includes LLM-generated narratives">
                      <Sparkles size={10} />
                      AI
                    </span>
                  )}
                </div>
                <div className={styles.rowMeta}>
                  {report.project && (
                    <>
                      <span className={styles.projectName}>{report.project.name}</span>
                      {projectTargetLabel(report.project) && (
                        <span className={styles.projectDomain}>{projectTargetLabel(report.project)}</span>
                      )}
                      <span className={styles.sep}>|</span>
                    </>
                  )}
                  <span>{formatDate(report.createdAt)}</span>
                  <span className={styles.sep}>|</span>
                  <span>{formatBytes(report.fileSize)}</span>
                  {report.metrics.riskScore != null && (
                    <>
                      <span className={styles.sep}>|</span>
                      <span className={`${styles.riskBadge} ${riskClass(report.metrics.riskLabel)}`}>
                        {report.metrics.riskScore}/100 {report.metrics.riskLabel}
                      </span>
                    </>
                  )}
                  {report.metrics.totalVulnerabilities != null && (
                    <>
                      <span className={styles.sep}>|</span>
                      <span>{report.metrics.totalVulnerabilities} vulns</span>
                    </>
                  )}
                  {(report.metrics.criticalCount ?? 0) > 0 && (
                    <span className={styles.criticalCount}>
                      {report.metrics.criticalCount} critical
                    </span>
                  )}
                  {(report.metrics.highCount ?? 0) > 0 && (
                    <span className={styles.highCount}>
                      {report.metrics.highCount} high
                    </span>
                  )}
                  {report.metrics.totalRemediations != null && report.metrics.totalRemediations > 0 && (
                    <>
                      <span className={styles.sep}>|</span>
                      <span>{report.metrics.totalRemediations} remediations</span>
                    </>
                  )}
                  {(report.metrics.exploitableCount ?? 0) > 0 && (
                    <>
                      <span className={styles.sep}>|</span>
                      <span className={styles.exploitCount}>{report.metrics.exploitableCount} exploitable</span>
                    </>
                  )}
                </div>
              </div>
              <div className={styles.rowActions}>
                <button
                  className={styles.actionBtn}
                  onClick={() => handleDownload(report)}
                  title="Download report"
                >
                  <Download size={14} />
                </button>
                <button
                  className={styles.actionBtn}
                  onClick={() => handleOpen(report)}
                  title="Open in new tab"
                >
                  <ExternalLink size={14} />
                </button>
                {deleteConfirm === report.id ? (
                  <div className={styles.confirmDelete}>
                    <button
                      className={styles.confirmYes}
                      onClick={() => handleDelete(report.projectId, report.id)}
                      disabled={isDeleting}
                    >
                      Delete
                    </button>
                    <button
                      className={styles.confirmNo}
                      onClick={() => setDeleteConfirm(null)}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    className={`${styles.actionBtn} ${styles.deleteBtn}`}
                    onClick={() => setDeleteConfirm(report.id)}
                    disabled={!!deleteRefusal}
                    title={deleteRefusal ?? 'Delete report'}
                    aria-label="Delete report"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

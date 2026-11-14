/**
 * useReports Hook
 *
 * TanStack Query hooks for fetching, generating, and deleting reports.
 * Supports both project-specific and all-projects modes.
 */

import { useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useFeatureModelGate, type FeatureModelGateApi } from '@/components/shared/FeatureModelGate'
import { featureModelMessage, GATE_CODES, providerFailureDetail, readFeatureModelCode } from '@/lib/llmFeatures'
import { fetchJson, fetchOk, readApiError } from '@/lib/apiError'

export interface ReportMeta {
  id: string
  projectId: string
  title: string
  filename: string
  fileSize: number
  format: string
  metrics: {
    riskScore?: number
    riskLabel?: string
    totalVulnerabilities?: number
    totalCves?: number
    criticalCount?: number
    highCount?: number
    mediumCount?: number
    lowCount?: number
    cveCriticalCount?: number
    cveHighCount?: number
    cveMediumCount?: number
    cveLowCount?: number
    totalRemediations?: number
    exploitableCount?: number
  }
  hasNarratives: boolean
  createdAt: string
  /** Set on a report just generated without narratives, saying why (`agent_unreachable`). */
  narrativesSkipped?: string
  project?: {
    id: string
    name: string
    targetDomain?: string
    subdomainList?: string[]
    ipMode?: boolean
    targetIps?: string[]
    domainBatchMode?: boolean
    domainBatchHosts?: string[]
  }
}

const REPORTS_KEY = 'reports'
const ALL_REPORTS_KEY = 'all-reports'

async function fetchReports(projectId: string): Promise<ReportMeta[]> {
  return fetchJson<ReportMeta[]>(`/api/projects/${projectId}/reports`, undefined, 'Failed to fetch reports')
}

async function fetchAllReports(): Promise<ReportMeta[]> {
  return fetchJson<ReportMeta[]>('/api/reports', undefined, 'Failed to fetch reports')
}

type ReportGate = Pick<FeatureModelGateApi, 'ensureFeatureModel' | 'fetchWithFeatureModel'>

export interface GenerateReportOptions {
  /**
   * The project is not the person's own (`readsOwnerCatalog`): the route runs the narratives on
   * the OWNER's "Report narratives" model, or skips them, so the person's own model is neither
   * asked for nor offered.
   */
  ownerModel?: boolean
}

const OWNER_MODEL_FAILED = "The project owner's Report narratives model could not be used"

/**
 * Generate one report. Resolves null when the user cancels the first model
 * prompt: nothing was sent, so there is no failure to show.
 */
async function generateReport(
  projectId: string,
  gate: ReportGate,
  { ownerModel = false }: GenerateReportOptions = {},
): Promise<ReportMeta | null> {
  const post = () => fetch(`/api/projects/${projectId}/reports`, { method: 'POST' })
  let res: Response
  if (ownerModel) {
    res = await post()
  } else {
    // The owner's narratives run on their own "Report narratives" model, which
    // the route reads itself; this only makes sure one is saved.
    if (!(await gate.ensureFeatureModel('report_narratives'))) return null
    res = await gate.fetchWithFeatureModel('report_narratives', post)
  }
  if (!res.ok) {
    const err = await readApiError(res, 'Report generation failed')
    const body = err.body ?? {}
    const code = readFeatureModelCode(body)
    // The provider's class and status tell a refused key from a rate limit or a
    // context overflow; the agent sends them instead of the provider's text.
    const provider = providerFailureDetail(body)
    if (code) {
      // "Your model" would point a collaborator at a model only the owner can change.
      const message = ownerModel && GATE_CODES.includes(code)
        ? OWNER_MODEL_FAILED
        : featureModelMessage(code, typeof body.model === 'string' ? body.model : undefined)
      throw new Error(provider ? `${message} (${provider})` : message)
    }
    if (provider) throw new Error(`${err.message} [${provider}]`)
    throw err
  }
  return res.json()
}

async function deleteReport(projectId: string, reportId: string): Promise<void> {
  await fetchOk(`/api/projects/${projectId}/reports/${reportId}`, { method: 'DELETE' }, 'Failed to delete report')
}

/** Hook for project-specific reports */
export function useReports(projectId: string, enabled = true) {
  const queryClient = useQueryClient()
  const gate = useFeatureModelGate()

  const query = useQuery({
    queryKey: [REPORTS_KEY, projectId],
    queryFn: () => fetchReports(projectId),
    enabled: enabled && !!projectId,
    staleTime: 30_000,
  })

  const generateMutation = useMutation({
    mutationFn: () => generateReport(projectId, gate),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REPORTS_KEY, projectId] })
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate: generateMutation.mutateAsync,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    /** Rejects with the cause; `deleteReport` never throws, so a failed delete looked like success. */
    deleteReportAsync: deleteMutation.mutateAsync,
    isDeleting: deleteMutation.isPending,
  }
}

/** Hook for all-projects reports listing */
export function useAllReports() {
  const queryClient = useQueryClient()
  const gate = useFeatureModelGate()

  const query = useQuery({
    queryKey: [ALL_REPORTS_KEY],
    queryFn: fetchAllReports,
    staleTime: 30_000,
  })

  const deleteMutation = useMutation({
    mutationFn: ({ projectId, reportId }: { projectId: string; reportId: string }) =>
      deleteReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })

  const generateMutation = useMutation({
    mutationFn: ({ projectId, ...opts }: { projectId: string } & GenerateReportOptions) =>
      generateReport(projectId, gate, opts),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ALL_REPORTS_KEY] })
    },
  })
  const { mutateAsync: generateAsync } = generateMutation
  const generate = useCallback(
    (projectId: string, opts: GenerateReportOptions = {}) => generateAsync({ projectId, ...opts }),
    [generateAsync],
  )

  return {
    reports: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    generate,
    isGenerating: generateMutation.isPending,
    generateError: generateMutation.error,
    deleteReport: deleteMutation.mutate,
    /** Rejects with the cause; `deleteReport` never throws, so a failed delete looked like success. */
    deleteReportAsync: deleteMutation.mutateAsync,
    isDeleting: deleteMutation.isPending,
  }
}

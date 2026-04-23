'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { Save, X, Loader2, Download, ShieldAlert, Zap, Bookmark, FolderOpen, List, GitBranch, Play } from 'lucide-react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import type { Project } from '@prisma/client'
import { validateProjectForm } from '@/lib/validation'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import { useProject } from '@/providers/ProjectProvider'
import useReconStatus from '@/hooks/useReconStatus'
import { useMultiPartialReconStatus } from '@/hooks/useMultiPartialReconStatus'
import { useMultiPartialReconSSE } from '@/hooks/useMultiPartialReconSSE'
import { useAlertModal, useToast } from '@/components/ui'
import type { PartialReconParams, PartialReconState } from '@/lib/recon-types'
import { PARTIAL_RECON_PHASE_MAP } from '@/lib/recon-types'
import type { ReconStatus } from '@/lib/recon-types'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { ReconLogsDrawer } from '@/app/graph/components/ReconLogsDrawer'
import { PartialReconBadges } from '@/components/PartialReconBadges'
import styles from './ProjectForm.module.css'

// Import sections
import { TargetSection } from './sections/TargetSection'
import { ScanModulesSection } from './sections/ScanModulesSection'
import { NaabuSection } from './sections/NaabuSection'
import { MasscanSection } from './sections/MasscanSection'
import { NmapSection } from './sections/NmapSection'
import { HttpxSection } from './sections/HttpxSection'
import { NucleiSection } from './sections/NucleiSection'
import { KatanaSection } from './sections/KatanaSection'
import { HakrawlerSection } from './sections/HakrawlerSection'
import { JsluiceSection } from './sections/JsluiceSection'
import { FfufSection } from './sections/FfufSection'
import { GauSection } from './sections/GauSection'
import { ParamSpiderSection } from './sections/ParamSpiderSection'
import { KiterunnerSection } from './sections/KiterunnerSection'
import { ArjunSection } from './sections/ArjunSection'
import { CveLookupSection } from './sections/CveLookupSection'
import { MitreSection } from './sections/MitreSection'
import { SecurityChecksSection } from './sections/SecurityChecksSection'
import { GithubSection } from './sections/GithubSection'
import { TrufflehogSection } from './sections/TrufflehogSection'
import { AgentBehaviourSection } from './sections/AgentBehaviourSection'
import { AttackSkillsSection } from './sections/AttackSkillsSection'
import { ShodanSection } from './sections/ShodanSection'
import { UrlscanSection } from './sections/UrlscanSection'
import { SubdomainDiscoverySection } from './sections/SubdomainDiscoverySection'
import { ToolMatrixSection } from './sections/ToolMatrixSection'
import { GvmScanSection } from './sections/GvmScanSection'
import { CypherFixSettingsSection } from './sections/CypherFixSettingsSection'
import { RoeSection } from './sections/RoeSection'
import { OsintEnrichmentSection } from './sections/OsintEnrichmentSection'
import { JsReconSection } from './sections/JsReconSection'
import { GraphqlScanSection } from './sections/GraphqlScanSection'
import { TakeoverSection } from './sections/TakeoverSection'
import { PartialReconModal } from './WorkflowView/PartialReconModal'
import { ReconPresetModal } from './ReconPresetModal'
import { SavePresetModal } from './SavePresetModal'
import { UserPresetDrawer } from './UserPresetDrawer'
import { getPresetById, type ReconPreset } from '@/lib/recon-presets'

const WorkflowView = dynamic(
  () => import('./WorkflowView/WorkflowView').then(m => ({ default: m.WorkflowView })),
  { ssr: false, loading: () => <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading workflow...</div> }
)

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ProjectFormProps {
  initialData?: Partial<ProjectFormData> & { id?: string }
  onSubmit: (data: ProjectFormData & { roeFile?: File | null }) => Promise<void>
  /** Save without navigating away (used by workflow modal save button) */
  onSaveAndStay?: (data: ProjectFormData & { roeFile?: File | null }) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
  mode: 'create' | 'edit'
  /** When set (e.g. from /projects/[id]/settings URL), ensures child sections always get a stable project id */
  projectIdFromRoute?: string
}

const TAB_GROUPS = [
  {
    label: 'Recon Pipeline',
    style: 'tabGroupRecon',
    tabs: [
      { id: 'preset', label: 'Recon Preset' },
      { id: 'target', label: 'Target & Modules' },
      { id: 'discovery', label: 'Discovery & OSINT' },
      { id: 'port', label: 'Port Scanning' },
      { id: 'http', label: 'HTTP Probing' },
      { id: 'resource', label: 'Resource Enum' },
      { id: 'jsrecon', label: 'JS Recon' },
      { id: 'vuln', label: 'Vulnerability Scanning' },
      { id: 'cve', label: 'CVE & MITRE' },
      { id: 'security', label: 'Security Checks' },
    ],
  },
  {
    label: '',
    style: 'tabGroupOther',
    tabs: [
      { id: 'integrations', label: 'Other Scans', wide: true },
    ],
  },
  {
    label: 'Scope',
    style: 'tabGroupScope',
    tabs: [
      { id: 'roe', label: 'RoE' },
    ],
  },
  {
    label: 'AI Agent',
    style: 'tabGroupAgent',
    tabs: [
      { id: 'agent', label: 'Agent Behaviour' },
      { id: 'toolmatrix', label: 'Tool Matrix' },
      { id: 'attack', label: 'Agent Skills' },
    ],
  },
  {
    label: 'Remediation',
    style: 'tabGroupRemediation',
    tabs: [
      { id: 'cypherfix', label: 'CypherFix' },
    ],
  },
] as const

type TabId = typeof TAB_GROUPS[number]['tabs'][number]['id']

const RECON_TAB_IDS = new Set<string>(['preset', 'target', 'discovery', 'port', 'http', 'resource', 'jsrecon', 'vuln', 'cve', 'security'])

// Minimal fallback defaults - only required fields
// Full defaults are fetched from /api/projects/defaults (served by recon backend)
const MINIMAL_DEFAULTS: Partial<ProjectFormData> = {
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}

// Fetch defaults from the recon backend (single source of truth)
async function fetchDefaults(): Promise<Partial<ProjectFormData>> {
  try {
    const response = await fetch('/api/projects/defaults')
    if (!response.ok) {
      console.warn('Failed to fetch defaults, using minimal fallback')
      return MINIMAL_DEFAULTS
    }
    const defaults = await response.json()
    // Merge with minimal defaults to ensure required fields exist
    return { ...MINIMAL_DEFAULTS, ...defaults }
  } catch (error) {
    console.warn('Error fetching defaults:', error)
    return MINIMAL_DEFAULTS
  }
}

export function ProjectForm({
  initialData,
  onSubmit,
  onSaveAndStay,
  onCancel,
  isSubmitting = false,
  mode,
  projectIdFromRoute,
}: ProjectFormProps) {
  const { alertError, alertWarning } = useAlertModal()
  const toast = useToast()
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<TabId>('target')
  const [viewMode, setViewMode] = useState<'tabs' | 'workflow'>('workflow')
  const [isLoadingDefaults, setIsLoadingDefaults] = useState(mode === 'create')
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...MINIMAL_DEFAULTS,
    ...initialData
  } as ProjectFormData))

  // Body wrapper ref -- used to pin log drawer top/bottom to the main content area
  const bodyRef = useRef<HTMLDivElement>(null)

  // Partial Recon
  const [partialReconToolId, setPartialReconToolId] = useState<string | null>(null)
  const [isPartialReconStarting, setIsPartialReconStarting] = useState(false)
  const [activePartialLogsRunId, setActivePartialLogsRunId] = useState<string | null>(null)
  // Locally tracked run state for immediate drawer rendering before polling catches up
  const [localPartialRun, setLocalPartialRun] = useState<PartialReconState | null>(null)

  // Recon Preset
  const [isPresetModalOpen, setIsPresetModalOpen] = useState(false)
  const [appliedPreset, setAppliedPreset] = useState<ReconPreset | null>(() => {
    if (initialData?.reconPresetId) {
      return getPresetById(initialData.reconPresetId as string) ?? null
    }
    return null
  })

  // User Presets
  const [isSavePresetModalOpen, setIsSavePresetModalOpen] = useState(false)
  const [isUserPresetDrawerOpen, setIsUserPresetDrawerOpen] = useState(false)


  // Guardrail block modal
  const [guardrailError, setGuardrailError] = useState<string | null>(null)

  // RoE document file (held in memory until project creation)
  const [roeFile, setRoeFile] = useState<File | null>(null)

  // GitHub Access Token check (stored in Global Settings, not project)
  const { userId } = useProject()
  const [hasGithubToken, setHasGithubToken] = useState(false)

  useEffect(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (settings) setHasGithubToken(!!settings.githubAccessToken)
      })
      .catch(() => setHasGithubToken(false))
  }, [userId])

  // Prefer URL param on settings page so wordlist upload etc. always get a real id.
  // In create mode, generate a stable ID upfront so uploads (JS Recon, FFuf wordlists)
  // can use it immediately — the same ID is sent to the backend on save.
  const [generatedId] = useState(() =>
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 25) : ''
  )
  const projectId =
    projectIdFromRoute ?? (initialData as { id?: string } | undefined)?.id ?? (mode === 'create' ? generatedId : undefined)

  // Track recon status in edit mode to reflect running state on the Start Recon button
  const { state: reconState } = useReconStatus({ projectId: mode === 'edit' ? (projectId ?? null) : null, enabled: mode === 'edit' })
  const isReconRunning = reconState?.status === 'running' || reconState?.status === 'starting'
  const isReconPaused = reconState?.status === 'paused'
  const isReconBusy = isReconRunning || isReconPaused

  // Track partial recon runs to show spinner on running tool nodes
  const {
    runs: allPartialReconRuns,
    activeRuns: activePartialRecons,
    refetch: refetchPartialReconStatuses,
  } = useMultiPartialReconStatus({
    projectId: mode === 'edit' ? (projectId ?? null) : null,
    enabled: mode === 'edit',
  })
  const runningPartialToolIds = new Set(
    activePartialRecons
      .filter(r => r.status === 'running' || r.status === 'starting')
      .map(r => r.tool_id)
  )

  // Find the active run for the logs drawer from the full run list so the drawer
  // keeps showing final status (completed/error) until the backend auto-cleans it.
  // Fall back to local state for the brief window before the first poll picks it up.
  const activePartialLogsRun = allPartialReconRuns.find(r => r.run_id === activePartialLogsRunId)
    ?? (localPartialRun?.run_id === activePartialLogsRunId ? localPartialRun : null)

  // SSE logs for the currently visible partial recon drawer
  const {
    logsMap: partialReconLogsMap,
    phaseMap: partialReconPhaseMap,
    clearLogsForRun: clearPartialReconLogsForRun,
  } = useMultiPartialReconSSE({
    projectId: projectId ?? null,
    activeRunId: activePartialLogsRunId,
    onComplete: () => { refetchPartialReconStatuses() },
  })

  // Fetch defaults from backend on mount (only for create mode)
  useEffect(() => {
    if (mode === 'create') {
      fetchDefaults().then(defaults => {
        setFormData(prev => ({ ...defaults, ...prev, ...initialData } as ProjectFormData))
        setIsLoadingDefaults(false)
      })
    }
  }, [mode, initialData])

  // Track body wrapper position so fixed-position log drawers pin to the main content area
  useEffect(() => {
    const body = bodyRef.current
    if (!body) return
    const update = () => {
      const rect = body.getBoundingClientRect()
      document.documentElement.style.setProperty('--drawer-top', `${rect.top}px`)
      document.documentElement.style.setProperty('--drawer-bottom', `${window.innerHeight - rect.bottom}px`)
    }
    update()
    const ro = new ResizeObserver(update)
    ro.observe(body)
    window.addEventListener('resize', update)
    window.addEventListener('scroll', update, true)
    return () => {
      ro.disconnect()
      window.removeEventListener('resize', update)
      window.removeEventListener('scroll', update, true)
    }
  }, [])

  const updateField = <K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  // Auto-save a single toggle field directly to DB (used in workflow mode)
  const autoSaveField = useCallback(async <K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    if (!projectId || mode !== 'edit') return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [field]: value }),
      })
      if (!res.ok) {
        const err = await res.json()
        toast.error(err.error || 'Failed to save')
      }
    } catch {
      toast.error('Failed to save setting')
    }
  }, [projectId, mode, toast])

  const updateMultipleFields = (fields: Partial<ProjectFormData>) => {
    setFormData(prev => ({ ...prev, ...fields }))
  }

  const applyPreset = useCallback(async (preset: ReconPreset) => {
    // Only apply the preset's own parameters (recon pipeline fields only).
    // User-entered fields (name, targetDomain, etc.) are preserved because
    // preset.parameters only contains recon-relevant keys.
    setFormData(prev => ({ ...prev, ...preset.parameters }))
    setAppliedPreset(preset)
    setIsPresetModalOpen(false)
    toast.success(`Recon preset "${preset.name}" applied`, 'Preset Applied')
  }, [toast])

  const handleLoadUserPreset = useCallback((settings: Record<string, unknown>) => {
    setFormData(prev => ({ ...prev, ...settings } as ProjectFormData))
    // Sync recon preset badge
    if (settings.reconPresetId) {
      setAppliedPreset(getPresetById(settings.reconPresetId as string) ?? null)
    } else {
      setAppliedPreset(null)
    }
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      alertWarning('Project name is required')
      return
    }

    if (!formData.ipMode && !formData.targetDomain.trim()) {
      alertWarning('Target domain is required')
      return
    }

    // Run field validation
    const validationErrors = validateProjectForm(formData as unknown as Record<string, unknown>)
    if (validationErrors.length > 0) {
      alertWarning('Validation errors:\n' + validationErrors.map(e => `- ${e.message}`).join('\n'))
      return
    }

    // Hard guardrail: block government/public domains before hitting API
    if (!formData.ipMode && formData.targetDomain) {
      const hardCheck = isHardBlockedDomain(formData.targetDomain)
      if (hardCheck.blocked) {
        setGuardrailError(hardCheck.reason)
        return
      }
    }

    try {
      // Attach roeFile and pre-generated ID to form data for submission
      const submitData = {
        ...formData,
        reconPresetId: appliedPreset?.id ?? formData.reconPresetId ?? null,
        ...(roeFile ? { roeFile } : {}),
        ...(mode === 'create' && projectId ? { id: projectId } : {}),
      }
      await onSubmit(submitData)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (message.toLowerCase().includes('guardrail') || message.toLowerCase().includes('permanently blocked')) {
        const reason = message
          .replace(/^Target blocked by guardrail:\s*/i, '')
          .replace(/^Target permanently blocked:\s*/i, '')
        setGuardrailError(reason || message)
      } else {
        alertError(message)
      }
    }
  }

  const handleSaveAndStay = async () => {
    if (!onSaveAndStay) return

    if (!formData.name.trim()) {
      alertWarning('Project name is required')
      return
    }
    if (!formData.ipMode && !formData.targetDomain.trim()) {
      alertWarning('Target domain is required')
      return
    }
    const validationErrors = validateProjectForm(formData as unknown as Record<string, unknown>)
    if (validationErrors.length > 0) {
      alertWarning('Validation errors:\n' + validationErrors.map(e => `- ${e.message}`).join('\n'))
      return
    }
    if (!formData.ipMode && formData.targetDomain) {
      const hardCheck = isHardBlockedDomain(formData.targetDomain)
      if (hardCheck.blocked) {
        setGuardrailError(hardCheck.reason)
        return
      }
    }
    try {
      const submitData = {
        ...formData,
        reconPresetId: appliedPreset?.id ?? formData.reconPresetId ?? null,
        ...(roeFile ? { roeFile } : {}),
        ...(mode === 'create' && projectId ? { id: projectId } : {}),
      }
      await onSaveAndStay(submitData)
      toast.success('Project saved')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (message.toLowerCase().includes('guardrail') || message.toLowerCase().includes('permanently blocked')) {
        const reason = message
          .replace(/^Target blocked by guardrail:\s*/i, '')
          .replace(/^Target permanently blocked:\s*/i, '')
        setGuardrailError(reason || message)
      } else {
        alertError(message)
      }
    }
  }

  // Partial recon confirm handler
  const handlePartialReconConfirm = useCallback(async (params: PartialReconParams) => {
    if (!projectId) return
    setIsPartialReconStarting(true)
    try {
      const response = await fetch(`/api/recon/${projectId}/partial`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        toast.error(data.error || 'Failed to start partial recon')
        return
      }
      const data: PartialReconState = await response.json()
      setPartialReconToolId(null)
      toast.success('Partial recon started')
      // Store locally for immediate drawer rendering, then open it
      setLocalPartialRun(data)
      setActivePartialLogsRunId(data.run_id)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to start partial recon')
    } finally {
      setIsPartialReconStarting(false)
    }
  }, [projectId, toast])

  // Determine if form can be submitted
  const canSubmit = !isSubmitting && !isLoadingDefaults

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
          {appliedPreset && (
            <span className={styles.presetBadge}>Started from: {appliedPreset.name}</span>
          )}
        </h1>
        <div className={styles.actions}>
          {mode === 'edit' && projectId ? (
            <>
              <button
                type="button"
                className={`reconStartButton${isReconBusy ? ' reconStartButtonActive' : ''}`}
                onClick={() => router.push(isReconBusy ? `/graph?project=${projectId}&openlogs=recon` : `/graph?project=${projectId}&autostart=true`)}
                disabled={isSubmitting || runningPartialToolIds.size > 0}
                title={runningPartialToolIds.size > 0 ? 'Partial recon is running -- stop it first' : isReconRunning ? 'Recon is running -- click to view progress' : isReconPaused ? 'Recon is paused -- click to view' : 'Navigate to the graph page and start the full recon pipeline'}
              >
                {isReconRunning ? (
                  <Loader2 size={14} className={styles.spinner} />
                ) : (
                  <Play size={14} />
                )}
                {isReconRunning ? 'Running...' : isReconPaused ? 'Paused' : 'Start Recon Pipeline'}
              </button>
              {/* Partial Recon Badges */}
              {activePartialRecons.length > 0 && (
                <PartialReconBadges
                  activePartialRecons={activePartialRecons}
                  activeLogsRunId={activePartialLogsRunId}
                  onToggleLogs={(runId) => setActivePartialLogsRunId(prev => prev === runId ? null : runId)}
                  onStop={async (runId) => {
                    await fetch(`/api/recon/${projectId}/partial/${runId}/stop`, { method: 'POST' })
                  }}
                />
              )}
            </>
          ) : (
            <button
              type="button"
              className="secondaryButton"
              onClick={onCancel}
              disabled={isSubmitting}
              title="Discard all unsaved changes and return to the previous page"
            >
              <X size={14} />
              Cancel
            </button>
          )}
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setIsUserPresetDrawerOpen(true)}
            disabled={isSubmitting || isLoadingDefaults}
            title="Load a previously saved preset to apply all its settings to this project (target and subdomain fields are preserved)"
          >
            <FolderOpen size={14} />
            Load Preset
          </button>
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setIsSavePresetModalOpen(true)}
            disabled={isSubmitting || isLoadingDefaults}
            title="Save the current project settings as a reusable preset (everything except target domain, subdomains, and IP list)"
          >
            <Bookmark size={14} />
            Save as Preset
          </button>
          {mode === 'edit' && projectId && (
            <button
              type="button"
              className="secondaryButton"
              onClick={() => window.open(`/api/projects/${projectId}/export`)}
              title="Download a full project backup as a ZIP file including settings, conversations, graph data, reports, and artifacts"
            >
              <Download size={14} />
              Export
            </button>
          )}
          <button
            type="submit"
            className="primaryButton"
            disabled={!canSubmit}
            title={mode === 'create' ? 'Create the project with the current settings and start working' : 'Save all changes to the project settings'}
          >
            {isLoadingDefaults ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Loading...
              </>
            ) : (
              <>
                <Save size={14} />
                {isSubmitting ? 'Saving...' : mode === 'edit' ? 'Update Settings' : 'Save Project'}
              </>
            )}
          </button>
        </div>
      </div>

      <div ref={bodyRef} className={styles.bodyWrapper}>
      {isLoadingDefaults ? (
        <div className={styles.loadingContainer}>
          <Loader2 size={24} className={styles.spinner} />
          <p>Loading configuration defaults...</p>
        </div>
      ) : (
        <>
          <div className={styles.tabsWrapper}>
          <div className={styles.tabs}>
            {TAB_GROUPS.map((group, gi) => (
              <div key={gi} className={group.style ? styles[group.style] : styles.tabGroup}>
                {group.label === 'Recon Pipeline' ? (
                  <>
                    <div className={styles.reconGroupInner}>
                      <div className={styles.viewModeToggle}>
                        <button
                          type="button"
                          className={`${styles.viewModeOption} ${viewMode === 'tabs' ? styles.viewModeOptionActive : ''}`}
                          onClick={() => setViewMode('tabs')}
                          title="Tab view"
                        >
                          <List size={11} />
                        </button>
                        <button
                          type="button"
                          className={`${styles.viewModeOption} ${viewMode === 'workflow' ? styles.viewModeOptionActive : ''}`}
                          onClick={() => {
                            setViewMode('workflow')
                            if (!RECON_TAB_IDS.has(activeTab)) setActiveTab('target')
                          }}
                          title="Workflow view"
                        >
                          <GitBranch size={11} />
                        </button>
                      </div>
                      <div className={styles.reconGroupContent}>
                        <span className={styles.tabGroupLabel}>{group.label}</span>
                        <div className={styles.tabGroupTabs}>
                          {group.tabs.map(tab => (
                            <button
                              key={tab.id}
                              type="button"
                              className={`tab ${activeTab === tab.id ? 'tabActive' : ''} ${styles.compactTab} ${tab.id === 'preset' ? styles.presetTab : ''} ${tab.id !== 'preset' && viewMode !== 'tabs' ? styles.hiddenTab : ''}`}
                              onClick={() => {
                                if ((tab.id as string) === 'preset') {
                                  setIsPresetModalOpen(true)
                                } else if (viewMode === 'tabs') {
                                  setActiveTab(tab.id)
                                }
                              }}
                            >
                              {tab.id === 'preset' && <Zap size={15} className={styles.presetIcon} />}
                              {tab.label}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    {group.label && (
                      <span className={styles.tabGroupLabel}>{group.label}</span>
                    )}
                    <div className={styles.tabGroupTabs}>
                      {group.tabs.map(tab => (
                        <button
                          key={tab.id}
                          type="button"
                          className={`tab ${activeTab === tab.id ? 'tabActive' : ''} ${styles.compactTab} ${'wide' in tab && tab.wide ? styles.wideTab : ''} ${(tab.id as string) === 'preset' ? styles.presetTab : ''}`}
                          onClick={() => {
                            if ((tab.id as string) === 'preset') {
                              setIsPresetModalOpen(true)
                            } else {
                              setActiveTab(tab.id)
                            }
                          }}
                        >
                          {(tab.id as string) === 'preset' && <Zap size={15} className={styles.presetIcon} />}
                          {tab.label}
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
          </div>

          <div className={viewMode === 'workflow' && RECON_TAB_IDS.has(activeTab) ? styles.contentWorkflow : styles.content}>
            {/* Workflow view -- replaces recon tab content when in workflow mode */}
            {viewMode === 'workflow' && RECON_TAB_IDS.has(activeTab) && (
              <WorkflowView
                formData={formData}
                updateField={updateField}
                projectId={projectId}
                mode={mode}
                onSave={onSaveAndStay ? handleSaveAndStay : undefined}
                onRunPartial={(toolId) => setPartialReconToolId(toolId)}
                runningPartialToolIds={runningPartialToolIds}
                onAutoSaveField={autoSaveField}
              />
            )}

            {/* Tab-based views */}
            {activeTab === 'roe' && (
          <RoeSection
            data={formData}
            updateField={updateField}
            updateMultipleFields={updateMultipleFields}
            mode={mode}
            onFileSelected={setRoeFile}
          />
        )}

        {activeTab === 'target' && viewMode === 'tabs' && (
          <>
            <TargetSection data={formData} updateField={updateField} mode={mode} />
            <ScanModulesSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'discovery' && viewMode === 'tabs' && (
          <>
            <SubdomainDiscoverySection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SubdomainDiscovery') : undefined} />
            <ShodanSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Shodan') : undefined} />
            <UrlscanSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Urlscan') : undefined} />
            <OsintEnrichmentSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('OsintEnrichment') : undefined} onRunUncover={mode === 'edit' && projectId ? () => setPartialReconToolId('Uncover') : undefined} />
          </>
        )}

        {activeTab === 'port' && viewMode === 'tabs' && (
          <>
            {!formData.naabuEnabled && !formData.masscanEnabled && (
              <div className={styles.shodanWarning}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Both port scanners are disabled. The recon pipeline will skip port scanning entirely &mdash; downstream modules (HTTP probe, vulnerability scanning) require open ports to function and will produce no results.</span>
              </div>
            )}
            <NaabuSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Naabu') : undefined} />
            <NmapSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Nmap') : undefined} />
            <MasscanSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Masscan') : undefined} />
          </>
        )}

        {activeTab === 'http' && viewMode === 'tabs' && (
          <HttpxSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Httpx') : undefined} />
        )}

        {activeTab === 'resource' && viewMode === 'tabs' && (
          <>
            <KatanaSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Katana') : undefined} />
            <HakrawlerSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Hakrawler') : undefined} />
            <JsluiceSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Jsluice') : undefined} />
            <FfufSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Ffuf') : undefined} />
            <GauSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Gau') : undefined} />
            <ParamSpiderSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('ParamSpider') : undefined} />
            <KiterunnerSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Kiterunner') : undefined} />
            <ArjunSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Arjun') : undefined} />
          </>
        )}

        {activeTab === 'jsrecon' && viewMode === 'tabs' && (
          <JsReconSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('JsRecon') : undefined} />
        )}

        {activeTab === 'vuln' && viewMode === 'tabs' && (
          <>
            <NucleiSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Nuclei') : undefined} />
            <TakeoverSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SubdomainTakeover') : undefined} />
            <GraphqlScanSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('GraphqlScan') : undefined} />
          </>
        )}

        {activeTab === 'cve' && viewMode === 'tabs' && (
          <>
            <CveLookupSection data={formData} updateField={updateField} />
            <MitreSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'security' && viewMode === 'tabs' && (
          <SecurityChecksSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SecurityChecks') : undefined} />
        )}

        {activeTab === 'integrations' && (
          <>
            <GvmScanSection data={formData} updateField={updateField} />
            <GithubSection data={formData} updateField={updateField} hasGithubToken={hasGithubToken} />
            <TrufflehogSection data={formData} updateField={updateField} hasGithubToken={hasGithubToken} />
          </>
        )}

        {activeTab === 'agent' && (
          <AgentBehaviourSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'toolmatrix' && (
          <ToolMatrixSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'attack' && (
          <AttackSkillsSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'cypherfix' && (
          <CypherFixSettingsSection data={formData} updateField={updateField} />
        )}
          </div>
        </>
      )}
      </div>

      {/* Recon Preset modal */}
      <ReconPresetModal
        isOpen={isPresetModalOpen}
        onClose={() => setIsPresetModalOpen(false)}
        onSelect={applyPreset}
        onLoadUserPreset={handleLoadUserPreset}
        currentPresetId={appliedPreset?.id}
        userId={userId}
        model={(formData.agentOpenaiModel as string) || 'claude-opus-4-6'}
      />

      {/* User Preset: Save modal */}
      <SavePresetModal
        isOpen={isSavePresetModalOpen}
        onClose={() => setIsSavePresetModalOpen(false)}
        formData={formData as unknown as Record<string, unknown>}
        userId={userId}
      />

      {/* User Preset: Load drawer */}
      <UserPresetDrawer
        isOpen={isUserPresetDrawerOpen}
        onClose={() => setIsUserPresetDrawerOpen(false)}
        onLoad={handleLoadUserPreset}
        userId={userId}
      />

      {/* Partial Recon Config Modal */}
      <PartialReconModal
        isOpen={!!partialReconToolId}
        toolId={partialReconToolId}
        onClose={() => setPartialReconToolId(null)}
        onConfirm={handlePartialReconConfirm}
        projectId={projectId}
        targetDomain={formData.targetDomain || ''}
        subdomainPrefixes={formData.subdomainList as string[] || []}
        isStarting={isPartialReconStarting}
        userId={userId ?? undefined}
      />

      {/* Partial Recon Logs Drawer */}
      {activePartialLogsRun && (
        <ReconLogsDrawer
          isOpen={!!activePartialLogsRunId}
          onClose={() => setActivePartialLogsRunId(null)}
          logs={partialReconLogsMap[activePartialLogsRunId!] || []}
          currentPhase={partialReconPhaseMap[activePartialLogsRunId!]?.phase || null}
          currentPhaseNumber={partialReconPhaseMap[activePartialLogsRunId!]?.phaseNumber || null}
          status={(activePartialLogsRun.status as ReconStatus) || 'idle'}
          errorMessage={activePartialLogsRun.error}
          onClearLogs={() => activePartialLogsRunId && clearPartialReconLogsForRun(activePartialLogsRunId)}
          onStop={async () => {
            if (activePartialLogsRunId) {
              await fetch(`/api/recon/${projectId}/partial/${activePartialLogsRunId}/stop`, { method: 'POST' })
              setActivePartialLogsRunId(null)
            }
          }}
          title={`Partial Recon: ${WORKFLOW_TOOLS.find(t => t.id === activePartialLogsRun.tool_id)?.label || 'Running'}`}
          phases={PARTIAL_RECON_PHASE_MAP[activePartialLogsRun.tool_id || ''] || ['Running']}
          totalPhases={(PARTIAL_RECON_PHASE_MAP[activePartialLogsRun.tool_id || ''] || ['Running']).length}
          hidePhaseProgress
        />
      )}

      {/* Guardrail block modal */}
      {guardrailError && (
        <div className={styles.guardrailOverlay} onClick={() => setGuardrailError(null)}>
          <div className={styles.guardrailModal} onClick={(e) => e.stopPropagation()}>
            <div className={styles.guardrailIconWrapper}>
              <ShieldAlert size={32} />
            </div>
            <h2 className={styles.guardrailTitle}>Target Blocked</h2>
            <p className={styles.guardrailMessage}>{guardrailError}</p>
            <p className={styles.guardrailHint}>
              This target appears to be a well-known public service that you are unlikely authorized to test.
              Please use a domain or IP range you own or have explicit permission to scan.
            </p>
            <button
              type="button"
              className={styles.guardrailButton}
              onClick={() => setGuardrailError(null)}
            >
              Understood
            </button>
          </div>
        </div>
      )}
    </form>
  )
}

export default ProjectForm

'use client'

import { DEFAULT_OPENAPI_DISCOVERY_PATHS } from '@/lib/openapi-defaults'
import { useState, useEffect, useCallback, useRef } from 'react'
import { Save, X, Loader2, Download, ShieldAlert, Zap, Bookmark, FolderOpen, List, GitBranch, Play } from 'lucide-react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import type { Project } from '@prisma/client'
import { validateProjectForm } from '@/lib/validation'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import { validateDomainBatch } from '@/lib/domainBatch'
import { tabForAnchor } from '@/lib/projectSettingsLinks'
import { graphScanHref, type ScanModal } from '@/lib/scanModalLink'
import { useProject } from '@/providers/ProjectProvider'
import useReconStatus from '@/hooks/useReconStatus'
import { useScanControls } from '@/hooks/useScanControls'
import { ScanActions } from '@/components/scans/ScanActions'
import { OtherScansModal } from '@/app/graph/components/OtherScansModal/OtherScansModal'
import { useMultiPartialReconStatus } from '@/hooks/useMultiPartialReconStatus'
import { useScanStartFailure } from '@/hooks/useScanStartFailure'
import { useMultiPartialReconSSE } from '@/hooks/useMultiPartialReconSSE'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { useDetectedHostIp } from '@/hooks/useDetectedHostIp'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
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
import { OpenApiSection } from './sections/OpenApiSection'
import { ZapAjaxSpiderSection } from './sections/ZapAjaxSpiderSection'
import { HakrawlerSection } from './sections/HakrawlerSection'
import { ResourceEnumAiSection } from './sections/ResourceEnumAiSection'
import { AiSurfaceReconSection } from './sections/AiSurfaceReconSection'
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
import { SupplyChainReconSection } from './sections/SupplyChainReconSection'
import { SupplyChainScanSection } from './sections/SupplyChainScanSection'
import { AgentBehaviourSection } from './sections/AgentBehaviourSection'
import { AttackSkillsSection } from './sections/AttackSkillsSection'
import { ShodanSection } from './sections/ShodanSection'
import { UrlscanSection } from './sections/UrlscanSection'
import { SubdomainDiscoverySection } from './sections/SubdomainDiscoverySection'
import { OriginDiscoverySection } from './sections/OriginDiscoverySection'
import { ToolMatrixSection } from './sections/ToolMatrixSection'
import { GvmScanSection } from './sections/GvmScanSection'
import { SectionScanActions } from './sections/SectionScanActions'
import { CypherFixSettingsSection } from './sections/CypherFixSettingsSection'
import { RoeSection } from './sections/RoeSection'
import { OsintEnrichmentSection } from './sections/OsintEnrichmentSection'
import { JsReconSection } from './sections/JsReconSection'
import { GraphqlScanSection } from './sections/GraphqlScanSection'
import { TakeoverSection } from './sections/TakeoverSection'
import { VhostSniSection } from './sections/VhostSniSection'
import { WebCachePoisonSection } from './sections/WebCachePoisonSection'
import { PartialReconModal } from './WorkflowView/PartialReconModal'
import { ReconPresetModal } from './ReconPresetModal'
import { ProviderRequiredModal, ModelSelectionModal } from './ProjectLlmGate'
import { seedInitialModels, needsModelGate, hasNoConfiguredProvider } from './projectLlmGate.logic'
import { SavePresetModal } from './SavePresetModal'
import { UserPresetDrawer } from './UserPresetDrawer'
import { getPresetById, type ReconPreset } from '@/lib/recon-presets'
import { resolveIpModeForPreset } from '@/lib/recon-presets/targeting'
import { PRESET_EXCLUDED_FIELDS } from '@/lib/project-preset-utils'

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
// All valid tab ids, for validating a `?tab=` deep-link.
const ALL_TAB_IDS = new Set<string>(TAB_GROUPS.flatMap(g => g.tabs.map(t => t.id)))

// Minimal fallback defaults - only required fields
// Full defaults are fetched from /api/projects/defaults (served by recon backend)
const MINIMAL_DEFAULTS: Partial<ProjectFormData> = {
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  domainBatchMode: false,
  domainBatchHosts: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
  openapiEnabled: true,
  openapiAutoDiscover: true,
  openapiDiscoveryPaths: [...DEFAULT_OPENAPI_DISCOVERY_PATHS],
  openapiSources: [],
  openapiDiscoveryHeaders: [],
  openapiTimeout: 10,
  openapiMaxDocuments: 50,
}

/** The target requirement per mode, shared by Save and Save-and-stay so the two
 *  can never disagree about what a valid target is. Returns a message or null. */
function validateTargetForMode(formData: ProjectFormData): string | null {
  if (formData.domainBatchMode) {
    const result = validateDomainBatch(formData.domainBatchHosts || [])
    return result.ok ? null : result.errors.join('\n')
  }
  if (!formData.ipMode && !formData.targetDomain.trim()) {
    return 'Target domain is required'
  }
  return null
}

/** The first target this project would scan that is permanently blocked, whatever
 *  the mode. A batch must be checked group by group: one blocked domain in a list
 *  of twenty is still a blocked scan. */
function firstHardBlockedTarget(
  formData: ProjectFormData
): { domain: string; reason: string } | null {
  const domains = formData.domainBatchMode
    ? validateDomainBatch(formData.domainBatchHosts || []).groups.map(g => g.rootDomain)
    : (!formData.ipMode && formData.targetDomain ? [formData.targetDomain] : [])

  for (const domain of domains) {
    const check = isHardBlockedDomain(domain)
    if (check.blocked) return { domain, reason: check.reason }
  }
  return null
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
  // A section anchor waiting to be scrolled to, e.g. arriving from an Other
  // Scans card via /projects/<id>/settings#github-secret-hunting.
  const [pendingAnchor, setPendingAnchor] = useState<string | null>(null)
  const [isLoadingDefaults, setIsLoadingDefaults] = useState(mode === 'create')
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...MINIMAL_DEFAULTS,
    ...initialData
  } as ProjectFormData))

  // Dirty tracking: baseline = the last saved/loaded formData. Edit mode adopts
  // the initial value on mount; create mode re-adopts once async defaults load
  // (see the defaults effect below). Drives the Update/Save button + the
  // unsaved-changes guard. Applying a preset mutates formData, so it naturally
  // marks the form dirty -- fixing the "preset applied but never saved" footgun.
  const { isDirty, setBaseline } = useDirtyState(formData)
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty)

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

  // LLM provider / model gates (create mode only)
  const [showProviderGate, setShowProviderGate] = useState(false)
  // create mode: false until the provider check resolves; gates the form render
  // so a no-provider user sees the "configure provider" gate immediately, not
  // the project form flashing first.
  const [providerChecked, setProviderChecked] = useState(mode !== 'create')
  const [showModelGate, setShowModelGate] = useState(false)
  // Which save action to resume once both models are picked in the gate
  const [pendingSaveAction, setPendingSaveAction] = useState<'submit' | 'stay' | null>(null)

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

  // Deep link into one section: /projects/<id>/settings#github-secret-hunting.
  // The tab has to be selected first - the section is not in the DOM until then -
  // so the scroll is deferred to the effect below rather than done here.
  const openSection = useCallback((anchor: string) => {
    const tab = tabForAnchor(anchor)
    if (!tab) return
    setActiveTab(tab as TabId)
    setPendingAnchor(anchor)
  }, [])

  useEffect(() => {
    const anchor = window.location.hash.slice(1)
    if (anchor) openSection(anchor)
  }, [openSection])

  // Both setters above batch into one render, so by the time this runs the
  // section has been committed and can be scrolled to. Cleared either way: a
  // missing element must not leave a scroll armed for a later tab switch.
  useEffect(() => {
    if (!pendingAnchor) return
    document.getElementById(pendingAnchor)?.scrollIntoView({ block: 'start', behavior: 'smooth' })
    setPendingAnchor(null)
  }, [pendingAnchor])

  // Prefer URL param on settings page so wordlist upload etc. always get a real id.
  // In create mode, generate a stable ID upfront so uploads (JS Recon, FFuf wordlists)
  // can use it immediately - the same ID is sent to the backend on save.
  const [generatedId] = useState(() =>
    typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '').slice(0, 25) : ''
  )
  const projectId =
    projectIdFromRoute ?? (initialData as { id?: string } | undefined)?.id ?? (mode === 'create' ? generatedId : undefined)
  // Scan Queue (Phase 3): a temporary partial-recon start refusal offers Cancel /
  // Add to queue instead of a dead-end toast.
  const { handleStartFailure: handlePartialStartFailure } = useScanStartFailure(projectId ?? null)

  // Deep-link support: `?tab=<id>` (e.g. from the CodeFix "missing settings" alert
  // linking to `/projects/[id]/settings?tab=cypherfix`) opens that tab directly.
  // Read from window after mount to avoid a Suspense boundary requirement.
  useEffect(() => {
    const tab = new URLSearchParams(window.location.search).get('tab')
    if (tab && ALL_TAB_IDS.has(tab)) {
      setActiveTab(tab as TabId)
      if (RECON_TAB_IDS.has(tab)) setViewMode('tabs')  // recon tabs only render in tabs view
    }
  }, [])

  // Track recon status in edit mode to reflect running state on the Start Recon button
  const { state: reconState } = useReconStatus({ projectId: mode === 'edit' ? (projectId ?? null) : null, enabled: mode === 'edit' })
  // Host LAN IP suggested for the LHOST field (issue #180). Fetched in both create
  // and edit mode; it is a separate signal, never merged into formData, so it never
  // reaches the save payload.
  const detectedHostIp = useDetectedHostIp()
  // The same scan cluster the graph toolbar shows. Only polls in edit mode with
  // a saved project: a create form has nothing to scan.
  const scans = useScanControls({
    projectId: mode === 'edit' ? projectId : null,
    enabled: mode === 'edit' && Boolean(projectId),
    // Slower than the graph page's default: this surface reports status, it is
    // not the live view, and matching the default would double the orchestrator
    // status traffic whenever both are open.
    pollingInterval: 15_000,
  })
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

  // Fetch defaults from backend on mount (only for create mode).
  // For a new project the LLM model fields are NOT taken from the backend
  // defaults (which are a hardcoded claude-* model). Instead they are seeded
  // from the user's remembered choices, or left empty to force an explicit
  // selection via the model gate on save.
  useEffect(() => {
    if (mode !== 'create') return
    Promise.all([
      fetchDefaults(),
      userId
        ? fetch(`/api/users/${userId}`).then(r => (r.ok ? r.json() : null)).catch(() => null)
        : Promise.resolve(null),
    ]).then(([defaults, user]) => {
      const seeded = seedInitialModels(user)
      let loaded: ProjectFormData | null = null
      setFormData(prev => {
        loaded = {
          ...defaults,
          ...prev,
          ...initialData,
          agentOpenaiModel: seeded.agentOpenaiModel,
          aiPipelineModel: seeded.aiPipelineModel,
        } as ProjectFormData
        return loaded
      })
      // Adopt the post-load value as the dirty baseline so freshly-loaded
      // defaults do NOT read as unsaved changes (would otherwise light up Save
      // and trigger the guard on a pristine create form).
      if (loaded) setBaseline(loaded)
      setIsLoadingDefaults(false)
    })
  }, [mode, initialData, userId, setBaseline])

  // Provider gate: block creating a project when no LLM provider is configured.
  useEffect(() => {
    if (mode !== 'create' || !userId) return
    fetch(`/api/users/${userId}/llm-providers`)
      .then(r => (r.ok ? r.json() : []))
      .then((providers) => {
        if (hasNoConfiguredProvider(providers)) {
          setShowProviderGate(true)
        }
        setProviderChecked(true)
      })
      .catch(() => { setProviderChecked(true) /* network error: don't hard-block, model gate still applies */ })
  }, [mode, userId])

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
        return
      }
      // Workflow toggles persist immediately; adopt the saved field into the
      // baseline so the batched Update button + guard don't flag it as unsaved.
      setBaseline(prev => ({ ...prev, [field]: value }))
    } catch {
      toast.error('Failed to save setting')
    }
  }, [projectId, mode, toast, setBaseline])

  const updateMultipleFields = (fields: Partial<ProjectFormData>) => {
    setFormData(prev => ({ ...prev, ...fields }))
  }

  const applyPreset = useCallback(async (preset: ReconPreset) => {
    // Apply ONLY this preset's settings on a clean backend-defaults baseline, so the
    // resulting recon config never depends on whichever preset was selected before
    // (no merge-from-previous-state - that made disabled tools "stick" across presets).
    // /api/projects/defaults carries no target-identity keys (name, targetDomain, IPs,
    // RoE), so the spread base `...prev` preserves everything the user entered; the
    // defaults reset every recon-tool field to its baseline; the preset then overrides
    // only the fields it explicitly declares. Mirrors the user-preset load path.
    let defaults: Record<string, unknown> = {}
    try {
      const res = await fetch('/api/projects/defaults')
      if (res.ok) defaults = await res.json()
    } catch {
      // Defaults unavailable: fall back to a plain merge so applying still works.
    }
    setFormData(prev => {
      const p = prev as Record<string, unknown>
      const d = defaults as Record<string, unknown>
      // Start from the current form and reset every EXISTING field to its backend
      // default. ONLY touch keys already present in the form: the /defaults blob also
      // carries recon/agent settings that are NOT Project columns (e.g.
      // takeoverCnameValidationEnabled), and writing those back makes the project
      // update fail with a Prisma "Unknown argument" error.
      const next: Record<string, unknown> = { ...p }
      for (const key of Object.keys(p)) {
        if (key in d) next[key] = d[key]
      }
      // Apply ONLY this preset's settings (all keys here are valid Project columns).
      Object.assign(next, preset.parameters)
      // A preset defines recon-tool config ONLY. Resetting to defaults must NOT reset
      // things presets never own: target identity/files (PRESET_EXCLUDED_FIELDS), the
      // user's LLM model choice, or RoE scope/client info (a safety boundary).
      for (const key of PRESET_EXCLUDED_FIELDS) next[key] = p[key]
      for (const key of Object.keys(p)) {
        if (key.startsWith('roe')) next[key] = p[key]
      }
      next.agentOpenaiModel = p.agentOpenaiModel
      next.aiPipelineModel = p.aiPipelineModel
      // Drive Start-from-IP from the preset's declared target type. ipMode is a
      // user-owned identity field (PRESET_EXCLUDED_FIELDS restored it to p above),
      // so this metadata-driven flip is the ONLY place a preset can set the mode.
      // Non-destructive: the now-hidden side (targetDomain / targetIps) is left
      // intact so switching back does not lose what the user typed. resolve()
      // returns undefined (leave as-is) in edit mode and for 'both' presets.
      const currentTargetMode = prev.ipMode ? 'ip' : prev.domainBatchMode ? 'batch' : 'domain'
      const resolvedIpMode = resolveIpModeForPreset(preset.targetProfile, mode, currentTargetMode)
      if (resolvedIpMode !== undefined) {
        next.ipMode = resolvedIpMode
        // Switching to IP targeting cannot leave a batch flagged as well, or the
        // project would claim two mutually exclusive modes.
        if (resolvedIpMode) next.domainBatchMode = false
      }
      return next as ProjectFormData
    })
    setAppliedPreset(preset)
    setIsPresetModalOpen(false)
    toast.success(`Recon preset "${preset.name}" applied`, 'Preset Applied')
  }, [toast, mode])

  const handleLoadUserPreset = useCallback((settings: Record<string, unknown>) => {
    // Only apply keys that already exist in the form: the merged settings can carry
    // backend-default keys that aren't Project columns (e.g. takeoverCnameValidationEnabled),
    // which would make the project update fail. reconPresetId is kept (handled below).
    setFormData(prev => {
      const p = prev as Record<string, unknown>
      const next: Record<string, unknown> = { ...p }
      for (const key of Object.keys(settings)) {
        if (key in p) next[key] = settings[key]
      }
      return next as ProjectFormData
    })
    // Sync recon preset badge
    if (settings.reconPresetId) {
      setAppliedPreset(getPresetById(settings.reconPresetId as string) ?? null)
    } else {
      setAppliedPreset(null)
    }
  }, [])

  // On save (create only), confirm an LLM provider exists before the model gate.
  // Without a provider the model picker can't load any models, so route the user
  // to "Configure an LLM provider first" instead of a broken model-selection modal.
  // Fetched fresh on save so a provider added/removed since mount is honored.
  const ensureProviderConfigured = async (): Promise<boolean> => {
    if (mode !== 'create' || !userId) return true
    try {
      const r = await fetch(`/api/users/${userId}/llm-providers`)
      const providers = r.ok ? await r.json() : []
      if (hasNoConfiguredProvider(providers)) {
        setShowProviderGate(true)
        return false
      }
    } catch {
      /* network error: don't hard-block; the model gate still applies */
    }
    return true
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      alertWarning('Project name is required')
      return
    }

    const targetError = validateTargetForMode(formData)
    if (targetError) {
      alertWarning(targetError)
      return
    }

    // Run field validation
    const validationErrors = validateProjectForm(formData as unknown as Record<string, unknown>)
    if (validationErrors.length > 0) {
      alertWarning('Validation errors:\n' + validationErrors.map(e => `- ${e.message}`).join('\n'))
      return
    }

    // Hard guardrail: block government/public domains before hitting API
    const blockedTarget = firstHardBlockedTarget(formData)
    if (blockedTarget) {
      setGuardrailError(blockedTarget.reason)
      return
    }

    // No LLM provider configured -> ask to set one up, don't open the model picker.
    if (!(await ensureProviderConfigured())) return

    // Force explicit LLM model selection on create (agent + AI recon pipeline)
    if (needsModelGate(mode, formData.agentOpenaiModel, formData.aiPipelineModel)) {
      setPendingSaveAction('submit')
      setShowModelGate(true)
      return
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
      // Adopt the just-saved state as the new baseline so the form reads clean
      // (create mode usually navigates away, but this keeps state correct if not).
      setBaseline(formData)
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

  /** `after` runs only once the save actually succeeded - it is how the section
   *  headers hand off to the graph page without navigating past a failed save.
   *
   *  Returns TRUE only when the project was actually written. Every early return
   *  below is a validation refusal, and a caller that treats "resolved" as
   *  "saved" will act on a save that never happened: the workflow node modal did
   *  exactly that and closed itself on a validation error, dropping the operator
   *  back to the graph with their unsaved input and only a transient alert to
   *  explain it. */
  const handleSaveAndStay = async (after?: () => void): Promise<boolean> => {
    if (!onSaveAndStay) return false

    if (!formData.name.trim()) {
      // Jump to the tab that owns the offending field, so the operator is not
      // told "required" about something the current view does not show.
      setActiveTab('target')
      alertWarning('Project name is required')
      return false
    }
    const targetError = validateTargetForMode(formData)
    if (targetError) {
      setActiveTab('target')
      alertWarning(targetError)
      return false
    }
    const validationErrors = validateProjectForm(formData as unknown as Record<string, unknown>)
    if (validationErrors.length > 0) {
      alertWarning('Validation errors:\n' + validationErrors.map(e => `- ${e.message}`).join('\n'))
      return false
    }
    const blockedTarget = firstHardBlockedTarget(formData)
    if (blockedTarget) {
      setActiveTab('target')
      setGuardrailError(blockedTarget.reason)
      return false
    }
    // No LLM provider configured -> ask to set one up, don't open the model picker.
    if (!(await ensureProviderConfigured())) return false

    // Force explicit LLM model selection on create (agent + AI recon pipeline)
    if (needsModelGate(mode, formData.agentOpenaiModel, formData.aiPipelineModel)) {
      setPendingSaveAction('stay')
      setShowModelGate(true)
      return false
    }
    try {
      const submitData = {
        ...formData,
        reconPresetId: appliedPreset?.id ?? formData.reconPresetId ?? null,
        ...(roeFile ? { roeFile } : {}),
        ...(mode === 'create' && projectId ? { id: projectId } : {}),
      }
      await onSaveAndStay(submitData)
      setBaseline(formData)
      toast.success('Project saved')
      after?.()
      return true
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
      return false
    }
  }

  // Update Settings / Start to Scan on a scan section's own header. The first is
  // the top bar's submit; the second saves in place (nothing to save = go now)
  // and then opens that scan's modal on the graph page.
  const updateSettingsFromSection = () => {
    void handleSubmit({ preventDefault: () => {} } as React.FormEvent)
  }

  const startScanFromSection = (scan: ScanModal) => {
    if (!projectId) return
    const openScan = () => router.push(graphScanHref(projectId, scan))
    if (!isDirty) {
      openScan()
      return
    }
    void handleSaveAndStay(openScan)
  }

  const sectionScanActions = (scan: ScanModal, scanLabel: string) =>
    mode === 'edit' && projectId ? (
      <SectionScanActions
        onUpdateSettings={updateSettingsFromSection}
        onStartScan={() => startScanFromSection(scan)}
        scanLabel={scanLabel}
        isDirty={isDirty}
        isSubmitting={isSubmitting}
      />
    ) : undefined

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
        setPartialReconToolId(null)
        // Temporary -> Cancel / Add to queue; permanent -> error (Scan Queue Phase 3).
        await handlePartialStartFailure(
          'partial_recon',
          { message: data.error || 'Failed to start partial recon', limit: data.limit, status: response.status },
          params as unknown as Record<string, unknown>,
        )
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
  }, [projectId, toast, handlePartialStartFailure])

  // Determine if form can be submitted
  const canSubmit = !isSubmitting && !isLoadingDefaults

  // Create mode: resolve the LLM-provider gate BEFORE rendering the project form.
  // While the check is in flight, show a brief loader (not the form); if no
  // provider exists, show ONLY the "configure provider" gate.
  if (mode === 'create' && !providerChecked) {
    return (
      <div className={styles.loadingContainer}>
        <Loader2 size={24} className={styles.spinner} />
        <p>Checking LLM provider...</p>
      </div>
    )
  }
  if (mode === 'create' && showProviderGate) {
    return <ProviderRequiredModal onCancel={onCancel} />
  }

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
          <WikiInfoButton
            target={mode === 'create' ? 'projectsNew' : 'projectSettings'}
            title={mode === 'create' ? 'Open Creating a Project wiki page' : 'Open Project Settings Reference wiki page'}
          />
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
                onClick={() => guardedNavigate(() => router.push(isReconBusy ? `/graph?project=${projectId}&openlogs=recon` : `/graph?project=${projectId}&autostart=true`))}
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

              <ScanActions scans={scans} stealthMode={formData.stealthMode} />
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
              onClick={() => guardedNavigate(onCancel)}
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
            disabled={!canSubmit || !isDirty}
            title={mode === 'create' ? 'Create the project with the current settings and start working' : !isDirty ? 'No unsaved changes' : 'Save all changes to the project settings'}
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
            <OriginDiscoverySection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('OriginDiscovery') : undefined} />
          </>
        )}

        {activeTab === 'port' && viewMode === 'tabs' && (
          <>
            {!formData.naabuEnabled && !formData.masscanEnabled && (
              <div className={styles.shodanWarning}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Both port scanners are disabled. The recon pipeline will skip port scanning entirely - downstream modules (HTTP probe, vulnerability scanning) require open ports to function and will produce no results.</span>
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
            <OpenApiSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('OpenAPI') : undefined} />
            <ZapAjaxSpiderSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('ZapAjaxSpider') : undefined} />
            <HakrawlerSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Hakrawler') : undefined} />
            <JsluiceSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Jsluice') : undefined} />
            <FfufSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Ffuf') : undefined} />
            <GauSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Gau') : undefined} />
            <ParamSpiderSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('ParamSpider') : undefined} />
            <KiterunnerSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Kiterunner') : undefined} />
            <ArjunSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Arjun') : undefined} />
            <ResourceEnumAiSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('EndpointAiClassifier') : undefined} />
            <AiSurfaceReconSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('AiSurfaceRecon') : undefined} />
          </>
        )}

        {activeTab === 'jsrecon' && viewMode === 'tabs' && (
          <>
            <JsReconSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('JsRecon') : undefined} />
            <SupplyChainReconSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SupplyChainRecon') : undefined} />
          </>
        )}

        {activeTab === 'vuln' && viewMode === 'tabs' && (
          <>
            <NucleiSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Nuclei') : undefined} />
            <TakeoverSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SubdomainTakeover') : undefined} />
            <VhostSniSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('VhostSni') : undefined} />
            <GraphqlScanSection data={formData} updateField={updateField} projectId={projectId} mode={mode} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('GraphqlScan') : undefined} />
            <WebCachePoisonSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('WebCachePoison') : undefined} />
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
            <GvmScanSection data={formData} updateField={updateField}
              actions={sectionScanActions('gvm', 'the GVM scan')} />
            <GithubSection data={formData} updateField={updateField} hasGithubToken={hasGithubToken}
              actions={sectionScanActions('other', 'Other Scans')} />
            <TrufflehogSection data={formData} updateField={updateField}
              projectId={projectId ?? null} mode={mode}
              actions={sectionScanActions('other', 'Other Scans')} />
            {/* Supply-Chain (L1): its input (uploaded SBOM / lockfile, GitHub
                repository, or an org to batch) is configured here, next to the
                other Other-Scans tools. The card in Other Scans owns only the
                run controls and stays disabled until this is set. */}
            <SupplyChainScanSection data={formData} updateField={updateField}
              projectId={projectId ?? null} mode={mode}
              actions={sectionScanActions('other', 'Other Scans')} />
          </>
        )}

        {activeTab === 'agent' && (
          <AgentBehaviourSection data={formData} updateField={updateField} detectedHostIp={detectedHostIp} />
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

      {/* LLM provider gate: no provider configured -> can't create a project */}
      {showProviderGate && (
        <ProviderRequiredModal onCancel={onCancel} />
      )}

      {/* Model selection gate: force picking both models before saving */}
      {showModelGate && (
        <ModelSelectionModal
          userId={userId}
          agentModel={(formData.agentOpenaiModel as string) || ''}
          aiPipelineModel={(formData.aiPipelineModel as string) || ''}
          onChangeAgent={(id) => updateField('agentOpenaiModel', id)}
          onChangeAiPipeline={(id) => updateField('aiPipelineModel', id)}
          onCancel={() => { setShowModelGate(false); setPendingSaveAction(null) }}
          onConfirm={() => {
            setShowModelGate(false)
            const action = pendingSaveAction
            setPendingSaveAction(null)
            if (action === 'submit') {
              void handleSubmit({ preventDefault: () => {} } as React.FormEvent)
            } else if (action === 'stay') {
              void handleSaveAndStay()
            }
          }}
        />
      )}

      {/* The same modal the graph page opens. Log drawers are deliberately not
          wired: this surface has nowhere to render a live log stream, so those
          controls stay disabled rather than opening an empty panel. */}
      <OtherScansModal
        isOpen={scans.otherScansOpen}
        onClose={scans.closeOtherScans}
        projectId={projectId ?? undefined}
        onOpenProjectSettings={(anchor) => {
          // The link's href is this very page, so the hash is updated here to
          // keep a refresh landing on the section the operator asked for.
          scans.closeOtherScans()
          window.history.replaceState(null, '', `#${anchor}`)
          openSection(anchor)
        }}
        hasReconData={scans.hasReconData}
        hasGithubToken={hasGithubToken}
        githubHuntStatus={scans.githubHunt.state?.status}
        onStartGithubHunt={() => void scans.githubHunt.startGithubHunt()}
        onPauseGithubHunt={() => void scans.githubHunt.pauseGithubHunt()}
        onResumeGithubHunt={() => void scans.githubHunt.resumeGithubHunt()}
        onStopGithubHunt={() => void scans.githubHunt.stopGithubHunt()}
        onDownloadGithubHuntJSON={() => projectId && window.open(`/api/github-hunt/${projectId}/download`, '_blank')}
        trufflehogProfiles={scans.trufflehog.profiles}
        trufflehogRunsBySource={scans.trufflehog.bySource}
        onStartTrufflehog={(source) => void scans.trufflehog.startTrufflehog(source)}
        onStopTrufflehog={(source) => void scans.trufflehog.stopTrufflehog(source)}
        onDownloadTrufflehogJSON={() => projectId && window.open(`/api/trufflehog/${projectId}/download`, '_blank')}
        supplyChainStatus={scans.supplyChain.state?.status}
        onStartSupplyChain={() => void scans.supplyChain.startSupplyChain()}
        onPauseSupplyChain={() => void scans.supplyChain.pauseSupplyChain()}
        onResumeSupplyChain={() => void scans.supplyChain.resumeSupplyChain()}
        onStopSupplyChain={() => void scans.supplyChain.stopSupplyChain()}
        onDownloadSupplyChainJSON={() => projectId && window.open(`/api/supply-chain/${projectId}/download`, '_blank')}
      />
    </form>
  )
}

export default ProjectForm

'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Save, X, Loader2, Download, ShieldAlert, Zap, Bookmark, FolderOpen, List, GitBranch, Play, Check } from 'lucide-react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import type { Project } from '@prisma/client'
import { validateProjectForm } from '@/lib/validation'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { validateDomainBatch } from '@/lib/domainBatch'
import { scopeGuardrailNames } from '@/lib/scopeGroups'
import { ipModeRoot, resolveProjectRoots } from '@/lib/partialReconScope'
import { tabForAnchor } from '@/lib/projectSettingsLinks'
import { graphScanHref, type ScanModal } from '@/lib/scanModalLink'
import { useProject } from '@/providers/ProjectProvider'
import { JevSelectionProvider } from '@/hooks/useHasJevProvider'
import useReconStatus from '@/hooks/useReconStatus'
import { useScanControls } from '@/hooks/useScanControls'
import { ScanActions } from '@/components/scans/ScanActions'
import { OtherScansModal } from '@/app/graph/components/OtherScansModal/OtherScansModal'
import { useMultiPartialReconStatus } from '@/hooks/useMultiPartialReconStatus'
import { useScanStartFailure } from '@/hooks/useScanStartFailure'
import { isStreamReconnecting } from '@/hooks/useReconSSE'
import { ApiError, errorMessage, fetchJson, fetchOk, readApiError, toApiError } from '@/lib/apiError'
import { readScanStartError, type ScanStartError } from '@/lib/scanStartError'
import { useDrawerOffsets } from '@/hooks/useDrawerOffsets'
import { useMultiPartialReconSSE } from '@/hooks/useMultiPartialReconSSE'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { useDetectedHostIp } from '@/hooks/useDetectedHostIp'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { deepEqual } from '@/lib/deepEqual'
import { clearRoeEntry, roeEntryBusy, useRoeEntry } from '@/components/roe/roeParseStore'
import { mergeServerRow } from '@/components/roe/mergeServerRow'
import { postUserSkillsChanged, useUserSkillsChanged } from '@/lib/userSkillsChannel'
import type { PartialReconParams, PartialReconState } from '@/lib/recon-types'
import { PARTIAL_RECON_TOTAL_PHASES } from '@/lib/recon-types'
import type { ReconStatus } from '@/lib/recon-types'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { MINIMAL_DEFAULTS } from './formDefaults'
import { ReconLogsDrawer } from '@/app/graph/components/ReconLogsDrawer'
import { PartialReconBadges } from '@/components/PartialReconBadges'
import styles from './ProjectForm.module.css'

// Import sections
import { TargetSection } from './sections/TargetSection'
import { AuthenticationSection } from './sections/AuthenticationSection'
import { ScanModulesSection } from './sections/ScanModulesSection'
import { NaabuSection } from './sections/NaabuSection'
import { MasscanSection } from './sections/MasscanSection'
import { NmapSection } from './sections/NmapSection'
import { TlsxSection } from './sections/TlsxSection'
import { HttpxSection } from './sections/HttpxSection'
import { IpAttributionSection } from './sections/IpAttributionSection'
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
import { SerializedScanSection } from './sections/SerializedScanSection'
import { GraphqlScanSection } from './sections/GraphqlScanSection'
import { TakeoverSection } from './sections/TakeoverSection'
import { VhostSniSection } from './sections/VhostSniSection'
import { WebCachePoisonSection } from './sections/WebCachePoisonSection'
import { RouteExposureSection } from './sections/RouteExposureSection'
import { PartialReconModal } from './WorkflowView/PartialReconModal'
import { usePartialLogsRun } from './usePartialLogsRun'
import { ReconPresetModal } from './ReconPresetModal'
import { ProviderRequiredModal, ModelSelectionModal } from './ProjectLlmGate'
import {
  seedInitialModels, needsModelGate, hasNoConfiguredProvider, providerGateApplies,
  pipelineModelOptional, loopModelOffered,
} from './projectLlmGate.logic'
import { fetchModelOptions } from '@/components/shared/modelOptions'
import { LOOP_MODEL_ID } from '@/lib/agentInTheLoop'
import { SavePresetModal } from './SavePresetModal'
import { UserPresetDrawer } from './UserPresetDrawer'
import { getPresetById, type ReconPreset } from '@/lib/recon-presets'
import { resolveIpModeForPreset } from '@/lib/recon-presets/targeting'
import {
  applyPresetSettings,
  appliedPresetName,
  pickPresetFields,
  presetFingerprint,
  type LoadedPreset,
} from '@/lib/project-preset-utils'
import { useUpdateProject } from '@/hooks/useProjects'
import { onProjectWrite, versionOf } from '@/lib/projectVersion'

const WorkflowView = dynamic(
  () => import('./WorkflowView/WorkflowView').then(m => ({ default: m.WorkflowView })),
  { ssr: false, loading: () => <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>Loading workflow...</div> }
)

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ProjectFormProps {
  initialData?: Partial<ProjectFormData> & { id?: string; userId?: string }
  /** Resolves to the saved row when there is one, so the form can adopt its `updatedAt`. */
  onSubmit: (data: ProjectFormData & { roeFile?: File | null }) => Promise<unknown>
  /** Save without navigating away (used by workflow modal save button) */
  onSaveAndStay?: (data: ProjectFormData & { roeFile?: File | null }) => Promise<unknown>
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

/** A preset picked in the built-in list, or one of the user's saved presets. */
type PresetSource =
  | { kind: 'builtin'; preset: ReconPreset }
  | { kind: 'user'; id: string; name: string }

function PresetLoadWarning({ saves, documentKeys = [] }: { saves: boolean; documentKeys?: string[] }) {
  return (
    <>
      {documentKeys.length > 0 && (
        <p>
          <strong>It also changes {documentKeys.length} setting{documentKeys.length === 1 ? '' : 's'} the Rules of
          Engagement document set:</strong> <code>{documentKeys.join(', ')}</code>. Replacing or removing the
          document later keeps these as the preset leaves them.
        </p>
      )}
      <p>
        The current project settings will be <strong>discarded</strong> and replaced with the
        preset&apos;s. Every setting the preset does not define goes back to its default.
      </p>
      <p>
        Not changed: the project name and description, the target and scope, the Rules of
        Engagement, uploaded files, and credentials.
      </p>
      <p>
        {saves
          ? 'The project is saved as soon as you confirm.'
          : 'Nothing is stored until you create the project.'}
      </p>
    </>
  )
}

const RECON_TAB_IDS = new Set<string>(['preset', 'target','discovery', 'port', 'http', 'resource', 'jsrecon', 'vuln', 'cve', 'security'])
// All valid tab ids, for validating a `?tab=` deep-link.
const ALL_TAB_IDS = new Set<string>(TAB_GROUPS.flatMap(g => g.tabs.map(t => t.id)))

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

/** The first name this project would scan that is permanently blocked, whatever
 *  the mode: every batch host and group root, or the target and its prefix hosts.
 *  One blocked host in a list of twenty is still a blocked scan. */
function firstHardBlockedTarget(
  formData: ProjectFormData
): { domain: string; reason: string } | null {
  const hit = firstHardBlocked(scopeGuardrailNames(formData))
  return hit ? { domain: hit.name, reason: hit.reason } : null
}

// Fetch defaults from the recon backend (single source of truth). On a failure
// the form still opens on the minimal fallback, and `error` says why, so the
// person knows the values are not the backend's.
async function fetchDefaults(): Promise<{ defaults: Partial<ProjectFormData>; error: string | null }> {
  try {
    const defaults = await fetchJson<Partial<ProjectFormData>>('/api/projects/defaults', undefined, 'Could not load the recon defaults')
    // Merge with minimal defaults to ensure required fields exist
    return { defaults: { ...MINIMAL_DEFAULTS, ...defaults }, error: null }
  } catch (error) {
    console.warn('Error fetching defaults:', error)
    return { defaults: MINIMAL_DEFAULTS, error: errorMessage(error, 'Could not load the recon defaults') }
  }
}

/**
 * Toast a scan hook's failure once per new message. The hooks keep their last
 * failed action or status read in `error`, and this page has no log drawer to
 * show it in. A start failure is left out: it opens the start-failure modal.
 */
export function useScanErrorToast(label: string, error: string | null | undefined, lastStartError?: () => ScanStartError | null) {
  const toast = useToast()
  const latest = useRef({ toast, lastStartError })
  latest.current = { toast, lastStartError }
  useEffect(() => {
    if (!error) return
    const start = latest.current.lastStartError?.()
    if (start && error.startsWith(start.message)) return
    latest.current.toast.error(error, label)
  }, [error, label])
}

/**
 * Toast each run seen ending in `error`, with the reason the orchestrator gave.
 * A run already in error when first seen is not announced: that is an earlier
 * visit's news, not something that just happened.
 */
export function useRunFailureToast(
  label: string,
  runs: Array<{ key: string; status?: string | null; error?: string | null }>,
) {
  const toast = useToast()
  const latest = useRef({ toast, runs })
  latest.current = { toast, runs }
  const seen = useRef<Record<string, string>>({})
  const signature = runs.map(r => `${r.key}=${r.status ?? ''}`).join('|')
  useEffect(() => {
    const before = seen.current
    const next: Record<string, string> = {}
    for (const run of latest.current.runs) {
      const status = run.status ?? ''
      next[run.key] = status
      const previous = before[run.key]
      if (status === 'error' && previous && previous !== 'error') {
        latest.current.toast.error(run.error ? `${label} failed: ${run.error}` : `${label} failed`, label)
      }
    }
    seen.current = next
  }, [signature, label])
}

/**
 * Strip the DERIVED engagement flag out of anything on its way into `formData`.
 *
 * `roeEnabled` is computed from whether any engagement limit is set, and nothing
 * writes it. It has to be kept out of the form's data for two separate reasons,
 * and only the first is obvious:
 *
 *  1. `useDirtyState(formData)` compares against a baseline, so a value the form
 *     derives rather than the user edits would make the form permanently dirty
 *     and fire the unsaved-changes guard on every navigation.
 *  2. The form SUBMITS `formData` wholesale. A project row loaded in edit mode
 *     spreads every scalar, so without this the form would read the stale
 *     column and write it straight back - leaving a stored value that disagrees
 *     with the derivation, which is the two-sources-of-truth state the
 *     derivation exists to end.
 *
 * TargetSection computes the value for display from the limits themselves.
 */
// Moved by every write, or the toggles a skills-changed event is about.
const SKILL_EVENT_IGNORED = new Set(['attackSkillConfig', 'updatedAt', 'updatedById'])

/**
 * Whether `fetched` differs from the row this form last saw from the server only in its skill
 * toggles. Only then may the form take the fetched updatedAt: taking it while another field had
 * changed would let the next whole-row save pass the stale check and revert that field.
 */
export function onlySkillTogglesChanged(known: Record<string, unknown> | null, fetched: Record<string, unknown>): boolean {
  if (!known) return false
  return Object.keys(fetched).every((k) => SKILL_EVENT_IGNORED.has(k) || deepEqual(fetched[k], known[k]))
}

function withoutDerived<T extends Record<string, unknown>>(row: T | undefined): T {
  if (!row) return {} as T
  const clone = { ...row }
  delete clone.roeEnabled
  return clone as T
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
  const { alertError, alertWarning, confirm: confirmModal, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const router = useRouter()
  // Saves a loaded preset. The mutation (not a bare fetch) so the cached project
  // is invalidated and a later visit is not seeded with the pre-preset settings.
  const presetSaveMutation = useUpdateProject()
  const [activeTab, setActiveTab] = useState<TabId>('target')
  const [viewMode, setViewMode] = useState<'tabs' | 'workflow'>('workflow')
  // A section anchor waiting to be scrolled to, e.g. arriving from an Other
  // Scans card via /projects/<id>/settings#github-secret-hunting.
  const [pendingAnchor, setPendingAnchor] = useState<string | null>(null)
  const [isLoadingDefaults, setIsLoadingDefaults] = useState(mode === 'create')
  const [defaultsWarning, setDefaultsWarning] = useState<string | null>(null)
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...MINIMAL_DEFAULTS,
    ...withoutDerived(initialData as Record<string, unknown>),
    jevProviderId: mode === 'create' ? null : initialData?.jevProviderId ?? null,
  } as ProjectFormData))

  // Dirty tracking: baseline = the last saved/loaded formData. Edit mode adopts
  // the initial value on mount; create mode re-adopts once async defaults load
  // (see the defaults effect below). Drives the Update/Save button + the
  // unsaved-changes guard. Applying a preset mutates formData, so it naturally
  // marks the form dirty -- fixing the "preset applied but never saved" footgun.
  const { isDirty, baseline, setBaseline } = useDirtyState(formData)
  // A RoE parse in flight, or a review not yet confirmed, is unsaved work too.
  const savedProjectId = mode === 'edit'
    ? projectIdFromRoute ?? (initialData as { id?: string } | undefined)?.id
    : undefined
  const roeEntry = useRoeEntry(savedProjectId ?? 'create')
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty || roeEntryBusy(roeEntry))

  // The loaded preset's name, while the settings still match it. Edit mode reads
  // the SAVED state, so an edit only hides it once Update Settings writes it; a
  // create form has nothing saved yet, so it reads the live form.
  const presetBadgeSource = mode === 'edit' ? baseline : formData
  const loadedPresetName = useMemo(
    () => appliedPresetName(presetBadgeSource as unknown as Record<string, unknown>),
    [presetBadgeSource],
  )

  // Body wrapper ref -- used to pin log drawer top/bottom to the main content area
  const bodyRef = useRef<HTMLDivElement>(null)

  // Partial Recon
  const [partialReconToolId, setPartialReconToolId] = useState<string | null>(null)
  const [isPartialReconStarting, setIsPartialReconStarting] = useState(false)

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
  // Agent in the Loop needs no provider: offered from the provider gate while
  // the deployment has it on (the model list then carries it).
  const [loopAvailable, setLoopAvailable] = useState(false)
  const [noProvider, setNoProvider] = useState(false)
  // create mode: false until the provider check resolves; gates the form render
  // so a no-provider user sees the "configure provider" gate immediately, not
  // the project form flashing first.
  const [providerChecked, setProviderChecked] = useState(mode !== 'create')
  const [showModelGate, setShowModelGate] = useState(false)
  // Which save action to resume once both models are picked in the gate
  const [pendingSaveAction, setPendingSaveAction] = useState<'submit' | 'stay' | null>(null)

  // RoE document file (held in memory until project creation)
  const [roeFile, setRoeFile] = useState<File | null>(null)
  // A create form owns the 'create' RoE entry: a review left by an earlier
  // create form belongs to a file that form no longer holds.
  useEffect(() => {
    if (mode !== 'create') return
    clearRoeEntry('create')
    return () => clearRoeEntry('create')
  }, [mode])

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

  // The row's updatedAt as this form last saw it written. A full save sends it
  // back and the PUT refuses a stale one with 409, so an MCP agent's change made
  // while the form sat open is not silently reverted by the next save. Kept out
  // of formData so adopting a new value never marks the form dirty.
  const savedVersionRef = useRef<string | null>(
    versionOf((initialData as { updatedAt?: unknown } | undefined)?.updatedAt)
  )
  // The row as the server last answered it (load, then each save's answer merged in: a PUT
  // answers without the relations a GET carries).
  const serverRowRef = useRef<Record<string, unknown> | null>(
    initialData ? { ...(initialData as Record<string, unknown>) } : null
  )
  const adoptSavedVersion = useCallback((row: unknown) => {
    const version = versionOf((row as { updatedAt?: unknown } | null | undefined)?.updatedAt)
    if (version) savedVersionRef.current = version
    if (row && typeof row === 'object' && !Array.isArray(row)) {
      serverRowRef.current = { ...(serverRowRef.current ?? {}), ...(row as Record<string, unknown>) }
    }
  }, [])
  // True when the server wrote the row and only a step after the write failed
  // (`stage: 'after_write'`). The save happened, so the row's new version is
  // read back: without it the next save would be refused as stale.
  const savedDespiteError = useCallback(async (error: unknown): Promise<boolean> => {
    if (!(error instanceof ApiError) || error.body?.stage !== 'after_write' || !projectId) return false
    try {
      adoptSavedVersion(await fetchJson(`/api/projects/${projectId}`, undefined, 'Could not reload the project'))
    } catch {
      /* the next save then reports the stale version itself */
    }
    return true
  }, [projectId, adoptSavedVersion])
  // The upload sections write the row through their own endpoints. The row is read back so a
  // later skills event does not take the uploaded column for another writer's change; only
  // when it is still at the announced version, so no one else's write is taken as known.
  useEffect(() => {
    if (!projectId || mode !== 'edit') return
    return onProjectWrite(projectId, version => {
      savedVersionRef.current = version
      void fetch(`/api/projects/${projectId}`)
        .then(res => (res.ok ? res.json() : null))
        .then(row => {
          if (row && versionOf(row.updatedAt) === version) {
            serverRowRef.current = { ...(serverRowRef.current ?? {}), ...(row as Record<string, unknown>) }
          }
        })
        .catch(() => {})
    })
  }, [projectId, mode])
  const formDataRef = useRef(formData)
  formDataRef.current = formData
  // Saving a skill version from a review window (here or in another tab) can switch the
  // project's user-skill toggles and moves its updatedAt. When nothing but the toggles changed
  // on the server and there is no unsaved toggle change here, the form takes both, so its next
  // save neither 409s nor reverts the switch. Otherwise it keeps the version it had, and says
  // so: the next save is refused as stale instead of overwriting another writer.
  useUserSkillsChanged(async (change) => {
    if (!projectId || mode !== 'edit' || (change.projectId && change.projectId !== projectId)) return
    const dirtyToggles = !deepEqual(formData.attackSkillConfig, baseline.attackSkillConfig)
    try {
      const res = await fetch(`/api/projects/${projectId}`)
      if (!res.ok) return
      const row = await res.json()
      if (!onlySkillTogglesChanged(serverRowRef.current, row)) {
        toast.warning('This project was changed in another window; reload it before saving')
        return
      }
      // The server's toggles did not move (a save elsewhere touched another project), or they
      // already are the form's: nothing to take, nothing to warn about.
      const local = formDataRef.current.attackSkillConfig
      if (deepEqual(row.attackSkillConfig, serverRowRef.current?.attackSkillConfig) || deepEqual(row.attackSkillConfig, local)) {
        adoptSavedVersion(row)
        return
      }
      // A toggle changed here, before the event or while the row was read, is not overwritten.
      if (dirtyToggles || !deepEqual(local, formData.attackSkillConfig)) {
        toast.warning('Your skill toggles were changed by a save elsewhere; reload before saving')
        return
      }
      setFormData(prev => ({ ...prev, attackSkillConfig: row.attackSkillConfig }))
      setBaseline(prev => ({ ...prev, attackSkillConfig: row.attackSkillConfig }))
      adoptSavedVersion(row)
    } catch {
      // The next full save's stale check still guards the row.
    }
  })
  // Scan Queue (Phase 3): a temporary partial-recon start refusal offers Cancel /
  // Add to queue instead of a dead-end toast.
  const { handleStartFailure: handlePartialStartFailure } = useScanStartFailure(projectId ?? null)
  const { handleStartFailure: handleScanStartFailure } = useScanStartFailure(projectId ?? null)

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
  const { state: reconState, error: reconStatusError } = useReconStatus({ projectId: mode === 'edit' ? (projectId ?? null) : null, enabled: mode === 'edit' })
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
  useScanErrorToast('GVM scan', scans.gvm.error, scans.gvm.getLastStartError)
  useScanErrorToast('GitHub Secret Hunt', scans.githubHunt.error, scans.githubHunt.getLastStartError)
  useScanErrorToast('Secret Multiscanner', scans.trufflehog.error, scans.trufflehog.getLastStartError)
  useScanErrorToast('Supply-Chain scan', scans.supplyChain.error, scans.supplyChain.getLastStartError)
  useRunFailureToast('GVM scan', [{ key: 'gvm', status: scans.gvm.state?.status, error: scans.gvm.state?.error }])
  useRunFailureToast('GitHub Secret Hunt', [{ key: 'github', status: scans.githubHunt.state?.status, error: scans.githubHunt.state?.error }])
  useRunFailureToast('Supply-Chain scan', [{ key: 'supply', status: scans.supplyChain.state?.status, error: scans.supplyChain.state?.error }])
  useRunFailureToast('Secret Multiscanner', scans.trufflehog.runs.map(r => ({ key: r.source ?? r.run_id ?? '', status: r.status, error: r.error })))
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

  const {
    runId: activePartialLogsRunId,
    run: activePartialLogsRun,
    setRunId: setActivePartialLogsRunId,
    showStarted: showStartedPartialRun,
  } = usePartialLogsRun(allPartialReconRuns)
  const partialLogsToolLabel = activePartialLogsRun
    ? WORKFLOW_TOOLS.find(t => t.id === activePartialLogsRun.tool_id)?.label || activePartialLogsRun.tool_id
    : null

  // SSE logs for the currently visible partial recon drawer
  const {
    logsMap: partialReconLogsMap,
    phaseMap: partialReconPhaseMap,
    error: partialReconStreamError,
    clearLogsForRun: clearPartialReconLogsForRun,
  } = useMultiPartialReconSSE({
    projectId: projectId ?? null,
    activeRunId: activePartialLogsRunId,
    onComplete: () => { refetchPartialReconStatuses() },
  })
  // The drawer shows a run's own error only; a log stream that could not be
  // reopened would otherwise just stop updating. Retries are not announced.
  useScanErrorToast(
    'Partial recon logs',
    isStreamReconnecting(partialReconStreamError) ? null : partialReconStreamError,
  )

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
    ]).then(([{ defaults, error: defaultsError }, user]) => {
      setDefaultsWarning(defaultsError)
      const seeded = seedInitialModels(user)
      let loaded: ProjectFormData | null = null
      setFormData(prev => {
        loaded = withoutDerived({
          ...defaults,
          ...prev,
          ...initialData,
          // Account-scoped configuration is never inherited from defaults or a copied row.
          jevProviderId: prev.jevProviderId ?? null,
          agentOpenaiModel: seeded.agentOpenaiModel,
          aiPipelineModel: seeded.aiPipelineModel,
        }) as ProjectFormData
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
  // A list that failed to load is not an empty one: it never shows the gate.
  const toastRef = useRef(toast)
  toastRef.current = toast
  useEffect(() => {
    if (mode !== 'create' || !userId) return
    fetchJson<unknown>(`/api/users/${userId}/llm-providers`, undefined, 'Could not check your LLM providers')
      .then(async (providers) => {
        if (hasNoConfiguredProvider(providers)) {
          setNoProvider(true)
          setLoopAvailable(await fetchModelOptions(userId).then(loopModelOffered, () => false))
          setShowProviderGate(true)
        }
        setProviderChecked(true)
      })
      .catch((err) => {
        // Don't hard-block on a failed check; the model gate still applies.
        setProviderChecked(true)
        toastRef.current.warning(errorMessage(err, 'Could not check your LLM providers'))
      })
  }, [mode, userId])

  // Log drawers pin to the body wrapper, which moves as the form scrolls.
  useDrawerOffsets(bodyRef, { trackScroll: true })

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
        const failure = await readApiError(res, 'Failed to save')
        if (await savedDespiteError(failure)) {
          setBaseline(prev => ({ ...prev, [field]: value }))
          toast.error(`Setting saved, but a step after the save failed: ${failure.message}`)
          return
        }
        toast.error(failure.message)
        return
      }
      adoptSavedVersion(await res.json().catch(() => null))
      // Workflow toggles persist immediately; adopt the saved field into the
      // baseline so the batched Update button + guard don't flag it as unsaved.
      setBaseline(prev => ({ ...prev, [field]: value }))
    } catch (err) {
      toast.error(toApiError(err, 'Failed to save setting').message)
    }
  }, [projectId, mode, toast, setBaseline, adoptSavedVersion, savedDespiteError])

  const updateMultipleFields = (fields: Partial<ProjectFormData>) => {
    setFormData(prev => ({ ...prev, ...fields }))
  }

  // Fields edited and not yet saved, so a RoE replace that overwrites one can say so.
  const unsavedKeys = useMemo(() => {
    const now = formData as unknown as Record<string, unknown>
    const saved = baseline as unknown as Record<string, unknown>
    return Object.keys(now).filter(k => !deepEqual(now[k], saved[k]))
  }, [formData, baseline])

  /**
   * Take the row the RoE route saved (mergeServerRow), so the next "Update
   * Settings" does not PUT the pre-replace values back.
   */
  const baselineRef = useRef(baseline)
  baselineRef.current = baseline
  const formDataNowRef = useRef(formData)
  formDataNowRef.current = formData
  const onServerRowMerged = useCallback((row: Record<string, unknown>, changedKeys: string[]) => {
    const merged = mergeServerRow(
      formDataNowRef.current as unknown as Record<string, unknown>,
      baselineRef.current as unknown as Record<string, unknown>,
      row,
      changedKeys,
    )
    setFormData(merged.form as unknown as ProjectFormData)
    setBaseline(merged.baseline as unknown as ProjectFormData)
    adoptSavedVersion(row)
  }, [setBaseline, adoptSavedVersion])

  /**
   * Load a preset: confirm, replace every preset-owned setting, and in edit mode
   * save straight away so the project never sits on a loaded-but-unsaved preset.
   *
   * Built-in and user presets share this one path on purpose. Two handlers is how
   * one of them ended up guarded and the other not.
   *
   * Only the preset fields are saved. Unsaved edits elsewhere (a target being
   * typed, an RoE field) stay unsaved: the confirmation promised to replace
   * settings, not to commit whatever else is in the form.
   */
  const loadPreset = async (source: PresetSource): Promise<void> => {
    const presetName = source.kind === 'builtin' ? source.preset.name : source.name
    const saves = mode === 'edit' && Boolean(projectId)

    // Fetched BEFORE the confirmation, so it can name the settings the RoE
    // document set that this preset would change.
    let presetSettings: Record<string, unknown>
    let backendDefaults: Record<string, unknown>
    try {
      ;[presetSettings, backendDefaults] = await Promise.all([
        source.kind === 'builtin'
          ? Promise.resolve({ ...source.preset.parameters, reconPresetId: source.preset.id })
          : fetchJson<{ settings?: Record<string, unknown> }>(`/api/presets/${source.id}`, undefined, 'Failed to fetch preset')
              .then(body => (body.settings ?? {}) as Record<string, unknown>),
        // Unavailable defaults are not fatal: the Prisma defaults cover every field.
        fetch('/api/projects/defaults')
          .then(r => (r.ok ? r.json() : {}))
          .catch(() => ({})),
      ])
    } catch (err) {
      toast.error(`Failed to load preset "${presetName}": ${errorMessage(err, 'Failed to fetch preset')}`)
      return
    }

    const next = applyPresetSettings(
      formData as unknown as Record<string, unknown>,
      presetSettings,
      backendDefaults,
    ) as unknown as ProjectFormData

    const roeApplied = (formData.roeParsedJson && typeof formData.roeParsedJson === 'object'
      ? (formData.roeParsedJson as { applied?: unknown }).applied
      : null) as Record<string, unknown> | null
    const documentKeys = Object.keys(roeApplied && typeof roeApplied === 'object' ? roeApplied : {})
      .filter(k => !deepEqual((next as unknown as Record<string, unknown>)[k], (formData as unknown as Record<string, unknown>)[k]))
      .sort()
    const ask = saves ? dangerConfirm : confirmModal
    const confirmed = await ask(<PresetLoadWarning saves={saves} documentKeys={documentKeys} />, `Load preset "${presetName}"?`, {
      confirmLabel: saves ? 'Replace and save' : 'Replace settings',
      size: 'default',
    })
    if (!confirmed) return

    if (source.kind === 'builtin') {
      // A built-in preset declares the kind of target it is for, and that is the
      // only way a preset can move ipMode (a scope field, never a preset field).
      // Non-destructive: the hidden side (targetDomain / targetIps) is left as
      // typed. resolve() returns undefined in edit mode and for 'both' presets.
      const currentTargetMode = formData.ipMode ? 'ip' : formData.domainBatchMode ? 'batch' : 'domain'
      const resolvedIpMode = resolveIpModeForPreset(source.preset.targetProfile, mode, currentTargetMode)
      if (resolvedIpMode !== undefined) {
        next.ipMode = resolvedIpMode
        // IP targeting cannot leave a batch flagged too: the modes are exclusive.
        if (resolvedIpMode) next.domainBatchMode = false
      }
    }

    const loadedPreset: LoadedPreset = {
      name: presetName,
      fingerprint: presetFingerprint(next as unknown as Record<string, unknown>),
      presetId: source.kind === 'builtin' ? source.preset.id : source.id,
      source: source.kind,
    }
    next.loadedPreset = loadedPreset as unknown as ProjectFormData['loadedPreset']

    setFormData(next)
    const presetId = presetSettings.reconPresetId
    setAppliedPreset(typeof presetId === 'string' ? getPresetById(presetId) ?? null : null)
    setIsPresetModalOpen(false)
    setIsUserPresetDrawerOpen(false)

    if (!saves || !projectId) {
      toast.success(`Preset "${presetName}" loaded`, 'Preset Loaded')
      return
    }

    const saved: Record<string, unknown> = {
      ...pickPresetFields(next as unknown as Record<string, unknown>),
      loadedPreset,
    }
    // A compare-and-swap like a whole-row save: a RoE replaced or an MCP write
    // made in another tab since this form loaded is refused (409), not reverted.
    const versioned = savedVersionRef.current ? { ...saved, updatedAt: savedVersionRef.current } : saved
    const invalid = validateProjectForm(next as unknown as Record<string, unknown>)
      .filter(e => e.field in saved)
    if (invalid.length > 0) {
      alertWarning(
        `Preset "${presetName}" was loaded but NOT saved, because it has invalid values:\n`
        + invalid.map(e => `- ${e.message}`).join('\n')
        + '\n\nFix them, then click Update Settings.'
      )
      return
    }
    try {
      adoptSavedVersion(await presetSaveMutation.mutateAsync({ projectId, data: versioned as Partial<Project> }))
      setBaseline(prev => ({ ...prev, ...saved }) as ProjectFormData)
      toast.success(`Preset "${presetName}" loaded and saved`, 'Preset Loaded')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (await savedDespiteError(error)) {
        setBaseline(prev => ({ ...prev, ...saved }) as ProjectFormData)
        alertError(`Preset "${presetName}" was loaded and saved, but a step after the save failed: ${message}`)
        return
      }
      alertError(`Preset "${presetName}" was loaded but NOT saved: ${message}\n\nClick Update Settings to retry.`)
    }
  }

  // On save (create only), confirm an LLM provider exists before the model gate.
  // Without a provider the model picker can't load any models, so route the user
  // to "Configure an LLM provider first" instead of a broken model-selection modal.
  // Fetched fresh on save so a provider added/removed since mount is honored.
  const ensureProviderConfigured = async (): Promise<boolean> => {
    if (mode !== 'create' || !userId) return true
    try {
      const providers = await fetchJson<unknown>(`/api/users/${userId}/llm-providers`, undefined, 'Could not check your LLM providers')
      setNoProvider(hasNoConfiguredProvider(providers))
      if (providerGateApplies(providers, formData.agentOpenaiModel as string, loopAvailable)) {
        setShowProviderGate(true)
        return false
      }
    } catch {
      /* a failed check is not "no provider": don't hard-block; the model gate still applies */
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
    if (needsModelGate(mode, formData.agentOpenaiModel, formData.aiPipelineModel,
      pipelineModelOptional(formData.agentOpenaiModel as string, noProvider))) {
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
        ...(mode === 'edit' && savedVersionRef.current ? { updatedAt: savedVersionRef.current } : {}),
      }
      const togglesChanged = !deepEqual(formData.attackSkillConfig, baseline.attackSkillConfig)
      adoptSavedVersion(await onSubmit(submitData))
      // Other open windows of this project (the chat drawer) take the new toggles.
      if (togglesChanged) postUserSkillsChanged({ projectId })
      // Adopt the just-saved state as the new baseline so the form reads clean
      // (create mode usually navigates away, but this keeps state correct if not).
      setBaseline(formData)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (await savedDespiteError(error)) {
        setBaseline(formData)
        alertError(`The project was saved, but a step after the save failed: ${message}`)
        return
      }
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
    if (needsModelGate(mode, formData.agentOpenaiModel, formData.aiPipelineModel,
      pipelineModelOptional(formData.agentOpenaiModel as string, noProvider))) {
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
        ...(mode === 'edit' && savedVersionRef.current ? { updatedAt: savedVersionRef.current } : {}),
      }
      const togglesChanged = !deepEqual(formData.attackSkillConfig, baseline.attackSkillConfig)
      adoptSavedVersion(await onSaveAndStay(submitData))
      if (togglesChanged) postUserSkillsChanged({ projectId })
      setBaseline(formData)
      toast.success('Project saved')
      after?.()
      return true
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save project'
      if (await savedDespiteError(error)) {
        // Written, so the caller may act on it; `after` is skipped so the
        // alert is not navigated away from.
        setBaseline(formData)
        alertError(`The project was saved, but a step after the save failed: ${message}`)
        return true
      }
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

  // The roots a partial run covers, as the form holds them. The modal shows them
  // only when it cannot fetch graph-inputs; the orchestrator decides the scope.
  const partialReconRoots = useMemo(() => {
    if (formData.ipMode) return projectId ? [ipModeRoot(projectId)] : []
    return resolveProjectRoots({
      domainBatchMode: formData.domainBatchMode,
      domainBatchHosts: formData.domainBatchHosts || [],
      targetDomain: formData.targetDomain,
      subdomainList: formData.subdomainList || [],
    }, projectId ?? '').roots
  }, [formData.ipMode, formData.domainBatchMode, formData.domainBatchHosts, formData.targetDomain, formData.subdomainList, projectId])

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
        const startError = await readScanStartError(response, 'Failed to start partial recon')
        setPartialReconToolId(null)
        // Temporary -> Cancel / Add to queue; permanent -> error (Scan Queue Phase 3).
        await handlePartialStartFailure('partial_recon', startError, params as unknown as Record<string, unknown>)
        return
      }
      const data: PartialReconState = await response.json()
      setPartialReconToolId(null)
      toast.success('Partial recon started')
      showStartedPartialRun(data)
      // List the run now, which also polls at the running pace, not the idle one.
      void refetchPartialReconStatuses()
    } catch (err) {
      toast.error(toApiError(err, 'Failed to start partial recon').message)
    } finally {
      setIsPartialReconStarting(false)
    }
  }, [projectId, toast, handlePartialStartFailure, showStartedPartialRun, refetchPartialReconStatuses])

  // A refused or unanswered stop leaves the run going, so it is said, and the
  // logs drawer stays open on it.
  const stopPartialRun = useCallback(async (runId: string): Promise<boolean> => {
    if (!projectId) return false
    try {
      await fetchOk(`/api/recon/${projectId}/partial/${runId}/stop`, { method: 'POST' }, 'Failed to stop partial recon')
      return true
    } catch (err) {
      toast.error(errorMessage(err, 'Failed to stop partial recon'))
      return false
    }
  }, [projectId, toast])

  // Starts from Other Scans: a refused start gets the same modal as on the
  // graph page (queue offer for a temporary refusal), never a silent no-op.
  const startOtherScan = useCallback(async (
    kind: string,
    start: () => Promise<unknown>,
    lastStartError: () => ScanStartError | null,
    payload?: Record<string, unknown>,
  ) => {
    let started = false
    try {
      started = (await start()) != null
    } catch {
      started = false
    }
    if (!started) await handleScanStartFailure(kind, lastStartError(), payload)
  }, [handleScanStartFailure])

  const [isExporting, setIsExporting] = useState(false)
  // Fetched rather than opened in a tab, so a failed export reads as an error
  // with its code instead of a tab of raw JSON.
  const exportProject = useCallback(async () => {
    if (!projectId) return
    setIsExporting(true)
    try {
      const res = await fetchOk(`/api/projects/${projectId}/export`, undefined, 'Export failed')
      const blob = await res.blob()
      const name = /filename="([^"]+)"/i.exec(res.headers.get('content-disposition') || '')?.[1] ?? `redamon-project-${projectId}.zip`
      const href = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = href
      a.download = name
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(href), 1000)
    } catch (err) {
      alertError(errorMessage(err, 'Export failed'), 'Export failed')
    } finally {
      setIsExporting(false)
    }
  }, [projectId, alertError])

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
  const useLoopInstead = loopAvailable
    ? () => { updateField('agentOpenaiModel', LOOP_MODEL_ID); setShowProviderGate(false) }
    : undefined
  if (mode === 'create' && showProviderGate) {
    return <ProviderRequiredModal onCancel={onCancel} onUseLoop={useLoopInstead} />
  }

  return (
    <JevSelectionProvider
      ownerUserId={mode === 'create' ? userId : initialData?.userId ?? null}
      ownerUnavailable={mode === 'edit' && !initialData?.userId}
      selectedProviderId={formData.jevProviderId ?? null}
    >
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
          <WikiInfoButton
            target={mode === 'create' ? 'projectsNew' : 'projectSettings'}
            title={mode === 'create' ? 'Open Creating a Project wiki page' : 'Open Project Settings Reference wiki page'}
          />
        </h1>
        <div className={styles.actions}>
          {mode === 'edit' && projectId ? (
            <>
              <button
                type="button"
                className={`reconStartButton${isReconBusy ? ' reconStartButtonActive' : ''}`}
                onClick={() => guardedNavigate(() => router.push(isReconBusy ? `/graph?project=${projectId}&openlogs=recon` : `/graph?project=${projectId}&autostart=true`))}
                disabled={isSubmitting || runningPartialToolIds.size > 0}
                title={runningPartialToolIds.size > 0 ? 'Partial recon is running -- stop it first' : isReconRunning ? 'Recon is running -- click to view progress' : isReconPaused ? 'Recon is paused -- click to view' : reconStatusError ? `${reconStatusError} -- a recon may be running; the graph page shows it` : 'Navigate to the graph page and start the full recon pipeline'}
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
                    await stopPartialRun(runId)
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
            title="Replace this project's settings with a saved preset. Asks first, and saves the project straight away. The target, RoE, uploaded files and credentials are kept"
          >
            <FolderOpen size={14} />
            Load Preset
          </button>
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setIsSavePresetModalOpen(true)}
            disabled={isSubmitting || isLoadingDefaults}
            title="Save every project setting as a reusable preset. Not included: the name, the target and scope, the RoE, uploaded files and credentials"
          >
            <Bookmark size={14} />
            Save as Preset
          </button>
          {mode === 'edit' && projectId && (
            <button
              type="button"
              className="secondaryButton"
              onClick={() => void exportProject()}
              disabled={isExporting}
              title="Download a full project backup as a ZIP file including settings, conversations, graph data, reports, and artifacts"
            >
              {isExporting ? <Loader2 size={14} className={styles.spinner} /> : <Download size={14} />}
              {isExporting ? 'Exporting...' : 'Export'}
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

      {defaultsWarning && (
        <div className={`${styles.callout} ${styles.calloutWarning}`} role="alert" data-testid="defaults-warning">
          <span>
            <strong>The recon defaults could not be loaded, so this form starts from built-in fallbacks.</strong>{' '}
            {defaultsWarning}
          </span>
        </div>
      )}

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
            {loadedPresetName && (
              <div
                className={styles.presetApplied}
                title={`The project still holds the settings that loading the "${loadedPresetName}" preset produced. Changing a setting and saving removes this.`}
              >
                <span className={styles.tabGroupLabel}>Preset applied</span>
                <span className={styles.presetAppliedName}>
                  <Check size={13} strokeWidth={3} />
                  <span>{loadedPresetName}</span>
                </span>
              </div>
            )}
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
                onOpenRoe={() => setActiveTab('roe' as TabId)}
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
            projectId={mode === 'edit' ? projectId : undefined}
            onServerRowMerged={onServerRowMerged}
            unsavedKeys={unsavedKeys}
          />
        )}

        {activeTab === 'target' && viewMode === 'tabs' && (
          <>
            <TargetSection
              data={formData} updateField={updateField} mode={mode}
              savedScope={mode === 'edit' ? baseline : undefined}
              projectId={mode === 'edit' ? projectId : undefined}
            />
            <AuthenticationSection data={formData} updateField={updateField} projectId={projectId} mode={mode} />
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

            <TlsxSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Tlsx') : undefined} />
            <MasscanSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Masscan') : undefined} />
          </>
        )}

        {activeTab === 'http' && viewMode === 'tabs' && (
          <>
            <HttpxSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Httpx') : undefined} />
            <IpAttributionSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('IpAttribution') : undefined} />
          </>
        )}

        {activeTab === 'resource' && viewMode === 'tabs' && (
          <>
            <KatanaSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('Katana') : undefined} />
            <OpenApiSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('OpenAPI') : undefined} projectId={mode === 'edit' ? projectId : undefined} />
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
            <SerializedScanSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('SerializedScan') : undefined} />
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
            <RouteExposureSection data={formData} updateField={updateField} onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('RouteExposure') : undefined} onOpenAuth={() => setActiveTab('target')} onOpenAgentSkills={() => setActiveTab('attack')} />
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
          <AttackSkillsSection data={formData} updateField={updateField} projectId={mode === 'edit' ? projectId : null}
                               onOpenRoe={() => setActiveTab('roe' as TabId)} />
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
        onSelect={(preset) => loadPreset({ kind: 'builtin', preset })}
        onLoadUserPreset={(preset) => loadPreset({ kind: 'user', ...preset })}
        currentPresetId={appliedPreset?.id}
        userId={userId}
      />

      {/* User Preset: Save modal */}
      <SavePresetModal
        isOpen={isSavePresetModalOpen}
        onClose={() => setIsSavePresetModalOpen(false)}
        // The applied built-in preset lives in appliedPreset until the project is
        // saved, so it is folded in here or the preset would lose its badge.
        formData={{
          ...(formData as unknown as Record<string, unknown>),
          reconPresetId: appliedPreset?.id ?? formData.reconPresetId ?? null,
        }}
        userId={userId}
      />

      {/* User Preset: Load drawer */}
      <UserPresetDrawer
        isOpen={isUserPresetDrawerOpen}
        onClose={() => setIsUserPresetDrawerOpen(false)}
        onLoad={(preset) => loadPreset({ kind: 'user', ...preset })}
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
        projectRoots={partialReconRoots}
        isStarting={isPartialReconStarting}
        userId={userId ?? undefined}
        openapiSources={formData.openapiSources}
        ipTargets={formData.ipMode ? formData.targetIps : null}
      />

      {/* Partial Recon Logs Drawer */}
      {activePartialLogsRun && (
        <ReconLogsDrawer
          isOpen={!!activePartialLogsRunId}
          onClose={() => setActivePartialLogsRunId(null)}
          logs={partialReconLogsMap[activePartialLogsRunId!] || []}
          currentPhase={partialLogsToolLabel}
          currentPhaseNumber={partialReconPhaseMap[activePartialLogsRunId!]?.phaseNumber || null}
          status={(activePartialLogsRun.status as ReconStatus) || 'idle'}
          errorMessage={activePartialLogsRun.error}
          onClearLogs={() => activePartialLogsRunId && clearPartialReconLogsForRun(activePartialLogsRunId)}
          onStop={async () => {
            if (activePartialLogsRunId && await stopPartialRun(activePartialLogsRunId)) {
              setActivePartialLogsRunId(null)
            }
          }}
          title={`Partial Recon: ${partialLogsToolLabel || 'Running'}`}
          totalPhases={PARTIAL_RECON_TOTAL_PHASES}
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
        <ProviderRequiredModal onCancel={onCancel} onUseLoop={useLoopInstead} />
      )}

      {/* Model selection gate: force picking both models before saving */}
      {showModelGate && (
        <ModelSelectionModal
          userId={userId}
          agentModel={(formData.agentOpenaiModel as string) || ''}
          aiPipelineModel={(formData.aiPipelineModel as string) || ''}
          onChangeAgent={(id) => updateField('agentOpenaiModel', id)}
          onChangeAiPipeline={(id) => updateField('aiPipelineModel', id)}
          pipelineOptional={pipelineModelOptional(formData.agentOpenaiModel as string, noProvider)}
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
        githubHuntError={scans.githubHunt.state?.error}
        githubHuntStatusError={scans.githubHunt.statusError}
        trufflehogProfilesError={scans.trufflehog.profilesError}
        trufflehogStatusError={scans.trufflehog.statusError}
        supplyChainError={scans.supplyChain.state?.error}
        supplyChainStatusError={scans.supplyChain.statusError}
        onStartGithubHunt={() => void startOtherScan('github_hunt', scans.githubHunt.startGithubHunt, scans.githubHunt.getLastStartError)}
        onPauseGithubHunt={() => void scans.githubHunt.pauseGithubHunt()}
        onResumeGithubHunt={() => void scans.githubHunt.resumeGithubHunt()}
        onStopGithubHunt={() => void scans.githubHunt.stopGithubHunt()}
        onDownloadGithubHuntJSON={() => projectId && window.open(`/api/github-hunt/${projectId}/download`, '_blank')}
        trufflehogProfiles={scans.trufflehog.profiles}
        trufflehogRunsBySource={scans.trufflehog.bySource}
        onStartTrufflehog={(source) => void startOtherScan('trufflehog', () => scans.trufflehog.startTrufflehog(source), scans.trufflehog.getLastStartError, { source })}
        onStopTrufflehog={(source) => void scans.trufflehog.stopTrufflehog(source)}
        onDownloadTrufflehogJSON={() => projectId && window.open(`/api/trufflehog/${projectId}/download`, '_blank')}
        supplyChainStatus={scans.supplyChain.state?.status}
        onStartSupplyChain={() => void startOtherScan('supply_chain', scans.supplyChain.startSupplyChain, scans.supplyChain.getLastStartError)}
        onPauseSupplyChain={() => void scans.supplyChain.pauseSupplyChain()}
        onResumeSupplyChain={() => void scans.supplyChain.resumeSupplyChain()}
        onStopSupplyChain={() => void scans.supplyChain.stopSupplyChain()}
        onDownloadSupplyChainJSON={() => projectId && window.open(`/api/supply-chain/${projectId}/download`, '_blank')}
      />
    </form>
    </JevSelectionProvider>
  )
}

export default ProjectForm

'use client'

import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { GraphToolbar } from './components/GraphToolbar'
import {
  agentStopFailureLabel, agentStopSummary, isEmergencyStopScope, type EmergencyStopScope,
} from './components/GraphToolbar/emergencyStopScope'
import { FileSystemDrawer } from './components/FileSystemDrawer'
import { GraphCanvas, AUTO_2D_THRESHOLD } from './components/GraphCanvas'
import { GraphEmptyState } from './components/GraphEmptyState'
import { NodeDrawer } from './components/NodeDrawer'
import { AgentDrawer } from './components/AIAssistantDrawer'
import type { PendingNodeQuery } from './components/AIAssistantDrawer/types'
import { PageBottomBar } from './components/PageBottomBar'
import { ReconConfirmModal } from './components/ReconConfirmModal'
import { GvmConfirmModal } from './components/GvmConfirmModal'
import { ReconLogsDrawer } from './components/ReconLogsDrawer'
import { ViewTabs, parseTableViewMode, type ViewMode, type TunnelStatus, type TableViewMode } from './components/ViewTabs'
import { DataTable } from './components/DataTable'
import { NodeDetailsTable } from './components/NodeDetailsTable'
import { JsReconTable, exportJsReconCsv, exportJsReconJson, exportJsReconMarkdown } from './components/JsReconTable'
import type { JsReconData } from './components/JsReconTable'
import {
  KillChainTable,
  BlastRadiusTable,
  TakeoverTable,
  SecretsTable,
  NetInitAccessTable,
  GraphqlLedgerTable,
  WebInitAccessTable,
  ParamMatrixTable,
  SharedInfraTable,
  DnsEmailTable,
  ThreatIntelTable,
  JsDepSignalsTable,
  SupplyChainScaTable,
  DnsDriftTable,
  AiSurfaceTable,
  AiRiskTable,
  WebCachePoisonTable,
  RouteExposureTable,
} from './components/RedZoneTables'
import { ActiveSessions } from './components/ActiveSessions'
import { RoeViewer } from './components/RoeViewer'
import { KaliTerminal } from './components/KaliTerminal'
import { GraphViews } from './components/GraphViews'
import { GitHubStarBanner } from './components/GitHubStarBanner'
import { useGraphData, useDimensions, useNodeSelection, useTableData, useGraphViews } from './hooks'
import { useScanVersions } from './hooks/useScanVersions'
import { useUnseenCounts } from './hooks/useUnseenCounts'
import { ActiveVersionOnlyNotice } from './components/VersionSwitch'
import { VersionManager } from './components/VersionManager'
import { ReconDeltaTable } from './components/ReconDelta'
import { TriageTable } from './components/Triage/TriageTable'
import { MutedNodesTable } from './components/MutedNodes/MutedNodesTable'
import type { MutedNodesFocus } from './components/MutedNodes/mutedNodes'
import { MuteNodeProvider } from './components/MuteNode'
import { NodeFiltersView } from './components/NodeFilters/NodeFiltersView'
import { useNodeFilterStatus } from './hooks/useNodeFilterStatus'
import { ScanScheduleTable } from './components/ScanSchedule'
import { useStableGraphData } from './hooks/useStableGraphData'
import { exportToCsv, exportToJson, exportToMarkdown } from './utils/exportCsv'
import { clusterGraphData } from './utils/clusterNodes'
import { isOverNodeCap } from './utils/nodeCap'
import { isGraphRenderOff, shouldFetchGraph } from './utils/renderGate'
import { resolveEmptyGraphState } from './utils/emptyGraph'
import { useTheme, useSession, useReconStatus, useReconSSE, useGvmStatus, useGvmSSE, useGithubHuntStatus, useGithubHuntSSE, useTrufflehogRuns, useTrufflehogSSE, useSupplyChainStatus, useSupplyChainSSE, useActiveSessions, useMultiPartialReconStatus, useMultiPartialReconSSE } from '@/hooks'
import { useErrorToast } from '@/hooks/useErrorToast'
import { useProjectById } from '@/hooks/useProjects'
import { useScanStartFailure } from '@/hooks/useScanStartFailure'
import { usePermissionRefused } from '@/hooks/useCan'
import { useDrawerOffsets } from '@/hooks/useDrawerOffsets'
import { useGraphTypeFilterPrefs, useGraphViewPrefs } from '@/hooks/useUserPreferences'
import { useProject } from '@/providers/ProjectProvider'
import { GITHUB_HUNT_PHASES, GVM_PHASES, PARTIAL_RECON_TOTAL_PHASES, TRUFFLEHOG_PHASES } from '@/lib/recon-types'
import { WORKFLOW_TOOLS } from '@/components/projects/ProjectForm/WorkflowView/workflowDefinition'
import type { ReconStatus } from '@/lib/recon-types'
import type { ScanMode } from '@/hooks/useReconStatus'
import { OtherScansModal } from './components/OtherScansModal/OtherScansModal'
import { parseScanModal } from '@/lib/scanModalLink'
import { useAlertModal, useToast } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import {
  downloadScanFile, fetchGvmAvailability, probeScanData, scanFailureToast, type GvmAvailability,
} from '@/components/scans/scanErrors'
import { useNavigationGuard } from '@/context/NavigationGuardContext'
import styles from './page.module.css'
import { deriveRoeEnabled } from '@/lib/engagement'
import { groupLabel } from '@/lib/scopeGroups'
import { staleViewNote } from './utils/staleViewNote'

// A saved (past) version is read-only, and GVM/GitHub-Hunt/TruffleHog write to the
// LIVE/active graph. Starting one while viewing an old version would silently add
// findings to the active version, not the one on screen - so block it (matches
// node-delete). Module-scoped so it is not a hook dependency.
const PAST_VERSION_SCAN_MSG =
  'You are viewing a saved version, which is read-only. Switch back to the active version to run this scan.'

export default function GraphPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { alertError, confirm: confirmModal } = useAlertModal()
  const toast = useToast()
  const { projectId, userId, currentProject, setCurrentProject, isLoading: projectLoading } = useProject()
  // Scan Queue (Phase 3): on a temporary start failure, offer Cancel / Add to queue.
  const { handleStartFailure } = useScanStartFailure(projectId)
  // What the start routes and the agent socket's ticket ask (route manifest). The buttons and the
  // drawer refuse on their own; the page keeps a deep link from opening a dialog whose start is refused.
  const reconRefused = usePermissionRefused('recon:scan', projectId)
  const gvmRefused = usePermissionRefused('scan:gvm', projectId)
  const agentRefused = usePermissionRefused('agent:chat', projectId)

  const [activeView, setActiveView] = useState<ViewMode>('graph')

  // Full project data for RoE viewer (only fetched when RoE tab is active)
  const { data: fullProject } = useProjectById(activeView === 'roe' ? projectId : null)
  // 2D/3D + labels are persisted per-user per-project. The hook returns the
  // saved value (or a sensible default) and the optimistic-updating setter.
  const {
    is3D,
    showLabels,
    renderEnabled: graphRenderEnabled,
    setIs3D,
    setShowLabels,
    setRenderEnabled: setGraphRenderEnabled,
    isLoading: graphPrefsLoading,
  } = useGraphViewPrefs(projectId)
  const [isAIOpen, setIsAIOpen] = useState(false)
  const [pendingNodeQuery, setPendingNodeQuery] = useState<PendingNodeQuery | null>(null)
  const [isFileSystemOpen, setIsFileSystemOpen] = useState(false)
  const [isReconModalOpen, setIsReconModalOpen] = useState(false)
  const [activeLogsDrawer, setActiveLogsDrawer] = useState<'recon' | 'gvm' | 'githubHunt' | 'supplyChain' | `trufflehog:${string}` | `partialRecon:${string}` | null>(null)
  const [hasReconData, setHasReconData] = useState(false)
  const [hasGvmData, setHasGvmData] = useState(false)
  const [hasGithubHuntData, setHasGithubHuntData] = useState(false)
  const [hasTrufflehogData, setHasTrufflehogData] = useState(false)
  const [hasSupplyChainData, setHasSupplyChainData] = useState(false)
  const [gvmAvailability, setGvmAvailability] = useState<GvmAvailability>({ available: true, reason: '' })
  // Set when a download route's HEAD check itself failed (5xx, no answer), so the
  // disabled button does not claim there is no data.
  const [dataProbeErrors, setDataProbeErrors] = useState<Record<string, string | null>>({})
  const setDataProbeError = useCallback((key: string, error: string | null) => {
    setDataProbeErrors(prev => (prev[key] ?? null) === error ? prev : { ...prev, [key]: error })
  }, [])
  const [isOtherScansModalOpen, setIsOtherScansModalOpen] = useState(false)
  const [hasGithubToken, setHasGithubToken] = useState(false)
  const [graphStats, setGraphStats] = useState<{ totalNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [gvmStats, setGvmStats] = useState<{ totalGvmNodes: number; nodesByType: Record<string, number> } | null>(null)
  const [isGvmModalOpen, setIsGvmModalOpen] = useState(false)
  // The confirm modal shows a start error only for a start made from this
  // opening of it, never one left over from an earlier attempt.
  const [gvmConfirmAttempted, setGvmConfirmAttempted] = useState(false)
  const contentRef = useRef<HTMLDivElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)

  const {
    selectedNode,
    drawerOpen,
    expandedChild,
    selectNode,
    clearSelection,
    expandChild,
    collapseChild,
  } = useNodeSelection()
  // Toggle the FS drawer. Opening must close the node drawer first - both
  // live on the left edge of the graph; otherwise the FS would slide over
  // the node panel and the user would see a confusing stack.
  const toggleFileSystemDrawer = useCallback(() => {
    setIsFileSystemOpen(prev => {
      if (!prev) clearSelection()
      return !prev
    })
  }, [clearSelection])
  const handleNodeClick = useCallback((node: Parameters<typeof selectNode>[0]) => {
    setIsFileSystemOpen(false)
    selectNode(node)
  }, [selectNode])
  const dimensions = useDimensions(contentRef)

  // Close all drawers when project changes
  useEffect(() => {
    setIsAIOpen(false)
    setPendingNodeQuery(null)
    setActiveLogsDrawer(null)
    clearSelection()
  }, [projectId, clearSelection])

  useDrawerOffsets(bodyRef)
  // Check if GVM stack is installed
  useEffect(() => {
    let cancelled = false
    void fetchGvmAvailability().then(a => { if (!cancelled) setGvmAvailability(a) })
    return () => { cancelled = true }
  }, [])

  const { isDark } = useTheme()
  const { sessionId, resetSession, switchSession } = useSession()

  // Data filters (formerly graph views) -- used in tab selector, Graph Map, Data Table, AI drawer
  const { views: graphViews, deleteView, executeCypher, fetchViews, actionError: graphViewActionError } = useGraphViews(projectId)
  // A filter deleted from the toolbar fails here, where nothing else shows the hook's error.
  const graphViewFailure = useMemo(() => (graphViewActionError ? { message: graphViewActionError } : null), [graphViewActionError])
  useErrorToast(graphViewFailure, 'Filter not changed')
  // A saved view naming a Domain the org model renamed is flagged, never rewritten.
  const dataFilterViews = useMemo(
    () => graphViews.map(v => ({ ...v, staleNote: staleViewNote(v.cypherQuery, currentProject?.scopeGroups ?? []) })),
    [graphViews, currentProject?.scopeGroups],
  )
  const [selectedFilterId, setSelectedFilterId] = useState<string | null>(null)
  const [filterGraphData, setFilterGraphData] = useState<{ nodes: any[]; links: any[]; projectId: string } | null>(null)
  const [filterLoading, setFilterLoading] = useState(false)

  // Resolve the Cypher query for the selected filter (stable across graphViews refetches)
  const selectedFilterCypherQuery = useMemo(() => {
    if (!selectedFilterId) return null
    return graphViews.find(v => v.id === selectedFilterId)?.cypherQuery ?? null
  }, [selectedFilterId, graphViews])

  // Active filter Cypher for the agent
  const selectedFilterCypher = selectedFilterCypherQuery ?? undefined

  // Clear filter if the selected filter gets deleted
  const handleDeleteFilter = useCallback(async (id: string) => {
    const ok = await deleteView(id)
    if (ok && selectedFilterId === id) {
      setSelectedFilterId(null)
    }
  }, [deleteView, selectedFilterId])

  // Callback for when a new filter is created in the GraphViews tab
  const handleFilterCreated = useCallback(() => {
    fetchViews()
  }, [fetchViews])

  const handleFilterCreatedAndSelect = useCallback((filterId: string) => {
    fetchViews()
    setSelectedFilterId(filterId)
    setActiveView('graph')
  }, [fetchViews])

  // Agent status polling - lightweight fetch every 5s for toolbar indicators
  const [agentSummary, setAgentSummary] = useState<{
    activeCount: number
    conversations: Array<{
      id: string
      title: string
      currentPhase: string
      iterationCount: number
      agentRunning: boolean
      sessionId: string
    }>
  }>({ activeCount: 0, conversations: [] })

  useEffect(() => {
    // The list asks agent:chat (route manifest): without it there is no chat to show and nothing to poll.
    if (agentRefused) {
      setAgentSummary({ activeCount: 0, conversations: [] })
      return
    }
    if (!projectId || !userId) return
    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/conversations?projectId=${projectId}&userId=${userId}`)
        if (!res.ok) return
        const convs = await res.json()
        const active = convs.filter((c: any) => c.agentRunning)
        setAgentSummary({ activeCount: active.length, conversations: convs })
      } catch { /* ignore fetch errors */ }
    }
    fetchStatus()
    const interval = setInterval(fetchStatus, 5000)
    return () => clearInterval(interval)
  }, [projectId, userId, agentRefused])

  // Tunnel status polling - check every 10s which tunnels are active
  const [tunnelStatus, setTunnelStatus] = useState<TunnelStatus>()

  useEffect(() => {
    const fetchTunnels = async () => {
      try {
        const res = await fetch('/api/agent/tunnel-status')
        if (res.ok) setTunnelStatus(await res.json())
      } catch { /* ignore */ }
    }
    fetchTunnels()
    const interval = setInterval(fetchTunnels, 10000)
    return () => clearInterval(interval)
  }, [])

  // Check if user has a GitHub access token configured in global settings
  useEffect(() => {
    if (!userId) return
    const checkToken = async () => {
      try {
        const res = await fetch(`/api/users/${userId}/settings`)
        if (res.ok) {
          const data = await res.json()
          setHasGithubToken((data.githubAccessToken || '').length > 0)
        }
      } catch { /* ignore */ }
    }
    checkToken()
  }, [userId])

  // Recon status hook - must be before useGraphData to provide isReconRunning
  const {
    state: reconState,
    isLoading: isReconLoading,
    error: reconError,
    startRecon,
    stopRecon,
    pauseRecon,
    resumeRecon,
    getLastStartError,
    getLastResumeError,
  } = useReconStatus({
    projectId,
    enabled: !!projectId,
  })

  // Check if recon is running to enable auto-refresh of graph data
  const isReconRunning = reconState?.status === 'running' || reconState?.status === 'starting' || reconState?.status === 'pausing'

  // Check if any agent conversation is active (writes attack chain nodes to graph)
  const isAgentRunning = agentSummary.activeCount > 0

  // Graph data -- no timer polling. Refetches are event-driven:
  //  - full recon SSE log events (via useReconSSE onLog)
  //  - partial recon SSE log events (via useMultiPartialReconSSE onLog)
  //  - agent tool-completion websocket events (via AIAssistantDrawer onRefetchGraph)
  //  - pipeline completion (refetchAfterCompletion)
  // Scan Timeline: which version the screen RENDERS. null = the current (active)
  // version, i.e. the live graph - the default, per the default-is-latest rule.
  // A non-null id renders that version's stored snapshot, read-only.
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)
  const [isVersionManagerOpen, setIsVersionManagerOpen] = useState(false)
  const {
    versions: scanVersions,
    currentVersion: activeVersion,
    activating: isActivatingVersion,
    refresh: refreshScanVersions,
    error: scanVersionsError,
  } = useScanVersions(projectId)
  // A failed version list leaves the switch showing no versions, which reads as
  // a project that has none; say why, once per reason.
  // The toast context changes with every toast, so the ref, not the deps, is
  // what keeps this to one toast.
  const scanVersionsErrorText = scanVersionsError ? scanVersionsError.message : null
  const scanVersionsErrorShownRef = useRef<string | null>(null)
  useEffect(() => {
    if (scanVersionsErrorText && scanVersionsErrorShownRef.current !== scanVersionsErrorText) {
      toast.error(scanVersionsErrorText, 'Scan versions unavailable')
    }
    scanVersionsErrorShownRef.current = scanVersionsErrorText
  }, [scanVersionsErrorText, toast])
  // A selection is dropped when the project changes or that version disappears
  // (deleted, or it just became the active one after an activation).
  useEffect(() => { setSelectedVersionId(null) }, [projectId])
  useEffect(() => {
    if (!selectedVersionId) return
    const still = scanVersions.find(v => v.id === selectedVersionId)
    if (!still || still.isCurrent) setSelectedVersionId(null)
  }, [scanVersions, selectedVersionId])
  const viewedVersion = selectedVersionId
    ? scanVersions.find(v => v.id === selectedVersionId) ?? null
    : activeVersion
  /** True while the screen shows a saved snapshot instead of the live graph. */
  const isViewingPastVersion = !!selectedVersionId

  // Render switch: while it is off the graph map is not fetched, queried or
  // drawn. It only suppresses the fetch on the map itself - every other view
  // (Node Inspector, All Nodes, the analytics panels) reads the same payload,
  // and the whole point of the off state is that those stay usable. Prefs are
  // loaded async, so nothing is fetched until the saved value is known:
  // treating "not loaded yet" as on would fire the very query being avoided.
  const graphGate = { prefsLoading: graphPrefsLoading, renderEnabled: graphRenderEnabled, activeView }
  const graphRenderOff = isGraphRenderOff(graphGate)
  const graphFetchEnabled = shouldFetchGraph(graphGate)

  const { data, isLoading, error, refetch: refetchGraph, refetchFresh } = useGraphData(projectId, selectedVersionId, graphFetchEnabled)

  // Debounced refetch: SSE log events fire rapidly during a scan; we only need
  // to re-pull the graph at most once per ~1.5s to pick up newly written nodes.
  const refetchGraphDebounceRef = useRef<NodeJS.Timeout | null>(null)
  const triggerGraphRefetch = useCallback(() => {
    if (refetchGraphDebounceRef.current) return
    refetchGraphDebounceRef.current = setTimeout(() => {
      refetchGraphDebounceRef.current = null
      refetchGraph()
    }, 1500)
  }, [refetchGraph])
  useEffect(() => () => {
    if (refetchGraphDebounceRef.current) clearTimeout(refetchGraphDebounceRef.current)
  }, [])

  // Execute filter Cypher when selected filter changes or when graph data refreshes
  // (so the filtered view stays in sync with live recon/agent data)
  const filterRefreshKey = data?.nodes.length ?? 0
  const filterErrorShownRef = useRef<string | null>(null)
  useEffect(() => {
    if (!selectedFilterCypherQuery || !projectId) {
      setFilterGraphData(null)
      return
    }
    let cancelled = false
    setFilterLoading(true)
    executeCypher(selectedFilterCypherQuery).then(result => {
      if (cancelled) return
      setFilterLoading(false)
      if ('error' in result) {
        setFilterGraphData(null)
        // The unfiltered graph is drawn while the filter stays selected, so say
        // why; once per filter and reason, since live scans re-run it often.
        const key = `${selectedFilterCypherQuery}\u0000${result.error}`
        if (filterErrorShownRef.current !== key) {
          filterErrorShownRef.current = key
          toast.error(result.error, 'Data filter failed: showing the unfiltered graph')
        }
      } else {
        filterErrorShownRef.current = null
        setFilterGraphData({ nodes: result.nodes, links: result.links, projectId })
      }
    })
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFilterCypherQuery, projectId, executeCypher, filterRefreshKey])

  // Recon logs SSE hook
  const {
    logs: reconLogs,
    currentPhase,
    currentPhaseNumber,
    currentGroup,
    groupNumber,
    totalGroups,
    clearLogs,
    error: reconStreamError,
  } = useReconSSE({
    projectId,
    enabled: reconState?.status === 'running' || reconState?.status === 'starting' || reconState?.status === 'paused' || reconState?.status === 'stopping' || reconState?.status === 'pausing',
    onLog: triggerGraphRefetch,
  })

  // Partial Recon multi-run status hook
  const {
    runs: allPartialReconRuns,
    activeRuns: activePartialRecons,
    isAnyRunning: isPartialReconRunning,
    error: partialReconError,
    stopPartialRecon,
    refetch: refetchPartialReconStatuses,
  } = useMultiPartialReconStatus({
    projectId,
    enabled: !!projectId,
  })

  // Derive the active run_id for SSE from the drawer state
  const activePartialReconRunId = activeLogsDrawer?.startsWith('partialRecon:')
    ? activeLogsDrawer.slice('partialRecon:'.length)
    : null

  // Partial Recon multi-run SSE hook (only connects to the visible drawer's run)
  const {
    logsMap: partialReconLogsMap,
    phaseMap: partialReconPhaseMap,
    clearLogsForRun: clearPartialReconLogsForRun,
    error: partialReconStreamError,
  } = useMultiPartialReconSSE({
    projectId,
    activeRunId: activePartialReconRunId,
    onLog: triggerGraphRefetch,
    onComplete: () => {
      triggerGraphRefetch()
      refetchPartialReconStatuses()
    },
  })

  // GVM status hook
  const {
    state: gvmState,
    isLoading: isGvmLoading,
    statusError: gvmStatusError,
    startError: gvmStartError,
    startGvm,
    stopGvm,
    pauseGvm,
    resumeGvm,
    getLastStartError: getGvmStartError,
    getLastActionError: getGvmActionError,
  } = useGvmStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGvmRunning = gvmState?.status === 'running' || gvmState?.status === 'starting' || gvmState?.status === 'pausing'

  // GVM logs SSE hook
  const {
    logs: gvmLogs,
    currentPhase: gvmCurrentPhase,
    currentPhaseNumber: gvmCurrentPhaseNumber,
    clearLogs: clearGvmLogs,
    error: gvmStreamError,
  } = useGvmSSE({
    projectId,
    enabled: gvmState?.status === 'running' || gvmState?.status === 'starting' || gvmState?.status === 'paused' || gvmState?.status === 'stopping' || gvmState?.status === 'pausing',
  })

  // GitHub Hunt status hook
  const {
    state: githubHuntState,
    isLoading: isGithubHuntLoading,
    statusError: githubHuntStatusError,
    startGithubHunt,
    stopGithubHunt,
    pauseGithubHunt,
    resumeGithubHunt,
    getLastStartError: getGithubStartError,
    getLastActionError: getGithubActionError,
  } = useGithubHuntStatus({
    projectId,
    enabled: !!projectId,
  })

  const isGithubHuntRunning = githubHuntState?.status === 'running' || githubHuntState?.status === 'starting' || githubHuntState?.status === 'pausing'

  // GitHub Hunt logs SSE hook
  const {
    logs: githubHuntLogs,
    currentPhase: githubHuntCurrentPhase,
    currentPhaseNumber: githubHuntCurrentPhaseNumber,
    clearLogs: clearGithubHuntLogs,
    error: githubHuntStreamError,
  } = useGithubHuntSSE({
    projectId,
    enabled: githubHuntState?.status === 'running' || githubHuntState?.status === 'starting' || githubHuntState?.status === 'paused' || githubHuntState?.status === 'stopping' || githubHuntState?.status === 'pausing',
  })

  // TruffleHog: run-keyed (one run per SOURCE, several in parallel), so the page
  // tracks the whole run list plus the configured profiles rather than one state.
  const {
    runs: trufflehogRuns,
    profiles: trufflehogProfiles,
    bySource: trufflehogRunsBySource,
    isAnyRunning: isTrufflehogRunning,
    statusError: trufflehogStatusError,
    profilesError: trufflehogProfilesError,
    startTrufflehog,
    stopTrufflehog,
    getLastStartError: getTrufflehogStartError,
    getLastActionError: getTrufflehogActionError,
  } = useTrufflehogRuns({
    projectId,
    enabled: !!projectId,
  })

  // Which source's log drawer is open. `activeLogsDrawer` carries the source so
  // two live containers do not share one stream.
  const openTrufflehogLogsSource = activeLogsDrawer?.startsWith('trufflehog:')
    ? activeLogsDrawer.slice('trufflehog:'.length)
    : null
  const openTrufflehogRun = openTrufflehogLogsSource
    ? trufflehogRunsBySource[openTrufflehogLogsSource]
    : undefined

  const {
    logs: trufflehogLogs,
    currentPhase: trufflehogCurrentPhase,
    currentPhaseNumber: trufflehogCurrentPhaseNumber,
    clearLogs: clearTrufflehogLogs,
    error: trufflehogStreamError,
  } = useTrufflehogSSE({
    projectId,
    source: openTrufflehogLogsSource,
    enabled: Boolean(openTrufflehogRun && ['running', 'starting', 'stopping'].includes(openTrufflehogRun.status)),
  })

  // Supply-Chain scan (L1) status + logs
  const {
    state: supplyChainState,
    statusError: supplyChainStatusError,
    startSupplyChain,
    stopSupplyChain,
    pauseSupplyChain,
    resumeSupplyChain,
    getLastStartError: getSupplyStartError,
    getLastActionError: getSupplyActionError,
  } = useSupplyChainStatus({ projectId, enabled: !!projectId })
  const {
    logs: supplyChainLogs,
    clearLogs: clearSupplyChainLogs,
    error: supplyChainStreamError,
  } = useSupplyChainSSE({
    projectId,
    enabled: supplyChainState?.status === 'running' || supplyChainState?.status === 'starting' || supplyChainState?.status === 'paused' || supplyChainState?.status === 'stopping' || supplyChainState?.status === 'pausing',
  })
  const handleStartSupplyChain = useCallback(async () => {
    try {
      clearSupplyChainLogs()
      const result = await startSupplyChain()
      if (result) {
        // The logs drawer opens BEHIND Other Scans, so the modal has to get out
        // of the way or the scan looks like it did nothing.
        setIsOtherScansModalOpen(false)
        setActiveLogsDrawer('supplyChain')
        toast.info('Supply-Chain scan started')
      }
    } catch {
      // Temporary -> Cancel / Add to queue; permanent -> error (Scan Queue Phase 3).
      await handleStartFailure('supply_chain', getSupplyStartError?.())
    }
  }, [startSupplyChain, clearSupplyChainLogs, toast, getSupplyStartError, handleStartFailure])
  const handleToggleSupplyChainLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'supplyChain' ? null : 'supplyChain')
  }, [])
  // Supply-chain input availability is no longer tracked here: the Other Scans
  // card configures the input itself (upload or repository) and therefore is
  // the only place that knows which source is selected and whether it is
  // populated. Duplicating that here could only disagree with it.

  // Active sessions hook - polls kali-sandbox session list
  const activeSessions = useActiveSessions({
    enabled: true,
    fastPoll: activeView === 'sessions',
  })

  // ── Table view state (lifted from DataTable) ──────────────────────────
  const tableRows = useTableData(data)
  const filterTableRows = useTableData(filterGraphData ?? undefined)
  const [globalFilter, setGlobalFilter] = useState('')
  const [tableViewMode, setTableViewMode] = useState<TableViewMode>('nodeDetails')
  // Sheet to pre-select inside a multi-sheet table when deep-linked (?sheet=...).
  // Cleared on any manual table switch so it never overrides a later manual open.
  const [deepLinkSheet, setDeepLinkSheet] = useState<string | null>(null)
  // Mute Rules opens at a kind (and rule) when a Muted Nodes row links to it.
  const [nodeFilterFocus, setNodeFilterFocus] = useState<{ kind: string; ruleId?: string } | null>(null)
  const openNodeFilterRule = useCallback((kind: string, ruleId: string) => {
    setNodeFilterFocus({ kind, ruleId })
    setDeepLinkSheet(null)
    setTableViewMode('nodeFilters')
  }, [])
  // Multi mute's "Keep hiding new ones": Mute Rules at the seed's kind, from
  // any view the modal was opened on.
  const openMuteRulesKind = useCallback((kind: string) => {
    setNodeFilterFocus({ kind })
    setDeepLinkSheet(null)
    setActiveView('table')
    setTableViewMode('nodeFilters')
  }, [])
  // Muted Nodes opens on these filters when set (Multi mute's one batch).
  const [mutedFocus, setMutedFocus] = useState<MutedNodesFocus | null>(null)
  const { status: nodeFilterStatus, refresh: refreshNodeFilterStatus } = useNodeFilterStatus(projectId, refetchGraph)

  // A tab switch unmounts the view being left, so a dirty form in it (Mute
  // Rules) asks before its edits go, the way the header links do. Only a switch
  // that actually leaves asks: a tab click fires the table-mode and the view
  // change together, and the half that stays put must not prompt again.
  const navGuard = useNavigationGuard()
  const guardedSwitch = useCallback((leaving: boolean, apply: () => void) => {
    if (!leaving || !navGuard?.hasGuards()) { apply(); return }
    void navGuard.confirmAllGuards().then(ok => { if (ok) apply() })
  }, [navGuard])
  const changeView = useCallback((view: ViewMode) => {
    guardedSwitch(view !== activeView, () => setActiveView(view))
  }, [guardedSwitch, activeView])
  const changeTableViewMode = useCallback((mode: TableViewMode) => {
    guardedSwitch(activeView === 'table' && mode !== tableViewMode, () => {
      setDeepLinkSheet(null)
      setNodeFilterFocus(null)
      setMutedFocus(null)
      setTableViewMode(mode)
    })
  }, [guardedSwitch, activeView, tableViewMode])

  // Unseen-row badges. The active tab is whichever table is on screen, so a tab
  // the user is reading stops counting as unseen while they read it.
  const {
    counts: unseenCounts,
    total: unseenTotal,
    markSeen: markTabSeen,
  } = useUnseenCounts(projectId, activeView === 'table' ? tableViewMode : null)

  const [jsReconSearch, setJsReconSearch] = useState('')
  const [jsReconData, setJsReconData] = useState<JsReconData | null>(null)
  const [activeNodeTypes, setActiveNodeTypes] = useState<Set<string>>(new Set())
  const [tableInitialized, setTableInitialized] = useState(false)

  // Clear a tab's badge the moment it is opened, rather than on the next poll:
  // a number that lingers for up to a poll interval after the user has looked
  // at the rows reads as "this is stuck", not "this is fresh".
  useEffect(() => {
    if (activeView !== 'table') return
    markTabSeen(tableViewMode)
  }, [activeView, tableViewMode, markTabSeen])

  // Persistent per-project filter for which node types are hidden in the graph
  // bottom-bar chips. Survives reloads and project switches.
  const {
    hiddenTypes: savedHiddenTypes,
    setHiddenTypes: setSavedHiddenTypes,
    isLoading: graphFilterPrefsLoading,
  } = useGraphTypeFilterPrefs(projectId)

  const nodeTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    tableRows.forEach(r => {
      counts[r.node.type] = (counts[r.node.type] || 0) + 1
    })
    return counts
  }, [tableRows])

  const filterNodeTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    filterTableRows.forEach(r => {
      counts[r.node.type] = (counts[r.node.type] || 0) + 1
    })
    return counts
  }, [filterTableRows])

  const effectiveNodeTypeCounts = selectedFilterId ? filterNodeTypeCounts : nodeTypeCounts
  const nodeTypes = useMemo(() => Object.keys(effectiveNodeTypeCounts).sort(), [effectiveNodeTypeCounts])

  // Types we've already observed at least once. Used to distinguish "user
  // deselected this type" (still in seen set, don't re-add) from "type just
  // appeared for the first time" (not in seen set, auto-enable).
  const seenNodeTypesRef = useRef<Set<string>>(new Set())

  // Reset active node types when filter selection changes (Surface filter switch).
  // Saved hidden-types are reapplied so the user's persistent selection survives
  // a Surface flip.
  useEffect(() => {
    if (graphFilterPrefsLoading) return
    const hidden = new Set(savedHiddenTypes)
    seenNodeTypesRef.current = new Set(nodeTypes)
    setActiveNodeTypes(new Set(nodeTypes.filter(t => !hidden.has(t))))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFilterId])

  // Re-init when projectId changes so the per-project saved selection takes
  // effect on switch. tableInitialized is reset in a separate effect below.
  useEffect(() => {
    setTableInitialized(false)
    seenNodeTypesRef.current = new Set()
  }, [projectId])

  useEffect(() => {
    // Defer first init until BOTH the graph data has types AND the user prefs
    // have loaded - otherwise we'd briefly show "all visible" and either flicker
    // or overwrite the saved selection.
    if (nodeTypes.length > 0 && !tableInitialized && !graphFilterPrefsLoading) {
      const hidden = new Set(savedHiddenTypes)
      seenNodeTypesRef.current = new Set(nodeTypes)
      setActiveNodeTypes(new Set(nodeTypes.filter(t => !hidden.has(t))))
      setTableInitialized(true)
      return
    }
    if (!tableInitialized) return
    // Auto-enable genuinely new node types (never observed before) so attack
    // chain nodes created mid-session show up. Deselected types stay hidden.
    const genuinelyNew = nodeTypes.filter((t: string) => !seenNodeTypesRef.current.has(t))
    if (genuinelyNew.length === 0) return
    genuinelyNew.forEach((t: string) => seenNodeTypesRef.current.add(t))
    setActiveNodeTypes((prev: Set<string>) => {
      const next = new Set(prev)
      genuinelyNew.forEach((t: string) => next.add(t))
      return next
    })
  }, [nodeTypes, tableInitialized, graphFilterPrefsLoading, savedHiddenTypes])

  const filteredByTypeOnly = useMemo(() => {
    if (activeNodeTypes.size === 0) return []
    return tableRows.filter(r => activeNodeTypes.has(r.node.type))
  }, [tableRows, activeNodeTypes])

  // ── Session (chain) visibility ──────────────────────────────────────
  const CHAIN_NODE_TYPES = useMemo(() => new Set([
    'AttackChain', 'ChainStep', 'ChainDecision', 'ChainFailure', 'ChainFinding',
  ]), [])

  const effectiveBarData = selectedFilterId ? filterGraphData : data

  const sessionChainIds = useMemo(() => {
    if (!effectiveBarData) return []
    const ids = new Set<string>()
    for (const node of effectiveBarData.nodes) {
      const chainId = node.properties?.chain_id as string | undefined
      if (chainId && CHAIN_NODE_TYPES.has(node.type)) {
        ids.add(chainId)
      }
    }
    return Array.from(ids).sort()
  }, [effectiveBarData, CHAIN_NODE_TYPES])

  const sessionTitles = useMemo(() => {
    if (!effectiveBarData) return {} as Record<string, string>
    const titles: Record<string, string> = {}
    for (const node of effectiveBarData.nodes) {
      if (node.type === 'AttackChain') {
        const chainId = node.properties?.chain_id as string | undefined
        const title = node.properties?.title as string | undefined
        if (chainId && title) {
          titles[chainId] = title
        }
      }
    }
    return titles
  }, [effectiveBarData])

  const [hiddenSessions, setHiddenSessions] = useState<Set<string>>(new Set())

  // Auto-show newly discovered sessions
  useEffect(() => {
    setHiddenSessions((prev: Set<string>) => {
      const updated = new Set<string>()
      for (const id of prev) {
        if (sessionChainIds.includes(id)) updated.add(id)
      }
      return updated.size !== prev.size ? updated : prev
    })
  }, [sessionChainIds])

  const handleToggleSession = useCallback((chainId: string) => {
    setHiddenSessions((prev: Set<string>) => {
      const next = new Set(prev)
      if (next.has(chainId)) next.delete(chainId)
      else next.add(chainId)
      return next
    })
  }, [])

  const handleShowAllSessions = useCallback(() => {
    setHiddenSessions(new Set())
  }, [])

  const handleHideAllSessions = useCallback(() => {
    setHiddenSessions(new Set(sessionChainIds))
  }, [sessionChainIds])

  // "Hide other chains" / "Show all" toggle for the AI drawer
  const isOtherChainsHidden = useMemo(() => {
    if (hiddenSessions.size === 0) return false
    const otherChains = sessionChainIds.filter((id: string) => id !== sessionId)
    if (otherChains.length === 0) return false
    return otherChains.every((id: string) => hiddenSessions.has(id))
  }, [hiddenSessions, sessionChainIds, sessionId])

  const handleToggleOtherChains = useCallback(() => {
    const otherChains = sessionChainIds.filter((id: string) => id !== sessionId)
    setHiddenSessions((prev: Set<string>) => {
      const allOthersHidden = otherChains.every((id: string) => prev.has(id))
      if (allOthersHidden) {
        return new Set()
      } else {
        return new Set(otherChains)
      }
    })
  }, [sessionChainIds, sessionId])
  // ── End session visibility ────────────────────────────────────────

  // Table rows filtered by type + hidden sessions
  const filteredByType = useMemo(() => {
    if (hiddenSessions.size === 0) return filteredByTypeOnly
    return filteredByTypeOnly.filter((r: { node: { type: string; properties: Record<string, unknown> } }) => {
      if (CHAIN_NODE_TYPES.has(r.node.type)) {
        const chainId = r.node.properties?.chain_id as string | undefined
        if (chainId && hiddenSessions.has(chainId)) return false
      }
      return true
    })
  }, [filteredByTypeOnly, hiddenSessions, CHAIN_NODE_TYPES])

  // Filtered graph data for GraphCanvas (filter nodes by type + hidden sessions, then prune links)
  const filteredGraphData = useMemo(() => {
    if (!data) return undefined
    const allTypesActive = activeNodeTypes.size === nodeTypes.length
    const noSessionsHidden = hiddenSessions.size === 0
    if (allTypesActive && noSessionsHidden) return data // nothing filtered
    const filteredNodes = data.nodes.filter(n => {
      if (!activeNodeTypes.has(n.type)) return false
      // Hide chain nodes belonging to hidden sessions
      if (hiddenSessions.size > 0 && CHAIN_NODE_TYPES.has(n.type)) {
        const chainId = n.properties?.chain_id as string | undefined
        if (chainId && hiddenSessions.has(chainId)) return false
      }
      return true
    })
    const visibleIds = new Set(filteredNodes.map(n => n.id))
    const filteredLinks = data.links.filter(l => {
      const srcId = typeof l.source === 'string' ? l.source : l.source.id
      const tgtId = typeof l.target === 'string' ? l.target : l.target.id
      return visibleIds.has(srcId) && visibleIds.has(tgtId)
    })
    return { ...data, nodes: filteredNodes, links: filteredLinks }
  }, [data, activeNodeTypes, nodeTypes.length, hiddenSessions, CHAIN_NODE_TYPES])

  // Hard render cap: measured on the node set clustering would actually process
  // (active saved-filter view, or the type/session-filtered set) - not the raw
  // unfiltered graph - so a large project narrowed by a filter still renders.
  const renderSource = filterGraphData ?? filteredGraphData
  const overNodeCap = isOverNodeCap(renderSource?.nodes.length ?? 0)

  // Clustered graph data for GraphCanvas (collapses >30 same-type leaf neighbors sharing a parent).
  // Applied AFTER filtering so hiding a child type also dissolves its clusters.
  // Skipped entirely when over the hard cap - clustering is the expensive step that would freeze the tab.
  const clusteredGraphData = useMemo(() => {
    if (overNodeCap) return undefined
    const src = filterGraphData ?? filteredGraphData
    if (!src) return undefined
    return clusterGraphData(src)
  }, [overNodeCap, filterGraphData, filteredGraphData])

  // Stable graph data for GraphCanvas: preserves node object identity across
  // refetches and pre-resolves link source/target string ids to node refs.
  // Without this, incremental updates (new nodes from recon/partial recon) flash
  // edges drawn to undefined coordinates ("edges to the void") until d3-force
  // finishes resolving ids on its next tick.
  const stableGraphData = useStableGraphData(clusteredGraphData)

  // Clusters count as single nodes for the 3D threshold - use clustered count.
  const displayedNodeCount = stableGraphData?.nodes.length ?? 0
  const effectiveIs3D = is3D && displayedNodeCount <= AUTO_2D_THRESHOLD

  // Effective table rows: use filter data when a data filter is active
  const effectiveTableRows = selectedFilterId ? filterTableRows : filteredByType

  const textFilteredCount = useMemo(() => {
    if (!globalFilter) return effectiveTableRows.length
    const search = globalFilter.toLowerCase()
    return effectiveTableRows.filter(r =>
      r.node.name?.toLowerCase().includes(search) ||
      r.node.type?.toLowerCase().includes(search)
    ).length
  }, [effectiveTableRows, globalFilter])

  const handleToggleNodeType = useCallback((type: string) => {
    setActiveNodeTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      // Persist as HIDDEN list (inverse of visible) so newly discovered types
      // default to visible without any DB write.
      setSavedHiddenTypes(nodeTypes.filter(t => !next.has(t)))
      return next
    })
  }, [nodeTypes, setSavedHiddenTypes])

  const handleSelectAllTypes = useCallback(() => {
    setActiveNodeTypes(new Set(nodeTypes))
    setSavedHiddenTypes([])
  }, [nodeTypes, setSavedHiddenTypes])

  const handleClearAllTypes = useCallback(() => {
    setActiveNodeTypes(new Set())
    setSavedHiddenTypes(nodeTypes.slice())
  }, [nodeTypes, setSavedHiddenTypes])

  const filteredExportRows = useCallback(() => {
    let rows = effectiveTableRows
    if (globalFilter) {
      const search = globalFilter.toLowerCase()
      rows = rows.filter(r =>
        r.node.name?.toLowerCase().includes(search) ||
        r.node.type?.toLowerCase().includes(search)
      )
    }
    return rows
  }, [effectiveTableRows, globalFilter])

  // Tracks which All-Nodes / JS Recon export format is currently being
  // generated, so the corresponding button can show a spinner instead of
  // the download icon.
  const [allNodesExporting, setAllNodesExporting] = useState<'csv' | 'json' | 'md' | null>(null)
  const [jsReconExporting, setJsReconExporting] = useState<'csv' | 'json' | 'md' | null>(null)

  const handleExportCsv = useCallback(async () => {
    if (allNodesExporting) return
    setAllNodesExporting('csv')
    try {
      await exportToCsv(filteredExportRows())
      toast.success('CSV exported')
    } catch (err) {
      console.error('Failed to export CSV:', err)
      toast.error('Failed to export CSV')
    } finally {
      setAllNodesExporting(null)
    }
  }, [filteredExportRows, toast, allNodesExporting])

  const handleExportJson = useCallback(async () => {
    if (allNodesExporting) return
    setAllNodesExporting('json')
    try {
      await exportToJson(filteredExportRows())
      toast.success('JSON exported')
    } catch (err) {
      console.error('Failed to export JSON:', err)
      toast.error('Failed to export JSON')
    } finally {
      setAllNodesExporting(null)
    }
  }, [filteredExportRows, toast, allNodesExporting])

  const handleExportMarkdown = useCallback(async () => {
    if (allNodesExporting) return
    setAllNodesExporting('md')
    try {
      await exportToMarkdown(filteredExportRows())
      toast.success('Markdown exported')
    } catch (err) {
      console.error('Failed to export Markdown:', err)
      toast.error('Failed to export Markdown')
    } finally {
      setAllNodesExporting(null)
    }
  }, [filteredExportRows, toast, allNodesExporting])

  // ── End table view state ──────────────────────────────────────────────

  // Check if recon data exists
  const checkReconData = useCallback(async () => {
    if (!projectId) return
    const probe = await probeScanData(`/api/recon/${projectId}/download`)
    setHasReconData(probe.has)
    setDataProbeError('recon', probe.error)
  }, [projectId, setDataProbeError])

  // Calculate graph stats when data changes
  useEffect(() => {
    if (data?.nodes) {
      const nodesByType: Record<string, number> = {}
      data.nodes.forEach(node => {
        const type = node.type || 'Unknown'
        nodesByType[type] = (nodesByType[type] || 0) + 1
      })
      setGraphStats({
        totalNodes: data.nodes.length,
        nodesByType,
      })
    } else {
      setGraphStats(null)
    }
  }, [data])

  // Calculate GVM-specific stats from graph data
  useEffect(() => {
    if (data?.nodes) {
      const gvmTypes: Record<string, number> = {}
      let total = 0
      data.nodes.forEach(node => {
        const isGvmVuln = node.type === 'Vulnerability' && node.properties?.source === 'gvm'
        const isGvmTech = node.type === 'Technology' && (node.properties?.detected_by as string[] | undefined)?.includes('gvm')
        if (isGvmVuln || isGvmTech) {
          const type = node.type || 'Unknown'
          gvmTypes[type] = (gvmTypes[type] || 0) + 1
          total++
        }
      })
      setGvmStats(total > 0 ? { totalGvmNodes: total, nodesByType: gvmTypes } : null)
    } else {
      setGvmStats(null)
    }
  }, [data])

  // Check if GVM data exists
  const checkGvmData = useCallback(async () => {
    if (!projectId) return
    const probe = await probeScanData(`/api/gvm/${projectId}/download`)
    setHasGvmData(probe.has)
    setDataProbeError('gvm', probe.error)
  }, [projectId, setDataProbeError])

  // Check if GitHub Hunt data exists
  const checkGithubHuntData = useCallback(async () => {
    if (!projectId) return
    const probe = await probeScanData(`/api/github-hunt/${projectId}/download`)
    setHasGithubHuntData(probe.has)
    setDataProbeError('githubHunt', probe.error)
  }, [projectId, setDataProbeError])

  // Check if TruffleHog data exists
  const checkTrufflehogData = useCallback(async () => {
    if (!projectId) return
    const probe = await probeScanData(`/api/trufflehog/${projectId}/download`)
    setHasTrufflehogData(probe.has)
    setDataProbeError('trufflehog', probe.error)
  }, [projectId, setDataProbeError])

  // Check if Supply-Chain (L1) data exists
  const checkSupplyChainData = useCallback(async () => {
    if (!projectId) return
    const probe = await probeScanData(`/api/supply-chain/${projectId}/download`)
    setHasSupplyChainData(probe.has)
    setDataProbeError('supplyChain', probe.error)
  }, [projectId, setDataProbeError])

  // Check for recon/GVM/GitHub Hunt/TruffleHog/Supply-Chain data on mount and when project changes
  useEffect(() => {
    checkReconData()
    checkGvmData()
    checkGithubHuntData()
    checkTrufflehogData()
    checkSupplyChainData()
  }, [checkReconData, checkGvmData, checkGithubHuntData, checkTrufflehogData, checkSupplyChainData])

  // Bypass all caches and refetch, with a delayed second fetch
  // to catch background graph-DB writes that may still be flushing.
  const refetchAfterCompletion = useCallback(() => {
    refetchFresh()
    const t = setTimeout(() => refetchFresh(), 3000)
    return () => clearTimeout(t)
  }, [refetchFresh])

  // A scan that ends in error used to change only a badge (and the drawer line,
  // if it happened to be open): say so, with the reason the orchestrator kept.
  const seenScanStatusRef = useRef<Record<string, string | undefined>>({})
  const trufflehogFailureKey = trufflehogRuns.map(r => `${r.source}:${r.status}`).join(',')
  useEffect(() => {
    const seen = seenScanStatusRef.current
    const check = (key: string, label: string, status?: string | null, error?: string | null) => {
      const message = scanFailureToast(label, seen[key], status, error)
      if (message) toast.error(message)
      seen[key] = status ?? undefined
    }
    check('gvm', 'GVM scan', gvmState?.status, gvmState?.error)
    check('githubHunt', 'GitHub Secret Hunt', githubHuntState?.status, githubHuntState?.error)
    check('supplyChain', 'Supply-Chain scan', supplyChainState?.status, supplyChainState?.error)
    for (const run of trufflehogRuns) {
      if (run.source) check(`trufflehog:${run.source}`, `Secret Multiscanner ${run.source} scan`, run.status, run.error)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gvmState?.status, githubHuntState?.status, supplyChainState?.status, trufflehogFailureKey, toast])

  // Refresh graph data when recon completes
  useEffect(() => {
    if (reconState?.status === 'completed' || reconState?.status === 'error') {
      const cleanup = refetchAfterCompletion()
      checkReconData()
      return cleanup
    }
  }, [reconState?.status, refetchAfterCompletion, checkReconData])

  // Refresh graph when GVM scan completes
  useEffect(() => {
    if (gvmState?.status === 'completed' || gvmState?.status === 'error') {
      const cleanup = refetchAfterCompletion()
      checkGvmData()
      return cleanup
    }
  }, [gvmState?.status, refetchAfterCompletion, checkGvmData])

  // Refresh when GitHub Hunt completes
  useEffect(() => {
    if (githubHuntState?.status === 'completed' || githubHuntState?.status === 'error') {
      const cleanup = refetchAfterCompletion()
      checkGithubHuntData()
      return cleanup
    }
  }, [githubHuntState?.status, refetchAfterCompletion, checkGithubHuntData])

  // Refresh when ANY TruffleHog source completes. Keyed on the joined statuses
  // so a second source finishing still triggers a refetch.
  const trufflehogStatusKey = trufflehogRuns.map(r => `${r.source}:${r.status}`).join(',')
  useEffect(() => {
    if (trufflehogRuns.some(r => r.status === 'completed' || r.status === 'error')) {
      const cleanup = refetchAfterCompletion()
      checkTrufflehogData()
      return cleanup
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trufflehogStatusKey, refetchAfterCompletion, checkTrufflehogData])

  // Refresh when Supply-Chain (L1) completes
  useEffect(() => {
    if (supplyChainState?.status === 'completed' || supplyChainState?.status === 'error') {
      const cleanup = refetchAfterCompletion()
      checkSupplyChainData()
      return cleanup
    }
  }, [supplyChainState?.status, refetchAfterCompletion, checkSupplyChainData])

  // Refresh graph when any partial recon run completes (detected via status changes in polling)
  const prevPartialRunStatusesRef = useRef<Record<string, string>>({})
  useEffect(() => {
    let shouldRefetch = false
    const newStatuses: Record<string, string> = {}
    for (const run of allPartialReconRuns) {
      newStatuses[run.run_id] = run.status
      const prev = prevPartialRunStatusesRef.current[run.run_id]
      if (prev && prev !== run.status && (run.status === 'completed' || run.status === 'error')) {
        shouldRefetch = true
      }
    }
    prevPartialRunStatusesRef.current = newStatuses
    if (shouldRefetch) {
      return refetchAfterCompletion()
    }
  }, [allPartialReconRuns, refetchAfterCompletion])

  const handleToggleAI = useCallback(async () => {
    // Section 4.2: the agent ALWAYS runs against the current (active) version -
    // it only ever queries the live graph. Say so before opening the drawer over
    // a past-version view, so the user is never confused about what it sees.
    if (!isAIOpen && isViewingPastVersion) {
      const proceed = await confirmModal(
        `The graph is showing an older version (${viewedVersion?.label ?? 'a saved snapshot'}). ` +
        `The agent will run against the active version${activeVersion ? ` (${activeVersion.label})` : ''}. ` +
        'To have the agent work on this older version, activate it first.',
        'Agent runs on the active version'
      )
      if (!proceed) return
    }
    setIsAIOpen((prev) => !prev)
  }, [isAIOpen, isViewingPastVersion, viewedVersion, activeVersion, confirmModal])

  const handleCloseAI = useCallback(() => {
    setIsAIOpen(false)
  }, [])

  // "Ask agent" from a node: close the node drawer, spin up a FRESH session
  // (forces the agent socket to reconnect on the new id), open the AI drawer,
  // and hand it the seed message. The drawer sends it once that socket is up.
  const handleStartAgentSession = useCallback((request: string, context: string, nodeLabel: string) => {
    clearSelection()
    // The drawer shows the refusal; a fresh session and a seeded message would wait there for nothing.
    if (agentRefused) {
      setIsAIOpen(true)
      return
    }
    resetSession()
    setIsAIOpen(true)
    setPendingNodeQuery({ token: Date.now(), nodeLabel, context, request })
  }, [clearSelection, resetSession, agentRefused])

  const handlePendingNodeQueryConsumed = useCallback(() => setPendingNodeQuery(null), [])

  const handleToggleStealth = useCallback(async (newValue: boolean) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stealthMode: newValue }),
      })
      if (!res.ok) {
        toast.error((await readApiError(res, 'Could not change Stealth Mode')).message)
        return
      }
      if (currentProject) {
        setCurrentProject({ ...currentProject, stealthMode: newValue })
      }
    } catch (error) {
      console.error('Failed to toggle stealth mode:', error)
      toast.error(toApiError(error, 'Could not change Stealth Mode').message)
    }
  }, [projectId, currentProject, setCurrentProject, toast])

  const handleModelChange = useCallback(async (modelId: string) => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentOpenaiModel: modelId }),
      })
      if (!res.ok) {
        toast.error((await readApiError(res, 'Could not change the agent model')).message)
        return
      }
      if (currentProject) {
        setCurrentProject({ ...currentProject, agentOpenaiModel: modelId })
      }
    } catch (error) {
      console.error('Failed to change model:', error)
      toast.error(toApiError(error, 'Could not change the agent model').message)
    }
  }, [projectId, currentProject, setCurrentProject, toast])

  const handleStartRecon = useCallback(() => {
    setIsReconModalOpen(true)
  }, [])

  // Auto-open recon modal when navigating from project settings with autostart param
  useEffect(() => {
    // A deep link that names a project must not be applied against whichever
    // project the provider still holds: it resolves ?project= with an async
    // fetch, so the first commit here can be the PREVIOUS one. Acting then also
    // rewrites the URL to that other project - a scan modal on the wrong target.
    // Wait for the provider to catch up; this effect re-runs when it does.
    const urlProjectId = searchParams.get('project')
    if (urlProjectId && urlProjectId !== projectId) return

    if (searchParams.get('autostart') === 'true' && projectId) {
      setIsReconModalOpen(true)
      router.replace(`/graph?project=${projectId}`)
    }
    const openLogs = searchParams.get('openlogs')
    if (openLogs && projectId) {
      setActiveLogsDrawer(openLogs as 'recon' | 'gvm' | 'githubHunt' | `trufflehog:${string}` | `partialRecon:${string}`)
      router.replace(`/graph?project=${projectId}`)
    }
    // Deep-link into a specific Red Zone table (e.g. ?table=aiRisk from the AI
    // Attack Surface page's "Show findings" button).
    // Validated, not cast: an unknown ?table= value used to fall through to All
    // Nodes while looking like the link worked. Legacy names are aliased.
    const tableParam = parseTableViewMode(searchParams.get('table'))
    if (tableParam && projectId) {
      setActiveView('table')
      setTableViewMode(tableParam)
      setDeepLinkSheet(searchParams.get('sheet'))   // optional sub-sheet to open
      router.replace(`/graph?project=${projectId}`)
    }
    // "Start to Scan" in a project-settings section header: the settings page
    // saved and sent the operator here with the scan's own modal to open.
    const scanParam = parseScanModal(searchParams.get('scan'))
    if (scanParam && projectId) {
      if (scanParam === 'gvm') { setGvmConfirmAttempted(false); setIsGvmModalOpen(true) }
      else setIsOtherScansModalOpen(true)
      router.replace(`/graph?project=${projectId}`)
    }
  }, [searchParams, projectId, router])

  const handleConfirmRecon = useCallback(async (mode: ScanMode = 'new') => {
    clearLogs()
    const result = await startRecon(mode)
    if (result) {
      refreshScanVersions()
      setIsReconModalOpen(false)
      setActiveLogsDrawer('recon')
      toast.info(mode === 'new'
        ? 'Previous graph saved as a version - recon scan started'
        : 'Recon scan started (previous graph discarded)')
      return
    }
    // Failed to start. On a temporary failure (RAM/hard limit, activation, 409)
    // the shared handler offers Cancel / Add to queue; permanent failures fall
    // back to a single-button error (Scan Queue Phase 3).
    const startErr = getLastStartError?.()
    if (startErr) {
      setIsReconModalOpen(false)
      await handleStartFailure('full_recon', startErr, { mode })
    }
  }, [startRecon, clearLogs, toast, getLastStartError, handleStartFailure, refreshScanVersions])

  const handleDownloadJSON = useCallback(async () => {
    if (!projectId) return
    const error = await downloadScanFile(`/api/recon/${projectId}/download`, `recon_${projectId}.json`)
    if (error) toast.error(error, 'Recon JSON not downloaded')
  }, [projectId, toast])

  const handleDeleteNode = useCallback(async (nodeId: string) => {
    if (!projectId) return
    // A past version is an immutable saved snapshot: no mutation affordance may
    // act on it (and node delete would otherwise silently hit the LIVE graph).
    if (isViewingPastVersion) {
      alertError(
        'You are viewing a saved version, which is read-only. Switch back to the active version to delete nodes.',
        'Read-only version'
      )
      return
    }
    let res: Response
    try {
      res = await fetch(`/api/graph?nodeId=${nodeId}&projectId=${projectId}`, {
        method: 'DELETE',
      })
    } catch (err) {
      alertError(toApiError(err, 'Failed to delete node').message)
      return
    }
    if (!res.ok) {
      alertError((await readApiError(res, 'Failed to delete node')).message)
      return
    }
    toast.success('Node deleted')
    refetchGraph()
  }, [projectId, refetchGraph, toast, isViewingPastVersion, alertError])

  // "View muted" on the mute toast, which the drawer raises from the graph view.
  const viewMutedNodes = useCallback((focus?: MutedNodesFocus) => {
    setActiveView('table')
    setDeepLinkSheet(null)
    setNodeFilterFocus(null)
    setMutedFocus(focus ? { ...focus } : null)
    setTableViewMode('muted')
  }, [])

  const handleToggleLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'recon' ? null : 'recon')
  }, [])

  const handleStartGvm = useCallback(() => {
    if (isViewingPastVersion) {
      alertError(PAST_VERSION_SCAN_MSG, 'Read-only version')
      return
    }
    setGvmConfirmAttempted(false)
    setIsGvmModalOpen(true)
  }, [isViewingPastVersion, alertError])

  const handleConfirmGvm = useCallback(async () => {
    if (isViewingPastVersion) {
      alertError(PAST_VERSION_SCAN_MSG, 'Read-only version')
      return
    }
    clearGvmLogs()
    setGvmConfirmAttempted(true)
    const result = await startGvm()
    if (result) {
      setIsGvmModalOpen(false)
      setActiveLogsDrawer('gvm')
      toast.info('GVM scan started')
      return
    }
    // Failed to start: temporary -> Cancel / Add to queue; permanent -> error
    // (Scan Queue Phase 3). startGvm keeps its return-null contract.
    const startErr = getGvmStartError?.()
    if (startErr) {
      setIsGvmModalOpen(false)
      await handleStartFailure('gvm', startErr)
    }
  }, [startGvm, clearGvmLogs, toast, isViewingPastVersion, alertError, getGvmStartError, handleStartFailure])

  const handleDownloadGvmJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/gvm/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGvmLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'gvm' ? null : 'gvm')
  }, [])

  const handleStartGithubHunt = useCallback(async () => {
    if (isViewingPastVersion) {
      alertError(PAST_VERSION_SCAN_MSG, 'Read-only version')
      return
    }
    try {
      clearGithubHuntLogs()
      const result = await startGithubHunt()
      if (result) {
        setIsOtherScansModalOpen(false)
        setActiveLogsDrawer('githubHunt')
        toast.info('GitHub Hunt started')
      }
    } catch {
      // Temporary -> Cancel / Add to queue; permanent -> error (Scan Queue Phase 3).
      await handleStartFailure('github_hunt', getGithubStartError?.())
    }
  }, [startGithubHunt, clearGithubHuntLogs, toast, isViewingPastVersion, getGithubStartError, handleStartFailure])

  const handleDownloadGithubHuntJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/github-hunt/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleGithubHuntLogs = useCallback(() => {
    setActiveLogsDrawer(prev => prev === 'githubHunt' ? null : 'githubHunt')
  }, [])

  const handleStartTrufflehog = useCallback(async (source: string) => {
    if (isViewingPastVersion) return
    try {
      clearTrufflehogLogs()
      const result = await startTrufflehog(source)
      if (result) {
        setIsOtherScansModalOpen(false)
        setActiveLogsDrawer(`trufflehog:${source}`)
        toast.info(`Secret Multiscanner ${source} scan started`)
      } else {
        throw new Error('start failed')
      }
    } catch {
      await handleStartFailure('trufflehog', getTrufflehogStartError?.(), { source })
    }
  }, [startTrufflehog, clearTrufflehogLogs, toast, isViewingPastVersion, getTrufflehogStartError, handleStartFailure])

  const handleDownloadTrufflehogJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/trufflehog/${projectId}/download`, '_blank')
  }, [projectId])

  const handleDownloadSupplyChainJSON = useCallback(async () => {
    if (!projectId) return
    window.open(`/api/supply-chain/${projectId}/download`, '_blank')
  }, [projectId])

  const handleToggleTrufflehogLogs = useCallback((source: string) => {
    setActiveLogsDrawer(prev => prev === `trufflehog:${source}` ? null : `trufflehog:${source}`)
  }, [])

  // Auto-open partial recon logs drawer when a new run appears or transitions to running
  const prevPartialRunStatusMapRef = useRef<Record<string, string>>({})
  useEffect(() => {
    for (const run of activePartialRecons) {
      const prev = prevPartialRunStatusMapRef.current[run.run_id]
      // Open drawer for newly appeared runs or runs transitioning to 'running'
      if (!prev || (run.status === 'running' && prev !== 'running')) {
        setActiveLogsDrawer(`partialRecon:${run.run_id}`)
        break // Only auto-open one at a time
      }
    }
    const newMap: Record<string, string> = {}
    for (const run of activePartialRecons) {
      newMap[run.run_id] = run.status
    }
    prevPartialRunStatusMapRef.current = newMap
  }, [activePartialRecons])

  // Recon and partial-recon stop/pause resolve to null on failure and keep the
  // reason only in the hook's `error`, which lands on the next render: the toast
  // is raised there, so it carries the reason (code and status) and not a guess.
  type FailedReconAction = { title: string; source: 'recon' | 'partial' }
  const [failedReconActions, setFailedReconActions] = useState<FailedReconAction[]>([])
  const reportReconFailure = useCallback((title: string, source: FailedReconAction['source']) => {
    setFailedReconActions(prev => [...prev, { title, source }])
  }, [])
  useEffect(() => {
    if (failedReconActions.length === 0) return
    for (const failed of failedReconActions) {
      const reason = failed.source === 'recon' ? reconError : partialReconError
      toast.error(reason || 'No reason was given.', failed.title)
    }
    setFailedReconActions([])
  }, [failedReconActions, reconError, partialReconError, toast])

  // The other scan hooks keep the reason of a failed action synchronously.
  const reportAction = useCallback((result: unknown, lastError: () => string | null, fallback: string) => {
    if (result) return true
    toast.error(lastError() ?? fallback)
    return false
  }, [toast])

  // Pause/Resume/Stop handlers
  const handlePauseRecon = useCallback(async () => {
    if (!await pauseRecon()) reportReconFailure('Recon did not pause', 'recon')
  }, [pauseRecon, reportReconFailure])
  // A resume outside the RoE time window is refused and the scan stays paused;
  // say so, or the button just does nothing. An outage is not a refusal, so the
  // wording leaves the reason (with its code and status) to say which it was.
  const handleResumeRecon = useCallback(async () => {
    if (await resumeRecon()) return
    toast.error(`Resume failed: ${getLastResumeError() ?? 'the scan could not be resumed'}. The scan stays paused.`)
  }, [resumeRecon, getLastResumeError, toast])
  const handleStopRecon = useCallback(async () => {
    if (!await stopRecon()) reportReconFailure('Recon did not stop', 'recon')
  }, [stopRecon, reportReconFailure])
  const handlePauseGvm = useCallback(async () => {
    if (reportAction(await pauseGvm(), getGvmActionError, 'Failed to pause GVM scan')) toast.info('GVM scan paused')
  }, [pauseGvm, getGvmActionError, reportAction, toast])
  const handleResumeGvm = useCallback(async () => {
    if (reportAction(await resumeGvm(), getGvmActionError, 'Failed to resume GVM scan')) toast.info('GVM scan resumed')
  }, [resumeGvm, getGvmActionError, reportAction, toast])
  const handleStopGvm = useCallback(async () => {
    if (reportAction(await stopGvm(), getGvmActionError, 'Failed to stop GVM scan')) toast.info('GVM scan stopped')
  }, [stopGvm, getGvmActionError, reportAction, toast])
  const handlePauseGithubHunt = useCallback(async () => {
    reportAction(await pauseGithubHunt(), getGithubActionError, 'Failed to pause GitHub hunt')
  }, [pauseGithubHunt, getGithubActionError, reportAction])
  const handleResumeGithubHunt = useCallback(async () => {
    reportAction(await resumeGithubHunt(), getGithubActionError, 'Failed to resume GitHub hunt')
  }, [resumeGithubHunt, getGithubActionError, reportAction])
  const handleStopGithubHunt = useCallback(async () => {
    reportAction(await stopGithubHunt(), getGithubActionError, 'Failed to stop GitHub Secret Hunt')
  }, [stopGithubHunt, getGithubActionError, reportAction])
  const handleStopTrufflehog = useCallback(async (source: string) => {
    reportAction(await stopTrufflehog(source), getTrufflehogActionError, 'Failed to stop Secret Multiscanner scan')
  }, [stopTrufflehog, getTrufflehogActionError, reportAction])
  const handlePauseSupplyChain = useCallback(async () => {
    reportAction(await pauseSupplyChain(), getSupplyActionError, 'Failed to pause supply-chain')
  }, [pauseSupplyChain, getSupplyActionError, reportAction])
  const handleResumeSupplyChain = useCallback(async () => {
    reportAction(await resumeSupplyChain(), getSupplyActionError, 'Failed to resume supply-chain')
  }, [resumeSupplyChain, getSupplyActionError, reportAction])
  const handleStopSupplyChain = useCallback(async () => {
    reportAction(await stopSupplyChain(), getSupplyActionError, 'Failed to stop Supply-Chain scan')
  }, [stopSupplyChain, getSupplyActionError, reportAction])

  // Partial Recon handlers
  const handleStopPartialRecon = useCallback(async (runId: string) => {
    if (!await stopPartialRecon(runId)) reportReconFailure('Partial recon did not stop', 'partial')
  }, [stopPartialRecon, reportReconFailure])
  const handleTogglePartialReconLogs = useCallback((runId: string) => {
    setActiveLogsDrawer(prev => prev === `partialRecon:${runId}` ? null : `partialRecon:${runId}`)
  }, [])

  // Emergency Pause All - freezes every running pipeline and agent at once
  const isAnyPipelineRunning = isReconRunning || isGvmRunning || isGithubHuntRunning || isTrufflehogRunning || isAgentRunning || isPartialReconRunning
  const [isEmergencyPausing, setIsEmergencyPausing] = useState(false)

  // Auto-clear the pausing state once all pipelines have actually stopped
  useEffect(() => {
    if (isEmergencyPausing && !isAnyPipelineRunning) {
      setIsEmergencyPausing(false)
    }
  }, [isEmergencyPausing, isAnyPipelineRunning])

  // Whose agent runs a press stops (every user's for an admin, otherwise the person's
  // own), for the tooltip. A failed read leaves it unknown and the tooltip says both.
  const [emergencyStopScope, setEmergencyStopScope] = useState<EmergencyStopScope | undefined>()
  useEffect(() => {
    let live = true
    fetch('/api/agent/emergency-stop-all')
      .then(res => (res.ok ? res.json() : null))
      .then(answer => { if (live && isEmergencyStopScope(answer?.scope)) setEmergencyStopScope(answer.scope) })
      .catch(() => {})
    return () => { live = false }
  }, [])

  const handleEmergencyPauseAll = useCallback(async () => {
    setIsEmergencyPausing(true)
    // Each target answers with the reason it did not stop, or null when it did:
    // the person pressed the emergency button and must learn which scan or agent
    // is still running.
    const tasks: Array<Promise<string | null>> = []
    const viaHook = (label: string, call: Promise<unknown>, lastError: () => string | null) => tasks.push(
      call.then(
        result => result ? null : `${label}: ${lastError() ?? 'no reason given'}`,
        err => `${label}: ${toApiError(err, 'request failed').message}`,
      ),
    )
    let reconFailed = false
    let partialFailed = false
    if (reconState?.status === 'running' || reconState?.status === 'starting') {
      tasks.push(pauseRecon().then(r => { reconFailed = !r; return null }, () => { reconFailed = true; return null }))
    }
    if (gvmState?.status === 'running' || gvmState?.status === 'starting') {
      viaHook('GVM scan', pauseGvm(), getGvmActionError)
    }
    if (githubHuntState?.status === 'running' || githubHuntState?.status === 'starting') {
      viaHook('GitHub Secret Hunt', pauseGithubHunt(), getGithubActionError)
    }
    // TruffleHog has no pause (dropped with the multi-source migration, matching
    // ai_attack): emergency stop stops each live SOURCE.
    for (const run of trufflehogRuns) {
      if (run.status === 'running' || run.status === 'starting') {
        viaHook(`Secret Multiscanner ${run.source ?? ''}`, stopTrufflehog(run.source ?? ''), getTrufflehogActionError)
      }
    }
    for (const run of activePartialRecons) {
      if (run.status === 'running' || run.status === 'starting') {
        tasks.push(stopPartialRecon(run.run_id).then(r => { if (!r) partialFailed = true; return null }, () => { partialFailed = true; return null }))
      }
    }
    // Stop the AI agent runs the person may stop: every user's, or their own.
    let agentSummary: string | null = null
    const agentLabel = agentStopFailureLabel(emergencyStopScope)
    tasks.push(fetch('/api/agent/emergency-stop-all', { method: 'POST' }).then(
      async res => {
        if (!res.ok) return `${agentLabel}: ${(await readApiError(res, 'Failed to stop agents')).message}`
        const answer = await res.json().catch(() => null)
        if (isEmergencyStopScope(answer?.scope)) setEmergencyStopScope(answer.scope)
        agentSummary = agentStopSummary(answer)
        return null
      },
      err => `${agentLabel}: ${toApiError(err, 'Failed to stop agents').message}`,
    ))
    const failures = (await Promise.allSettled(tasks))
      .map(r => r.status === 'fulfilled' ? r.value : `${toApiError(r.reason, 'request failed').message}`)
      .filter((f): f is string => !!f)
    if (failures.length) toast.error(failures.join('; '), 'Emergency pause: not everything stopped')
    if (agentSummary) toast.info(agentSummary)
    // The recon hooks keep their reason for the next render (see reportReconFailure).
    if (reconFailed) reportReconFailure('Emergency pause: recon did not pause', 'recon')
    if (partialFailed) reportReconFailure('Emergency pause: a partial recon did not stop', 'partial')
  }, [reconState?.status, gvmState?.status, githubHuntState?.status, trufflehogRuns, activePartialRecons, pauseRecon, pauseGvm, pauseGithubHunt, stopTrufflehog, stopPartialRecon, getGvmActionError, getGithubActionError, getTrufflehogActionError, reportReconFailure, toast, emergencyStopScope])

  // Show message if no project is selected
  if (!projectLoading && !projectId) {
    return (
      <div className={styles.page}>
        <div className={styles.noProject}>
          <h2>No Project Selected</h2>
          <p>Select a project from the dropdown in the header or create a new one.</p>
          <button className="primaryButton" onClick={() => router.push('/projects')}>
            Go to Projects
          </button>
        </div>
      </div>
    )
  }

  // Reads the raw payload, not the filtered one: a graph whose nodes are all
  // hidden by a filter is not an empty graph.
  const emptyGraphState = resolveEmptyGraphState({
    nodeCount: data?.nodes.length,
    isLoading,
    hasError: !!error,
    reconStatus: reconState?.status || 'idle',
    hasActivePartialRecons: activePartialRecons.length > 0,
    viewingPastVersion: isViewingPastVersion,
    isActivatingVersion,
  })

  // Bound to a name rather than wrapped inline so the provider does not
  // re-indent the whole page.
  const page = (
    <div className={styles.page}>
      <GraphToolbar
        projectId={projectId || ''}
        is3D={is3D}
        showLabels={showLabels}
        onToggle3D={setIs3D}
        onToggleLabels={setShowLabels}
        onToggleAI={handleToggleAI}
        isAIOpen={isAIOpen}
        onOpenFileSystem={toggleFileSystemDrawer}
        isFileSystemOpen={isFileSystemOpen}
        // Target info
        targetLabel={currentProject?.targetLabel || currentProject?.targetDomain}
        scopeLines={(currentProject?.scopeGroups ?? []).map(groupLabel)}
        // Recon props
        onStartRecon={handleStartRecon}
        onPauseRecon={handlePauseRecon}
        onResumeRecon={handleResumeRecon}
        onStopRecon={handleStopRecon}
        onDownloadJSON={handleDownloadJSON}
        onToggleLogs={handleToggleLogs}
        reconStatus={reconState?.status || 'idle'}
        hasReconData={hasReconData}
        reconDataError={dataProbeErrors.recon}
        isLogsOpen={activeLogsDrawer === 'recon'}
        // GVM props
        gvmAvailable={gvmAvailability.available}
        gvmUnavailableReason={gvmAvailability.reason}
        onStartGvm={handleStartGvm}
        onPauseGvm={handlePauseGvm}
        onResumeGvm={handleResumeGvm}
        onStopGvm={handleStopGvm}
        onDownloadGvmJSON={handleDownloadGvmJSON}
        onToggleGvmLogs={handleToggleGvmLogs}
        gvmStatus={gvmState?.status || 'idle'}
        hasGvmData={hasGvmData}
        gvmDataError={dataProbeErrors.gvm}
        isGvmLogsOpen={activeLogsDrawer === 'gvm'}
        scanStatusErrors={[gvmStatusError, githubHuntStatusError, trufflehogStatusError, supplyChainStatusError]}
        // GitHub Hunt props
        onStartGithubHunt={handleStartGithubHunt}
        onPauseGithubHunt={handlePauseGithubHunt}
        onResumeGithubHunt={handleResumeGithubHunt}
        onStopGithubHunt={handleStopGithubHunt}
        onDownloadGithubHuntJSON={handleDownloadGithubHuntJSON}
        onToggleGithubHuntLogs={handleToggleGithubHuntLogs}
        githubHuntStatus={githubHuntState?.status || 'idle'}
        hasGithubHuntData={hasGithubHuntData}
        isGithubHuntLogsOpen={activeLogsDrawer === 'githubHunt'}
        // TruffleHog props: the toolbar only shows whether a source is live;
        // the per-source controls are in the Other Scans modal.
        isTrufflehogRunning={isTrufflehogRunning}
        hasTrufflehogData={hasTrufflehogData}
        // Partial Recon props (multi-run)
        activePartialRecons={activePartialRecons}
        activePartialReconLogsDrawer={activePartialReconRunId}
        onStopPartialRecon={handleStopPartialRecon}
        onTogglePartialReconLogs={handleTogglePartialReconLogs}
        // Other Scans modal
        onToggleOtherScansModal={() => setIsOtherScansModalOpen(prev => !prev)}
        // Stealth mode
        stealthMode={currentProject?.stealthMode}
        // RoE
        engagementLimitsActive={deriveRoeEnabled(currentProject)}
        // Emergency Pause All
        onEmergencyPauseAll={handleEmergencyPauseAll}
        isAnyPipelineRunning={isAnyPipelineRunning}
        isEmergencyPausing={isEmergencyPausing}
        emergencyStopScope={emergencyStopScope}
        tunnelStatus={tunnelStatus}
        // Scan Timeline (version switch)
        scanVersions={scanVersions}
        selectedVersionId={selectedVersionId}
        onSelectVersion={setSelectedVersionId}
        onManageVersions={() => setIsVersionManagerOpen(true)}
        isActivatingVersion={isActivatingVersion}
        viewingPastVersion={isViewingPastVersion}
        // Agent status
        agentActiveCount={agentSummary.activeCount}
        agentConversations={agentSummary.conversations}
      />

      <OtherScansModal
        isOpen={isOtherScansModalOpen}
        onClose={() => setIsOtherScansModalOpen(false)}
        hasReconData={hasReconData}
        hasGithubToken={hasGithubToken}
        // Scan Timeline: past versions are read-only; the raw JSON is latest-only.
        viewingPastVersion={isViewingPastVersion}
        isActivatingVersion={isActivatingVersion}
        // GitHub Hunt
        onStartGithubHunt={handleStartGithubHunt}
        onPauseGithubHunt={handlePauseGithubHunt}
        onResumeGithubHunt={handleResumeGithubHunt}
        onStopGithubHunt={handleStopGithubHunt}
        onDownloadGithubHuntJSON={handleDownloadGithubHuntJSON}
        onToggleGithubHuntLogs={handleToggleGithubHuntLogs}
        githubHuntStatus={githubHuntState?.status || 'idle'}
        githubHuntError={githubHuntState?.error}
        githubHuntStatusError={githubHuntStatusError}
        hasGithubHuntData={hasGithubHuntData}
        githubHuntDataError={dataProbeErrors.githubHunt}
        isGithubHuntLogsOpen={activeLogsDrawer === 'githubHunt'}
        // TruffleHog
        onStartTrufflehog={handleStartTrufflehog}
        onStopTrufflehog={handleStopTrufflehog}
        onDownloadTrufflehogJSON={handleDownloadTrufflehogJSON}
        onToggleTrufflehogLogs={handleToggleTrufflehogLogs}
        trufflehogProfiles={trufflehogProfiles}
        trufflehogProfilesError={trufflehogProfilesError}
        trufflehogRunsBySource={trufflehogRunsBySource}
        trufflehogStatusError={trufflehogStatusError}
        hasTrufflehogData={hasTrufflehogData}
        trufflehogDataError={dataProbeErrors.trufflehog}
        openTrufflehogLogsSource={openTrufflehogLogsSource}
        // Supply Chain (L1)
        onStartSupplyChain={handleStartSupplyChain}
        onPauseSupplyChain={() => { void handlePauseSupplyChain() }}
        onResumeSupplyChain={() => { void handleResumeSupplyChain() }}
        onStopSupplyChain={() => { void handleStopSupplyChain() }}
        onDownloadSupplyChainJSON={handleDownloadSupplyChainJSON}
        onToggleSupplyChainLogs={handleToggleSupplyChainLogs}
        supplyChainStatus={supplyChainState?.status || 'idle'}
        supplyChainError={supplyChainState?.error}
        supplyChainStatusError={supplyChainStatusError}
        hasSupplyChainData={hasSupplyChainData}
        supplyChainDataError={dataProbeErrors.supplyChain}
        projectId={projectId || undefined}
        isSupplyChainLogsOpen={activeLogsDrawer === 'supplyChain'}
      />

      <ViewTabs
        activeView={activeView}
        onViewChange={changeView}
        globalFilter={globalFilter}
        onGlobalFilterChange={setGlobalFilter}
        onExport={handleExportCsv}
        onExportJson={handleExportJson}
        onExportMarkdown={handleExportMarkdown}
        allNodesExporting={allNodesExporting}
        totalRows={effectiveTableRows.length}
        filteredRows={textFilteredCount}
        sessionCount={activeSessions.totalCount}
        tunnelStatus={tunnelStatus}
        dataFilters={dataFilterViews}
        selectedFilterId={selectedFilterId}
        onSelectFilter={setSelectedFilterId}
        onDeleteFilter={handleDeleteFilter}
        tableViewMode={tableViewMode}
        onTableViewModeChange={changeTableViewMode}
        unseenCounts={unseenCounts}
        unseenTotal={unseenTotal}
        nodeFilterStatus={nodeFilterStatus}
        jsReconSearch={jsReconSearch}
        onJsReconSearchChange={setJsReconSearch}
        onJsReconExportCsv={jsReconData ? async () => {
          if (jsReconExporting) return
          setJsReconExporting('csv')
          try { await exportJsReconCsv(jsReconData) } finally { setJsReconExporting(null) }
        } : undefined}
        onJsReconExportJson={jsReconData ? async () => {
          if (jsReconExporting) return
          setJsReconExporting('json')
          try { await exportJsReconJson(jsReconData) } finally { setJsReconExporting(null) }
        } : undefined}
        onJsReconExportMarkdown={jsReconData ? async () => {
          if (jsReconExporting) return
          setJsReconExporting('md')
          try { await exportJsReconMarkdown(jsReconData) } finally { setJsReconExporting(null) }
        } : undefined}
        jsReconExporting={jsReconExporting}
        jsReconMeta={jsReconData ? `${jsReconData.scan_metadata?.js_files_analyzed || 0} files${jsReconData.summary?.validated_keys?.live ? ` | ${jsReconData.summary.validated_keys.live} LIVE` : ''}` : undefined}
        is3D={effectiveIs3D}
        showLabels={showLabels}
        onToggle3D={setIs3D}
        onToggleLabels={setShowLabels}
        renderEnabled={!graphRenderOff}
        onToggleRender={setGraphRenderEnabled}
        nodeCount={displayedNodeCount}
      />

      <div ref={bodyRef} className={styles.body}>
        {activeView === 'graph' && (
          <NodeDrawer
            node={selectedNode}
            isOpen={drawerOpen}
            onClose={clearSelection}
            onDeleteNode={isViewingPastVersion ? undefined : handleDeleteNode}
            expandedChild={expandedChild}
            onExpandChild={expandChild}
            onCollapseChild={collapseChild}
            graphData={data}
            projectName={currentProject?.name}
            targetDomain={currentProject?.targetDomain}
            scopeGroups={isViewingPastVersion ? undefined : currentProject?.scopeGroups}
            onStartAgentSession={isViewingPastVersion ? undefined : handleStartAgentSession}
          />
        )}

        <div ref={contentRef} className={styles.content}>
          {activeView === 'graph' ? (
            graphRenderOff ? (
              <div className={styles.nodeCap}>
                <h2>Graph rendering is off</h2>
                <p>
                  Rendering is usually switched off once a graph has grown large enough that
                  laying it out makes the tab sluggish.
                </p>
                <p>
                  Your data is untouched: open the Node inspector section to browse every
                  node and its properties, or turn rendering back on with the Render switch
                  at the top right.
                </p>
                <button className="primaryButton" onClick={() => setGraphRenderEnabled(true)}>
                  Turn rendering on
                </button>
              </div>
            ) : overNodeCap ? (
              <div className={styles.nodeCap}>
                <h2>Graph too large to render</h2>
                <p>
                  This graph has more than 100,000 nodes. Rendering is disabled to keep your
                  browser responsive. To review the recon data, consult the Node inspector section instead.
                </p>
              </div>
            ) : emptyGraphState ? (
              <GraphEmptyState
                state={emptyGraphState}
                onStartRecon={handleStartRecon}
                onResumeRecon={handleResumeRecon}
              />
            ) : (
              <GraphCanvas
                data={stableGraphData}
                isLoading={filterLoading || isLoading}
                error={error}
                projectId={projectId || ''}
                is3D={effectiveIs3D}
                width={dimensions.width}
                height={dimensions.height}
                showLabels={showLabels}
                selectedNode={selectedNode}
                onNodeClick={handleNodeClick}
                isDark={isDark}
                activeChainId={sessionId}
              />
            )
          ) : activeView === 'graphViews' ? (
            <GraphViews
              projectId={projectId || ''}
              userId={userId || ''}
              modelConfigured={!!currentProject?.agentOpenaiModel}
              is3D={is3D}
              showLabels={showLabels}
              isDark={isDark}
              onFilterCreated={handleFilterCreated}
              onFilterCreatedAndSelect={handleFilterCreatedAndSelect}
            />
          ) : activeView === 'table' ? (
            // F0: the graph map, Node Inspector and All Nodes render the SELECTED
            // version's payload; every analytics/RedZone panel below runs Cypher
            // against the live graph, so it always reflects the ACTIVE version.
            tableViewMode === 'scanSchedule' ? (
              // Schedules + run history are project-level, not version-scoped.
              <ScanScheduleTable projectId={projectId} />
            ) : tableViewMode === 'reconDelta' ? (
              // Recon Delta compares two stored versions, so it works regardless
              // of which version is being viewed.
              <ReconDeltaTable projectId={projectId} versions={scanVersions} isDark={isDark} />
            ) : tableViewMode === 'nodeFilters' ? (
              // The rules are project settings, not version state, so they are
              // editable while a past version is viewed; the view itself refuses
              // "apply to the current graph" then, and says why.
              <NodeFiltersView
                projectId={projectId}
                isViewingPastVersion={isViewingPastVersion}
                viewedVersionLabel={viewedVersion?.label}
                viewedVersionId={viewedVersion?.id ?? null}
                focus={nodeFilterFocus ?? (deepLinkSheet ? { kind: deepLinkSheet } : null)}
                onStatusChange={refreshNodeFilterStatus}
                onGraphChanged={refetchGraph}
              />
            ) : isViewingPastVersion && tableViewMode !== 'nodeDetails' && tableViewMode !== 'all' ? (
              <div className={styles.pastVersionPanel}>
                <ActiveVersionOnlyNotice
                  activeVersionLabel={activeVersion?.label ?? 'the active version'}
                  viewedVersionLabel={viewedVersion?.label ?? 'a saved snapshot'}
                  onOpenManager={() => setIsVersionManagerOpen(true)}
                />
              </div>
            ) : tableViewMode === 'triage' ? (
              // Verdicts and mute state are LIVE, never version-scoped, so this
              // sits BELOW the past-version guard: viewing an old snapshot shows
              // the same "active version only" notice the RedZone panels show,
              // rather than silently rendering current data under an old label.
              <TriageTable
                projectId={projectId}
                onViewMuted={() => { setDeepLinkSheet(null); setTableViewMode('muted') }}
              />
            ) : tableViewMode === 'muted' ? (
              // Mute state is live, like triage, so this also sits below the guard.
              <MutedNodesTable projectId={projectId} onOpenRule={openNodeFilterRule} focus={mutedFocus} />
            ) : tableViewMode === 'nodeDetails' ? (
              <NodeDetailsTable
                data={filterGraphData ?? data}
                isLoading={filterLoading || isLoading}
                error={error}
                projectId={projectId}
              />
            ) : tableViewMode === 'jsRecon' ? (
              <JsReconTable projectId={projectId} search={jsReconSearch} onDataLoaded={setJsReconData} />
            ) : tableViewMode === 'aiSurface' ? (
              <AiSurfaceTable projectId={projectId} />
            ) : tableViewMode === 'aiRisk' ? (
              <AiRiskTable projectId={projectId} initialSheet={deepLinkSheet} />
            ) : tableViewMode === 'killChain' ? (
              <KillChainTable projectId={projectId} />
            ) : tableViewMode === 'blastRadius' ? (
              <BlastRadiusTable projectId={projectId} />
            ) : tableViewMode === 'takeover' ? (
              <TakeoverTable projectId={projectId} />
            ) : tableViewMode === 'secrets' ? (
              <SecretsTable projectId={projectId} />
            ) : tableViewMode === 'netInitAccess' ? (
              <NetInitAccessTable projectId={projectId} />
            ) : tableViewMode === 'graphql' ? (
              <GraphqlLedgerTable projectId={projectId} />
            ) : tableViewMode === 'webInitAccess' ? (
              <WebInitAccessTable projectId={projectId} />
            ) : tableViewMode === 'paramMatrix' ? (
              <ParamMatrixTable projectId={projectId} />
            ) : tableViewMode === 'sharedInfra' ? (
              <SharedInfraTable projectId={projectId} />
            ) : tableViewMode === 'dnsEmail' ? (
              <DnsEmailTable projectId={projectId} />
            ) : tableViewMode === 'threatIntel' ? (
              <ThreatIntelTable projectId={projectId} />
            ) : tableViewMode === 'jsDepSignals' ? (
              <JsDepSignalsTable projectId={projectId} />
            ) : tableViewMode === 'supplyChainSca' ? (
              <SupplyChainScaTable projectId={projectId} initialSheet={deepLinkSheet} />
            ) : tableViewMode === 'dnsDrift' ? (
              <DnsDriftTable projectId={projectId} />
            ) : tableViewMode === 'webCachePoison' ? (
              <WebCachePoisonTable projectId={projectId} />
            ) : tableViewMode === 'routeExposure' ? (
              <RouteExposureTable projectId={projectId} />
            ) : (
              <DataTable
                data={filterGraphData ?? data}
                isLoading={filterLoading || isLoading}
                error={error}
                rows={effectiveTableRows}
                globalFilter={globalFilter}
                onGlobalFilterChange={setGlobalFilter}
                projectId={projectId}
              />
            )
          ) : activeView === 'sessions' ? (
            <ActiveSessions
              sessions={activeSessions.sessions}
              jobs={activeSessions.jobs}
              nonMsfSessions={activeSessions.nonMsfSessions}
              agentBusy={activeSessions.agentBusy}
              isLoading={activeSessions.isLoading}
              error={activeSessions.error}
              projectId={projectId || ''}
              onInteract={activeSessions.interactWithSession}
              onKillSession={activeSessions.killSession}
              onKillJob={activeSessions.killJob}
            />
          ) : activeView === 'terminal' ? (
            <KaliTerminal userId={userId} projectId={projectId} />
          ) : activeView === 'roe' ? (
            <RoeViewer
              projectId={projectId || ''}
              project={fullProject || {}}
            />
          ) : null}
        </div>

      </div>

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'recon'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={reconLogs}
        currentPhase={currentPhase}
        currentPhaseNumber={currentPhaseNumber}
        currentGroup={currentGroup}
        groupNumber={groupNumber}
        totalGroups={totalGroups}
        status={reconState?.status || 'idle'}
        errorMessage={reconState?.error}
        statusError={reconError}
        streamError={reconStreamError}
        onClearLogs={clearLogs}
        onPause={handlePauseRecon}
        onResume={handleResumeRecon}
        onStop={handleStopRecon}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'gvm'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={gvmLogs}
        currentPhase={gvmCurrentPhase}
        currentPhaseNumber={gvmCurrentPhaseNumber}
        status={gvmState?.status || 'idle'}
        errorMessage={gvmState?.error}
        statusError={gvmStatusError}
        streamError={gvmStreamError}
        onClearLogs={clearGvmLogs}
        onPause={handlePauseGvm}
        onResume={handleResumeGvm}
        onStop={handleStopGvm}
        title="GVM Vulnerability Scan Logs"
        totalPhases={GVM_PHASES.length}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'githubHunt'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={githubHuntLogs}
        currentPhase={githubHuntCurrentPhase}
        currentPhaseNumber={githubHuntCurrentPhaseNumber}
        status={githubHuntState?.status || 'idle'}
        errorMessage={githubHuntState?.error}
        statusError={githubHuntStatusError}
        streamError={githubHuntStreamError}
        onClearLogs={clearGithubHuntLogs}
        onPause={handlePauseGithubHunt}
        onResume={handleResumeGithubHunt}
        onStop={handleStopGithubHunt}
        title="GitHub Secret Hunt Logs"
        totalPhases={GITHUB_HUNT_PHASES.length}
      />

      <ReconLogsDrawer
        isOpen={Boolean(openTrufflehogLogsSource)}
        onClose={() => setActiveLogsDrawer(null)}
        logs={trufflehogLogs}
        currentPhase={trufflehogCurrentPhase}
        currentPhaseNumber={trufflehogCurrentPhaseNumber}
        status={openTrufflehogRun?.status || 'idle'}
        errorMessage={openTrufflehogRun?.error}
        statusError={trufflehogStatusError}
        streamError={trufflehogStreamError}
        onClearLogs={clearTrufflehogLogs}
        onStop={() => { if (openTrufflehogLogsSource) void handleStopTrufflehog(openTrufflehogLogsSource) }}
        title={`Secret Multiscanner Logs — ${openTrufflehogLogsSource ?? ''}`}
        totalPhases={TRUFFLEHOG_PHASES.length}
      />

      <ReconLogsDrawer
        isOpen={activeLogsDrawer === 'supplyChain'}
        onClose={() => setActiveLogsDrawer(null)}
        logs={supplyChainLogs}
        currentPhase={null}
        currentPhaseNumber={null}
        status={supplyChainState?.status || 'idle'}
        errorMessage={supplyChainState?.error}
        statusError={supplyChainStatusError}
        streamError={supplyChainStreamError}
        onClearLogs={clearSupplyChainLogs}
        onPause={() => { void handlePauseSupplyChain() }}
        onResume={() => { void handleResumeSupplyChain() }}
        onStop={() => { void handleStopSupplyChain() }}
        title="Supply Chain Scanner Logs"
        totalPhases={1}
      />

      {allPartialReconRuns.map(run => (
        <ReconLogsDrawer
          key={run.run_id}
          isOpen={activeLogsDrawer === `partialRecon:${run.run_id}`}
          onClose={() => setActiveLogsDrawer(null)}
          logs={partialReconLogsMap[run.run_id] || []}
          currentPhase={WORKFLOW_TOOLS.find(t => t.id === run.tool_id)?.label || run.tool_id || null}
          currentPhaseNumber={partialReconPhaseMap[run.run_id]?.phaseNumber || null}
          status={(run.status as ReconStatus) || 'idle'}
          errorMessage={run.error}
          statusError={partialReconError}
          streamError={activePartialReconRunId === run.run_id ? partialReconStreamError : null}
          onClearLogs={() => clearPartialReconLogsForRun(run.run_id)}
          onStop={() => handleStopPartialRecon(run.run_id)}
          title={`Partial Recon: ${WORKFLOW_TOOLS.find(t => t.id === run.tool_id)?.label || 'Running'}`}
          totalPhases={PARTIAL_RECON_TOTAL_PHASES}
          hidePhaseProgress
        />
      ))}

      <AgentDrawer
        isOpen={isAIOpen}
        onClose={handleCloseAI}
        userId={userId || ''}
        projectId={projectId || ''}
        sessionId={sessionId || ''}
        onResetSession={resetSession}
        onSwitchSession={switchSession}
        modelName={currentProject?.agentOpenaiModel}
        onModelChange={handleModelChange}
        toolPhaseMap={currentProject?.agentToolPhaseMap}
        stealthMode={currentProject?.stealthMode}
        onToggleStealth={handleToggleStealth}
        onRefetchGraph={refetchGraph}
        isOtherChainsHidden={isOtherChainsHidden}
        onToggleOtherChains={handleToggleOtherChains}
        hasOtherChains={sessionChainIds.length > 1 || (sessionChainIds.length === 1 && sessionChainIds[0] !== sessionId)}
        requireToolConfirmation={currentProject?.agentRequireToolConfirmation ?? true}
        graphViewCypher={selectedFilterCypher}
        onOpenFileSystem={toggleFileSystemDrawer}
        pendingNodeQuery={pendingNodeQuery}
        onPendingNodeQueryConsumed={handlePendingNodeQueryConsumed}
      />

      <FileSystemDrawer
        isOpen={isFileSystemOpen}
        onClose={() => setIsFileSystemOpen(false)}
        projectId={projectId || ''}
      />

      <ReconConfirmModal
        isOpen={isReconModalOpen && !reconRefused}
        onClose={() => setIsReconModalOpen(false)}
        onConfirm={handleConfirmRecon}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetDomain || 'Unknown'}
        ipMode={currentProject?.ipMode}
        targetIps={currentProject?.targetIps}
        batchGroups={currentProject?.domainBatchMode ? currentProject.scopeGroups : undefined}
        stats={graphStats}
        isLoading={isReconLoading}
        currentVersionLabel={activeVersion?.label ?? null}
      />

      <VersionManager
        isOpen={isVersionManagerOpen}
        onClose={() => setIsVersionManagerOpen(false)}
        projectId={projectId || ''}
        versions={scanVersions}
        onChanged={refreshScanVersions}
        onActivated={() => { refetchFresh(); refetchGraph() }}
        selectedVersionId={selectedVersionId}
        onSelectVersion={setSelectedVersionId}
        liveScanStatus={reconState?.status}
      />

      <GvmConfirmModal
        isOpen={isGvmModalOpen && !gvmRefused}
        onClose={() => setIsGvmModalOpen(false)}
        onConfirm={handleConfirmGvm}
        projectName={currentProject?.name || 'Unknown'}
        targetDomain={currentProject?.targetLabel || currentProject?.targetDomain || currentProject?.targetIps?.join(', ') || 'Unknown'}
        stats={gvmStats}
        isLoading={isGvmLoading}
        // Only the start's own failure: the status poll and pause/stop have their
        // own surfaces, and their errors here read as a reason not to start.
        error={gvmConfirmAttempted ? gvmStartError : null}
      />

      <GitHubStarBanner hasAttackChain={(graphStats?.nodesByType?.['AttackChain'] ?? 0) > 0} />

      <PageBottomBar
        data={effectiveBarData ?? undefined}
        is3D={is3D}
        showLabels={showLabels}
        activeView={activeView}
        tableViewMode={tableViewMode}
        activeNodeTypes={activeNodeTypes}
        nodeTypeCounts={effectiveNodeTypeCounts}
        onToggleNodeType={handleToggleNodeType}
        onSelectAllTypes={handleSelectAllTypes}
        onClearAllTypes={handleClearAllTypes}
        sessionChainIds={sessionChainIds}
        sessionTitles={sessionTitles}
        hiddenSessions={hiddenSessions}
        onToggleSession={handleToggleSession}
        onShowAllSessions={handleShowAllSessions}
        onHideAllSessions={handleHideAllSessions}
      />
    </div>
  )

  return (
    <MuteNodeProvider
      projectId={projectId}
      readOnly={isViewingPastVersion}
      onViewMuted={viewMutedNodes}
      onGraphChanged={refetchGraph}
      onOpenMuteRules={openMuteRulesKind}
    >
      {page}
    </MuteNodeProvider>
  )
}

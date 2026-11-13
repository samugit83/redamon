/**
 * The project as the header, the selector, the cards and the dashboards hold it.
 *
 * Built in one place, from a full project read or a list row, so every surface
 * names the same target. A batch project's targetDomain is EMPTY: its scope is
 * the scope groups derived from domainBatchHosts, never the stored legacy
 * domainBatchGroups record.
 */
import { type ScopeGroup, resolveScopeGroups, scopeSummary } from '@/lib/scopeGroups'
import { ipHostnameModeLabel } from '@/lib/ipHostnameModeLabels'
import type { MyAccess } from '@/lib/authz/projectAccess'

export interface ProjectSummary {
  id: string
  name: string
  targetDomain: string
  ipMode?: boolean
  targetIps?: string[]
  domainBatchMode?: boolean
  /** IP mode: the hostname policy, absent when the read did not carry it (absent
   *  is unknown, never "IP only"). */
  ipHostnameMode?: string
  ipHostnameInclude?: string[]
  ipHostnameExclude?: string[]
  ipHostnameScanAllConfirmed?: boolean
  /** Empty in IP mode, and when the read carried no scope fields. */
  scopeGroups?: ScopeGroup[]
  /** One line naming the target, for cards and headers. */
  targetLabel?: string
  subdomainList?: string[]
  description?: string
  agentOpenaiModel?: string
  agentToolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  agentRequireToolConfirmation?: boolean
  /** The three columns the engagement-limit derivation reads. Never the flag. */
  roeGlobalMaxRps?: number
  roeExcludedHosts?: string[]
  roeTimeWindowEnabled?: boolean
  /** The person's own access, when the read carried it (RBAC_SHARING_ENABLED on, step 4.3); absent
   *  is the person's own project as before sharing (DV-30). The read-only screens read it (4.11). */
  myAccess?: MyAccess
  createdAt: string
  updatedAt: string
}

/** The scope fields a project read may carry; a list row carries fewer. */
export interface ScopeLabelFields {
  targetDomain?: string | null
  ipMode?: boolean | null
  targetIps?: readonly string[] | null
  domainBatchMode?: boolean | null
  domainBatchHosts?: readonly string[] | null
  subdomainList?: readonly string[] | null
  ipHostnameMode?: string | null
  /** As GET /api/projects/[id] returns them. */
  scopeGroups?: unknown
}

/** The project's scope groups: the server's derivation when the read carries it,
 *  else derived here from the host list; empty when neither is present. */
export function summaryScopeGroups(p: ScopeLabelFields): ScopeGroup[] {
  if (p.ipMode) return []
  if (Array.isArray(p.scopeGroups)) return p.scopeGroups as ScopeGroup[]
  const derivable = p.domainBatchMode ? p.domainBatchHosts != null : p.subdomainList != null
  return derivable ? resolveScopeGroups(p).groups : []
}

/** The typed target for a single domain, the scope summary for a batch, the
 *  address count in IP mode (with the hostname mode when the read carries it);
 *  '' when the read does not say. */
export function projectTargetLabel(p: ScopeLabelFields): string {
  if (p.ipMode) {
    const n = (p.targetIps ?? []).length
    if (!n) return ''
    const count = `${n} IP target${n === 1 ? '' : 's'}`
    return typeof p.ipHostnameMode === 'string' ? `${count} · ${ipHostnameModeLabel(p.ipHostnameMode)}` : count
  }
  if (p.domainBatchMode) return scopeSummary(summaryScopeGroups(p)) || 'Domain batch'
  return String(p.targetDomain ?? '').trim()
}

/** A project read (the GET, a list row, a saved row) as toProjectSummary takes it. */
export type ProjectRead = ScopeLabelFields & {
  id: string
  name: string
  description?: string | null
  agentOpenaiModel?: string
  agentToolPhaseMap?: unknown
  stealthMode?: boolean
  agentRequireToolConfirmation?: boolean
  roeGlobalMaxRps?: number
  roeExcludedHosts?: string[]
  roeTimeWindowEnabled?: boolean
  myAccess?: MyAccess | null
  ipHostnameInclude?: readonly string[] | null
  ipHostnameExclude?: readonly string[] | null
  ipHostnameScanAllConfirmed?: boolean | null
  createdAt?: string | Date | null
  updatedAt?: string | Date | null
}

function phaseMap(value: unknown): Record<string, string[]> | undefined {
  if (typeof value !== 'string') return (value ?? undefined) as Record<string, string[]> | undefined
  try {
    return JSON.parse(value)
  } catch {
    return undefined
  }
}

function isoString(value: string | Date | null | undefined): string {
  if (!value) return ''
  return value instanceof Date ? value.toISOString() : String(value)
}

export function toProjectSummary(project: ProjectRead): ProjectSummary {
  const groups = summaryScopeGroups(project)
  return {
    id: project.id,
    name: project.name,
    targetDomain: String(project.targetDomain ?? ''),
    ipMode: project.ipMode ?? undefined,
    targetIps: project.targetIps ? [...project.targetIps] : undefined,
    domainBatchMode: project.domainBatchMode ?? undefined,
    ...(typeof project.ipHostnameMode === 'string' ? { ipHostnameMode: project.ipHostnameMode } : {}),
    ...(project.ipHostnameInclude ? { ipHostnameInclude: [...project.ipHostnameInclude] } : {}),
    ...(project.ipHostnameExclude ? { ipHostnameExclude: [...project.ipHostnameExclude] } : {}),
    ...(typeof project.ipHostnameScanAllConfirmed === 'boolean'
      ? { ipHostnameScanAllConfirmed: project.ipHostnameScanAllConfirmed } : {}),
    scopeGroups: groups,
    targetLabel: projectTargetLabel(project),
    subdomainList: project.subdomainList ? [...project.subdomainList] : undefined,
    description: project.description || undefined,
    agentOpenaiModel: project.agentOpenaiModel,
    agentToolPhaseMap: phaseMap(project.agentToolPhaseMap),
    stealthMode: project.stealthMode,
    agentRequireToolConfirmation: project.agentRequireToolConfirmation,
    roeGlobalMaxRps: project.roeGlobalMaxRps,
    roeExcludedHosts: project.roeExcludedHosts,
    roeTimeWindowEnabled: project.roeTimeWindowEnabled,
    ...(project.myAccess ? { myAccess: project.myAccess } : {}),
    createdAt: isoString(project.createdAt),
    updatedAt: isoString(project.updatedAt),
  }
}

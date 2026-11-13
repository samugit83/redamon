/**
 * update_project_scope: change an EXISTING project's target lists.
 *
 * Scope was create-only on this surface for every token. This reopens exactly
 * the target lists the project form already lets a person edit after creation -
 * a batch project's host list, the standalone scanners' targets and an IP
 * project's hostname policy (which names on its addresses are recorded or
 * scanned) - and nothing else. The target domain, the address list, the
 * targeting mode, ownership verification and the target guardrail stay refused
 * whatever the token holds (the registry's `rescope` attribute is the list).
 *
 * The controls, in the order they run:
 *  - its own permission, never auto-ticked by any profile;
 *  - refused while anything reads or writes the graph: the in-app agent reads
 *    the batch groups every turn, and the scanners read their targets at spawn;
 *  - every value validated, every batch host and root through the permanent
 *    guardrail and, unless the project switched it off, the soft (LLM) one,
 *    the batch grouping re-derived here and never taken from a caller;
 *  - on a third-party engagement a WIDENING must arrive with an authorization
 *    record, written in the same transaction, and passing one needs
 *    engagement:authorize as well;
 *  - a compare-and-swap on `updatedAt`, and an audit row with every before/after;
 *  - a batch that gains hosts, or a hostname policy that widens, pauses the
 *    project's scan schedules in the same transaction, so no unattended run
 *    reaches the new hosts before a person has looked at them;
 *  - an active login recording is re-pointed at the new scope;
 *  - a hostname policy that narrows marks the names earlier runs scanned and it
 *    no longer admits, after the commit (`hostnamePolicyMarked`).
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { validateDomainBatch } from '@/lib/domainBatch'
import {
  IP_HOSTNAME_FIELDS, type ScopeFields, type ScopeGroup, ipHostnameIncludeBases, ipHostnamePolicyNarrowed,
  ipHostnameWidenings, isScopeWidening, resolveScopeGroups, sameScope, scopeGuardrailNames, scopeSignature,
  softGuardrailNames,
} from '@/lib/scopeGroups'
import { markOutOfPolicy } from '@/lib/ipHostnamePolicy'
import { refreshActiveRecordingScope } from '@/lib/recordingSession'
import { activationBusy } from '@/lib/activationLock'
import { ACTIVATION_STATE_TRANSFERRING, TRANSFER_IN_PROGRESS_MESSAGE, holdOf } from '@/lib/graphHold'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { seedDomainNames, seedProjectDomains } from '@/lib/graphSeedDomains'
import { LEGACY_GRAPH_MESSAGE, legacyGraphDomains } from '@/lib/legacyGraph'
import { McpLevelDenied, mcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { assertReadableSelect } from '@/lib/mcpReadableFields'
import { auditableKey, filterReconSettings } from '@/lib/reconSettings/filter'
import { rescopableFields } from '@/lib/reconSettings/registry'
import { validateCrossFieldRules } from '@/lib/reconSettings/crossField'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import {
  normaliseAuthorization, refuseHardBlocked, softGuardrailRefusal, type AuthorizationArgs,
} from '@/lib/mcp/engagementTools'
import {
  busyHint, casVersion, countQueuedJobsNeedingReview, describeAffectedSchedules, refuseSettingsChange,
} from '@/lib/mcp/writeTools'

export interface UpdateProjectScopeArgs {
  projectId: string
  changes: Record<string, unknown>
  authorization?: AuthorizationArgs
  expectedUpdatedAt?: string
}

type Row = Record<string, unknown> & {
  updatedAt: Date
  engagementKind: string
  domainBatchMode: boolean
  domainBatchHosts: unknown
  domainBatchGroups: unknown
}

const batchScope = (hosts: unknown) => resolveScopeGroups({
  domainBatchMode: true,
  domainBatchHosts: Array.isArray(hosts) ? hosts.filter((h): h is string => typeof h === 'string') : [],
}).groups

/**
 * How many entries this change adds to what the batch admits; 0 unless it is a
 * widening by containment (D-21): a narrowing, a reorder or a regroup of the
 * same hosts adds nothing, a seed under an enumerated root adds nothing.
 * Both sides are derived from host lists, never from a stored group record.
 */
function batchEntriesAdded(row: Row, data: Record<string, unknown>): number {
  if (!('domainBatchHosts' in data)) return 0
  const before = batchScope(row.domainBatchHosts)
  const after = batchScope(data.domainBatchHosts)
  if (!isScopeWidening(before, after)) return 0
  const known = scopeSignature(before)
  return Math.max(1, [...scopeSignature(after)].filter(x => !known.has(x)).length)
}

const scanRootsOf = (groups: readonly ScopeGroup[]) => new Set(groups.map(g => g.scanRoot))

const repoSet = (v: unknown) => new Set(
  String(v ?? '').split(',').map(r => r.trim().toLowerCase()).filter(Boolean)
)

const text = (v: unknown) => String(v ?? '').trim().toLowerCase()

/**
 * What this change adds to what the engagement can reach, in words, or an
 * empty list. Removals, a narrower GitHub repository list and the GVM strategy
 * are not widenings.
 */
function wideningsOf(row: Row, data: Record<string, unknown>): string[] {
  const out: string[] = []
  const added = batchEntriesAdded(row, data)
  if (added > 0) out.push(`the batch gains ${added} host or wildcard entr${added === 1 ? 'y' : 'ies'}`)
  if ('githubTargetOrg' in data && text(data.githubTargetOrg) && text(data.githubTargetOrg) !== text(row.githubTargetOrg)) {
    out.push('the GitHub hunt points at a different organisation')
  }
  if ('githubTargetRepos' in data) {
    const before = repoSet(row.githubTargetRepos)
    const after = repoSet(data.githubTargetRepos)
    // An empty list means EVERY repository, so emptying it is the widest move.
    if ((after.size === 0 && before.size > 0) || [...after].some(r => before.size > 0 && !before.has(r))) {
      out.push('the GitHub hunt covers more repositories')
    }
  }
  if ('supplyChainOrgName' in data && text(data.supplyChainOrgName) && text(data.supplyChainOrgName) !== text(row.supplyChainOrgName)) {
    out.push('the supply-chain scan points at a different organisation')
  }
  if ('supplyChainRepoUrl' in data && text(data.supplyChainRepoUrl) && text(data.supplyChainRepoUrl) !== text(row.supplyChainRepoUrl)) {
    out.push('the supply-chain scan points at a different repository')
  }
  out.push(...hostnameWideningsOf(row, data))
  return out
}

/** The hostname-policy half of wideningsOf (design §9): a move towards scan_all,
 *  an include entry added, an exclude entry removed, passive expansion turned on,
 *  a cap raised. ip_only -> record_only adds lookups, not target traffic. */
function hostnameWideningsOf(row: Row, data: Record<string, unknown>): string[] {
  if (!IP_HOSTNAME_FIELDS.some(k => k in data)) return []
  return ipHostnameWidenings(row as ScopeFields, { ...row, ...data } as ScopeFields)
}

export async function updateProjectScope(ctx: McpContext, args: UpdateProjectScopeArgs) {
  requireScope(ctx.token, 'project:rescope')
  // Recording what authorized a widening is its own durable claim.
  if (args.authorization !== undefined) requireScope(ctx.token, 'engagement:authorize')
  // project:rescope (M): a co-owner narrows, widening is the owner's (classifyChange), and the
  // `authorization` argument stays the owner's below.
  const { project: { userId: owner }, access } = await mcpProjectAccess(ctx.token, args.projectId, 'M')
  // What authorized a wider scope is the owner's to record (OQ-23), whatever level reaches the rest.
  if (args.authorization !== undefined && access.level !== 'owner') {
    throw new McpLevelDenied("Recording an engagement authorization is the project owner's. Nothing was written.")
  }
  enforceRate(ctx, 'write')

  const busy = await describeLiveGraphWriters(args.projectId)
  if (busy) {
    throw new McpToolError(
      `Cannot change this project's targets while ${busy}: the work in progress read its targets ` +
      'when it started and would report on a scope that no longer exists. ' +
      busyHint(busy),
      'busy'
    )
  }

  const filtered = filterReconSettings(args.changes, { mode: 'rescope', projectId: args.projectId })
  if (!filtered.ok) {
    throw new McpToolError(filtered.error, 'setting_rejected', { rejectedKey: auditableKey(filtered.key) })
  }

  const select = {
    ...Object.fromEntries(rescopableFields().map(f => [f.key, true])),
    engagementKind: true, domainBatchMode: true, domainBatchHosts: true, domainBatchGroups: true, updatedAt: true,
    // Not changed here; read for the soft guardrail and the recording scope, and
    // ipMode because the hostname policy applies only to an IP project.
    targetGuardrailEnabled: true, roeExcludedHosts: true, ipMode: true,
    activationState: true, activationStartedAt: true,
  }
  assertReadableSelect(select, 'update_project_scope')
  const row = await prisma.project.findUnique({ where: { id: args.projectId }, select }) as Row | null
  if (!row) throw new McpToolError('Project not found', 'not_found')
  // The project changes owner meanwhile (step 5.12): its scope waits for the transfer to end.
  if (holdOf(row as { activationState?: string; activationStartedAt?: Date | null }) === ACTIVATION_STATE_TRANSFERRING) {
    throw new McpToolError(TRANSFER_IN_PROGRESS_MESSAGE, 'project_transfer_in_progress')
  }

  const data: Record<string, unknown> = { ...filtered.data }
  let addedRoots: string[] = []
  let removedRoots: string[] = []
  if ('domainBatchHosts' in data) {
    if (row.domainBatchMode !== true) {
      throw new McpToolError(
        'domainBatchHosts is the host list of a domain-batch project, and this project is not one. ' +
        'Its targeting mode is fixed at creation.',
        'setting_rejected', { rejectedKey: 'domainBatchHosts' }
      )
    }
    const batch = validateDomainBatch(data.domainBatchHosts as string[])
    if (!batch.ok) throw new McpToolError(batch.errors.join(' '), 'setting_rejected', { rejectedKey: 'domainBatchHosts' })
    // Scan roots, both sides derived from host lists: a legacy stored record
    // grouped under `co.uk` is not a removed root of a row now under acme.co.uk.
    const before = scanRootsOf(batchScope(row.domainBatchHosts))
    const after = scanRootsOf(batch.groups)
    addedRoots = [...after].filter(r => !before.has(r)).sort()
    removedRoots = [...before].filter(r => !after.has(r)).sort()
    // Every host and root this project would scan, not only the new ones: a
    // name that joined the permanent blocklist since it was added must not ride
    // along, and a host under a government name must not hide behind its root.
    refuseHardBlocked(scopeGuardrailNames({
      domainBatchMode: true, domainBatchHosts: data.domainBatchHosts as string[],
    }))
    // The grouping is the scope every reader uses, so it is derived here from
    // the host list and never accepted from a caller.
    data.domainBatchHosts = batch.entries
    data.domainBatchGroups = batch.legacy
  }

  // The hostname include entries are names a run may scan: the permanent
  // guardrail refuses them as it refuses a batch host.
  if ('ipHostnameInclude' in data) refuseHardBlocked(ipHostnameIncludeBases(data.ipHostnameInclude as string[]))

  const effective: Record<string, unknown> = { ...row, ...data }
  const crossField = await validateCrossFieldRules(effective, Object.keys(data), ctx.token.userId)
  if (crossField) throw new McpToolError(crossField, 'setting_rejected')
  // The rule stores the policy normalized: canonical filter entries, and no
  // scan_all confirmation left behind when the mode moves away from scan_all.
  for (const key of IP_HOSTNAME_FIELDS) {
    if (key in data || JSON.stringify(effective[key] ?? null) !== JSON.stringify(row[key] ?? null)) {
      data[key] = effective[key]
    }
  }

  // A collaborator's change judged as the project form's save judges it; the derived grouping and
  // the normalized policy columns follow the list and mode the caller changed, which decide.
  refuseSettingsChange(row, data, access, 'project:rescope')

  const widenings = wideningsOf(row, data)
  if (widenings.length > 0 && row.engagementKind === 'third_party' && args.authorization === undefined) {
    throw new McpToolError(
      `This widens a third-party engagement (${widenings.join('; ')}), which needs a record of what ` +
      'authorized the wider scope. Pass `authorization` with the new scope document\'s digest; that ' +
      'also needs the engagement:authorize permission. Nothing was written.',
      'authorization_required'
    )
  }
  const authorization = args.authorization !== undefined ? normaliseAuthorization(args.authorization) : null

  const changed = Object.keys(data)
  if (changed.every(k => JSON.stringify(row[k] ?? null) === JSON.stringify(data[k] ?? null)) && !authorization) {
    throw new McpToolError('Nothing to change: the project already holds these values.', 'bad_args')
  }

  // A version activation swaps the graph out and back; a scope written between
  // its clear and its restore would describe neither graph. The hostname policy
  // decides which restored names count as scanned, so it waits too.
  const policyTouched = IP_HOSTNAME_FIELDS.some(k => k in data)
  if (('domainBatchHosts' in data || policyTouched) && await activationBusy(args.projectId)) {
    throw new McpToolError(
      'A version activation is in progress for this project. Nothing was written; retry once it finishes.',
      'busy'
    )
  }

  // A rewrite of the derived record alone (a legacy row re-saved with the same
  // hosts) is not a scope change and must not read as one in the activity feed.
  const regroupOnly = 'domainBatchHosts' in data
    && sameScope(batchScope(row.domainBatchHosts), batchScope(data.domainBatchHosts))
  const batchRescoped = 'domainBatchHosts' in data && !regroupOnly

  // Every scope change, as the project form's save does: the soft guardrail
  // judges the whole new scope, a narrowing included.
  if (batchRescoped && row.targetGuardrailEnabled !== false) {
    const refusal = await softGuardrailRefusal({
      targetDomains: softGuardrailNames(batchScope(data.domainBatchHosts)),
      userId: ctx.token.userId,
    })
    if (refusal) throw new McpToolError(`Target blocked by the guardrail: ${refusal}`, 'target_blocked')
  }

  const version = casVersion(row.updatedAt, args.expectedUpdatedAt)
  const batchGained = batchEntriesAdded(row, data) > 0
  const hostnamesWidened = hostnameWideningsOf(row, data).length > 0
  const { authorizationId, paused } = await prisma.$transaction(async tx => {
    const { count } = await tx.project.updateMany({
      where: { id: args.projectId, updatedAt: version },
      data: { ...data, updatedById: ctx.token.userId } as never,
    })
    if (count === 0) {
      throw new McpToolError(
        'The project changed since this call read it. Nothing was written; read it again and retry.',
        'conflict'
      )
    }
    // A scheduled run is a full recon that nobody watches start. Only the batch
    // and the hostname policy pause them: the GitHub and supply-chain targets
    // are never read by a scheduled run, and a narrowing takes nothing new.
    const paused = batchGained || hostnamesWidened
      ? await tx.scanSchedule.findMany({
          where: { projectId: args.projectId, enabled: true },
          select: { id: true, label: true },
        })
      : []
    if (paused.length > 0) {
      await tx.scanSchedule.updateMany({
        where: { id: { in: paused.map(s => s.id) }, enabled: true },
        data: { enabled: false },
      })
    }
    if (!authorization) return { authorizationId: null, paused }
    const created = await tx.engagementAuthorization.create({
      data: {
        projectId: args.projectId,
        ...authorization,
        recordedVia: 'mcp',
        recordedByTokenId: ctx.token.tokenId,
        recordedByUserId: ctx.token.userId,
      },
      select: { id: true },
    })
    return { authorizationId: created.id, paused }
  })
  const pausedSchedules = { count: paused.length, names: paused.map(s => s.label || s.id) }

  // A narrowed hostname policy marks the names earlier runs scanned that it no
  // longer admits (design §6.3). After the commit and best-effort: every reader
  // re-applies the current policy, so a failure leaves only the graph behind.
  let hostnamePolicyMarked: boolean | undefined
  if (policyTouched && ipHostnamePolicyNarrowed(row as ScopeFields, { ...row, ...data } as ScopeFields)) {
    try {
      hostnamePolicyMarked = await markOutOfPolicy(args.projectId, owner, { ...row, ...data } as ScopeFields)
    } catch (e) {
      console.warn('[mcp] update_project_scope: hostname policy marker failed:', e)
      hostnamePolicyMarked = false
    }
  }

  // After the commit, and best-effort: the partial-recon picker lists Domain
  // nodes, so a new root without one could not be scanned on its own.
  // The graph's tenant is the project's owner as mcpProjectAccess
  // answered it; the row's own userId is not an MCP-readable column.
  // Seeding attaches to Domain nodes too, so on a graph built under the old
  // scope model (§4.11.6) it waits for the full recon that rebuilds it.
  const legacyGraph = addedRoots.length > 0
    ? (await legacyGraphDomains(owner, args.projectId, batchScope(data.domainBatchHosts))) ?? []
    : []
  // The orgs of the added scan roots: the graph names its Domain after the org.
  const addedOrgs = seedDomainNames(
    batchScope(data.domainBatchHosts).filter(g => addedRoots.includes(g.scanRoot)))
  const graphSeeded = legacyGraph.length === 0
    && await seedProjectDomains(addedOrgs, owner, args.projectId)

  const recordingScopeUpdated = batchRescoped && await refreshActiveRecordingScope(prisma, args.projectId, {
    domainBatchMode: true,
    domainBatchHosts: data.domainBatchHosts as string[],
    roeExcludedHosts: Array.isArray(row.roeExcludedHosts) ? row.roeExcludedHosts as string[] : [],
  })

  const shown = changed.filter(k => k !== 'domainBatchGroups')
  const audited = regroupOnly ? shown : changed
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.update_project_scope',
    targetType: 'project',
    targetId: args.projectId,
    before: Object.fromEntries(audited.map(k => [k, row[k] ?? null])),
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      changes: Object.fromEntries(audited.map(k => [k, data[k] ?? null])),
      widenings,
      authorizationId,
      authorizationDigest: authorization?.documentSha256 ?? null,
      graphSeeded,
      pausedScheduleIds: paused.map(s => s.id),
    },
    source: 'mcp',
  })

  const [queuedJobsNeedingReview, affectedSchedules] = await Promise.all([
    countQueuedJobsNeedingReview(args.projectId),
    describeAffectedSchedules(args.projectId),
  ])

  return {
    projectId: args.projectId,
    changes: shown.map(k => ({ key: k, before: row[k] ?? null, after: data[k] ?? null })),
    addedRoots,
    removedRoots,
    widenings,
    authorizationId,
    queuedJobsNeedingReview,
    pausedSchedules,
    affectedSchedules,
    graphSeeded,
    legacyGraph,
    recordingScopeUpdated,
    ...(hostnamePolicyMarked === undefined ? {} : { hostnamePolicyMarked }),
    note:
      (graphSeeded ? '' : "The new registrable domains' Domain nodes could not be added to the graph yet; the next full recon adds them. ") +
      (legacyGraph.length > 0 ? `${LEGACY_GRAPH_MESSAGE} (old domain nodes: ${legacyGraph.join(', ')}). ` : '') +
      (pausedSchedules.count > 0
        ? `${batchGained ? 'The batch gained hosts' : 'The hostname policy widened'}, so ` +
          `${pausedSchedules.count} scheduled scan(s) were paused; a person ` +
          're-enables them in the Scans tab once they have reviewed the new scope. '
        : '') +
      (hostnamePolicyMarked === false
        ? 'The hostnames earlier runs scanned and the narrower policy no longer admits could not be ' +
          'marked out_of_policy in the graph; every reader still applies the current policy, so none ' +
          'of them is treated as a target. '
        : '') +
      'The change applies to the NEXT scan. Call preflight_scope_check and report what it says.',
  }
}

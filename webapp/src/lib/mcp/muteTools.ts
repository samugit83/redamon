/**
 * Mute and unmute over MCP: hiding a finding, and bringing one back.
 *
 * THIS REVERSES A DELIBERATE RULE. The surface was built on "only a person
 * mutes or unmutes", because a mute makes a finding invisible to every read -
 * the graph views, the reports, RedAmon's own agent and every tool here - and
 * "this is a false positive, mute it" is an entirely plausible injection
 * against an agent whose context is full of target-controlled text. That rule
 * is what bounded a prompt injection to "mislabel a verdict a human can
 * overrule".
 *
 * What replaces it is enforced in code, not in the tool descriptions, which an
 * injected agent will not read charitably:
 *
 *  - an opt-in permission (`triage:mute`) no profile ever ticks;
 *  - evidence guards in the graph write, under the node's lock: a proven
 *    finding and one a person brought back (it has an exemption) are refused;
 *  - no mute is ever overwritten, whoever made it;
 *  - a rule mute is released only on an explicit flag, and never while a recon
 *    scan is running (its end-of-scan sweep read the exemptions when it began);
 *  - a reason on every mute, a per-call cap and a per-token rate limit. There
 *    is no cap on the total: what an agent hid is bounded by review, below;
 *  - provenance that is READ, not just written: `muted_channel` / `muted_token`
 *    split agent mutes from people's in Muted Nodes, the report and here, so
 *    they can be reviewed and reverted per token;
 *  - busy checks that fail closed, and an unknown outcome that says so rather
 *    than "unavailable", because a lost answer to a write may have committed.
 *
 * `set_finding_verdict` still refuses a muted finding, and now for a narrower
 * reason: so that `triage:write` alone can never release a rule mute.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { activationBusy } from '@/lib/activationLock'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { describeScanWriters } from '@/lib/graphWriters'
import { invalidateCache } from '@/app/api/graph/cache'
import { auditUnmute, ensureExemptions, removeExemptions, type ExemptionPair } from '@/lib/unmuteExemptions'
import {
  annotateMutedFacets,
  loadMutedRuleDoc,
  mutedViaOf,
  MUTED_TOKEN_PATTERN,
} from '@/lib/nodeFilters/mutedAnnotate'
import { describeMutedBy, liveRuleMutedBy } from '@/lib/nodeFilters/model'
import { McpToolError } from '@/lib/mcp/errors'
import {
  listMutedPage,
  muteMany,
  mutedFacets,
  resolveMuted,
  unmuteMany,
  type MuteManyItem,
  type TriageFinding,
} from '@/lib/mcp/triageGraph'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

export const MUTE_MAX_REFS = 5000
export const UNMUTE_MAX_REFS = 5000
export const MUTE_REASON_MIN = 3
export const MUTE_REASON_MAX = 500

export const SEARCH_DEFAULT_LIMIT = 50
export const SEARCH_MAX_LIMIT = 100
/**
 * Every page runs the exact count and a full sort of the filtered set, so a
 * deep offset is paid on every call. Past this, narrow with a filter instead.
 */
export const SEARCH_MAX_OFFSET = 10_000

export const FINDING_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/
export const NODE_ID_PATTERN = /^\d{1,18}$/
export const MUTED_VIA_FILTERS = ['person', 'rule', 'mcp', 'deleted_rule'] as const
export const MUTED_ORDERS = ['recent', 'person_first'] as const

function busy(what: string): McpToolError {
  return new McpToolError(
    `Refused (busy): nothing was changed: ${what}. A mute or unmute written now could be lost or undone. ` +
      'Retry once it has finished.',
    'busy'
  )
}

const ACTIVATION_BUSY = 'a version activation is in progress on this project, or its state could not be read'

/** De-duplicated refs, checked, and bounded in total. A numeric Node ID (as
 *  query_graph returns it) is taken as its digits. */
function refsOf(
  findingIds: string[] | undefined,
  nodeIds: (string | number)[] | undefined,
  max: number
): { keys: string[]; graphIds: string[] } {
  const keys = [...new Set(findingIds ?? [])]
  const graphIds = [...new Set((nodeIds ?? []).map(String))]
  for (const k of keys) {
    if (!k || k.length > 200 || !FINDING_ID_PATTERN.test(k)) {
      throw new McpToolError(`"${String(k).slice(0, 40)}" is not a finding id.`, 'bad_args')
    }
  }
  for (const g of graphIds) {
    if (!NODE_ID_PATTERN.test(g)) {
      throw new McpToolError(`"${String(g).slice(0, 40)}" is not a Node ID.`, 'bad_args')
    }
  }
  const total = keys.length + graphIds.length
  if (total === 0) {
    throw new McpToolError('Name at least one finding, in findingIds or nodeIds.', 'bad_args')
  }
  if (total > max) {
    throw new McpToolError(`At most ${max} findings per call; this named ${total}.`, 'bad_args')
  }
  return { keys, graphIds }
}

const pairKey = (label: unknown, key: unknown) => `${String(label)}\u0000${String(key)}`

/** How many ids one audit row names; its count says how many there were. */
const AUDIT_MAX_REFS = 100

function requestedForAudit(keys: string[], graphIds: string[]) {
  return {
    findingIds: keys.slice(0, AUDIT_MAX_REFS),
    nodeIds: graphIds.slice(0, AUDIT_MAX_REFS),
    count: keys.length + graphIds.length,
  }
}

/**
 * Put back what this call re-hid behind a person's back.
 *
 * The exemptions reach the write as a snapshot read before it, and the call
 * can then wait at the agent (its MCP concurrency ceiling) for up to a minute.
 * A person who unmutes one of these findings in that window gets an
 * exemption the write never saw, and the write mutes the finding again. So
 * the exemptions are read once more AFTER the write, and any finding this
 * call muted that now has one is unmuted: it was a person's decision.
 *
 * The UI route unmutes the graph before it writes the exemption, so a
 * few-millisecond window stays open where both writes land between this
 * read and theirs. Bounded, and the mute is attributed to this token.
 */
async function releaseBroughtBack(
  userId: string,
  projectId: string,
  muted: MuteManyItem[]
): Promise<{ released: Set<string>; warning?: string }> {
  const released = new Set<string>()
  if (muted.length === 0) return { released }
  let back: MuteManyItem[]
  try {
    const rows = await prisma.nodeFilterExemption.findMany({
      where: { projectId, OR: muted.map(i => ({ label: String(i.label), nodeKey: String(i.key) })) },
      select: { label: true, nodeKey: true },
    })
    const exempt = new Set(rows.map(r => pairKey(r.label, r.nodeKey)))
    back = muted.filter(i => exempt.has(pairKey(i.label, i.key)))
  } catch (err) {
    console.error('[mcp] mute_findings could not re-read the exemptions:', err)
    return {
      released,
      warning: 'Whether a person brought any of these back during this call could not be checked. ' +
        'Re-check with search_muted_findings and list what you muted in your report.',
    }
  }
  if (back.length === 0) return { released }
  try {
    const undone = await unmuteMany(userId, projectId, {
      keys: [...new Set(back.map(i => String(i.key)))],
      includeRuleMutes: false,
    })
    const skipped = new Set(undone.skipped.map(s => pairKey(s.label, s.key)))
    for (const i of back) if (!skipped.has(pairKey(i.label, i.key))) released.add(pairKey(i.label, i.key))
  } catch (err) {
    console.error('[mcp] mute_findings could not release what a person brought back:', err)
  }
  const stuck = back.filter(i => !released.has(pairKey(i.label, i.key)))
  return {
    released,
    ...(stuck.length > 0 ? {
      warning: `A person brought back ${stuck.map(i => i.key).join(', ')} during this call, and this ` +
        'mute could not be undone. Tell a person; do not mute them again.',
    } : {}),
  }
}

// --- mute ------------------------------------------------------------------------

export async function muteFindings(
  ctx: McpContext,
  projectId: string,
  args: { findingIds?: string[]; nodeIds?: (string | number)[]; reason: string }
) {
  requireScope(ctx.token, 'triage:mute')
  enforceRate(ctx, 'mute')
  const { userId: tenant } = await assertMcpProjectAccess(ctx.token, projectId)

  const { keys, graphIds } = refsOf(args.findingIds, args.nodeIds, MUTE_MAX_REFS)
  const reason = (args.reason ?? '').trim()
  if (reason.length < MUTE_REASON_MIN || reason.length > MUTE_REASON_MAX) {
    throw new McpToolError(
      `A reason of ${MUTE_REASON_MIN}-${MUTE_REASON_MAX} characters is required: people read it in Muted Nodes.`,
      'bad_args'
    )
  }

  const tokenId = ctx.token.tokenId
  if (await activationBusy(projectId)) throw busy(ACTIVATION_BUSY)

  let exemptPairs: [string, string][]
  try {
    const rows = await prisma.nodeFilterExemption.findMany({
      where: { projectId },
      select: { label: true, nodeKey: true },
    })
    exemptPairs = rows.map(r => [r.label, r.nodeKey])
  } catch (err) {
    console.error('[mcp] mute_findings could not read the exemptions:', err)
    throw busy('the findings a person brought back could not be read, so they could not be protected')
  }

  let result: { items: MuteManyItem[]; notFound: string[] }
  try {
    result = await muteMany(tenant, projectId, {
      keys, graphIds, exemptPairs, reason, tokenPrefix: ctx.token.tokenPrefix,
    })
  } catch (err) {
    if (err instanceof McpToolError && err.code === 'mute_outcome_unknown') {
      // It may have landed, so the cached graph may be stale.
      invalidateCache(projectId)
      void writeAudit({
        actorId: ctx.token.userId,
        action: 'muted_nodes.muted',
        targetType: 'project',
        targetId: projectId,
        after: {
          tokenId, tokenPrefix: ctx.token.tokenPrefix, reason, outcome: 'unknown',
          requested: requestedForAudit(keys, graphIds),
        },
        source: 'mcp',
      })
    }
    throw err
  }

  if (result.items.some(i => i.outcome === 'muted')) invalidateCache(projectId)
  const release = await releaseBroughtBack(
    tenant, projectId, result.items.filter(i => i.outcome === 'muted'))
  // A finding released above is reported as the refusal it would have been
  // had the write seen the person's exemption.
  const items = result.items.map(i =>
    release.released.has(pairKey(i.label, i.key)) ? { ...i, outcome: 'kept_visible' } : i)
  const muted = items.filter(i => i.outcome === 'muted')

  const warnings = [
    ...(await activationBusy(projectId)
      ? ['A version activation started during this call, and these mutes may not survive it. ' +
          'Re-check with search_muted_findings when it finishes.']
      : []),
    ...(release.warning ? [release.warning] : []),
  ]
  const warning = warnings.length > 0 ? warnings.join(' ') : undefined

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'muted_nodes.muted',
    targetType: 'project',
    targetId: projectId,
    after: {
      tokenId,
      tokenPrefix: ctx.token.tokenPrefix,
      reason,
      count: muted.length,
      items: items.slice(0, AUDIT_MAX_REFS).map(i => ({ key: i.key ?? i.ref, label: i.label, outcome: i.outcome })),
      ...(result.notFound.length ? { notFound: result.notFound.slice(0, AUDIT_MAX_REFS) } : {}),
    },
    source: 'mcp',
  })

  const nodeIdOf = (i: MuteManyItem) =>
    typeof i.node_id === 'string' && NODE_ID_PATTERN.test(i.node_id) ? { nodeId: i.node_id } : {}
  return {
    projectId,
    muted: muted.map(i => ({
      findingId: i.key, ...nodeIdOf(i), label: i.label, name: i.name, severity: i.severity,
    })),
    alreadyMuted: items
      .filter(i => i.outcome === 'already_muted')
      .map(i => ({ findingId: i.key, ...nodeIdOf(i), label: i.label, mutedVia: i.was_via })),
    refused: items
      .filter(i => ['proven', 'kept_visible', 'not_a_finding'].includes(i.outcome))
      .map(i => ({ ref: i.ref, reason: i.outcome, label: i.label })),
    notFound: result.notFound,
    ...(warning ? { warning } : {}),
    notes: [
      'A muted finding is hidden from everyone, including you: no read here returns it except ' +
        'search_muted_findings and list_muted_findings.',
      'Each mute is marked as an agent\'s, with this token\'s prefix, and a person can undo it in ' +
        'Muted Nodes.',
      '"proven" and "kept_visible" are refusals a person decides on, in RedAmon. Do not retry them.',
      'If every finding of a remediation is muted, the next triage run removes that remediation.',
    ],
  }
}

// --- unmute ----------------------------------------------------------------------

export async function unmuteFindings(
  ctx: McpContext,
  projectId: string,
  args: { findingIds?: string[]; nodeIds?: (string | number)[]; includeRuleMutes?: boolean }
) {
  requireScope(ctx.token, 'triage:mute')
  enforceRate(ctx, 'mute')
  const { userId: tenant } = await assertMcpProjectAccess(ctx.token, projectId)

  const { keys, graphIds } = refsOf(args.findingIds, args.nodeIds, UNMUTE_MAX_REFS)
  const includeRuleMutes = args.includeRuleMutes === true
  // Who unmutes; the findings are the project owner's (`tenant`).
  const actor = ctx.token.userId

  // A rule mute is re-muted by a sweep that read the exemptions before this
  // unmute wrote one: an apply (a NodeFilterRun) or, for a rule mute, the
  // end-of-scan sweep, which only the scan check sees. Both fail closed.
  const graphWriter = () => (includeRuleMutes ? describeScanWriters(projectId) : describeNodeFilterWriter(projectId))

  if (await activationBusy(projectId)) throw busy(ACTIVATION_BUSY)
  const writer = await graphWriter()
  if (writer) throw busy(writer)

  const resolved = await resolveMuted(tenant, projectId, { keys, graphIds, includeRuleMutes })
  const pairs: ExemptionPair[] = resolved.toUnmute.map(r => ({ label: r.label, key: r.key }))

  const doc = resolved.skippedRuleMutes.length > 0 ? await loadMutedRuleDoc(projectId) : null
  const skippedRuleMutes = resolved.skippedRuleMutes.map(r => {
    const state = doc ? describeMutedBy(doc, r.muted_by) : { via: 'person' as const }
    return {
      findingId: r.key,
      ...(r.node_id && NODE_ID_PATTERN.test(r.node_id) ? { nodeId: r.node_id } : {}),
      label: r.label,
      ruleName: state.via === 'rule' ? state.ruleName : null,
    }
  })

  const base = {
    projectId,
    skippedRuleMutes,
    notFound: resolved.notFound,
  }
  if (pairs.length === 0) {
    return { ...base, unmuted: [], exempted: 0, notes: unmuteNotes(includeRuleMutes, skippedRuleMutes.length) }
  }

  // The exemptions go in FIRST: a lost answer then converges on its own (the
  // next sweep releases a rule mute on an exempt finding), and a retry of the
  // rest is safe.
  let exemptions: { created: ExemptionPair[]; total: number }
  try {
    exemptions = await ensureExemptions(projectId, pairs, { createdBy: actor, realActorUserId: null })
  } catch (err) {
    console.error('[mcp] unmute_findings could not save the exemptions:', err)
    throw new McpToolError(
      'The exemptions that keep an unmuted finding visible could not be saved, so nothing was unmuted.',
      'exemptions_failed'
    )
  }

  if ((await activationBusy(projectId)) || (await graphWriter())) {
    await removeExemptions(projectId, exemptions.created)
    throw busy('the project started writing its graph during this call')
  }

  let result: Awaited<ReturnType<typeof unmuteMany>>
  try {
    result = await unmuteMany(tenant, projectId, {
      keys: [...new Set(pairs.map(p => p.key))],
      includeRuleMutes,
    })
  } catch (err) {
    if (err instanceof McpToolError && err.code === 'unmute_outcome_unknown') {
      invalidateCache(projectId)
      void auditUnmute({
        actorId: actor, projectId, source: 'mcp', realActorUserId: null,
        tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
        items: [], exempted: exemptions.total, outcome: 'unknown',
        requested: requestedForAudit(keys, graphIds),
      })
    } else {
      await removeExemptions(projectId, exemptions.created)
    }
    throw err
  }

  // A finding the agent left muted (a rule re-muted it after the lookup, and
  // the flag was off) must not keep an exemption that would release it later.
  const skippedNow = new Set(result.skipped.map(s => `${s.label}\u0000${s.key}`))
  const dropped = exemptions.created.filter(p => skippedNow.has(`${p.label}\u0000${p.key}`))
  if (dropped.length > 0) await removeExemptions(projectId, dropped)

  invalidateCache(projectId)
  // A finding resolved above that someone else unmuted meanwhile is not in the
  // agent's rows; it is visible, which is what was asked, so it is reported.
  const unmuted = resolved.toUnmute
    .filter(r => !skippedNow.has(`${r.label}\u0000${r.key}`))
    .map(r => ({
      findingId: r.key,
      ...(r.node_id && NODE_ID_PATTERN.test(r.node_id) ? { nodeId: r.node_id } : {}),
      label: r.label,
      wasMutedVia: r.was_via,
    }))

  await auditUnmute({
    actorId: actor, projectId, source: 'mcp', realActorUserId: null,
    tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
    items: unmuted.map(u => ({ key: u.findingId, label: u.label, wasMutedVia: u.wasMutedVia })),
    exempted: exemptions.total - dropped.length, outcome: 'ok',
  })

  return {
    ...base,
    unmuted,
    exempted: exemptions.total - dropped.length,
    notes: unmuteNotes(includeRuleMutes, skippedRuleMutes.length),
  }
}

function unmuteNotes(includeRuleMutes: boolean, skipped: number): string[] {
  return [
    'The verdict on each finding is kept; it is ranked again at the next triage run.',
    'Each unmuted finding is now exempt from the Mute Rules, visible on the Mute Rules page, ' +
      'so no rule hides it again until a person clears that.',
    ...(skipped > 0 && !includeRuleMutes
      ? ['Findings a Mute Rule muted were left muted. Pass includeRuleMutes only when a person asked for them.']
      : []),
    'An unmuted finding shows as ADDED in a comparison against a version frozen while it was muted.',
  ]
}

// --- search ----------------------------------------------------------------------

export async function searchMutedFindings(
  ctx: McpContext,
  projectId: string,
  args: {
    limit?: number
    offset?: number
    label?: string
    mutedVia?: string
    rule?: string
    mutedByToken?: string
    search?: string
    order?: string
    facets?: boolean
  } = {}
) {
  requireScope(ctx.token, 'triage:read')
  enforceRate(ctx, 'read')
  const project = await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const limit = Math.max(1, Math.min(args.limit ?? SEARCH_DEFAULT_LIMIT, SEARCH_MAX_LIMIT))
  const offset = Math.max(0, Math.min(args.offset ?? 0, SEARCH_MAX_OFFSET))
  if (args.mutedByToken !== undefined && !MUTED_TOKEN_PATTERN.test(args.mutedByToken)) {
    throw new McpToolError('mutedByToken must be a token prefix, as facets.tokens lists them.', 'bad_args')
  }

  const doc = await loadMutedRuleDoc(projectId)
  const page = await listMutedPage(project.userId, projectId, {
    limit,
    offset,
    label: args.label,
    mutedVia: args.mutedVia,
    rule: args.rule?.slice(0, 200) || undefined,
    search: args.search?.slice(0, 200) || undefined,
    order: args.order,
    token: args.mutedByToken,
    liveRules: args.mutedVia === 'deleted_rule' ? liveRuleMutedBy(doc) : undefined,
  })

  const findings = page.findings.map(f => mutedRow(doc, f))
  const total = typeof page.total === 'number' ? page.total : null

  let facets: Record<string, unknown> | undefined
  if (args.facets === true) {
    const raw = annotateMutedFacets(doc, await mutedFacets(project.userId, projectId))
    facets = {
      total: raw.total,
      byPerson: raw.by_person,
      byMcp: raw.by_mcp ?? 0,
      labels: raw.labels,
      rules: (raw.rules as Record<string, unknown>[]).map(r => ({
        mutedBy: r.muted_by,
        count: r.count,
        ruleName: r.rule_name,
        ...(r.rule_deleted ? { ruleDeleted: true } : {}),
      })),
      tokens: Array.isArray(raw.tokens) ? raw.tokens : [],
    }
  }

  return {
    projectId,
    total,
    offset,
    returned: findings.length,
    ...(total !== null && offset + findings.length < total ? { truncated: true } : {}),
    findings,
    ...(facets ? { facets } : {}),
  }
}

/** The row allowlist. Nothing outside it reaches a caller. */
function mutedRow(doc: Parameters<typeof describeMutedBy>[0], f: TriageFinding): Record<string, unknown> {
  const mutedBy = String(f.muted_by ?? '')
  const state = describeMutedBy(doc, mutedBy)
  const via = mutedViaOf(f as Record<string, unknown>)
  const nodeId = typeof f.node_id === 'string' && NODE_ID_PATTERN.test(f.node_id) ? f.node_id : undefined
  const token = typeof f.muted_token === 'string' && MUTED_TOKEN_PATTERN.test(f.muted_token)
    ? f.muted_token : undefined
  return {
    id: f.id,
    ...(nodeId ? { nodeId } : {}),
    label: f.label,
    name: f.name,
    severity: f.severity,
    source: f.source,
    host: f.host,
    mutedAt: f.muted_at,
    mutedVia: via,
    mutedBy,
    ...(via === 'mcp' && token ? { mutedByToken: token } : {}),
    ruleName: state.via === 'rule' ? state.ruleName : null,
    ...(state.via === 'rule' && state.deleted ? { ruleDeleted: true } : {}),
    mutedReason: f.muted_reason,
    staleSince: f.stale_since ?? null,
    triageStatus: f.triage_status,
  }
}

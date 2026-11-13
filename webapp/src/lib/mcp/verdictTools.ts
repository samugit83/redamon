/**
 * A person's decision on a finding, over MCP: Real, False positive, or Reset.
 *
 * It closes the loop for an external triage assistant. The decision layer
 * always wins over the rules and any review, and the agent rescores the finding
 * in the same transaction, so the answer carries the score before and after.
 *
 * THE PROVENANCE DESIGN IS NOT THE OBVIOUS ONE. The instinct is to write a
 * third `triage_source` value so an agent's verdict is not laundered as a
 * human's. That is wrong: `triage_source = 'human'` is what the prune keeps and
 * the Mute Rules guards read, so a third value would make the finding
 * prune-eligible. The verdict stays `'human'` - the token is the operator's own
 * delegated credential carrying their authority - and the CHANNEL is recorded
 * separately (`triage_verdict_channel = 'mcp'`, with the token prefix).
 *
 * WHAT A TOKEN MAY NOT DO
 * - Change or reset a decision a person made in the APP (`decided_in_app`). An
 *   absent channel is the app: every decision made before channels existed was
 *   a person's click. MCP creates, changes and resets MCP decisions only.
 * - Decide a MUTED finding. A human verdict is one of the Mute Rules guards, so
 *   on a rule-muted finding it would release the mute at the next apply: an
 *   unmute by another name, reachable without the mute permission. A person
 *   who wants a muted finding judged unmutes it first.
 * - Write while a triage run is live UNLESS the agent acknowledges that its
 *   publish honours decisions made meanwhile (`layered_publish`). An older
 *   agent would re-file the finding from its pre-verdict analysis, so without
 *   the acknowledgement the write is refused: version skew fails closed. That
 *   check lives in `lib/triage/actions.ts`, shared with the UI door.
 */
import { requireScope } from '@/lib/mcpAuth'
import { assertMcpProjectAccess } from '@/lib/mcpAuth'
import { writeAudit } from '@/lib/audit'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import {
  recordVerdict, TriageActionError, VERDICT_STATUSES as ACTION_STATUSES, type VerdictStatus,
} from '@/lib/triage/actions'

export const VERDICT_STATUSES = ACTION_STATUSES
export type { VerdictStatus }

export async function setFindingVerdict(
  ctx: McpContext,
  projectId: string,
  nodeId: string,
  status: string,
  reason?: string,
  label?: string
) {
  requireScope(ctx.token, 'triage:write')
  enforceRate(ctx, 'write')
  const { userId: owner } = await assertMcpProjectAccess(ctx.token, projectId)

  if (!(VERDICT_STATUSES as readonly string[]).includes(status)) {
    throw new McpToolError(
      `Unknown verdict '${status}'. One of: ${VERDICT_STATUSES.join(', ')}.`,
      'bad_args'
    )
  }

  let result
  try {
    result = await recordVerdict(
      { userId: owner, projectId },
      {
        findingId: nodeId,
        status: status as VerdictStatus,
        reason: (reason ?? '').slice(0, 500),
        label,
        channel: 'mcp',
        verdictBy: ctx.token.userId,
        tokenPrefix: ctx.token.tokenPrefix,
      },
    )
  } catch (err) {
    if (!(err instanceof TriageActionError)) throw err
    if (err.code === 'muted') {
      throw new McpToolError(
        'Refused (muted): a verdict is refused on a muted finding. If a person wants it judged, ' +
        'unmute it first with unmute_findings (needs the triage:mute permission), then record the ' +
        'verdict. On a finding a Mute Rule muted, a verdict alone would release the mute. Nothing ' +
        'was written.',
        'muted'
      )
    }
    if (err.code === 'decided_in_app') {
      throw new McpToolError(
        'Refused (decided_in_app): a person decided this in the app, and only the app can change ' +
        'or reset that decision. Nothing was written. Report the disagreement instead.',
        'decided_in_app'
      )
    }
    if (err.code === 'not_found' || err.code === 'not_updated') {
      const why = err.code === 'not_updated' ? ` ${err.message}` : ''
      // list_findings returns a graph `nodeId` beside the finding `id`, and the
      // input here is also called nodeId, so the likeliest wrong value is that one.
      const nodeIdHint = /^\d+$/.test(nodeId)
        ? ` "${nodeId}" looks like a graph Node ID (the \`nodeId\` field); pass the finding's \`id\` instead.`
        : ''
      throw new McpToolError(
        `Refused (not_updated): the verdict was NOT recorded.${why} The finding no longer exists, ` +
        'was never in this project, or is not a type a verdict can be set on. A finding id is only ' +
        `valid until the next scan of that source, so re-read list_findings before retrying.${nodeIdHint}`,
        'not_updated'
      )
    }
    throw new McpToolError(`Refused (${err.code}): ${err.message}`, err.code,
                           Object.keys(err.details).length ? { details: err.details } : undefined)
  }

  // The agent logs the verdict too; this is the half that ties it to a token.
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.set_finding_verdict',
    targetType: 'finding',
    targetId: nodeId,
    after: {
      projectId,
      status,
      label: result.label,
      channel: 'mcp',
      tokenId: ctx.token.tokenId,
      tokenPrefix: ctx.token.tokenPrefix,
      before: result.before,
      after: result.after,
    },
    source: 'mcp',
  })

  return {
    projectId,
    nodeId,
    status,
    label: result.label,
    recorded: true,
    rescored: result.rescored,
    ...(result.rescoreReason ? { rescoreReason: result.rescoreReason } : {}),
    before: result.before,
    after: result.after,
    notes: [
      status === 'confirmed'
        ? 'Real: the finding\'s `real` factor is now 100%, and its score was recomputed.'
        : status === 'likely_noise'
          ? 'False positive: the finding moved to the false-positive section. It is still visible; hiding it is a mute, a separate permission.'
          : 'Reset: the decision is gone. The finding is ranked from its rules and any review again, and is no longer protected from Mute Rules or from removal when a scan stops reporting it.',
      'It is recorded as the operator\'s decision, because it carries their authority; the node ' +
        'separately records that it arrived over MCP, with this token\'s prefix.',
      'A decision outranks every review, including the built-in AI\'s, and survives re-scans.',
    ],
  }
}

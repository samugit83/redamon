/**
 * Apply a confirmed RoE replace or remove to an existing project.
 *
 * Every step fails closed, in this order: the row (404, or 409 `roe_stale` when
 * it moved since the review), a project's first RoE set by anyone but its
 * owner (403), running scan work (409 `roe_busy`, 503 when it
 * cannot be checked), the confirmed keys (400), the values and the shared
 * project-write guards (400), a collaborator's widening or a change beyond
 * their level (403, OQ-23), the third-party rules (400 / 403), the schedules
 * to pause (503 when they cannot be computed), then ONE transaction: the
 * outgoing document into the revision history, a compare-and-swap update of
 * the row, and the schedule pause.
 *
 * The proposal is recomputed here from the model output the review was built
 * on, never taken from the client: `changes` is what the person confirmed, and
 * it must equal what the server would write, or the write is refused as stale.
 */
import { NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'

import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { roeTextDigest } from '@/lib/engagement'
import { guardProjectWrite, recordProjectWrite } from '@/lib/projectWriteGuards'
import { refreshActiveRecordingScope } from '@/lib/recordingSession'
import { fetchBackendDefaults } from '@/lib/reconPresets/server'
import { field } from '@/lib/reconSettings/registry'
import { parseValueProblem } from '@/lib/reconSettings/roeParse'
import { validateValue } from '@/lib/reconSettings/validators'
import { describeAffectedSchedules, countQueuedJobsNeedingReview } from '@/lib/mcp/writeTools'
import type { EffectiveUser } from '@/lib/session'
import type { ProjectAccess } from '@/lib/authz/projectAccess'
import { classifyChange, settingsRefusal, type SettingsChange } from '@/lib/authz/settingsRisk'
import { actingAdminId } from './actor'
import { cleanRoeFileName as cleanFileName } from './createRoe'
import { agentEnforcementWarning } from './agentWarning'
import { sha256Hex, type ExtractedDocument } from './extractText'
import { canonicalMimeType, MAX_MODEL_CHARS, type RoeFileKind } from './limits'
import {
  CEILING_REQUIRED_MESSAGE,
  NEEDS_AUTHORIZATION_MESSAGE,
  roeBlockingWork,
  schedulesToPause,
  thirdPartyCheck,
} from './roeEffects'
import {
  buildReplaceProposal,
  buildRoeParsedJson,
  changesMap,
  keyAllowedInChanges,
  readStoredRoeParse,
  replaceIsImplausible,
  sameChanges,
  type ReplaceProposal,
} from './roeReplace'

/** Superseded documents kept per project. */
export const REVISIONS_KEPT = 10

export type ApplyRoeInput =
  | {
      mode: 'replace'
      projectId: string
      eff: EffectiveUser
      /** The caller's access (the route's requirePermission): anyone but the owner is judged (OQ-23). */
      access: ProjectAccess | null
      rowVersion: string
      changes: Record<string, unknown>
      parsedFields: Record<string, unknown>
      doc: ExtractedDocument
      file: { name: string; kind: RoeFileKind; bytes: Buffer }
      modelUsed: string | null
      unknownKeys: string[]
    }
  | {
      mode: 'remove'
      projectId: string
      eff: EffectiveUser
      access: ProjectAccess | null
      rowVersion: string
      changes: Record<string, unknown>
    }

const err = (status: number, code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status })

export const STALE_ROE_MESSAGE =
  'The project changed while you were reviewing this RoE. Nothing was written; the review has been rebuilt against the current project.'

class StaleRow extends Error {}

/**
 * The document's own record: the client and contacts it names (`share: secret`, written by the
 * parse). A collaborator who may replace the document replaces these with it, as the document's
 * text and parse; every other column it changes is judged as a settings change.
 */
const documentRecord = (key: string): boolean => {
  const spec = field(key)
  return spec?.share === 'secret' && spec.roe_parse === 'allow'
}

/**
 * Who else but the owner may apply this RoE (OQ-23 default): a replace or removal the review finds
 * no widening row in, whose changes their level reaches. A wider one is the owner's; the review's
 * judgment is `wideningReason`, as the schedules and the third-party rules read it.
 */
function collaboratorRefusal(
  access: ProjectAccess | null,
  row: Record<string, unknown>,
  proposal: ReplaceProposal,
  updateData: Record<string, unknown>,
): NextResponse | null {
  const widening: SettingsChange[] = proposal.changes.filter(c => c.widening).map(c => ({
    key: c.key, share: field(c.key)?.share ?? 'ordinary', needs: 'owner', reason: `widens the engagement: ${c.widening}`, ok: false,
  }))
  const verdict = widening.length > 0
    ? { ok: false, changes: widening, refused: widening }
    : classifyChange(row, Object.fromEntries(Object.entries(updateData).filter(([k]) => !documentRecord(k))), access)
  const refusal = settingsRefusal(verdict, 'roe:manage')
  return refusal ? NextResponse.json(refusal, { status: 403 }) : null
}

export async function applyRoe(input: ApplyRoeInput): Promise<NextResponse> {
  const started = Date.now()
  const { projectId, eff } = input
  const log = (outcome: string, extra: Record<string, unknown> = {}) => {
    const parts = Object.entries({ project: projectId, user: eff.userId, mode: input.mode, ms: Date.now() - started, ...extra })
      .map(([k, v]) => `${k}=${v}`)
    console.info(`[roe-apply] outcome=${outcome} ${parts.join(' ')}`)
  }

  // 3. The row, and the version the review was built on.
  const row = await prisma.project.findUnique({ where: { id: projectId } }) as (Record<string, unknown> & {
    id: string; userId: string; updatedAt: Date; engagementKind: string
    roeDocumentData: Uint8Array | null; roeDocumentName: string; roeDocumentMimeType: string
    roeRawText: string; roeParsedJson: unknown
  }) | null
  if (!row) {
    log('not_found')
    return err(404, 'not_found', 'The project no longer exists.')
  }
  const expected = new Date(input.rowVersion)
  if (Number.isNaN(expected.getTime()) || row.updatedAt.getTime() !== expected.getTime()) {
    log('roe_stale')
    return err(409, 'roe_stale', STALE_ROE_MESSAGE)
  }
  const hasDocument = Boolean(row.roeDocumentData || row.roeRawText || row.roeDocumentName || row.roeParsedJson)
  if (input.mode === 'remove' && !hasDocument) {
    log('no_roe')
    return err(404, 'no_roe', 'This project has no Rules of Engagement document to remove.')
  }
  const byOwner = input.access?.level === 'owner'
  if (!byOwner && !hasDocument) {
    log('roe_owner_only', { reason: 'first' })
    return NextResponse.json({
      error: "Only the project's owner can set its first Rules of Engagement document.",
      code: 'forbidden', permission: 'roe:manage', level: 'O',
    }, { status: 403 })
  }

  // 4. Running work keeps its spawn-time settings, so it would not see the new RoE.
  const busy = await roeBlockingWork(projectId)
  if (busy.busy) {
    log(busy.verified ? 'roe_busy' : 'roe_busy_unverified')
    return busy.verified
      ? err(409, 'roe_busy', `Cannot change the Rules of Engagement while ${busy.what}. Stop it first, or wait for it to finish.`, { busy: busy.what })
      : err(503, 'roe_busy_unverified', `Could not check for running scans (${busy.what}). Nothing was written; try again.`)
  }

  let defaults: Record<string, unknown>
  try {
    defaults = await fetchBackendDefaults()
  } catch (e) {
    console.error('[roe-apply] defaults unavailable:', e)
    log('defaults_unavailable')
    return err(503, 'defaults_unavailable', 'The recon and agent defaults could not be read, so the values to reset are unknown. Nothing was written; try again.')
  }

  const proposal: ReplaceProposal = buildReplaceProposal({
    parsed: input.mode === 'replace' ? input.parsedFields : {},
    current: row,
    previous: row.roeParsedJson,
    defaults,
  })
  if (input.mode === 'replace' && replaceIsImplausible(proposal)) {
    log('implausible')
    return err(422, 'implausible', 'The document proposes more changes than any Rules of Engagement document should make. Nothing was written.')
  }

  // 5. Every confirmed key must be one a document may write, or one a restore writes.
  const previous = readStoredRoeParse(row.roeParsedJson)
  const notAllowed = Object.keys(input.changes).filter(k => !keyAllowedInChanges(k, previous))
  if (notAllowed.length > 0) {
    log('roe_key_not_allowed', { keys: notAllowed.length })
    return err(400, 'roe_key_not_allowed', `A Rules of Engagement document may not change: ${notAllowed.join(', ')}.`, { keys: notAllowed })
  }

  // 6. Values: what the person confirmed, then what the server would write. A
  // reset or a restore writes a default or an operator's earlier value, which is
  // held to the validator but not to the document-only rules.
  const undoKeys = new Set(proposal.changes.filter(c => c.kind !== 'set').map(c => c.key))
  const valueProblem = (key: string, value: unknown): string | null => {
    const spec = field(key)
    if (!spec) return 'is not a project setting'
    return undoKeys.has(key) ? validateValue(key, spec, value, projectId) : parseValueProblem(key, spec, value)
  }
  for (const [key, value] of [...Object.entries(input.changes), ...proposal.changes.map(c => [c.key, c.after] as const)]) {
    const problem = valueProblem(key, value)
    if (problem) {
      log('roe_invalid_value')
      return err(400, 'roe_invalid_value', `${key} ${problem}`, { keys: [key] })
    }
  }
  const updateData = changesMap(proposal)
  if (!sameChanges(updateData, input.changes)) {
    log('roe_stale', { reason: 'proposal_changed' })
    return err(409, 'roe_stale', STALE_ROE_MESSAGE)
  }

  if (!byOwner) {
    const refused = collaboratorRefusal(input.access, row, proposal, updateData)
    if (refused) {
      log('roe_level_refused')
      console.warn(`[rbac] settings_refused project=${projectId} user=${eff.userId} via=roe`)
      return refused
    }
  }

  // The guards every project write runs.
  const guardError = await guardProjectWrite({ existing: row, updateData, actorUserId: eff.userId })
  if (guardError) {
    log('guard_refused')
    return err(400, 'roe_guard_refused', guardError)
  }

  // 7. Third party.
  const resulting = { ...row, ...updateData }
  const third = thirdPartyCheck(row, resulting, proposal)
  if (third.ceilingMissing) {
    log('roe_ceiling_required')
    return err(400, 'roe_ceiling_required', CEILING_REQUIRED_MESSAGE)
  }
  if (third.needsAuthorization) {
    log('roe_needs_authorization')
    return err(403, 'roe_needs_authorization', NEEDS_AUTHORIZATION_MESSAGE)
  }

  // 8. Schedules this RoE pauses.
  let toPause
  try {
    toPause = await schedulesToPause(projectId, proposal, resulting)
  } catch (e) {
    console.error('[roe-apply] could not evaluate schedules:', e)
    log('schedules_unavailable')
    return err(503, 'schedules_unavailable', 'The scan schedules could not be checked against the new RoE. Nothing was written; try again.')
  }

  // 9. One transaction.
  const adminId = await actingAdminId(eff)
  const artefacts = input.mode === 'replace'
    ? {
        roeDocumentData: new Uint8Array(input.file.bytes),
        roeDocumentName: cleanFileName(input.file.name),
        roeDocumentMimeType: canonicalMimeType(input.file.kind),
        roeRawText: input.doc.text,
        roeParsedJson: buildRoeParsedJson({
          proposal,
          documentName: cleanFileName(input.file.name),
          mimeType: canonicalMimeType(input.file.kind),
          bytesSha256: input.doc.bytesSha256,
          textSha256: input.doc.textSha256,
          modelUsed: input.modelUsed,
          truncated: input.doc.truncated || input.doc.text.length > MAX_MODEL_CHARS,
          appliedById: eff.userId,
          actingAdminId: adminId,
          unknownKeys: input.unknownKeys,
        }) as unknown as Prisma.InputJsonValue,
      }
    : {
        roeDocumentData: null,
        roeDocumentName: '',
        roeDocumentMimeType: '',
        roeRawText: '',
        roeParsedJson: Prisma.DbNull,
      }

  const storedParse = (row.roeParsedJson && typeof row.roeParsedJson === 'object' ? row.roeParsedJson : {}) as Record<string, unknown>
  const before: Record<string, unknown> = Object.fromEntries(Object.keys(updateData).map(k => [k, row[k]]))
  let updated
  try {
    updated = await prisma.$transaction(async tx => {
      if (hasDocument) {
        await tx.roeDocumentRevision.create({
          data: {
            projectId,
            documentName: row.roeDocumentName || 'roe-document',
            mimeType: row.roeDocumentMimeType || '',
            data: row.roeDocumentData ? new Uint8Array(row.roeDocumentData) : null,
            bytesSha256: typeof storedParse.bytesSha256 === 'string'
              ? storedParse.bytesSha256
              : row.roeDocumentData ? sha256Hex(row.roeDocumentData) : '',
            textSha256: roeTextDigest(row.roeRawText) ?? '',
            rawText: row.roeRawText || '',
            parsedJson: row.roeParsedJson === null || row.roeParsedJson === undefined
              ? Prisma.DbNull
              : row.roeParsedJson as Prisma.InputJsonValue,
            appliedAt: typeof storedParse.appliedAt === 'string' ? new Date(storedParse.appliedAt) : null,
            supersededById: eff.userId,
            reason: input.mode === 'replace' ? 'replaced' : 'removed',
          },
        })
        const stale = await tx.roeDocumentRevision.findMany({
          where: { projectId },
          orderBy: { supersededAt: 'desc' },
          skip: REVISIONS_KEPT,
          select: { id: true },
        })
        if (stale.length > 0) await tx.roeDocumentRevision.deleteMany({ where: { id: { in: stale.map(s => s.id) } } })
      }

      const { count } = await tx.project.updateMany({
        where: { id: projectId, updatedAt: row.updatedAt },
        data: { ...updateData, ...artefacts, updatedById: eff.userId } as Prisma.ProjectUpdateManyMutationInput,
      })
      if (count === 0) throw new StaleRow()

      if (toPause.length > 0) {
        await tx.scanSchedule.updateMany({
          where: { id: { in: toPause.map(s => s.id) }, enabled: true },
          data: { enabled: false },
        })
      }
      return tx.project.findUnique({ where: { id: projectId } })
    })
  } catch (e) {
    if (e instanceof StaleRow) {
      log('roe_stale', { reason: 'cas' })
      return err(409, 'roe_stale', STALE_ROE_MESSAGE)
    }
    throw e
  }
  if (!updated) return err(404, 'not_found', 'The project no longer exists.')

  // After commit: the audits are best-effort and must not abort the transaction.
  await recordProjectWrite(projectId, before, updateData, { userId: row.userId, source: 'roe' })
  const textSha256After = input.mode === 'replace' ? input.doc.textSha256 : null
  await writeAudit({
    actorId: eff.userId,
    action: input.mode === 'replace' ? 'project.roe.replace' : 'project.roe.remove',
    targetType: 'project',
    targetId: projectId,
    before: { documentName: row.roeDocumentName || null, textSha256: roeTextDigest(row.roeRawText) },
    after: {
      documentName: input.mode === 'replace' ? cleanFileName(input.file.name) : null,
      textSha256: textSha256After,
      changed: Object.keys(updateData),
      kept: proposal.kept.map(k => k.key),
      pausedSchedules: toPause.map(s => s.id),
      actingAdminId: adminId,
    },
    source: 'ui',
  })

  // 10. The active login recording captures by a scope computed at its start.
  const recordingScopeUpdated = await refreshActiveRecordingScope(prisma, projectId, updated as never)

  const [queued, affected] = await Promise.all([
    countQueuedJobsNeedingReview(projectId),
    describeAffectedSchedules(projectId),
  ])
  const enforcement = agentEnforcementWarning(Object.keys(proposal.applied), updated as Record<string, unknown>)
  log('ok', { changes: proposal.changes.length, kept: proposal.kept.length, paused: toPause.length })

  const { roeDocumentData: _binary, ...project } = updated
  return NextResponse.json({
    project,
    appliesFrom: 'next-scan',
    changed: Object.keys(updateData),
    kept: proposal.kept,
    queuedJobsNeedingReview: queued,
    pausedSchedules: toPause,
    affectedSchedules: affected,
    recordingScopeUpdated,
    warnings: enforcement ? [enforcement] : [],
  })
}

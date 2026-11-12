/**
 * Every write of a user's own agent skills goes through here: upload (one skill, or a batch
 * that is saved whole or not at all), edit, community import, delete, quarantine and release,
 * and saving a plugin's proposal as a new skill.
 *
 * Each runs in one transaction holding the per-user advisory lock, so the name check and
 * the cap count are exact (two uploads cannot both take the last slot or the same name), and
 * a delete cannot interleave with another write to the same user's projects. Audit rows are
 * written after the commit and hold names and content hashes, never the text.
 *
 * Lock order: the per-user lock FIRST, then any override scope lock. A transaction that took
 * them the other way round could deadlock against a delete.
 */
import { createHash } from 'crypto'
import { NextResponse } from 'next/server'
import type { Prisma, UserAttackSkill } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { auditActorOf } from '@/lib/auditActor'
import { actingAsOwnerRefusal } from '@/lib/authz/actAsRefusals'
import {
  DESCRIPTION_MAX_CHARS, MAX_CONTENT_SIZE, MAX_ENABLED_USER_SKILLS_PER_PROJECT, MAX_SKILLS_PER_BATCH,
  MAX_SKILLS_PER_USER, UserSkillError, normalizeUserToggleMap, type BatchItemRefusal,
} from './userSkills'
import { checkNames, isNameTaken, nameProblem, normalizeName, suggestVersionName } from './userSkillNames'
import { cleanSkillText } from './skillMetadata'
import { FEATURE_MODEL_MAX_LEN } from './llmFeatures'
import { deleteUserSkillProposalsTx } from './plugins/overrides'
import { now } from './plugins/clock'

type Tx = Prisma.TransactionClient

export const USER_SKILL_AUDIT_TARGET = 'user_attack_skill'

export const contentSha256 = (content: string) => createHash('sha256').update(content, 'utf8').digest('hex')
/** The prefix the agent records for the user skill a session ran (skill_workflow.contentSha256). */
export const contentSha16 = (content: string) => contentSha256(content).slice(0, 16)

export async function lockUserSkills(tx: Tx, userId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`user_attack_skills:${userId}`}))`
}

/**
 * Who wrote it: the real session user, and the owner when that is someone else (an admin
 * passes requireUserAccess for any user without acting as them).
 */
export interface AuditActor {
  actorId: string | null
  onBehalfOf?: string
  source: 'ui' | 'api' | 'system'
}

export function auditActorFor(sessionUserId: string | null | undefined, ownerId: string, source: AuditActor['source'] = 'ui'): AuditActor {
  const actor = auditActorOf(sessionUserId ? { id: sessionUserId } : null, ownerId)
  return {
    actorId: actor.actorId,
    ...(actor.onBehalfOfUserId ? { onBehalfOf: actor.onBehalfOfUserId } : {}),
    source: actor.actorId ? source : 'system',
  }
}

/**
 * Writing the skills of the account an admin acts as is refused on every path here (step 3.14,
 * IM-08; permissions switch on): 403 `not_while_acting_as`, audited, before the lock is taken.
 */
export async function refuseSkillWriteWhileActingAs(ownerId: string, actor: AuditActor): Promise<void> {
  const refusal = await actingAsOwnerRefusal(ownerId, actor.actorId, 'write_agent_skills')
  if (refusal) throw new UserSkillError(403, refusal.code, refusal.error, { action: refusal.action })
}

/** What a list or a write answers with; the text is fetched on its own (download, review). */
export const USER_SKILL_SELECT = {
  id: true,
  name: true,
  description: true,
  createdAt: true,
  updatedAt: true,
  version: true,
  lineageRootId: true,
  derivedFromId: true,
  originPluginId: true,
  quarantinedAt: true,
  quarantineReason: true,
} as const satisfies Prisma.UserAttackSkillSelect

function readDescription(value: unknown): string | null {
  if (value === undefined || value === null) return null
  if (typeof value !== 'string') throw new UserSkillError(400, 'description_invalid', 'description must be a string')
  const trimmed = value.trim()
  if (trimmed.length > DESCRIPTION_MAX_CHARS) {
    throw new UserSkillError(400, 'description_too_long', `description must be ${DESCRIPTION_MAX_CHARS} characters or less`)
  }
  return trimmed || null
}

const SKILL_LIMIT_MESSAGE = `You have ${MAX_SKILLS_PER_USER} skills, the maximum. Delete one in Global Settings first.`

function readContent(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new UserSkillError(400, 'content_required', 'content is required')
  if (value.length > MAX_CONTENT_SIZE) {
    throw new UserSkillError(400, 'content_too_large', `content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`)
  }
  return value
}

async function readName(tx: Tx, userId: string, value: unknown, exceptId?: string): Promise<string> {
  if (typeof value !== 'string') throw new UserSkillError(400, 'name_invalid', 'name is required')
  const name = normalizeName(value)
  const problem = nameProblem(name)
  if (problem) throw problem
  if (await isNameTaken(tx, userId, name, exceptId)) {
    const { name: suggestion } = await suggestVersionName(tx, userId, { id: exceptId ?? '', name, lineageRootId: null })
    throw new UserSkillError(409, 'name_taken', `You already have a skill named "${name}".`, { suggestion })
  }
  return name
}

/** Lineage and provenance of a version saved from a plugin's proposal. */
export interface SkillLineage {
  derivedFromId: string | null
  lineageRootId: string
  version: number
  originChangeSetId: string
  originPluginId: string
  originPluginVersion: string
  /** Its own origin and its source's chain (originPair). */
  originChain: string[]
  /** The source's releases that still apply: text its owner accepted stays accepted. */
  releasedFor: string[]
}

/** How a plugin version is named in originChain, releasedFor and quarantinedFor. */
export const originPair = (pluginId: string, version: string) => `${pluginId}@${version}`

export interface CreateUserSkillInput {
  userId: string
  name: unknown
  description?: unknown
  content: unknown
  lineage?: SkillLineage
}

/** Create one skill; the caller holds lockUserSkills(tx, input.userId). */
export async function createUserSkillTx(tx: Tx, input: CreateUserSkillInput): Promise<UserAttackSkill> {
  const content = readContent(input.content)
  const description = readDescription(input.description)
  const name = await readName(tx, input.userId, input.name)
  const count = await tx.userAttackSkill.count({ where: { userId: input.userId } })
  if (count >= MAX_SKILLS_PER_USER) {
    throw new UserSkillError(409, 'skill_limit', SKILL_LIMIT_MESSAGE, { limit: MAX_SKILLS_PER_USER })
  }
  return tx.userAttackSkill.create({
    data: { userId: input.userId, name, description, content, ...(input.lineage ?? {}) },
  })
}

function auditFields(skill: Pick<UserAttackSkill, 'name' | 'content'>) {
  return { name: skill.name, contentSha256: contentSha256(skill.content) }
}

function withOwner(actor: AuditActor, after: Record<string, unknown>) {
  return actor.onBehalfOf ? { ...after, onBehalfOf: actor.onBehalfOf } : after
}

export async function createUserSkill(input: CreateUserSkillInput, actor: AuditActor) {
  await refuseSkillWriteWhileActingAs(input.userId, actor)
  const skill = await prisma.$transaction(async (tx) => {
    await lockUserSkills(tx, input.userId)
    return createUserSkillTx(tx, input)
  })
  await writeAudit({
    actorId: actor.actorId,
    action: 'user_attack_skill.create',
    targetType: USER_SKILL_AUDIT_TARGET,
    targetId: skill.id,
    after: withOwner(actor, { ...auditFields(skill), userId: input.userId }),
    source: actor.source,
  })
  return pick(skill)
}

function pick(skill: UserAttackSkill) {
  return Object.fromEntries(Object.keys(USER_SKILL_SELECT).map((k) => [k, skill[k as keyof UserAttackSkill]]))
}

const DECLARED_SOURCES = ['frontmatter', 'heading', 'file', 'ai', 'typed'] as const
type DeclaredSource = (typeof DECLARED_SOURCES)[number]

const declaredSource = (v: unknown): DeclaredSource | null =>
  (DECLARED_SOURCES as readonly unknown[]).includes(v) ? (v as DeclaredSource) : null

const declaredModel = (v: unknown): string | null =>
  typeof v === 'string' && v && v.length <= FEATURE_MODEL_MAX_LEN && !/[\p{Cc}\p{Cf}]/u.test(v) ? v : null

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

interface BatchRow {
  name: string
  description: string | null
  content: string
  /** What the dialog says the name and description came from: audited as a claim, never stored. */
  declared: { nameSource: DeclaredSource | null; descriptionSource: DeclaredSource | null; aiModel: string | null }
}

/** One item's pure checks, in the order createUserSkillTx applies them; the first problem wins. */
function readBatchRow(raw: unknown): BatchRow | UserSkillError {
  const item = isObject(raw) ? raw : {}
  try {
    const content = readContent(item.content)
    // Postgres TEXT refuses 0x00, and Prisma's engine a lone surrogate (half of a UTF-16 pair):
    // without this the whole batch would be a 500.
    if (content.includes('\u0000') || /\p{Cs}/u.test(content)) {
      return new UserSkillError(400, 'content_not_text', 'The file is not text.')
    }
    let description: string | null = null
    if (item.description !== undefined && item.description !== null) {
      if (typeof item.description !== 'string') {
        return new UserSkillError(400, 'description_invalid', 'description must be a string')
      }
      // One line: the description reaches the router's skill menu raw, where a line break
      // from an untrusted file could imitate the menu's own structure.
      description = cleanSkillText(item.description) || null
      if (description && description.length > DESCRIPTION_MAX_CHARS) {
        return new UserSkillError(400, 'description_too_long', `description must be ${DESCRIPTION_MAX_CHARS} characters or less`)
      }
    }
    if (typeof item.name !== 'string') return new UserSkillError(400, 'name_invalid', 'name is required')
    const name = normalizeName(item.name)
    const problem = nameProblem(name)
    if (problem) return problem
    return {
      name, description, content,
      declared: {
        nameSource: declaredSource(item.nameSource),
        descriptionSource: declaredSource(item.descriptionSource),
        aiModel: declaredModel(item.aiModel),
      },
    }
  } catch (e) {
    if (e instanceof UserSkillError) return e
    throw e
  }
}

export interface BatchResult {
  created: Record<string, unknown>[]
  enabled: string[]
  leftOff: string[]
  /** The project's stored map already broke a toggle rule, so nothing was switched. */
  enableSkipped?: string
}

const refusal = (index: number, e: UserSkillError): BatchItemRefusal => ({
  index, code: e.code, error: e.message,
  ...(typeof e.extra.suggestion === 'string' ? { suggestion: e.extra.suggestion } : {}),
})

function batchRefused(items: BatchItemRefusal[], total: number): UserSkillError {
  const sorted = [...items].sort((a, b) => a.index - b.index)
  return new UserSkillError(409, 'batch_refused',
    `${sorted.length} of ${total} skills cannot be saved; nothing was saved.`, { items: sorted })
}

/**
 * Create every skill of an upload batch, or none. Every row is validated first, under the
 * per-user lock (content, description, its name against the stored names and the rows before
 * it, the cap), so a refusal names every refused row with batch-aware suggestions; only a fully
 * valid batch is written. With a project, the new skills are switched on in that same
 * transaction while room under the per-project limit remains, as plugin adoption does.
 */
export async function createUserSkillsBatch(
  input: { userId: string; items: unknown; enableInProjectId?: unknown },
  actor: AuditActor,
): Promise<BatchResult> {
  const { userId, items, enableInProjectId } = input
  await refuseSkillWriteWhileActingAs(userId, actor)
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_SKILLS_PER_BATCH) {
    throw new UserSkillError(400, 'batch_invalid', `Send 1 to ${MAX_SKILLS_PER_BATCH} skills.`)
  }
  if (enableInProjectId !== undefined && enableInProjectId !== null
    && (typeof enableInProjectId !== 'string' || enableInProjectId.length < 1 || enableInProjectId.length > 64)) {
    throw new UserSkillError(400, 'batch_invalid', 'enableInProjectId must be a project id.')
  }
  const projectId = typeof enableInProjectId === 'string' ? enableInProjectId : null

  // Everything that needs no database runs before the lock: other writers wait for it with
  // their own short transaction timeouts.
  const read = items.map(readBatchRow)
  const refused: BatchItemRefusal[] = []
  read.forEach((r, i) => { if (r instanceof UserSkillError) refused.push(refusal(i, r)) })
  const valid = read.flatMap((r, i) => (r instanceof UserSkillError ? [] : [{ index: i, row: r }]))

  const outcome = await prisma.$transaction(async (tx) => {
    await lockUserSkills(tx, userId)
    const count = await tx.userAttackSkill.count({ where: { userId } })
    const checks = await checkNames(tx, userId, valid.map((v) => v.row.name))
    const writable: typeof valid = []
    valid.forEach((v, k) => {
      const check = checks[k]
      if (check.reason === 'name_taken' || check.reason === 'name_duplicate') {
        refused.push({
          index: v.index, code: check.reason,
          error: check.reason === 'name_taken'
            ? `You already have a skill named "${check.normalized}".`
            : `Another file in this upload is also named "${check.normalized}".`,
          ...(check.suggestion ? { suggestion: check.suggestion } : {}),
        })
      } else {
        writable.push(v)
      }
    })
    const room = MAX_SKILLS_PER_USER - count
    writable.forEach((v, k) => {
      if (k >= room) refused.push({ index: v.index, code: 'skill_limit', error: SKILL_LIMIT_MESSAGE })
    })
    if (refused.length) throw batchRefused(refused, items.length)

    const created: UserAttackSkill[] = []
    for (const v of writable) {
      try {
        created.push(await createUserSkillTx(tx, { userId, name: v.row.name, description: v.row.description, content: v.row.content }))
      } catch (e) {
        // The checks above ran under this same lock, so this is a second line of defence only.
        if (e instanceof UserSkillError) throw batchRefused([refusal(v.index, e)], items.length)
        throw e
      }
    }

    const toggles = projectId ? await enableInProjectTx(tx, userId, projectId, created.map((s) => s.id)) : null
    return { created, declared: writable.map((v) => v.row.declared), toggles }
  }, { timeout: 30_000, maxWait: 5_000 })

  const { created, declared, toggles } = outcome
  for (const [i, skill] of created.entries()) {
    await writeAudit({
      actorId: actor.actorId,
      action: 'user_attack_skill.create',
      targetType: USER_SKILL_AUDIT_TARGET,
      targetId: skill.id,
      after: withOwner(actor, {
        ...auditFields(skill), userId, via: 'batch', batchSize: created.length, declared: declared[i],
      }),
      source: actor.source,
    })
  }
  if (toggles?.project) {
    await writeAudit({
      actorId: actor.actorId,
      action: 'project.update',
      targetType: 'project',
      targetId: toggles.project.id,
      before: { attackSkillConfig: toggles.project.before ?? null },
      after: withOwner(actor, { changed: ['attackSkillConfig'], values: { attackSkillConfig: toggles.project.after } }),
      source: actor.source,
    })
  }
  return {
    created: created.map(pick),
    enabled: toggles?.enabled ?? [],
    leftOff: toggles?.leftOff ?? [],
    ...(toggles?.skipped ? { enableSkipped: toggles.skipped } : {}),
  }
}

/**
 * Turn `ids` on in the owner's project, in order, while room under the per-project limit
 * remains; the caller holds the per-user lock. Counted from the stored map, so a stale map in
 * an open form or drawer can never push the project past the limit.
 */
async function enableInProjectTx(tx: Tx, userId: string, projectId: string, ids: string[]) {
  const row = await tx.project.findFirst({ where: { id: projectId, userId }, select: { id: true, attackSkillConfig: true } })
  if (!row) throw new UserSkillError(404, 'project_not_found', 'That project is not yours.')
  const config = isObject(row.attackSkillConfig) ? row.attackSkillConfig : {}
  const user = isObject(config.user) ? (config.user as Record<string, boolean>) : {}
  let current: Record<string, boolean>
  try {
    current = await normalizeUserToggleMap(tx, userId, user)
  } catch (e) {
    // The stored map already breaks a rule (a quarantined skill left on): the skills are what
    // the person asked for, the toggles an extra, so the project is left as it is.
    if (e instanceof UserSkillError) return { enabled: [], leftOff: [], skipped: e.code, project: null }
    throw e
  }
  // Counted as normalizeUserToggleMap counts (truthy), or a legacy "true" left room it then refuses.
  let room = Math.max(0, MAX_ENABLED_USER_SKILLS_PER_PROJECT - Object.values(current).filter(Boolean).length)
  const next = { ...current }
  const enabled: string[] = []
  const leftOff: string[] = []
  for (const id of ids) {
    if (room > 0) {
      next[id] = true
      enabled.push(id)
      room--
    } else {
      leftOff.push(id)
    }
  }
  if (!enabled.length) return { enabled, leftOff, skipped: null, project: null }
  // builtIn is kept exactly as stored, absent included: filling it in would change which
  // built-in skills the agent runs.
  const after = { ...config, user: await normalizeUserToggleMap(tx, userId, next) }
  // Through Prisma, never raw SQL: updatedAt moves, so every form holding the old map sees a
  // stale save instead of writing the switch back.
  await tx.project.update({ where: { id: row.id }, data: { attackSkillConfig: after as Prisma.InputJsonValue } })
  return { enabled, leftOff, skipped: null, project: { id: row.id, before: row.attackSkillConfig, after } }
}

export interface UpdateUserSkillInput {
  userId: string
  skillId: string
  name?: unknown
  description?: unknown
  content?: unknown
}

export async function updateUserSkill(input: UpdateUserSkillInput, actor: AuditActor) {
  await refuseSkillWriteWhileActingAs(input.userId, actor)
  const { before, after } = await prisma.$transaction(async (tx) => {
    await lockUserSkills(tx, input.userId)
    const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })
    if (!existing) throw new UserSkillError(404, 'not_found', 'Skill not found')
    const data: Prisma.UserAttackSkillUpdateInput = {}
    // The edit window sends the name with every save; an unchanged one is not checked again, so a
    // name stored before the rules (a duplicate, a long one) never blocks editing the rest.
    const unchangedName = typeof input.name === 'string' && normalizeName(input.name) === existing.name
    if (input.name !== undefined && !unchangedName) data.name = await readName(tx, input.userId, input.name, existing.id)
    if (input.description !== undefined) {
      data.description = input.description === '' ? null : readDescription(input.description)
    }
    if (input.content !== undefined) data.content = readContent(input.content)
    const updated = Object.keys(data).length
      ? await tx.userAttackSkill.update({ where: { id: existing.id }, data })
      : existing
    return { before: existing, after: updated }
  })
  await writeAudit({
    actorId: actor.actorId,
    action: 'user_attack_skill.update',
    targetType: USER_SKILL_AUDIT_TARGET,
    targetId: after.id,
    before: auditFields(before),
    after: withOwner(actor, {
      ...auditFields(after),
      changed: (['name', 'description', 'content'] as const).filter((k) => before[k] !== after[k]),
    }),
    source: actor.source,
  })
  return pick(after)
}

/** Remove `skillId` from every project of `userId` that names it; returns how many changed. */
async function stripFromProjects(tx: Tx, userId: string, skillId: string): Promise<string[]> {
  const projects = await tx.project.findMany({ where: { userId }, select: { id: true, attackSkillConfig: true } })
  const changed: string[] = []
  for (const project of projects) {
    const config = project.attackSkillConfig
    if (!config || typeof config !== 'object' || Array.isArray(config)) continue
    const user = (config as Prisma.JsonObject).user
    if (!user || typeof user !== 'object' || Array.isArray(user) || !(skillId in user)) continue
    const { [skillId]: _removed, ...rest } = user as Prisma.JsonObject
    // Through Prisma, never raw SQL: updatedAt moves, so a form holding the old map gets a
    // stale-save refusal instead of writing the deleted id back.
    await tx.project.update({
      where: { id: project.id },
      data: { attackSkillConfig: { ...(config as Prisma.JsonObject), user: rest } },
    })
    changed.push(project.id)
  }
  return changed
}

/** How many of the skill's proposals a delete would remove (for the confirmation). */
export async function pendingProposalCount(userId: string, skillId: string): Promise<number> {
  const rows = await prisma.pluginOverride.findMany({
    where: { extensionPoint: 'user_skill.text', scopeType: 'user', scopeId: userId, targetGroup: skillId, status: 'proposed' },
    select: { changeSetId: true },
  })
  return new Set(rows.map((r) => r.changeSetId)).size
}

export async function deleteUserSkill(input: { userId: string; skillId: string }, actor: AuditActor) {
  await refuseSkillWriteWhileActingAs(input.userId, actor)
  const result = await prisma.$transaction(async (tx) => {
    await lockUserSkills(tx, input.userId)
    const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })
    if (!existing) throw new UserSkillError(404, 'not_found', 'Skill not found')
    const proposals = await deleteUserSkillProposalsTx(tx, input.userId, existing.id)
    await tx.userAttackSkill.delete({ where: { id: existing.id } })
    const projects = await stripFromProjects(tx, input.userId, existing.id)
    return { existing, proposals, projects }
  }, { timeout: 20_000 })
  for (const set of result.proposals) {
    await writeAudit({
      actorId: actor.actorId,
      action: 'plugin.override.delete',
      targetType: 'plugin_change_set',
      targetId: set.changeSetId,
      after: withOwner(actor, {
        pluginId: set.pluginId, point: 'user_skill.text', targetGroup: input.skillId,
        scope: 'user', scopeId: input.userId, reason: 'source_deleted',
      }),
      source: actor.source,
    })
  }
  await writeAudit({
    actorId: actor.actorId,
    action: 'user_attack_skill.delete',
    targetType: USER_SKILL_AUDIT_TARGET,
    targetId: input.skillId,
    before: auditFields(result.existing),
    after: withOwner(actor, { deletedProposals: result.proposals.length, projectsUpdated: result.projects.length }),
    source: actor.source,
  })
  return { deletedProposals: result.proposals.length, projectsUpdated: result.projects.length }
}

/**
 * Quarantine a skill whose originChain holds the revoked `pair`, under the owner's lock the
 * caller holds. False when it is already quarantined, or its owner released it from that
 * revocation after reading it.
 */
export async function quarantineUserSkillTx(tx: Tx, skillId: string, pair: string, reason: string): Promise<boolean> {
  const skill = await tx.userAttackSkill.findFirst({ where: { id: skillId }, select: { quarantinedAt: true, releasedFor: true } })
  if (!skill || skill.quarantinedAt || skill.releasedFor.includes(pair)) return false
  await tx.userAttackSkill.update({
    where: { id: skillId },
    data: { quarantinedAt: now(), quarantineReason: reason, quarantinedFor: pair },
  })
  return true
}

/** Make a never-versioned skill the first of its family, when a version is saved from it. */
export async function startLineageTx(tx: Tx, skill: { id: string; lineageRootId: string | null; version: number | null }) {
  if (skill.lineageRootId) return
  await tx.userAttackSkill.update({ where: { id: skill.id }, data: { lineageRootId: skill.id, version: skill.version ?? 1 } })
}

/**
 * Clear a quarantine. The caller has checked that the actor IS the owner. The release is
 * recorded for the revocation that caused it (releasedFor), so the reconciliation that still
 * sees that revocation does not quarantine it again, while a later one still can.
 */
export async function releaseUserSkill(input: { userId: string; skillId: string }, actor: AuditActor) {
  await refuseSkillWriteWhileActingAs(input.userId, actor)
  const skill = await prisma.$transaction(async (tx) => {
    await lockUserSkills(tx, input.userId)
    const existing = await tx.userAttackSkill.findFirst({ where: { id: input.skillId, userId: input.userId } })
    if (!existing) throw new UserSkillError(404, 'not_found', 'Skill not found')
    if (!existing.quarantinedAt) throw new UserSkillError(409, 'not_quarantined', 'This skill is not quarantined.')
    return {
      existing,
      updated: await tx.userAttackSkill.update({
        where: { id: existing.id },
        data: {
          quarantinedAt: null,
          quarantineReason: null,
          quarantinedFor: null,
          releasedFor: existing.quarantinedFor && !existing.releasedFor.includes(existing.quarantinedFor)
            ? [...existing.releasedFor, existing.quarantinedFor]
            : existing.releasedFor,
        },
      }),
    }
  })
  await writeAudit({
    actorId: actor.actorId,
    action: 'user_attack_skill.release',
    targetType: USER_SKILL_AUDIT_TARGET,
    targetId: input.skillId,
    before: { ...auditFields(skill.existing), quarantineReason: skill.existing.quarantineReason, quarantinedFor: skill.existing.quarantinedFor },
    after: withOwner(actor, auditFields(skill.updated)),
    source: actor.source,
  })
  return pick(skill.updated)
}

/** The route answer for a UserSkillError (`{error, code, ...}`), or null for anything else. */
export function userSkillErrorResponse(e: unknown): NextResponse | null {
  if (!(e instanceof UserSkillError)) return null
  return NextResponse.json({ error: e.message, code: e.code, ...e.extra }, { status: e.status })
}

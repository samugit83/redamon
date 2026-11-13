/**
 * The recon preset tools: list them (recon:read), keep a library of your own
 * (preset:write), and apply one to a project (preset:apply).
 *
 * Apply is the project form's "Load preset", run server-side: the same field
 * set, the same REPLACE semantics, the same "Preset applied" badge. It exists
 * because a preset cannot be reproduced any other way - update_recon_settings
 * caps a call at 200 keys, and a preset resets every field it does not name to
 * the running backends' default, which that tool knows nothing about.
 *
 * What makes each safe to hand an agent:
 *  - A preset only ever carries PRESET_FIELD_KEYS: never the scope, the
 *    engagement's limits or record, a credential, an upload or the MCP sandbox
 *    switch. Every value is validated like a recon:settings write, at storage
 *    and again at apply.
 *  - Presets are per user. Another user's preset id reads exactly like a
 *    missing one, and apply needs the caller to own both the project and the
 *    preset.
 *  - Every write is a compare-and-swap on `updatedAt` and is never retried
 *    here; every write is audited with its before and after, and deleting a
 *    preset audits its settings, which is the only undo there is.
 */
import prisma from '@/lib/prisma'
import { ACTIVATION_STATE_TRANSFERRING, TRANSFER_IN_PROGRESS_MESSAGE, holdOf } from '@/lib/graphHold'
import { writeAudit } from '@/lib/audit'
import { canonicalJson } from '@/lib/fingerprint'
import { RECON_PRESETS, getPresetById, type ReconPreset } from '@/lib/recon-presets'
import { assertMcpProjectAccess, mcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { assertReadableSelect } from '@/lib/mcpReadableFields'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { PRESET_FIELD_KEYS, extractPresetSettings } from '@/lib/project-preset-utils'
import { auditableKey } from '@/lib/reconSettings/filter'
import { field } from '@/lib/reconSettings/registry'
import { validateValue } from '@/lib/reconSettings/validators'
import { writeFireteamAudit } from '@/lib/reconSettings/crossField'
import { ipHostnameModeOf } from '@/lib/scopeGroups'
import { IP_PRESETS_RELYING_ON_HOSTNAMES } from '@/lib/recon-presets/targeting'
import {
  DefaultsUnavailable,
  MAX_USER_PRESETS,
  PRESET_DESCRIPTION_MAX,
  PRESET_NAME_MAX,
  PRESET_ROW_SELECT,
  computePresetApplication,
  fetchBackendDefaults,
  presetNameKey,
  projectPresetForRead,
  resolvePreset,
  sanitizePresetText,
  validateApplication,
  validatePresetSettings,
  type ResolvedPreset,
} from '@/lib/reconPresets/server'
import { clearPresetBadges, renamePresetBadges } from '@/lib/reconPresets/badges'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import {
  busyHint, casVersion, countQueuedJobsNeedingReview, describeAffectedSchedules, refuseSettingsChange,
} from '@/lib/mcp/writeTools'

/** How many changed keys a response lists before it only counts them. */
const UPDATE_DIFF_CAP = 50
const APPLY_LIST_CAP = 100

function builtinRow(p: ReconPreset) {
  return {
    id: p.id,
    source: 'builtin' as const,
    name: p.name,
    shortDescription: p.shortDescription,
    targetProfile: p.targetProfile,
    environment: p.environment,
    keyCount: Object.keys(p.parameters ?? {}).length,
  }
}

function userRow(row: {
  id: string; name: string; description: string; settings: unknown; updatedAt: Date
  createdVia: string; updatedVia: string; lastWriterTokenPrefix: string | null
}) {
  const { settings, ignoredKeys } = projectPresetForRead(row.settings)
  return {
    id: row.id,
    source: 'user' as const,
    name: row.name,
    description: row.description,
    keyCount: Object.keys(settings).length,
    ignoredKeyCount: ignoredKeys.length,
    updatedAt: row.updatedAt.toISOString(),
    createdVia: row.createdVia,
    updatedVia: row.updatedVia,
    lastWriterTokenPrefix: row.lastWriterTokenPrefix,
  }
}

const notFound = (presetId: string) => new McpToolError(
  `No preset '${presetId}' that this token can reach. Call list_recon_presets for the ids.`,
  'not_found'
)

const builtinImmutable = (presetId: string) => new McpToolError(
  `'${presetId}' is a built-in preset and cannot be changed or deleted. To start from it, ` +
  `create_recon_preset with fromPresetId: '${presetId}' and change the copy.`,
  'builtin_immutable'
)

// --- list_recon_presets ------------------------------------------------------------

const LIST_NOTES = [
  'Built-in presets are the curated engagement types and cannot be changed. User presets are ' +
    'this account\'s own library; another account\'s are never visible.',
  'apply_recon_preset applies one to a project and needs its own permission. It REPLACES the ' +
    'configuration: every preset field the preset does not name goes back to its default. Run it ' +
    'with dryRun first and read resetToDefault.',
  'To overlay ONLY the keys a preset names instead, read it with includeSettings and write those ' +
    'keys with update_recon_settings.',
  'No preset carries the engagement scope, its limits or its record, a credential, an upload, or ' +
    'the MCP sandbox switch, so applying one never touches those.',
]

export async function listReconPresets(
  ctx: McpContext,
  args: { presetId?: string; includeSettings?: boolean } = {}
) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const id = args.presetId?.trim()
  if (!id) {
    if (args.includeSettings) {
      throw new McpToolError(
        'includeSettings needs a presetId: a preset can hold over 600 values, so they are read one ' +
        'preset at a time.',
        'bad_args'
      )
    }
    return {
      builtin: RECON_PRESETS.map(builtinRow),
      user: await listUserPresets(ctx.token.userId),
      notes: LIST_NOTES,
    }
  }

  const builtin = getPresetById(id)
  if (builtin) {
    return {
      preset: {
        ...builtinRow(builtin),
        // The full description only for a named preset: they run to forty-plus
        // lines each, and twenty-six at once would crowd out everything else.
        fullDescription: builtin.fullDescription,
        ...(args.includeSettings ? { settings: builtin.parameters } : {}),
      },
    }
  }

  const row = await prisma.userProjectPreset.findFirst({
    where: { id, userId: ctx.token.userId },
    select: PRESET_ROW_SELECT,
  })
  if (!row) throw notFound(id)
  return {
    preset: {
      ...userRow(row),
      ...(args.includeSettings ? { settings: projectPresetForRead(row.settings).settings } : {}),
    },
  }
}

/**
 * The user's presets, or an explicit "unavailable". Never an empty list for a
 * failed read: "you have no presets" and "they could not be read" lead an agent
 * to different decisions.
 */
async function listUserPresets(userId: string) {
  try {
    const rows = await prisma.userProjectPreset.findMany({
      where: { userId },
      orderBy: { updatedAt: 'desc' },
      select: PRESET_ROW_SELECT,
    })
    return rows.map(userRow)
  } catch (err) {
    console.error('[mcp] could not read user presets:', err)
    return {
      status: 'unavailable' as const,
      note: 'Your saved presets could not be read right now. The built-in presets are complete.',
    }
  }
}

// --- create_recon_preset -------------------------------------------------------------

export interface CreatePresetArgs {
  name: string
  description?: string
  settings?: Record<string, unknown>
  fromPresetId?: string
  fromProjectId?: string
}

function refusedSetting(error: string, key: string, hint = '') {
  return new McpToolError(`${error}${hint}`, 'setting_rejected', { rejectedKey: auditableKey(key) })
}

async function assertNameFree(userId: string, name: string, exceptId?: string) {
  const mine = await prisma.userProjectPreset.findMany({ where: { userId }, select: { id: true, name: true } })
  const clash = mine.find(p => p.id !== exceptId && presetNameKey(p.name) === presetNameKey(name))
  if (clash) {
    throw new McpToolError(
      `You already have a preset called '${clash.name}' (id ${clash.id}). Choose another name, or ` +
      'change that one with update_recon_preset.',
      'preset_exists',
      { existingPresetId: clash.id }
    )
  }
}

/** A project's preset fields, minus upload paths that only that project may read. */
async function captureFromProject(ctx: McpContext, projectId: string) {
  await assertMcpProjectAccess(ctx.token, projectId)
  const select = Object.fromEntries(PRESET_FIELD_KEYS.map(k => [k, true]))
  assertReadableSelect(select, 'create_recon_preset')
  const row = await prisma.project.findUnique({ where: { id: projectId }, select })
  if (!row) throw new McpToolError('Project not found', 'not_found')

  const settings = extractPresetSettings(row as Record<string, unknown>)
  const notCaptured: string[] = []
  for (const key of Object.keys(settings)) {
    const spec = field(key)
    if (spec?.validator !== 'project_file' || settings[key] === null) continue
    // A path into this project's own upload directory is valid on the project
    // and on no other, and a preset exists to be loaded somewhere else.
    if (validateValue(key, spec, settings[key])) {
      notCaptured.push(key)
      delete settings[key]
    }
  }
  return { settings, notCaptured }
}

export async function createReconPreset(ctx: McpContext, args: CreatePresetArgs) {
  requireScope(ctx.token, 'preset:write')
  enforceRate(ctx, 'write')

  const name = sanitizePresetText(args.name, PRESET_NAME_MAX)
  if (!name) throw new McpToolError('A preset needs a name.', 'bad_args')
  const description = sanitizePresetText(args.description, PRESET_DESCRIPTION_MAX, { multiline: true })

  const sources = (['settings', 'fromPresetId', 'fromProjectId'] as const).filter(k => args[k] !== undefined)
  if (sources.length !== 1) {
    throw new McpToolError(
      'Pass exactly one source: settings, fromPresetId (copy a preset) or fromProjectId (capture a ' +
      `project). ${sources.length === 0 ? 'None was' : `${sources.join(' and ')} were`} given.`,
      'bad_args'
    )
  }

  let raw: Record<string, unknown>
  let notCaptured: string[] = []
  let origin: string
  let hint = ''
  if (args.settings !== undefined) {
    raw = args.settings
    origin = 'settings'
  } else if (args.fromPresetId !== undefined) {
    const from = await resolvePreset(ctx.token.userId, args.fromPresetId)
    if (!from) throw notFound(args.fromPresetId)
    raw = from.settings
    origin = `${from.source}:${from.id}`
    hint = from.source === 'user'
      ? ' That preset holds a value this surface no longer accepts: fix it with update_recon_preset first.'
      : ' The built-in preset holds a value this build refuses; report it.'
  } else {
    const captured = await captureFromProject(ctx, args.fromProjectId!)
    raw = captured.settings
    notCaptured = captured.notCaptured
    origin = 'project'
  }

  const valid = validatePresetSettings(raw)
  if (!valid.ok) throw refusedSetting(valid.error, valid.key, hint)

  const count = await prisma.userProjectPreset.count({ where: { userId: ctx.token.userId } })
  if (count >= MAX_USER_PRESETS) {
    throw new McpToolError(
      `You already have ${count} presets, which is the limit of ${MAX_USER_PRESETS}. Delete one first.`,
      'preset_limit'
    )
  }
  await assertNameFree(ctx.token.userId, name)

  const created = await prisma.userProjectPreset.create({
    data: {
      userId: ctx.token.userId,
      name,
      description,
      settings: valid.settings as never,
      createdVia: 'mcp',
      updatedVia: 'mcp',
      lastWriterTokenPrefix: ctx.token.tokenPrefix,
    },
    select: { id: true, name: true, updatedAt: true },
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.create_recon_preset',
    targetType: 'preset',
    targetId: created.id,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      origin, name, settings: valid.settings, notCaptured,
    },
    source: 'mcp',
  })

  return {
    presetId: created.id,
    name: created.name,
    keyCount: Object.keys(valid.settings).length,
    updatedAt: created.updatedAt.toISOString(),
    notCaptured,
    note:
      notCaptured.length > 0
        ? 'The notCaptured fields hold paths into that project\'s own upload directory, which no other ' +
          'project can read, so they were left out. Applying this preset resets them to their default.'
        : 'Saved to your preset library. apply_recon_preset applies it to a project.',
  }
}

// --- update_recon_preset -------------------------------------------------------------

export interface UpdatePresetArgs {
  presetId: string
  name?: string
  description?: string
  settings?: Record<string, unknown>
  removeKeys?: string[]
  expectedUpdatedAt?: string
}

/** jsonb does not keep object key order, so a stored value compares canonically. */
const canonical = (v: unknown) => canonicalJson(v ?? null)

export async function updateReconPreset(ctx: McpContext, args: UpdatePresetArgs) {
  requireScope(ctx.token, 'preset:write')
  enforceRate(ctx, 'write')
  if (getPresetById(args.presetId)) throw builtinImmutable(args.presetId)

  const row = await prisma.userProjectPreset.findFirst({
    where: { id: args.presetId, userId: ctx.token.userId },
    select: PRESET_ROW_SELECT,
  })
  if (!row) throw notFound(args.presetId)

  const before = projectPresetForRead(row.settings).settings
  const merged: Record<string, unknown> = { ...before, ...(args.settings ?? {}) }
  for (const key of args.removeKeys ?? []) delete merged[key]

  const name = args.name === undefined ? row.name : sanitizePresetText(args.name, PRESET_NAME_MAX)
  if (!name) throw new McpToolError('A preset needs a name.', 'bad_args')
  const description = args.description === undefined
    ? row.description
    : sanitizePresetText(args.description, PRESET_DESCRIPTION_MAX, { multiline: true })

  const keys = new Set([...Object.keys(before), ...Object.keys(merged)])
  const changed = [...keys].filter(k => canonical(before[k]) !== canonical(merged[k])).sort()
  if (changed.length === 0 && name === row.name && description === row.description) {
    throw new McpToolError(
      'Nothing to change: the name, description and settings you sent are what the preset already holds.',
      'bad_args'
    )
  }

  // Judged whole, after the merge: a preset is what it holds, not the patch.
  const valid = validatePresetSettings(merged)
  if (!valid.ok) throw refusedSetting(valid.error, valid.key)
  if (name !== row.name) await assertNameFree(ctx.token.userId, name, row.id)

  const renamed = name !== row.name
  const badgesRenamed = await prisma.$transaction(async tx => {
    const { count } = await tx.userProjectPreset.updateMany({
      where: { id: row.id, userId: ctx.token.userId, updatedAt: casVersion(row.updatedAt, args.expectedUpdatedAt) },
      data: {
        name,
        description,
        settings: valid.settings as never,
        updatedVia: 'mcp',
        lastWriterTokenPrefix: ctx.token.tokenPrefix,
      },
    })
    if (count === 0) {
      throw new McpToolError(
        'The preset changed since you read it. Read it again with list_recon_presets and retry.',
        'conflict'
      )
    }
    return renamed ? renamePresetBadges(tx, ctx.token.userId, row.id, name) : 0
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.update_recon_preset',
    targetType: 'preset',
    targetId: row.id,
    before: {
      name: row.name, description: row.description,
      settings: Object.fromEntries(changed.map(k => [k, before[k] ?? null])),
    },
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      name, description,
      settings: Object.fromEntries(changed.map(k => [k, valid.settings[k] ?? null])),
      ...(renamed ? { badgesRenamed } : {}),
    },
    source: 'mcp',
  })

  return {
    presetId: row.id,
    name,
    changedCount: changed.length,
    changed: changed.slice(0, UPDATE_DIFF_CAP).map(k => ({
      key: k,
      before: before[k] ?? null,
      after: Object.prototype.hasOwnProperty.call(valid.settings, k) ? valid.settings[k] : '(removed)',
    })),
    ...(renamed ? { renamedFrom: row.name, badgesRenamed } : {}),
    note:
      'Projects that already loaded this preset keep the settings it produced then; nothing is ' +
      're-applied. ' +
      (renamed
        ? `Their "Preset applied" badge now shows the new name (${badgesRenamed} project(s)).`
        : 'Their "Preset applied" badge stays: they still hold what loading it produced.'),
  }
}

// --- delete_recon_preset -------------------------------------------------------------

export async function deleteReconPreset(
  ctx: McpContext,
  args: { presetId: string; expectedUpdatedAt?: string }
) {
  requireScope(ctx.token, 'preset:write')
  enforceRate(ctx, 'write')
  if (getPresetById(args.presetId)) throw builtinImmutable(args.presetId)

  const row = await prisma.userProjectPreset.findFirst({
    where: { id: args.presetId, userId: ctx.token.userId },
    select: PRESET_ROW_SELECT,
  })
  if (!row) throw notFound(args.presetId)

  const badgesCleared = await prisma.$transaction(async tx => {
    const { count } = await tx.userProjectPreset.deleteMany({
      where: { id: row.id, userId: ctx.token.userId, updatedAt: casVersion(row.updatedAt, args.expectedUpdatedAt) },
    })
    return count === 0 ? null : clearPresetBadges(tx, ctx.token.userId, row.id)
  })
  if (badgesCleared === null) {
    const still = await prisma.userProjectPreset.findFirst({
      where: { id: row.id, userId: ctx.token.userId }, select: { id: true },
    })
    if (!still) throw notFound(args.presetId)
    throw new McpToolError(
      'The preset changed since you read it, so it was not deleted. Read it again and decide.',
      'conflict'
    )
  }

  // The audit row is the only way back: it keeps what the preset held.
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.delete_recon_preset',
    targetType: 'preset',
    targetId: row.id,
    before: { name: row.name, description: row.description, settings: projectPresetForRead(row.settings).settings },
    after: { tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix, deleted: true, badgesCleared },
    source: 'mcp',
  })

  return {
    presetId: row.id,
    name: row.name,
    deleted: true,
    badgesCleared,
    note:
      `Projects that loaded it keep their settings; their "Preset applied" badge is cleared ` +
      `(${badgesCleared} project(s)). There is no undo on this surface.`,
  }
}

// --- apply_recon_preset ----------------------------------------------------------------

/** Read for the apply, beside every preset field: the badge, and what the target is. */
const APPLY_CONTEXT_FIELDS = ['loadedPreset', 'ipMode', 'domainBatchMode', 'ipHostnameMode'] as const

export { IP_PRESETS_RELYING_ON_HOSTNAMES }

function hostnameModeNote(preset: ResolvedPreset, row: Record<string, unknown>): string | undefined {
  if (preset.source !== 'builtin' || !IP_PRESETS_RELYING_ON_HOSTNAMES.has(preset.builtin.id)) return undefined
  if (row.ipMode !== true || ipHostnameModeOf(row.ipHostnameMode) !== 'ip_only') return undefined
  return `'${preset.name}' expects hostnames found on the target IPs (reverse DNS), but this project's ` +
    'Hostnames on target IPs is ip_only, so no hostname is looked up and none is recorded. A preset ' +
    'never changes that mode: to record names, set ipHostnameMode to record_only (or a scanning mode) ' +
    'with update_project_scope.'
}

function targetMismatch(preset: ResolvedPreset, row: Record<string, unknown>): string | undefined {
  if (preset.source !== 'builtin') return undefined
  const profile = preset.builtin.targetProfile
  if (profile === 'ip' && row.ipMode !== true) {
    return `'${preset.name}' is built for IP targets and this project targets domains. It was ` +
      'applied as asked; its targeting was NOT changed.'
  }
  if (profile === 'domain' && row.ipMode === true) {
    return `'${preset.name}' is built for domain targets and this project targets IP addresses. It ` +
      'was applied as asked; its targeting was NOT changed.'
  }
  return undefined
}

export async function applyReconPreset(
  ctx: McpContext,
  args: { projectId: string; presetId: string; dryRun?: boolean; expectedUpdatedAt?: string }
) {
  requireScope(ctx.token, 'preset:apply')
  // preset:apply (W); a collaborator's apply is judged like the project save.
  const { access } = await mcpProjectAccess(ctx.token, args.projectId, 'W')
  enforceRate(ctx, 'write')

  // The LIVE writers, not only the scans: the in-app agent re-reads project
  // settings on every turn, and a preset carries the agent's settings too.
  const busy = await describeLiveGraphWriters(args.projectId)
  if (busy) {
    throw new McpToolError(
      `Cannot apply a preset while ${busy} for this project: it would change settings under work ` +
      'that is reading them. ' +
      busyHint(busy),
      'busy'
    )
  }

  const preset = await resolvePreset(ctx.token.userId, args.presetId)
  if (!preset) throw notFound(args.presetId)

  let defaults: Record<string, unknown>
  try {
    defaults = await fetchBackendDefaults()
  } catch (err) {
    if (!(err instanceof DefaultsUnavailable)) throw err
    console.error('[mcp] apply_recon_preset: backend defaults unavailable:', err)
    throw new McpToolError(
      'The recon and agent backends\' default settings could not be read, and a preset resets every ' +
      'field it does not name to those defaults. Nothing was written. Retry once the stack is healthy.',
      'defaults_unavailable'
    )
  }

  const select = {
    ...Object.fromEntries([...PRESET_FIELD_KEYS, ...APPLY_CONTEXT_FIELDS].map(k => [k, true])),
    updatedAt: true, activationState: true, activationStartedAt: true,
  }
  assertReadableSelect(select, 'apply_recon_preset')
  const row = await prisma.project.findUnique({ where: { id: args.projectId }, select }) as
    (Record<string, unknown> & { updatedAt: Date }) | null
  if (!row) throw new McpToolError('Project not found', 'not_found')
  // A transfer clears the old owner's providers and templates from the row (step 5.12): no preset meanwhile.
  if (holdOf(row as { activationState?: string; activationStartedAt?: Date | null }) === ACTIVATION_STATE_TRANSFERRING) {
    throw new McpToolError(TRANSFER_IN_PROGRESS_MESSAGE, 'project_transfer_in_progress')
  }

  const application = computePresetApplication(row, preset.settings, defaults, preset)
  const problem = await validateApplication(application, row, args.projectId, ctx.token.userId)
  if (problem) {
    const fromPreset = problem.key !== '' && Object.prototype.hasOwnProperty.call(preset.settings, problem.key)
    throw new McpToolError(
      `${problem.error}. Nothing was written. ` +
      (fromPreset
        ? preset.source === 'user'
          ? 'The preset holds this value: re-save the preset or fix it with update_recon_preset.'
          : 'The built-in preset holds this value, which this build refuses; report it.'
        : problem.key
          ? 'It is the running backend\'s DEFAULT for a field the preset does not name. Report it; ' +
            'no preset can be applied while a default breaks its own bound.'
          : ''),
      'setting_rejected',
      { rejectedKey: auditableKey(problem.key) }
    )
  }

  // Judged before the dry run answers, so a dry run tells a collaborator what applying would be refused.
  refuseSettingsChange(row, { ...application.data, loadedPreset: application.loadedPreset }, access, 'preset:apply')

  const mismatch = targetMismatch(preset, row)
  const hostnameNote = hostnameModeNote(preset, row)
  const report = {
    preset: { id: preset.id, source: preset.source, name: preset.name },
    changedCount: application.changed.length,
    changed: application.changed.slice(0, APPLY_LIST_CAP),
    resetToDefault: application.resetToDefault.slice(0, APPLY_LIST_CAP),
    resetToDefaultCount: application.resetToDefault.length,
    keptAsIs: application.keptAsIs,
    unchangedCount: application.unchangedCount,
    ...(mismatch ? { targetMismatch: mismatch } : {}),
    ...(hostnameNote ? { hostnameModeNote: hostnameNote } : {}),
  }

  if (args.dryRun) {
    return {
      ...report,
      dryRun: true,
      written: false,
      note: 'Nothing was written. Apply it without dryRun to write exactly this.',
    }
  }

  const { count } = await prisma.project.updateMany({
    where: { id: args.projectId, updatedAt: casVersion(row.updatedAt, args.expectedUpdatedAt) },
    data: { ...application.data, loadedPreset: application.loadedPreset } as never,
  })
  if (count === 0) {
    throw new McpToolError(
      'The project changed since this call read it. Nothing was written; run it again (a dryRun ' +
      'first) and decide on the new state.',
      'conflict'
    )
  }

  const changedData = Object.fromEntries(application.changed.map(k => [k, application.data[k]]))
  await writeFireteamAudit(args.projectId, row, changedData, { userId: ctx.token.userId, source: 'mcp' })
  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.apply_recon_preset',
    targetType: 'project',
    targetId: args.projectId,
    before: Object.fromEntries(application.changed.map(k => [k, row[k] ?? null])),
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      preset: report.preset,
      changes: changedData,
    },
    source: 'mcp',
  })

  const [queuedJobsNeedingReview, affectedSchedules] = await Promise.all([
    countQueuedJobsNeedingReview(args.projectId),
    describeAffectedSchedules(args.projectId),
  ])

  return {
    ...report,
    dryRun: false,
    written: true,
    queuedJobsNeedingReview,
    affectedSchedules,
    note:
      'Applied: settings take effect on the NEXT scan. The engagement\'s limits were not touched ' +
      'and still cap every rate at scan start. Call preflight_scope_check to see what will run.',
  }
}

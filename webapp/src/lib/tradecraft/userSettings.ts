/**
 * The account's ingestion settings, the values of the Configure ingestion dialog (§3.2, §4):
 * `TradecraftUserSettings.ingestion` holds only the keys a person changed, so a default the
 * spec changes later reaches every account that never touched it. The only writer of that
 * column; the merge with a resource's overrides is `effectiveSettings.ts`.
 *
 * Also the only writer of the account's focus recipes (`recipes`, §4.8 "My focus recipes").
 */
import { randomUUID } from 'node:crypto'
import prisma from '@/lib/prisma'
import { MAX_USER_RECIPES, RECIPE_NAME_MAX, type UserRecipe } from './focus'
import { lockTradecraftUserSettings } from './switch'
import { foreignSkillTopics, validateKinds, validateTopics } from './v2/focusFields'
import { effectiveSettings, canonicalJson } from './effectiveSettings'
import {
  SECTIONS, SETTINGS, cloneValue, validateUserSettings, type SettingError, type SettingsValues,
} from './settingsSpec'

const USER_KEYS = SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource')
const USER_KEY_SET: ReadonlySet<string> = new Set(USER_KEYS.map(s => s.key))

/** The ingestion sections that hold at least one setting a person sets at account level. */
export const INGESTION_SECTIONS: readonly string[] = SECTIONS
  .filter(sec => sec.scope === 'ingestion' && USER_KEYS.some(s => s.section === sec.id))
  .map(sec => sec.id)

export interface IngestionSettingsView {
  values: SettingsValues
  /** The keys whose value comes from the account (a saved value), in spec order. */
  changed: string[]
  defaults: SettingsValues
}

export type SaveResult = { ok: true; view: IngestionSettingsView } | { ok: false; errors: SettingError[] }

export function ingestionDefaults(): SettingsValues {
  const out: SettingsValues = {}
  for (const s of USER_KEYS) out[s.key] = cloneValue(s.default)
  return out
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function viewOf(stored: unknown): IngestionSettingsView {
  const eff = effectiveSettings({ user: { ingestion: stored }, scope: 'ingestion' })
  const values: SettingsValues = {}
  const changed: string[] = []
  for (const s of USER_KEYS) {
    values[s.key] = eff.values[s.key]
    if (eff.provenance[s.key] === 'user') changed.push(s.key)
  }
  return { values, changed, defaults: ingestionDefaults() }
}

export async function readIngestionSettings(userId: string): Promise<IngestionSettingsView> {
  const row = await prisma.tradecraftUserSettings.findUnique({ where: { userId }, select: { ingestion: true } })
  return viewOf(row?.ingestion ?? {})
}

/**
 * Applies `edit` to the stored values under the account's row lock, so two saves at once
 * (two tabs) each start from the other's committed result. Keys the spec does not know are
 * kept: a newer version may have written them, and a roll-back must not erase them.
 */
async function writeStored(
  userId: string, edit: (stored: Record<string, unknown>) => Record<string, unknown>,
): Promise<IngestionSettingsView> {
  return prisma.$transaction(async (tx) => {
    await lockTradecraftUserSettings(tx, userId)
    const row = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { ingestion: true } })
    const before = isPlainObject(row?.ingestion) ? row!.ingestion as Record<string, unknown> : {}
    const after = edit({ ...before })
    if (canonicalJson(after) !== canonicalJson(before)) {
      await tx.tradecraftUserSettings.upsert({
        where: { userId },
        create: { userId, ingestion: after as object },
        update: { ingestion: after as object },
      })
    }
    return viewOf(after)
  })
}

/**
 * Saves the values a person changed. Every key must be an ingestion setting of level
 * `user` or `both`, within the range the dialog shows; one bad key refuses the whole save.
 * A value equal to its default removes the key.
 */
export async function saveIngestionSettings(userId: string, input: unknown): Promise<SaveResult> {
  const parsed = validateUserSettings('ingestion', input)
  if (!parsed.ok) return parsed
  const defaults = ingestionDefaults()
  const view = await writeStored(userId, (stored) => {
    for (const [key, value] of Object.entries(parsed.value)) {
      if (canonicalJson(value) === canonicalJson(defaults[key])) delete stored[key]
      else stored[key] = value
    }
    return stored
  })
  return { ok: true, view }
}

/** Resets one section of the dialog, or `all`. */
export async function resetIngestionSettings(userId: string, section: string): Promise<SaveResult> {
  if (section !== 'all' && !INGESTION_SECTIONS.includes(section)) {
    return {
      ok: false,
      errors: [{ key: 'reset', code: 'bad_value', message: `reset must be "all" or one of ${INGESTION_SECTIONS.join(', ')}` }],
    }
  }
  const view = await writeStored(userId, (stored) => {
    for (const key of Object.keys(stored)) {
      if (!USER_KEY_SET.has(key)) continue
      if (section === 'all' || SETTINGS.find(s => s.key === key)!.section === section) delete stored[key]
    }
    return stored
  })
  return { ok: true, view }
}

// --- focus recipes ------------------------------------------------------------------

export type RecipeResult =
  | { ok: true; recipes: UserRecipe[] }
  | { ok: false; status: 400 | 404 | 409; code: string; field?: string; error: string }

const RECIPE_ID = /^[A-Za-z0-9_-]{1,64}$/
const CONTROL = /[\u0000-\u001f\u007f]/
const RECIPE_KEYS: ReadonlySet<string> = new Set(['name', 'topics', 'kinds'])

function recipesOf(stored: unknown): UserRecipe[] {
  if (!Array.isArray(stored)) return []
  return stored.flatMap((r): UserRecipe[] => {
    if (!isPlainObject(r) || typeof r.id !== 'string' || !RECIPE_ID.test(r.id) || typeof r.name !== 'string') return []
    const topics = Array.isArray(r.topics) ? r.topics.filter((t): t is string => typeof t === 'string') : []
    const kinds = Array.isArray(r.kinds) ? r.kinds.filter((k): k is string => typeof k === 'string') : []
    return [{ id: r.id, name: r.name, topics, kinds }]
  })
}

/** The account's recipes, oldest first; a malformed entry is skipped, never an error. */
export async function readRecipes(userId: string): Promise<UserRecipe[]> {
  const row = await prisma.tradecraftUserSettings.findUnique({ where: { userId }, select: { recipes: true } })
  return recipesOf(row?.recipes)
}

const refuse = (status: 400 | 404 | 409, code: string, error: string, field?: string): RecipeResult =>
  ({ ok: false, status, code, error, ...(field ? { field } : {}) })

function recipeName(input: unknown): { ok: true; name: string } | { ok: false; result: RecipeResult } {
  const name = typeof input === 'string' ? input.trim() : ''
  if (!name) return { ok: false, result: refuse(400, 'bad_recipe', 'A recipe needs a name', 'name') }
  if (name.length > RECIPE_NAME_MAX) return { ok: false, result: refuse(400, 'bad_recipe', `A recipe name holds at most ${RECIPE_NAME_MAX} characters`, 'name') }
  if (CONTROL.test(name)) return { ok: false, result: refuse(400, 'bad_recipe', 'A recipe name cannot hold a control character', 'name') }
  return { ok: true, name }
}

const nameKey = (name: string) => name.trim().replace(/\s+/g, ' ').toLowerCase()

type RecipeEdit =
  | { kind: 'add'; name: string; topics: string[]; kinds: string[] }
  | { kind: 'rename'; id: string; name: string }
  | { kind: 'delete'; id: string }

const BAD_EDIT = 'Send exactly one of {"add": {name, topics, kinds}}, {"rename": {id, name}} or {"delete": "<id>"}'

async function parseRecipeEdit(userId: string, input: unknown): Promise<{ ok: true; edit: RecipeEdit } | { ok: false; result: RecipeResult }> {
  const keys = isPlainObject(input) ? Object.keys(input) : []
  if (!isPlainObject(input) || keys.length !== 1) return { ok: false, result: refuse(400, 'bad_request', BAD_EDIT) }
  if (isPlainObject(input.add)) {
    const unknown = Object.keys(input.add).find(k => !RECIPE_KEYS.has(k))
    if (unknown) return { ok: false, result: refuse(400, 'bad_recipe', `A recipe has no field ${unknown}`, 'recipe') }
    const name = recipeName(input.add.name)
    if (!name.ok) return name
    const topics = validateTopics(input.add.topics, 'topics')
    if (!topics.ok) return { ok: false, result: refuse(400, 'bad_recipe', topics.error, topics.field) }
    const kinds = validateKinds(input.add.kinds, 'kinds')
    if (!kinds.ok) return { ok: false, result: refuse(400, 'bad_recipe', kinds.error, kinds.field) }
    if (topics.value.length === 0 && kinds.value.length === 0) {
      return { ok: false, result: refuse(400, 'bad_recipe', 'Pick at least one topic or content type', 'topics') }
    }
    const foreign = await foreignSkillTopics(userId, topics.value)
    if (foreign.length > 0) return { ok: false, result: refuse(400, 'foreign_skill', `Not one of your skills: ${foreign.join(', ')}`, 'topics') }
    return { ok: true, edit: { kind: 'add', name: name.name, topics: topics.value, kinds: kinds.value } }
  }
  if (isPlainObject(input.rename) && typeof input.rename.id === 'string') {
    const name = recipeName(input.rename.name)
    if (!name.ok) return name
    return { ok: true, edit: { kind: 'rename', id: input.rename.id, name: name.name } }
  }
  if (typeof input.delete === 'string') return { ok: true, edit: { kind: 'delete', id: input.delete } }
  return { ok: false, result: refuse(400, 'bad_request', BAD_EDIT) }
}

/**
 * Adds, renames or deletes one of the account's recipes, under the account's row lock so two
 * tabs adding at once cannot pass the cap together or both take one name.
 */
export async function editRecipes(userId: string, input: unknown): Promise<RecipeResult> {
  const parsed = await parseRecipeEdit(userId, input)
  if (!parsed.ok) return parsed.result
  const { edit } = parsed
  return prisma.$transaction(async (tx) => {
    await lockTradecraftUserSettings(tx, userId)
    const row = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { recipes: true } })
    const recipes = recipesOf(row?.recipes)
    const taken = (name: string, except?: string) => recipes.some(r => r.id !== except && nameKey(r.name) === nameKey(name))
    let next: UserRecipe[]
    if (edit.kind === 'add') {
      if (recipes.length >= MAX_USER_RECIPES) return refuse(409, 'recipe_cap', `An account holds at most ${MAX_USER_RECIPES} recipes`)
      if (taken(edit.name)) return refuse(409, 'recipe_name_taken', 'You already have a recipe with this name', 'name')
      next = [...recipes, { id: randomUUID().replace(/-/g, ''), name: edit.name, topics: edit.topics, kinds: edit.kinds }]
    } else {
      const target = recipes.find(r => r.id === edit.id)
      if (!target) return refuse(404, 'recipe_not_found', 'Recipe not found')
      if (edit.kind === 'rename') {
        if (taken(edit.name, edit.id)) return refuse(409, 'recipe_name_taken', 'You already have a recipe with this name', 'name')
        next = recipes.map(r => (r.id === edit.id ? { ...r, name: edit.name } : r))
      } else {
        next = recipes.filter(r => r.id !== edit.id)
      }
    }
    await tx.tradecraftUserSettings.upsert({
      where: { userId },
      create: { userId, recipes: next as unknown as object },
      update: { recipes: next as unknown as object },
    })
    return { ok: true, recipes: next }
  })
}

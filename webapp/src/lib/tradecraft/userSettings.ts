/**
 * The account's ingestion settings, the values of the Configure ingestion dialog (§3.2, §4), and
 * its search settings with its own synonym pairs, the values of Configure search (Q11):
 * `TradecraftUserSettings.ingestion` holds only the keys a person changed, so a default the
 * spec changes later reaches every account that never touched it. The only writer of that
 * column; the merge with a resource's overrides is `effectiveSettings.ts`.
 *
 * Also the only writer of the account's focus recipes (`recipes`, §4.8 "My focus recipes"), of
 * `search` and of `synonyms` (Q11 "My synonyms", user only).
 */
import { randomUUID } from 'node:crypto'
import prisma from '@/lib/prisma'
import { agentFetch } from '@/lib/agentFetch'
import { now } from '@/lib/authz/clock'
import { AGENT_ROUTES, ConvertAnswer } from './agentContract'
import { MAX_USER_RECIPES, RECIPE_NAME_MAX, type UserRecipe } from './focus'
import { lockTradecraftUserSettings } from './switch'
import { foreignSkillTopics, validateKinds, validateTopics } from './v2/focusFields'
import { effectiveSettings, canonicalJson } from './effectiveSettings'
import {
  SECTIONS, SETTINGS, SETTINGS_CONSTANTS, cloneValue, validateUserSettings, type SettingError, type SettingsValues,
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

// --- search settings (Configure search, Q11) ------------------------------------------

const SEARCH_KEYS = SETTINGS.filter(s => s.scope === 'search' && s.level !== 'resource')

/** One of the account's own synonym pairs, e.g. `PATT = PayloadsAllTheThings`; each works both ways. */
export interface SynonymPair {
  term: string
  expansion: string
}

export interface SearchSettingsView {
  values: SettingsValues
  /** The keys whose value comes from the account (a saved value), in spec order. */
  changed: string[]
  defaults: SettingsValues
  synonyms: SynonymPair[]
}

export type SearchSaveResult = { ok: true; view: SearchSettingsView } | { ok: false; errors: SettingError[] }

export const MAX_USER_SYNONYMS: number = SETTINGS_CONSTANTS.maxUserSynonyms
/** The agent clips a term to this many characters (`library/synonyms.MAX_TERM_CHARS`). */
export const SYNONYM_TERM_MAX = 100

export function searchDefaults(): SettingsValues {
  const out: SettingsValues = {}
  for (const s of SEARCH_KEYS) out[s.key] = cloneValue(s.default)
  return out
}

/**
 * The stored pairs, in the agent's shape (`{term, expansions}`, `library/synonyms.parse_user`),
 * as the dialog edits them: one expansion each. A malformed entry is skipped, never an error.
 */
function pairsOf(stored: unknown): SynonymPair[] {
  if (!Array.isArray(stored)) return []
  return stored.flatMap((p): SynonymPair[] => {
    if (!isPlainObject(p) || typeof p.term !== 'string' || !Array.isArray(p.expansions) || typeof p.expansions[0] !== 'string') return []
    return [{ term: p.term, expansion: p.expansions[0] }]
  }).slice(0, MAX_USER_SYNONYMS)
}

function searchViewOf(stored: unknown, synonyms: unknown): SearchSettingsView {
  const eff = effectiveSettings({ user: { search: stored }, scope: 'search' })
  const values: SettingsValues = {}
  const changed: string[] = []
  for (const s of SEARCH_KEYS) {
    values[s.key] = eff.values[s.key]
    if (eff.provenance[s.key] === 'user') changed.push(s.key)
  }
  return { values, changed, defaults: searchDefaults(), synonyms: pairsOf(synonyms) }
}

export async function readSearchSettings(userId: string): Promise<SearchSettingsView> {
  const row = await prisma.tradecraftUserSettings.findUnique({ where: { userId }, select: { search: true, synonyms: true } })
  return searchViewOf(row?.search ?? {}, row?.synonyms ?? [])
}

const synonymError = (message: string): SettingError => ({ key: 'synonyms', code: 'bad_value', message })

/** The pairs as typed, trimmed; refused whole when one is malformed, a duplicate, or past the cap. */
export function validateSynonyms(input: unknown): { ok: true; value: SynonymPair[] } | { ok: false; errors: SettingError[] } {
  if (!Array.isArray(input)) return { ok: false, errors: [synonymError('synonyms is a list of {term, expansion}')] }
  if (input.length > MAX_USER_SYNONYMS) return { ok: false, errors: [synonymError(`At most ${MAX_USER_SYNONYMS} synonym pairs`)] }
  const out: SynonymPair[] = []
  const seen = new Set<string>()
  for (const [i, raw] of input.entries()) {
    if (!isPlainObject(raw) || Object.keys(raw).some(k => k !== 'term' && k !== 'expansion')) {
      return { ok: false, errors: [synonymError(`Pair ${i + 1} is {term, expansion}`)] }
    }
    const rawTerm = typeof raw.term === 'string' ? raw.term : ''
    const rawExpansion = typeof raw.expansion === 'string' ? raw.expansion : ''
    // Checked before the trim: a line break is no edge space to forgive.
    if (CONTROL.test(rawTerm) || CONTROL.test(rawExpansion)) return { ok: false, errors: [synonymError(`Pair ${i + 1} cannot hold a control character`)] }
    const term = rawTerm.trim()
    const expansion = rawExpansion.trim()
    if (!term || !expansion) return { ok: false, errors: [synonymError(`Pair ${i + 1} needs both words`)] }
    if (term.length > SYNONYM_TERM_MAX || expansion.length > SYNONYM_TERM_MAX) {
      return { ok: false, errors: [synonymError(`Pair ${i + 1}: each side holds at most ${SYNONYM_TERM_MAX} characters`)] }
    }
    if (term.toLowerCase() === expansion.toLowerCase()) return { ok: false, errors: [synonymError(`Pair ${i + 1} names the same word twice`)] }
    const key = `${term.toLowerCase()}\u0000${expansion.toLowerCase()}`
    if (seen.has(key)) return { ok: false, errors: [synonymError(`${term} = ${expansion} is listed twice`)] }
    seen.add(key)
    out.push({ term, expansion })
  }
  return { ok: true, value: out }
}

/**
 * Saves Configure search (Q11): the search settings a person changed (user level only, each
 * within its range; a value equal to its default removes the key) and, when given, the whole list
 * of the account's synonym pairs. One bad value refuses the whole save. A change reaches the agent
 * from the next message (the run catalog reads it); nothing is re-ingested and nothing turns stale.
 */
export async function saveSearchSettings(userId: string, input: unknown): Promise<SearchSaveResult> {
  if (!isPlainObject(input)) return { ok: false, errors: [{ key: '', code: 'not_an_object', message: 'search must be an object' }] }
  const { synonyms: rawSynonyms, ...values } = input
  const parsed = validateUserSettings('search', values)
  if (!parsed.ok) return parsed
  let synonyms: SynonymPair[] | null = null
  if (rawSynonyms !== undefined) {
    const s = validateSynonyms(rawSynonyms)
    if (!s.ok) return s
    synonyms = s.value
  }
  const defaults = searchDefaults()
  return { ok: true, view: await writeSearch(userId, (stored) => {
    for (const [key, value] of Object.entries(parsed.value)) {
      if (canonicalJson(value) === canonicalJson(defaults[key])) delete stored[key]
      else stored[key] = value
    }
    return stored
  }, synonyms) }
}

/** Every search setting back to its default; the synonym pairs are the person's own and stay. */
export async function resetSearchSettings(userId: string): Promise<SearchSaveResult> {
  const keys: ReadonlySet<string> = new Set(SEARCH_KEYS.map(s => s.key))
  return { ok: true, view: await writeSearch(userId, (stored) => {
    for (const key of Object.keys(stored)) if (keys.has(key)) delete stored[key]
    return stored
  }, null) }
}

/** Under the account's row lock, as the ingestion writer: two tabs saving at once each see the other's result. */
async function writeSearch(
  userId: string, edit: (stored: Record<string, unknown>) => Record<string, unknown>, synonyms: SynonymPair[] | null,
): Promise<SearchSettingsView> {
  return prisma.$transaction(async (tx) => {
    await lockTradecraftUserSettings(tx, userId)
    const row = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { search: true, synonyms: true } })
    const before = isPlainObject(row?.search) ? row!.search as Record<string, unknown> : {}
    const after = edit({ ...before })
    const nextSynonyms = synonyms === null ? row?.synonyms ?? [] : synonyms.map(p => ({ term: p.term, expansions: [p.expansion] }))
    const data: Record<string, object> = {}
    if (canonicalJson(after) !== canonicalJson(before)) data.search = after as object
    if (synonyms !== null && canonicalJson(nextSynonyms) !== canonicalJson(row?.synonyms ?? [])) data.synonyms = nextSynonyms as object
    if (Object.keys(data).length > 0) {
      await tx.tradecraftUserSettings.upsert({ where: { userId }, create: { userId, ...data }, update: data })
    }
    return searchViewOf(after, nextSynonyms)
  })
}

// --- the conversion of 1.x resources (T9.1) ---------------------------------------------

const CONVERT_TIMEOUT_MS = 10_000

/**
 * Asks the agent to convert the account's 1.x resources (§7.2), after 2.0 is turned on; answers
 * how many it queued, or null when it did not answer. Best effort: the conversion is idempotent
 * and the agent's boot sweep converts what a missed call left, so a refusal or an unreachable
 * agent is logged, never an error of the switch.
 */
export async function startConversion(userId: string): Promise<number | null> {
  try {
    const resp = await agentFetch(AGENT_ROUTES.convert(userId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, { timeoutMs: CONVERT_TIMEOUT_MS })
    if (!resp.ok) {
      console.error(`[tradecraft] convert_refused status=${resp.status}`)
      return null
    }
    const answer = ConvertAnswer.safeParse(await resp.json().catch(() => null))
    return answer.success ? answer.data.queued : null
  } catch {
    console.error('[tradecraft] convert_unreachable')
    return null
  }
}

/**
 * Records the person's answer to the Save & refresh all offer (§7.2: it is offered once), whichever
 * it was. Under the account's row lock, so the first answer's time stays.
 */
export async function markBulkRefreshOffered(userId: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await lockTradecraftUserSettings(tx, userId)
    const row = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { bulkRefreshOfferedAt: true } })
    if (row?.bulkRefreshOfferedAt) return
    const at = now()
    await tx.tradecraftUserSettings.upsert({
      where: { userId },
      create: { userId, bulkRefreshOfferedAt: at },
      update: { bulkRefreshOfferedAt: at },
    })
  })
}

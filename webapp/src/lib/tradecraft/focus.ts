/**
 * The ingestion focus of a resource (§6.14): what the form edits, what
 * `UserTradecraftResource.focus` stores, and what the agent's focus stage reads. An empty
 * object is no focus at all (mode Everything, today's behaviour), so a row written before
 * phase 5 needs no change.
 *
 * Client-safe: the Focus section and the server's validator (`v2/focusFields.ts`) share these
 * names and limits.
 */
import type { PreviewResult } from './agentContract'
import { SETTINGS_CONSTANTS } from './settingsSpec'
import { KINDS, RECIPES, topicById } from './vocab'

export const FOCUS_MODES = ['everything', 'focused', 'tagOnly'] as const
export const FOCUS_STRICTNESS = ['loose', 'balanced', 'strict'] as const
export const FOCUS_SKIP_MODES = ['add', 'replace'] as const

export type FocusMode = (typeof FOCUS_MODES)[number]
export type FocusStrictness = (typeof FOCUS_STRICTNESS)[number]
export type FocusSkipMode = (typeof FOCUS_SKIP_MODES)[number]

export interface Focus {
  mode: FocusMode
  /** The recipe that last filled the chips (a built-in id or one of the owner's); the chips stay editable. */
  recipe?: string
  /** Vocabulary topic ids, or `user_skill:<id>` for the owner's own skills. */
  topics: string[]
  kinds: string[]
  keep: string
  skip: string
  /** `add`: the Skip text joins the account's "Always skip"; `replace`: it stands alone. */
  skipMode: FocusSkipMode
  strictness: FocusStrictness
}

/** Keep and Skip each, the focus prompt the model reads (§6.14). */
export const FOCUS_TEXT_MAX: number = SETTINGS_CONSTANTS.focusPromptMaxChars
/** Topics on one resource: what the agent's focus stage reads (its `MAX_TOPICS`); the fixed list is about 20. */
export const FOCUS_TOPICS_MAX = 30

export const USER_SKILL_TOPIC_PREFIX = 'user_skill:'
const SKILL_ID = /^[A-Za-z0-9_-]{1,64}$/

export function userSkillTopic(skillId: string): string {
  return `${USER_SKILL_TOPIC_PREFIX}${skillId}`
}

/** The skill id a `user_skill:<id>` topic names, or null for any other topic. */
export function userSkillIdOf(topic: string): string | null {
  if (!topic.startsWith(USER_SKILL_TOPIC_PREFIX)) return null
  const id = topic.slice(USER_SKILL_TOPIC_PREFIX.length)
  return SKILL_ID.test(id) ? id : null
}

/**
 * The account's default mode (`focus.defaultMode`) as a resource's mode: the settings spec
 * spells Tag only `tag_only`, the stored focus `tagOnly`.
 */
export function focusModeOfDefault(value: unknown): FocusMode {
  if (value === 'tag_only') return 'tagOnly'
  return (FOCUS_MODES as readonly unknown[]).includes(value) ? value as FocusMode : 'everything'
}

/** One of the owner's recipes (§4.8 "My focus recipes"), kept in `TradecraftUserSettings.recipes`. */
export interface UserRecipe {
  id: string
  name: string
  topics: string[]
  kinds: string[]
}

export const MAX_USER_RECIPES: number = SETTINGS_CONSTANTS.maxUserRecipes
export const RECIPE_NAME_MAX = 60

// --- the Focus section's rules (T5.6) ------------------------------------------------

export const EMPTY_FOCUS: Readonly<Focus> = Object.freeze({
  mode: 'everything', topics: [], kinds: [], keep: '', skip: '', skipMode: 'add', strictness: 'balanced',
})

const KIND_LABEL: Readonly<Record<string, string>> = Object.fromEntries(KINDS.map(k => [k.id, k.label]))

export function clampFocusText(text: string): string {
  return text.slice(0, FOCUS_TEXT_MAX)
}

/** A topic in words: the fixed list's label, the owner's skill by its name, else the id itself. */
export function topicLabel(topic: string, skillNames: Readonly<Record<string, string>> = {}): string {
  const skill = userSkillIdOf(topic)
  if (skill) return skillNames[skill] ?? topic
  return topicById(topic)?.label ?? topic
}

/** The Keep text the chips write: what the model is asked to keep, in plain words. */
export function keepTextFor(topics: readonly string[], kinds: readonly string[], skillNames: Readonly<Record<string, string>> = {}): string {
  const about = topics.map(t => topicLabel(t, skillNames)).join(' or ')
  // A label is lowered only when it starts with an ordinary word: "PoC" stays as written.
  const what = kinds.map(k => (KIND_LABEL[k] ?? k).replace(/^[A-Z](?=[a-z]*\b)/, c => c.toLowerCase())).join(', ')
  if (about && what) return clampFocusText(`Pages about ${about}: ${what}.`)
  if (about) return clampFocusText(`Pages about ${about}.`)
  if (what) return clampFocusText(`Pages with ${what}.`)
  return ''
}

/** The account's defaults (§4.8) as a new resource's focus. */
export function newResourceFocus(values: Readonly<Record<string, unknown>>): Focus {
  const strictness = (FOCUS_STRICTNESS as readonly unknown[]).includes(values['focus.defaultStrictness'])
    ? values['focus.defaultStrictness'] as FocusStrictness
    : 'balanced'
  return { ...EMPTY_FOCUS, topics: [], kinds: [], mode: focusModeOfDefault(values['focus.defaultMode']), strictness }
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** A saved resource's focus as the form edits it; `{}` (no focus) is Everything. */
export function focusFromStored(stored: unknown): Focus {
  const f = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored as Record<string, unknown> : {}
  const pick = <T extends string>(v: unknown, values: readonly T[], fallback: T): T => ((values as readonly unknown[]).includes(v) ? v as T : fallback)
  return {
    mode: pick(f.mode, FOCUS_MODES, 'everything'),
    ...(typeof f.recipe === 'string' && f.recipe ? { recipe: f.recipe } : {}),
    topics: strings(f.topics),
    kinds: strings(f.kinds),
    keep: typeof f.keep === 'string' ? f.keep : '',
    skip: typeof f.skip === 'string' ? f.skip : '',
    skipMode: pick(f.skipMode, FOCUS_SKIP_MODES, 'add'),
    strictness: pick(f.strictness, FOCUS_STRICTNESS, 'balanced'),
  }
}

/** What a save sends: Everything is no focus at all, so choosing it never marks the resource stale. */
export function focusPayload(f: Focus): Focus | Record<string, never> {
  return f.mode === 'everything' ? {} : f
}

/**
 * New chips. Keep follows them while it is empty or still the text the old chips wrote; once
 * the person edited it, it is theirs.
 */
export function setChips(f: Focus, next: { topics?: string[]; kinds?: string[] }, skillNames: Readonly<Record<string, string>> = {}): Focus {
  const topics = (next.topics ?? f.topics).slice(0, FOCUS_TOPICS_MAX)
  const kinds = next.kinds ?? f.kinds
  const generated = f.keep === '' || f.keep === keepTextFor(f.topics, f.kinds, skillNames)
  return { ...f, topics, kinds, keep: generated ? keepTextFor(topics, kinds, skillNames) : f.keep }
}

/** A recipe fills the chips (and the built-in recipe's Skip, unless the person wrote one); it stays editable. */
export function applyRecipe(
  f: Focus, recipe: { id: string; topics: readonly string[]; kinds: readonly string[]; skip?: string },
  skillNames: Readonly<Record<string, string>> = {},
): Focus {
  const previousSkip = RECIPES.find(r => r.id === f.recipe)?.skip ?? ''
  const skipIsTheRecipes = f.skip === '' || f.skip === previousSkip
  const filled = setChips(f, { topics: [...recipe.topics], kinds: [...recipe.kinds] }, skillNames)
  return { ...filled, recipe: recipe.id, skip: skipIsTheRecipes ? clampFocusText(recipe.skip ?? '') : f.skip }
}

export interface FocusCost {
  /** null while the page count is unknown (before Check URL). */
  triageCalls: number | null
  contentChecks: number
}

/** §6.14 "Cost before saving": one small call per batch of titles, then the content checks up to their limit. */
export function focusCost({ mode, entries, maxContentChecks }: { mode: FocusMode; entries: number | null; maxContentChecks: number }): FocusCost {
  if (mode === 'everything') return { triageCalls: 0, contentChecks: 0 }
  const batch = SETTINGS_CONSTANTS.titleTriageBatch
  if (entries === null) return { triageCalls: null, contentChecks: maxContentChecks }
  return { triageCalls: Math.ceil(entries / batch), contentChecks: Math.min(maxContentChecks, entries) }
}

export function focusCostText({ triageCalls, contentChecks }: FocusCost): string {
  if (triageCalls === 0 && contentChecks === 0) return 'No model calls: every page is kept'
  const triage = triageCalls === null
    ? `title triage ≈ 1 small LLM call per ${SETTINGS_CONSTANTS.titleTriageBatch} pages`
    : `title triage ≈ ${triageCalls} small LLM ${triageCalls === 1 ? 'call' : 'calls'}`
  const checks = contentChecks > 0 ? ` · content checks up to ${contentChecks} ${contentChecks === 1 ? 'call' : 'calls'}` : ''
  return `Estimated cost: ${triage}${checks}`
}

/** The preview's counts in words. A model error drops nothing (TD-20): the sample stays kept. */
export function previewSummary(r: PreviewResult): string {
  if (r.error_code) return `The model could not judge the titles (${r.error_code}): every page would be kept`
  const total = r.kept + r.maybe + r.dropped
  const maybe = r.maybe > 0 ? `, ${r.maybe} uncertain,` : ''
  return `Would keep ${r.kept}, drop ${r.dropped}${maybe} of ${total} pages`
}

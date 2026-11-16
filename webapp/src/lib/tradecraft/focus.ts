/**
 * The ingestion focus of a resource (§6.14): what the form edits, what
 * `UserTradecraftResource.focus` stores, and what the agent's focus stage reads. An empty
 * object is no focus at all (mode Everything, today's behaviour), so a row written before
 * phase 5 needs no change.
 *
 * Client-safe: the Focus section and the server's validator (`v2/focusFields.ts`) share these
 * names and limits.
 */
import { SETTINGS_CONSTANTS } from './settingsSpec'

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
/** Topics on one resource: the fixed list is about 20, the rest are the owner's skills. */
export const FOCUS_TOPICS_MAX = 100

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

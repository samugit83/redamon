/**
 * The Tradecraft vocabulary: the fixed topic list (the 14 built-in attack skills plus the
 * areas no skill covers), the eight content kinds, the 10 built-in focus recipes, the
 * keywords that tag a page by rules, the technology names entities are matched against,
 * the built-in synonyms of search, and the kind each phase prefers.
 *
 * A code constant, not a table (master plan TD-14). scripts/gen-tradecraft-spec.mjs
 * copies vocab.json to agentic/tradecraft/vocab.json; the skill topic ids equal the
 * agent's KNOWN_ATTACK_PATHS so the Intent Router's choice maps to a topic.
 */
import vocab from './vocab.json'

export interface Topic { id: string; label: string; source: 'skill' | 'area' }
export interface Kind { id: string; label: string; mapLabel: string }
export interface Recipe { id: string; label: string; topics: string[]; kinds: string[]; skip: string }
export interface Technology { id: string; name: string; category: string; aliases: string[] }
export interface Synonym { term: string; expansions: string[] }

export const VOCAB_VERSION: number = vocab.version
export const TOPICS: readonly Topic[] = vocab.topics as Topic[]
export const KINDS: readonly Kind[] = vocab.kinds
export const KIND_ALIASES: Readonly<Record<string, string>> = vocab.kindAliases
/** Empty `topics` or `kinds` in a recipe means any. */
export const RECIPES: readonly Recipe[] = vocab.recipes
export const TOPIC_KEYWORDS: Readonly<Record<string, string[]>> = vocab.keywords
export const KIND_KEYWORDS: Readonly<Record<string, string[]>> = vocab.kindKeywords
export const TECHNOLOGIES: readonly Technology[] = vocab.technologies
export const SYNONYMS: readonly Synonym[] = vocab.synonyms
export const KIND_PREFERENCE_BY_PHASE: Readonly<Record<string, string[]>> = vocab.kindPreferenceByPhase

export function topicIds(): string[] {
  return TOPICS.map(t => t.id)
}

export function skillTopicIds(): string[] {
  return TOPICS.filter(t => t.source === 'skill').map(t => t.id)
}

export function kindIds(): string[] {
  return KINDS.map(k => k.id)
}

export function topicById(id: string): Topic | undefined {
  return TOPICS.find(t => t.id === id)
}

export function recipeById(id: string): Recipe | undefined {
  return RECIPES.find(r => r.id === id)
}

/** A kind id from a kind id or one of its aliases ("methodology", "misconfigurations"...). */
export function resolveKind(name: string): string | undefined {
  const key = name.trim().toLowerCase()
  if (KINDS.some(k => k.id === key)) return key
  return KIND_ALIASES[key]
}

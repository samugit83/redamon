/**
 * The resource's ingestion focus (§6.14) as a person may save it, and the chips the focus
 * recipes share. The shape lives in `../focus.ts`; this module judges what the browser sent.
 * The agent's focus stage reads the stored value as it is, so every field is checked here:
 * the topics and kinds against the fixed lists (the model's answer is validated against the
 * same lists), Keep and Skip against the prompt limit.
 *
 * A `user_skill:<id>` topic must name one of the owner's own skills; that needs a database
 * read, so the writers ask `foreignSkillTopics` after the shape passed.
 */
import type { Prisma } from '@prisma/client'
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import {
  FOCUS_MODES, FOCUS_SKIP_MODES, FOCUS_STRICTNESS, FOCUS_TEXT_MAX, FOCUS_TOPICS_MAX, userSkillIdOf, type Focus,
} from '../focus'
import { kindIds, topicIds } from '../vocab'

type Db = Prisma.TransactionClient | typeof prisma

export type FocusResult =
  | { ok: true; value: Focus | Record<string, never> }
  | { ok: false; field: string; error: string }

export type ListResult = { ok: true; value: string[] } | { ok: false; field: string; error: string }

const KEYS: ReadonlySet<string> = new Set(['mode', 'recipe', 'topics', 'kinds', 'keep', 'skip', 'skipMode', 'strictness'])
const RECIPE_ID = /^[A-Za-z0-9_:-]{1,100}$/
const TOPIC_IDS: ReadonlySet<string> = new Set(topicIds())
const KIND_IDS: ReadonlySet<string> = new Set(kindIds())

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function stringList(input: unknown, field: string, max: number, known: (s: string) => boolean, what: string): ListResult {
  if (input === undefined) return { ok: true, value: [] }
  if (!Array.isArray(input)) return { ok: false, field, error: `${field} must be a list` }
  const out: string[] = []
  for (const item of input) {
    if (typeof item !== 'string' || !known(item)) {
      return { ok: false, field, error: `${JSON.stringify(item)} is not ${what}` }
    }
    if (!out.includes(item)) out.push(item)
  }
  if (out.length > max) return { ok: false, field, error: `${field} holds at most ${max} entries` }
  return { ok: true, value: out }
}

/** Vocabulary topic ids, or `user_skill:<id>` of a skill (whose owner `foreignSkillTopics` checks). */
export function validateTopics(input: unknown, field: string): ListResult {
  return stringList(input, field, FOCUS_TOPICS_MAX, t => TOPIC_IDS.has(t) || userSkillIdOf(t) !== null,
    'a topic of the fixed list or user_skill:<id> of one of your skills')
}

export function validateKinds(input: unknown, field: string): ListResult {
  return stringList(input, field, KIND_IDS.size, k => KIND_IDS.has(k), `a content type (${[...KIND_IDS].join(', ')})`)
}

function promptText(input: unknown, field: string): { ok: true; value: string } | { ok: false; field: string; error: string } {
  if (input === undefined) return { ok: true, value: '' }
  if (typeof input !== 'string') return { ok: false, field, error: `${field} must be text` }
  const text = input.trim()
  if (text.includes('\u0000')) return { ok: false, field, error: `${field} cannot hold a NUL character` }
  if (text.length > FOCUS_TEXT_MAX) return { ok: false, field, error: `${field} holds at most ${FOCUS_TEXT_MAX} characters` }
  return { ok: true, value: text }
}

function oneOf<T extends string>(input: unknown, values: readonly T[], fallback: T): T | null {
  if (input === undefined) return fallback
  return (values as readonly unknown[]).includes(input) ? input as T : null
}

export function validateFocus(input: unknown): FocusResult {
  if (input === undefined) return { ok: true, value: {} }
  if (!isPlainObject(input)) return { ok: false, field: 'focus', error: 'The focus must be an object' }
  if (Object.keys(input).length === 0) return { ok: true, value: {} }
  const unknown = Object.keys(input).find(k => !KEYS.has(k))
  if (unknown) return { ok: false, field: 'focus', error: `The focus has no field ${unknown}` }

  if (!(FOCUS_MODES as readonly unknown[]).includes(input.mode)) {
    return { ok: false, field: 'focus.mode', error: `The focus mode is one of ${FOCUS_MODES.join(', ')}` }
  }
  const strictness = oneOf(input.strictness, FOCUS_STRICTNESS, 'balanced')
  if (!strictness) return { ok: false, field: 'focus.strictness', error: `Strictness is one of ${FOCUS_STRICTNESS.join(', ')}` }
  const skipMode = oneOf(input.skipMode, FOCUS_SKIP_MODES, 'add')
  if (!skipMode) return { ok: false, field: 'focus.skipMode', error: 'The Skip text is added to "Always skip" (add) or replaces it (replace)' }
  const topics = validateTopics(input.topics, 'focus.topics')
  if (!topics.ok) return topics
  const kinds = validateKinds(input.kinds, 'focus.kinds')
  if (!kinds.ok) return kinds
  const keep = promptText(input.keep, 'focus.keep')
  if (!keep.ok) return keep
  const skip = promptText(input.skip, 'focus.skip')
  if (!skip.ok) return skip

  const value: Focus = {
    mode: input.mode as Focus['mode'],
    topics: topics.value,
    kinds: kinds.value,
    keep: keep.value,
    skip: skip.value,
    skipMode,
    strictness,
  }
  if (input.recipe !== undefined && input.recipe !== '') {
    if (typeof input.recipe !== 'string' || !RECIPE_ID.test(input.recipe)) {
      return { ok: false, field: 'focus.recipe', error: 'Not a recipe id' }
    }
    value.recipe = input.recipe
  }
  return { ok: true, value }
}

/** The `user_skill:<id>` topics that name no skill of `ownerId` (another account's, or a deleted one). */
export async function foreignSkillTopics(ownerId: string, topics: readonly string[], db: Db = prisma): Promise<string[]> {
  const wanted = topics.flatMap(t => {
    const id = userSkillIdOf(t)
    return id ? [{ topic: t, id }] : []
  })
  if (wanted.length === 0) return []
  const own = await db.userAttackSkill.findMany({
    where: { userId: ownerId, id: { in: wanted.map(w => w.id) } },
    select: { id: true },
  })
  const ownIds = new Set(own.map(s => s.id))
  return wanted.filter(w => !ownIds.has(w.id)).map(w => w.topic)
}

/** The 400 a writer answers when a focus names a skill the owner does not have; null otherwise. */
export async function focusSkillRefusal(ownerId: string, focus: Focus | Record<string, never> | undefined): Promise<NextResponse | null> {
  const topics = focus && 'topics' in focus ? focus.topics : []
  const foreign = await foreignSkillTopics(ownerId, topics)
  if (foreign.length === 0) return null
  return NextResponse.json({
    field: 'focus.topics', code: 'foreign_skill', error: `Not one of your skills: ${foreign.join(', ')}`,
  }, { status: 400 })
}

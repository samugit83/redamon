/**
 * The ingestion focus a person may save on a resource (§6.14, T5.5): the mode, the chips
 * (vocabulary topics and kinds, or the owner's own skills), the Keep and Skip prompt of at
 * most 1,000 characters each, the skip mode and the strictness. An empty focus is no focus.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as never)[k] }) }))

import { foreignSkillTopics, validateFocus, validateKinds, validateTopics } from './focusFields'

const FULL = {
  mode: 'focused', recipe: 'sql_injection_deep_dive', topics: ['sql_injection'], kinds: ['payloads', 'bypasses'],
  keep: 'Pages with SQL injection payloads', skip: 'News', skipMode: 'add', strictness: 'strict',
}

beforeEach(() => {
  h.db = createTradecraftDb()
})

describe('validateFocus', () => {
  test('nothing or an empty focus is no focus', () => {
    expect(validateFocus(undefined)).toEqual({ ok: true, value: {} })
    expect(validateFocus({})).toEqual({ ok: true, value: {} })
  })

  test('a whole focus is kept as sent', () => {
    expect(validateFocus(FULL)).toEqual({ ok: true, value: FULL })
  })

  test('the mode alone: the rest takes its empty value, Balanced, Skip added', () => {
    expect(validateFocus({ mode: 'tagOnly' })).toEqual({
      ok: true, value: { mode: 'tagOnly', topics: [], kinds: [], keep: '', skip: '', skipMode: 'add', strictness: 'balanced' },
    })
  })

  test.each([
    ['not an object', [], 'focus'],
    ['null', null, 'focus'],
    ['no mode', { topics: ['xss'] }, 'focus.mode'],
    ['an unknown mode', { mode: 'tag_only' }, 'focus.mode'],
    ['an unknown key', { mode: 'focused', tagEveryPage: 'rules' }, 'focus'],
    ['an unknown strictness', { mode: 'focused', strictness: 'medium' }, 'focus.strictness'],
    ['an unknown skip mode', { mode: 'focused', skipMode: 'merge' }, 'focus.skipMode'],
    ['an unknown topic', { mode: 'focused', topics: ['sqli'] }, 'focus.topics'],
    ['an unknown kind', { mode: 'focused', kinds: ['methodology'] }, 'focus.kinds'],
    ['topics not a list', { mode: 'focused', topics: 'xss' }, 'focus.topics'],
    ['a bad recipe id', { mode: 'focused', recipe: 'a b' }, 'focus.recipe'],
  ])('refused: %s', (_why, input, field) => {
    expect(validateFocus(input)).toMatchObject({ ok: false, field })
  })

  test('focus_keep_skip_1000: Keep and Skip hold at most 1,000 characters each, and no NUL', () => {
    const at = 'k'.repeat(1000)
    expect(validateFocus({ mode: 'focused', keep: at, skip: at })).toMatchObject({ ok: true, value: { keep: at, skip: at } })
    expect(validateFocus({ mode: 'focused', keep: `${at}k` })).toMatchObject({ ok: false, field: 'focus.keep' })
    expect(validateFocus({ mode: 'focused', skip: `${at}s` })).toMatchObject({ ok: false, field: 'focus.skip' })
    expect(validateFocus({ mode: 'focused', keep: 'a\u0000b' })).toMatchObject({ ok: false, field: 'focus.keep' })
    expect(validateFocus({ mode: 'focused', keep: 7 })).toMatchObject({ ok: false, field: 'focus.keep' })
    expect(validateFocus({ mode: 'focused', keep: '  payloads\nand bypasses  ' })).toMatchObject({ ok: true, value: { keep: 'payloads\nand bypasses' } })
  })

  test('a repeated chip is kept once', () => {
    expect(validateFocus({ mode: 'focused', topics: ['xss', 'xss'], kinds: ['poc', 'poc'] }))
      .toMatchObject({ ok: true, value: { topics: ['xss'], kinds: ['poc'] } })
  })

  test('user_skill_topics_allowed: an owner skill is a topic by its id', () => {
    expect(validateFocus({ mode: 'focused', topics: ['xss', 'user_skill:cm1abc_DEF-2'] }))
      .toMatchObject({ ok: true, value: { topics: ['xss', 'user_skill:cm1abc_DEF-2'] } })
    for (const bad of ['user_skill:', 'user_skill:a b', `user_skill:${'x'.repeat(65)}`]) {
      expect(validateFocus({ mode: 'focused', topics: [bad] }), bad).toMatchObject({ ok: false, field: 'focus.topics' })
    }
  })

  test('at most 30 topics, what the agent\'s focus stage reads', () => {
    const topics = Array.from({ length: 31 }, (_, i) => `user_skill:s${i}`)
    expect(validateFocus({ mode: 'focused', topics })).toMatchObject({ ok: false, field: 'focus.topics' })
    expect(validateFocus({ mode: 'focused', topics: topics.slice(0, 30) }).ok).toBe(true)
  })
})

describe('validateTopics and validateKinds (the recipes share them)', () => {
  test('recipe_topics_validated: vocabulary ids and owner skills only', () => {
    expect(validateTopics(['ssrf', 'user_skill:s1'], 'topics')).toEqual({ ok: true, value: ['ssrf', 'user_skill:s1'] })
    expect(validateTopics(['ssrf', 'SSRF'], 'topics')).toMatchObject({ ok: false, field: 'topics' })
    expect(validateKinds(['tool_commands'], 'kinds')).toEqual({ ok: true, value: ['tool_commands'] })
    expect(validateKinds(['tool'], 'kinds')).toMatchObject({ ok: false, field: 'kinds' })
  })
})

describe('foreignSkillTopics', () => {
  test('foreign_skill_refused: a skill of another account, or none, is named; the owner\'s pass', async () => {
    h.db.seed('userAttackSkill', { id: 'mine', userId: 'owner', name: 'Mine' })
    h.db.seed('userAttackSkill', { id: 'theirs', userId: 'other', name: 'Theirs' })
    expect(await foreignSkillTopics('owner', ['xss', 'user_skill:mine'])).toEqual([])
    expect(await foreignSkillTopics('owner', ['user_skill:mine', 'user_skill:theirs', 'user_skill:gone'])).toEqual(['user_skill:theirs', 'user_skill:gone'])
  })

  test('no skill topic reads nothing', async () => {
    expect(await foreignSkillTopics('owner', ['xss', 'ssrf'])).toEqual([])
    expect(h.db.calls).toEqual([])
  })
})

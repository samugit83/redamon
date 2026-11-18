/**
 * The Focus section's rules (§6.14, T5.6), as pure functions: the chips write Keep and Skip until
 * the person edits them, a recipe fills the chips, the prompt texts stop at 1,000 characters, the
 * cost estimate, the preview's counts, and what a save sends.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  FOCUS_TEXT_MAX, FOCUS_TOPICS_MAX, applyRecipe, clampFocusText, focusCost, focusCostText, focusFromStored, focusModeOfDefault, focusPayload,
  keepTextFor, newResourceFocus, previewSummary, setChips, topicLabel, userSkillTopic, type Focus,
} from './focus'
import { RECIPES } from './vocab'

const BASE: Focus = { mode: 'focused', topics: [], kinds: [], keep: '', skip: '', skipMode: 'add', strictness: 'balanced' }
const recipe = (id: string) => RECIPES.find(r => r.id === id)!

describe('the chips and the prompt', () => {
  test('keepTextFor: the topics, then the content types, in words', () => {
    expect(keepTextFor(['sql_injection', 'xss'], ['payloads', 'bypasses'])).toBe('Pages about SQL injection or XSS: payloads & cheat sheets, bypasses & evasion.')
    expect(keepTextFor([], ['poc'])).toBe('Pages with PoC / exploit code.')
    expect(keepTextFor(['cloud'], [])).toBe('Pages about Cloud.')
    expect(keepTextFor([], [])).toBe('')
    expect(keepTextFor([userSkillTopic('s1')], [], { s1: 'My GraphQL skill' })).toBe('Pages about My GraphQL skill.')
  })

  test('chips_write_keep_skip: a chip rewrites Keep while the person has not edited it; an edited Keep stays', () => {
    const one = setChips(BASE, { topics: ['sql_injection'] })
    expect(one).toMatchObject({ topics: ['sql_injection'], keep: 'Pages about SQL injection.' })
    const two = setChips(one, { kinds: ['payloads'] })
    expect(two.keep).toBe('Pages about SQL injection: payloads & cheat sheets.')
    const edited = { ...two, keep: 'Only blind SQL injection' }
    expect(setChips(edited, { topics: ['sql_injection', 'xss'] }).keep).toBe('Only blind SQL injection')
    // Back to the generated text: the chips write it again.
    const cleared = { ...two, keep: '' }
    expect(setChips(cleared, { topics: ['xss'] }).keep).toBe('Pages about XSS: payloads & cheat sheets.')
  })

  test('recipe_fills_chips: the recipe\'s topics, types and Skip; its id is recorded; the chips stay editable', () => {
    const filled = applyRecipe(BASE, recipe('web_payload_library'))
    expect(filled).toMatchObject({ recipe: 'web_payload_library', topics: ['sql_injection', 'xss', 'ssrf', 'xxe'], kinds: ['payloads', 'bypasses'] })
    expect(filled.keep).toBe(keepTextFor(['sql_injection', 'xss', 'ssrf', 'xxe'], ['payloads', 'bypasses']))
    const offensive = applyRecipe(BASE, recipe('offensive_no_defense'))
    expect(offensive.skip).toBe('news and hardening guides')
    expect(offensive.kinds).not.toContain('detection')
    expect(setChips(filled, { topics: ['xss'] }).topics).toEqual(['xss'])
    // A Skip the person wrote is kept by a recipe that has none.
    expect(applyRecipe({ ...BASE, skip: 'my own skip' }, recipe('tool_cheat_sheets')).skip).toBe('my own skip')
  })

  test('limits_1000: Keep and Skip are cut at 1,000 characters; a recipe of many skills keeps 30 topics', () => {
    expect(FOCUS_TEXT_MAX).toBe(1000)
    expect(clampFocusText('k'.repeat(1200))).toHaveLength(1000)
    expect(FOCUS_TOPICS_MAX).toBe(30)
    const many = Array.from({ length: 40 }, (_, i) => userSkillTopic(`s${i}`))
    expect(setChips(BASE, { topics: many }).topics).toHaveLength(30)
  })

  test('topicLabel: the fixed list, the owner\'s skills by name, else the id', () => {
    expect(topicLabel('sql_injection')).toBe('SQL injection')
    expect(topicLabel('user_skill:s1', { s1: 'Mine' })).toBe('Mine')
    expect(topicLabel('user_skill:gone')).toBe('user_skill:gone')
  })
})

describe('what the form starts from and sends', () => {
  test('a new resource starts on the account\'s default mode and strictness', () => {
    expect(newResourceFocus({ 'focus.defaultMode': 'focused', 'focus.defaultStrictness': 'strict' })).toEqual({ ...BASE, strictness: 'strict' })
    expect(newResourceFocus({ 'focus.defaultMode': 'tag_only' }).mode).toBe('tagOnly')
    expect(newResourceFocus({}).mode).toBe('everything')
    expect(focusModeOfDefault('nonsense')).toBe('everything')
  })

  test('a saved resource with no focus is Everything; a saved focus reads as it is', () => {
    expect(focusFromStored({})).toEqual({ ...BASE, mode: 'everything' })
    const saved = { mode: 'focused', recipe: 'x', topics: ['xss'], kinds: ['poc'], keep: 'k', skip: 's', skipMode: 'replace', strictness: 'loose' }
    expect(focusFromStored(saved)).toEqual(saved)
    expect(focusFromStored({ mode: 'focused', topics: 'junk' })).toEqual({ ...BASE, mode: 'focused' })
  })

  test('Everything sends no focus, so the resource is not marked stale; anything else is sent whole', () => {
    expect(focusPayload({ ...BASE, mode: 'everything', topics: ['xss'] })).toEqual({})
    expect(focusPayload({ ...BASE, topics: ['xss'] })).toEqual({ ...BASE, topics: ['xss'] })
  })
})

describe('cost and preview', () => {
  test('cost_estimate: one small call per 100 titles, content checks up to the limit; Everything costs nothing', () => {
    expect(focusCost({ mode: 'focused', entries: 4800, maxContentChecks: 100 })).toEqual({ triageCalls: 48, contentChecks: 100 })
    expect(focusCost({ mode: 'focused', entries: 30, maxContentChecks: 100 })).toEqual({ triageCalls: 1, contentChecks: 30 })
    expect(focusCost({ mode: 'everything', entries: 4800, maxContentChecks: 100 })).toEqual({ triageCalls: 0, contentChecks: 0 })
    expect(focusCost({ mode: 'focused', entries: null, maxContentChecks: 100 })).toEqual({ triageCalls: null, contentChecks: 100 })
    expect(focusCostText({ triageCalls: 48, contentChecks: 100 })).toBe('Estimated cost: title triage ≈ 48 small LLM calls · content checks up to 100 calls')
    expect(focusCostText({ triageCalls: 1, contentChecks: 0 })).toBe('Estimated cost: title triage ≈ 1 small LLM call')
    expect(focusCostText({ triageCalls: null, contentChecks: 100 })).toBe('Estimated cost: title triage ≈ 1 small LLM call per 100 pages · content checks up to 100 calls')
    expect(focusCostText({ triageCalls: 0, contentChecks: 0 })).toBe('No model calls: every page is kept')
  })

  test('preview_shows_counts: kept, maybe and dropped of the sample', () => {
    expect(previewSummary({ kept: 34, maybe: 0, dropped: 66, examples: [], llm_calls: 1, error_code: '' })).toBe('Would keep 34, drop 66 of 100 pages')
    expect(previewSummary({ kept: 30, maybe: 4, dropped: 66, examples: [], llm_calls: 1, error_code: '' })).toBe('Would keep 30, drop 66, 4 uncertain, of 100 pages')
    expect(previewSummary({ kept: 0, maybe: 100, dropped: 0, examples: [], llm_calls: 1, error_code: 'model_unavailable' })).toBe('The model could not judge the titles (model_unavailable): every page would be kept')
  })
})

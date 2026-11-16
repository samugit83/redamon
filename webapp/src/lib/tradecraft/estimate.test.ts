/**
 * The live estimate of Configure ingestion (§3.2, §4.4, R-023, R-076): the worst-case time and
 * model calls of one website ingestion, and which crawl limit stops it first.
 */
import { describe, test, expect } from 'vitest'
import { estimateWebsite, estimateText, LLM_CALL_SEC, PAGE_SEC } from './estimate'
import { ingestionDefaultsForEstimate } from './estimate'

const base = () => ingestionDefaultsForEstimate()

describe('estimateWebsite', () => {
  test('first_limit: with the defaults the LLM call limit binds before time and pages', () => {
    const e = estimateWebsite(base())
    expect(e.firstLimit).toBe('maxLlmCalls')
    expect(e.pages).toBe(20)
  })

  test('first_limit: raising the calls makes the time budget bind; a long budget leaves the page limit', () => {
    const v = { ...base(), 'crawl.maxLlmCalls': 200 }
    expect(estimateWebsite(v).firstLimit).toBe('timeBudgetSec')
    const w = { ...v, 'crawl.timeBudgetSec': 1800, 'crawl.maxPages': 50 }
    expect(estimateWebsite(w).firstLimit).toBe('maxPages')
    expect(estimateWebsite(w).pages).toBe(50)
  })

  test('first_limit: rule-based uses no model call, so pages or time bind', () => {
    const v = { ...base(), 'crawl.strategy': 'rules', 'crawl.timeBudgetSec': 1800 }
    const e = estimateWebsite(v)
    expect(e.breakdown.crawl).toBe(0)
    expect(e.firstLimit).toBe('maxPages')
    expect(e.pages).toBe(200)
    const short = estimateWebsite({ ...v, 'crawl.timeBudgetSec': 30 })
    expect(short.firstLimit).toBe('timeBudgetSec')
    expect(short.pages).toBe(Math.floor(30 / PAGE_SEC))
  })

  test('worst_case_numbers: crawl calls plus tagging, folder descriptions, content checks and one summary', () => {
    const e = estimateWebsite(base())
    expect(e.breakdown).toEqual({ crawl: 20, tagging: 1, folders: 1, contentChecks: 0, summary: 1 })
    expect(e.llmCalls).toBe(23)
    expect(e.crawlSeconds).toBe(20 * (PAGE_SEC + LLM_CALL_SEC))
    expect(e.seconds).toBe(e.crawlSeconds + 3 * LLM_CALL_SEC)
  })

  test('worst_case_numbers: a focused default adds one content check per page, up to its limit', () => {
    const e = estimateWebsite({ ...base(), 'focus.defaultMode': 'focused', 'focus.maxContentChecks': 5 })
    expect(e.breakdown.contentChecks).toBe(5)
    const tagOnly = estimateWebsite({ ...base(), 'focus.tagEveryPage': 'rules' })
    expect(tagOnly.breakdown.tagging).toBe(0)
  })

  test('the crawl never runs past its time budget; parallel requests and a delay change the pace', () => {
    const v = { ...base(), 'crawl.strategy': 'rules', 'crawl.maxPages': 500, 'crawl.timeBudgetSec': 60 }
    expect(estimateWebsite(v).crawlSeconds).toBeLessThanOrEqual(60)
    const fast = estimateWebsite({ ...v, 'crawl.parallel': 8 })
    expect(fast.pages).toBeGreaterThan(estimateWebsite(v).pages)
    const slow = estimateWebsite({ ...v, 'crawl.delaySec': 10 })
    expect(slow.pages).toBeLessThan(estimateWebsite(v).pages)
  })

  test('Auto is estimated at its worst case, the LLM-guided fallback', () => {
    expect(estimateWebsite({ ...base(), 'crawl.strategy': 'auto' })).toEqual(estimateWebsite(base()))
  })

  test('a value that is not a number falls back to its default', () => {
    expect(estimateWebsite({ ...base(), 'crawl.maxLlmCalls': 'x' as unknown as number })).toEqual(estimateWebsite(base()))
  })
})

describe('estimateText', () => {
  test('says the worst case and which limit stops the crawl first', () => {
    const t = estimateText(estimateWebsite(base()))
    expect(t.headline).toBe('Worst case per website: about 3 min, up to 23 LLM calls')
    expect(t.stop).toBe('The crawl stops first at the LLM call limit (20 calls, about 20 pages).')
  })

  test('seconds under a minute and the other limits', () => {
    const rules = estimateText(estimateWebsite({ ...base(), 'crawl.strategy': 'rules', 'crawl.maxPages': 3 }))
    expect(rules.headline).toMatch(/^Worst case per website: about \d+ s, up to 3 LLM calls$/)
    expect(rules.stop).toBe('The crawl stops first at the page limit (3 pages).')
    const time = estimateText(estimateWebsite({ ...base(), 'crawl.maxLlmCalls': 200 }))
    expect(time.stop).toMatch(/^The crawl stops first at the time budget \(180 s, about \d+ pages\)\.$/)
  })
})

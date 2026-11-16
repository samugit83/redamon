/**
 * The live estimate at the top of Configure ingestion (§3.2, §4.4): the worst-case time and
 * model calls of one website ingestion under the settings being edited, and which crawl limit
 * stops the crawl first (R-076). A guide for the person, not a promise: the per-page and
 * per-call times are typical values, and the agent enforces the real limits.
 *
 * Client-safe: the dialog recomputes it on every keystroke.
 */
import { SETTINGS_CONSTANTS, settingDef, specDefaults, type SettingsValues } from './settingsSpec'

/** A plain fetch and parse of one crawled page, typical. */
export const PAGE_SEC = 2
/** One model call (a crawl decision, a tagging batch, a summary), typical. */
export const LLM_CALL_SEC = 5

export type CrawlLimit = 'maxPages' | 'maxLlmCalls' | 'timeBudgetSec'

export interface WebsiteEstimate {
  pages: number
  firstLimit: CrawlLimit
  timeBudgetSec: number
  crawlSeconds: number
  seconds: number
  llmCalls: number
  breakdown: { crawl: number; tagging: number; folders: number; contentChecks: number; summary: number }
}

export function ingestionDefaultsForEstimate(): SettingsValues {
  return specDefaults('ingestion')
}

function num(values: Record<string, unknown>, key: string): number {
  const v = values[key]
  if (typeof v === 'number' && Number.isFinite(v)) return v
  return settingDef(key)!.default as number
}

function str(values: Record<string, unknown>, key: string): string {
  const v = values[key]
  return typeof v === 'string' ? v : (settingDef(key)!.default as string)
}

/**
 * Auto is estimated at its worst case: a site without a usable sitemap is crawled LLM-guided.
 * Each visited page of an LLM-guided crawl costs one decision, so the call limit caps the pages.
 */
export function estimateWebsite(values: Record<string, unknown>): WebsiteEstimate {
  const usesModel = str(values, 'crawl.strategy') !== 'rules'
  const parallel = Math.max(1, num(values, 'crawl.parallel'))
  const perPage = (PAGE_SEC + num(values, 'crawl.delaySec')) / parallel + (usesModel ? LLM_CALL_SEC : 0)
  const budget = num(values, 'crawl.timeBudgetSec')
  const candidates: [CrawlLimit, number][] = [
    ['maxPages', num(values, 'crawl.maxPages')],
    ['maxLlmCalls', usesModel ? num(values, 'crawl.maxLlmCalls') : Infinity],
    ['timeBudgetSec', Math.floor(budget / perPage)],
  ]
  let [firstLimit, pages] = candidates[0]
  for (const [limit, n] of candidates.slice(1)) if (n < pages) [firstLimit, pages] = [limit, n]
  pages = Math.max(0, pages)
  const crawlSeconds = Math.min(budget, Math.round(pages * perPage))

  const focused = str(values, 'focus.defaultMode') !== 'everything'
  const breakdown = {
    crawl: usesModel ? pages : 0,
    tagging: str(values, 'focus.tagEveryPage') === 'rules_model' ? Math.ceil(pages / SETTINGS_CONSTANTS.titleTriageBatch) : 0,
    folders: Math.min(SETTINGS_CONSTANTS.folderDescriptionCalls, Math.ceil(pages / SETTINGS_CONSTANTS.foldersPerDescriptionCall)),
    contentChecks: focused ? Math.min(num(values, 'focus.maxContentChecks'), pages) : 0,
    summary: 1,
  }
  const extraCalls = breakdown.tagging + breakdown.folders + breakdown.contentChecks + breakdown.summary
  return {
    pages,
    firstLimit,
    timeBudgetSec: budget,
    crawlSeconds,
    seconds: crawlSeconds + extraCalls * LLM_CALL_SEC,
    llmCalls: breakdown.crawl + extraCalls,
    breakdown,
  }
}

function duration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`
  return `${Math.round(seconds / 60)} min`
}

export function estimateText(e: WebsiteEstimate): { headline: string; stop: string } {
  const headline = `Worst case per website: about ${duration(e.seconds)}, up to ${e.llmCalls} LLM calls`
  const pages = `${e.pages} ${e.pages === 1 ? 'page' : 'pages'}`
  let stop: string
  if (e.firstLimit === 'maxPages') stop = `The crawl stops first at the page limit (${pages}).`
  else if (e.firstLimit === 'maxLlmCalls') stop = `The crawl stops first at the LLM call limit (${e.breakdown.crawl} calls, about ${pages}).`
  else stop = `The crawl stops first at the time budget (${e.timeBudgetSec} s, about ${pages}).`
  return { headline, stop }
}

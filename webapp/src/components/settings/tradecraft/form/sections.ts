/**
 * Which per-resource settings each section of the resource form holds (§6.2-§6.11), and which
 * sections a type shows. Only `both` and `resource` keys of the spec appear: a user-only setting
 * never reaches the form (§6.1, R-133). The focus (phase 5), the access logins (phase 6) and real
 * page titles (phase 6) join with their features.
 */
import { settingDef, type SettingDef } from '@/lib/tradecraft/settingsSpec'

export type TypeSection = 'github' | 'cve' | 'wiki' | 'gitbook' | 'docs' | 'pdf' | 'website'

const keys = (...k: string[]) => k

export const SECTION_KEYS: Readonly<Record<TypeSection | 'detection' | 'fetching' | 'content' | 'summary' | 'refreshing', string[]>> = {
  detection: keys('detection.thinHomepageChars', 'detection.cveArchiveThreshold'),
  github: keys('type.github.branch', 'type.github.includeFolders', 'type.github.excludeFolders', 'type.github.folderEntries',
    'knownTypes.githubFileTypes', 'knownTypes.maxMapEntries.github'),
  cve: keys('type.cve.pathPatterns', 'type.cve.branch', 'type.cve.readmeFallback'),
  wiki: keys('type.wiki.sitemapUrls', 'type.wiki.menuSelector', 'knownTypes.language', 'knownTypes.preferredLanguage', 'knownTypes.maxMapEntries.wiki'),
  gitbook: keys('type.gitbook.sitemapUrls', 'type.gitbook.menuSelector', 'knownTypes.language', 'knownTypes.preferredLanguage', 'knownTypes.maxMapEntries.gitbook'),
  docs: keys('type.docs.searchIndexUrl', 'knownTypes.maxMapEntries.docs'),
  pdf: keys('type.pdf.firstPage', 'type.pdf.lastPage', 'type.pdf.mapBy', 'type.pdf.skipPages', 'knownTypes.pdfMaxPages'),
  website: keys('type.website.startPages', 'type.website.sitemapUrls', 'type.website.followPagination',
    'crawl.strategy', 'crawl.maxPages', 'crawl.maxLlmCalls', 'crawl.timeBudgetSec', 'crawl.maxDepth', 'crawl.linksPerPage',
    'crawl.preferBodyLinks', 'crawl.onLlmStop', 'crawl.ignoreStopUntilPages', 'crawl.minTextChars', 'crawl.requireTitle',
    'crawl.excludePaths', 'crawl.includePaths', 'crawl.stayInFolder', 'crawl.hostScope', 'crawl.queryStrings',
    'crawl.queryStringsPerPath', 'crawl.respectRobots', 'crawl.delaySec', 'crawl.parallel', 'knownTypes.maxMapEntries.website'),
  fetching: keys('fetching.requestTimeoutSec', 'fetching.userAgent', 'fetching.acceptLanguage', 'fetching.browserEnabled',
    'fetching.browserBelowChars', 'fetching.crawlBrowserBelowBytes', 'fetching.browserWaitUntil', 'fetching.browserTimeoutSec',
    'fetching.browserMaxChars', 'fetching.alwaysBrowser', 'fetching.waitForSelector'),
  content: keys('content.bodySelector', 'content.removeSelectors', 'storage.maxPages', 'storage.maxPageKb', 'storage.maxResourceMb',
    'storage.incremental'),
  summary: keys('summary.targetTokens', 'summary.homepageChars', 'summary.titles', 'summary.extraInstructions'),
  refreshing: keys('refreshing.onFailure'),
}

/** The type section of a resource's (forced or detected) type; none while the type is unknown. */
export function typeSectionOf(type: string): TypeSection | null {
  switch (type) {
    case 'github-repo': return 'github'
    case 'cve-poc-db': return 'cve'
    case 'mkdocs-wiki': return 'wiki'
    case 'gitbook': return 'gitbook'
    case 'sphinx-docs': return 'docs'
    case 'pdf': return 'pdf'
    case 'agentic-crawl': return 'website'
    default: return null
  }
}

export function defsOf(section: keyof typeof SECTION_KEYS): SettingDef[] {
  return SECTION_KEYS[section].map(k => {
    const def = settingDef(k)
    if (!def || def.level === 'user') throw new Error(`${k} is not a per-resource setting`)
    return def
  })
}

/** "Inherit" or "N overrides", the one-line status of a collapsed section (§6.2). */
export function overrideStatus(keysOf: readonly string[], overrides: Record<string, unknown>): string {
  const n = keysOf.filter(k => Object.hasOwn(overrides, k)).length
  if (n === 0) return 'Inherit'
  return n === 1 ? '1 override' : `${n} overrides`
}

export const TYPE_LABELS: Readonly<Record<string, string>> = {
  'mkdocs-wiki': 'Wiki (MkDocs/mdBook)', 'sphinx-docs': 'Docs (Sphinx/Docusaurus)', gitbook: 'GitBook',
  'github-repo': 'GitHub repository', 'cve-poc-db': 'CVE archive', pdf: 'PDF', 'agentic-crawl': 'Website',
}

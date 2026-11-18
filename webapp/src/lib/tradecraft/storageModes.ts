/**
 * The storage mode rules of §4.5, client-safe: the server's writes and the form's recommendation
 * read the same functions.
 */
import type { StorageMode } from './agentContract'

/**
 * The storage a type always gets (§4.5, R-082, R-142): a PDF is downloaded once, so it is
 * kept; a CVE database is a live index of many small repositories, so it is read live.
 */
export function forcedStorageMode(type: string): StorageMode | null {
  if (type === 'pdf') return 'stored'
  if (type === 'cve-poc-db') return 'live'
  return null
}

/**
 * The type's recommended mode (§4.5 "Recommended mode per type"). A wiki, GitBook or docs site is
 * Stored only when Check URL found it fits the size limits (T4.1); without that estimate, and
 * for a type not yet known (Auto, before detection), it is the spec's own default, Live.
 */
export function recommendedStorageMode(type: string, fitsSizeLimits: boolean | null = null): StorageMode {
  const forced = forcedStorageMode(type)
  if (forced) return forced
  if (type === 'agentic-crawl' || type === 'github-repo') return 'stored'
  if (type === 'mkdocs-wiki' || type === 'sphinx-docs' || type === 'gitbook') return fitsSizeLimits === true ? 'stored' : 'live'
  return 'live'
}

/** The account's `storage.defaultMode` as a mode a row can hold: `recommended` becomes the type's. */
export function defaultStorageMode(setting: unknown, type: string): StorageMode {
  if (setting === 'recommended') return recommendedStorageMode(type)
  return setting === 'stored' ? 'stored' : 'live'
}

/**
 * The stale badge's rule (§3.3, §6.13, R-174): a changed settings hash or forced type, or a
 * Stored resource whose live version holds no stored text because it was ingested Live. A Stored
 * ingestion that the quota or a size limit left without text is current: re-ingesting would
 * store nothing more, so the badge would never clear.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { IngestionReport } from './agentContract'
import { ingestionHash, isStale } from './staleness'

const HASH = 'a1b2c3d4e5f60718'
const report = (stored: Partial<IngestionReport['stored']> = {}, kept = 5): IngestionReport =>
  IngestionReport.parse({ visited: kept, kept, stored: { pages: 0, bytes: 0, notStoredQuota: 0, notStoredSize: 0, ...stored } })
const row = (over: Partial<{ settingsHash: string; forcedType: string; resourceType: string; storageMode: string }> = {}) =>
  ({ settingsHash: HASH, forcedType: '', resourceType: 'mkdocs-wiki', storageMode: 'stored', ...over })

describe('isStale', () => {
  test('a resource 2.0 never ingested is never stale', () => {
    expect(isStale(row({ settingsHash: '' }), HASH, null)).toBe(false)
  })

  test('the settings hash or the forced type changed', () => {
    expect(isStale(row(), 'another-hash', report({ pages: 5 }))).toBe(true)
    expect(isStale(row({ forcedType: 'gitbook' }), HASH, report({ pages: 5 }))).toBe(true)
    expect(isStale(row({ forcedType: 'gitbook', settingsHash: ingestionHash(HASH, 'gitbook') }), HASH, report({ pages: 5 }))).toBe(false)
  })

  test('Stored after a Live ingestion: stale until an ingestion takes the Stored path', () => {
    expect(isStale(row(), HASH, report())).toBe(true)
    expect(isStale(row(), HASH, report({ pages: 5, bytes: 500 }))).toBe(false)
    expect(isStale(row({ storageMode: 'live' }), HASH, report())).toBe(false)
  })

  test('a Stored ingestion the quota or a size limit left without text is current', () => {
    expect(isStale(row(), HASH, report({ notStoredQuota: 5 }))).toBe(false)
    expect(isStale(row(), HASH, report({ notStoredSize: 5 }))).toBe(false)
  })

  test('nothing kept, or a type that never stores text, is not stale for its mode', () => {
    expect(isStale(row(), HASH, report({}, 0))).toBe(false)
    expect(isStale(row({ resourceType: 'cve-poc-db' }), HASH, report())).toBe(false)
  })
})

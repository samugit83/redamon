import { createHash } from 'crypto'
import {
  GRAPH_PERF_DEBUG,
  GRAPH_CACHE_MAX_ENTRIES,
  GRAPH_CACHE_MAX_ELEMENTS,
} from './config'
import type { TruncationInfo } from './truncate'

/** What the cache reads of a node: its id, and the triage properties the ETag hashes. */
interface CachedNode {
  id: string
  properties?: Record<string, unknown>
}

interface CachedGraph {
  nodes: CachedNode[]
  links: unknown[]
}

interface CacheEntry {
  data: CachedGraph
  etag: string
  timestamp: number
  /** Truncation state is cached WITH the payload: a cache hit must report the
   *  same "showing N of M" the miss did, or the UI flips between complete and
   *  partial for identical data. */
  info?: TruncationInfo
  /** nodes+links, kept so eviction does not have to re-walk the payload. */
  elements: number
}

/**
 * Bounded LRU. Map preserves insertion order, so the oldest key is the first
 * one `keys().next()` yields; re-inserting on read moves an entry to the back.
 *
 * WHY BOUNDED: this used to be an unbounded Map keyed by project. N projects
 * with large graphs each pinned a full copy of their payload for the whole
 * process lifetime -- on top of the response object and its JSON string. The
 * webapp OOM that started this work had that as a multiplier.
 */
const cache = new Map<string, CacheEntry>()
const TTL = 10_000 // 10 seconds

let totalElements = 0

/**
 * What a finding's disposition reads from the Priority Board. A triage run or a
 * verdict changes these and nothing structural, so without them a revalidation
 * got a 304 and the node drawer kept the disposition from before the run.
 */
const TRIAGE_ETAG_PROPS = [
  'triage_tier_rule', 'triage_state', 'triage_status', 'triage_source',
  'triage_disposition', 'triage_blocker',
] as const

/**
 * Generate a fast ETag from graph data.
 * XOR-hashes all node IDs, plus each finding's triage result, for an O(n)
 * fingerprint. Other property changes keep the ETag.
 */
function generateEtag(nodes: CachedNode[], links: unknown[]): string {
  // Fast numeric hash: XOR all node ID chars with position mixing
  let hash = 0
  for (let i = 0; i < nodes.length; i++) {
    const id = nodes[i].id as string
    for (let j = 0; j < id.length; j++) {
      hash = ((hash << 5) - hash + id.charCodeAt(j)) | 0
    }
    const props = nodes[i].properties
    if (props) {
      for (let k = 0; k < TRIAGE_ETAG_PROPS.length; k++) {
        const value = props[TRIAGE_ETAG_PROPS[k]]
        if (typeof value !== 'string') continue
        hash = ((hash << 5) - hash + (k + 1) * 7919) | 0
        for (let j = 0; j < value.length; j++) {
          hash = ((hash << 5) - hash + value.charCodeAt(j)) | 0
        }
      }
    }
    hash = (hash ^ (i * 2654435761)) | 0 // mix with position
  }

  const raw = `${nodes.length}:${links.length}:${hash >>> 0}`
  return createHash('md5').update(raw).digest('hex').slice(0, 16)
}

function drop(projectId: string): void {
  const entry = cache.get(projectId)
  if (!entry) return
  totalElements -= entry.elements
  if (totalElements < 0) totalElements = 0
  cache.delete(projectId)
}

/** Evict oldest-first until BOTH bounds are satisfied. */
function evictToFit(): void {
  const maxEntries = GRAPH_CACHE_MAX_ENTRIES()
  const maxElements = GRAPH_CACHE_MAX_ELEMENTS()
  while (cache.size > maxEntries || totalElements > maxElements) {
    const oldest = cache.keys().next()
    if (oldest.done) break
    if (GRAPH_PERF_DEBUG) {
      console.log(`[GraphPerf:Cache] EVICT projectId=${oldest.value} (entries=${cache.size} elements=${totalElements})`)
    }
    drop(oldest.value)
  }
}

export function getCached(projectId: string): CacheEntry | null {
  const entry = cache.get(projectId)
  if (!entry) return null

  const age = Date.now() - entry.timestamp
  if (age > TTL) {
    drop(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] EXPIRED projectId=${projectId} (age=${age}ms)`)
    return null
  }

  // Touch: re-insert so this becomes the most-recently-used key.
  cache.delete(projectId)
  cache.set(projectId, entry)
  return entry
}

export function setCached(
  projectId: string,
  data: CachedGraph,
  info?: TruncationInfo,
): string {
  const etag = generateEtag(data.nodes, data.links)
  drop(projectId) // replacing: release the previous entry's element count first
  const elements = data.nodes.length + data.links.length
  cache.set(projectId, { data, etag, timestamp: Date.now(), info, elements })
  totalElements += elements
  evictToFit()
  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] SET projectId=${projectId} etag=${etag} nodes=${data.nodes.length} links=${data.links.length}`)
  return etag
}

export function invalidateCache(projectId: string): void {
  if (cache.has(projectId)) {
    drop(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] INVALIDATE projectId=${projectId}`)
  }
}

/** Test/introspection hook: current cache occupancy. */
export function cacheStats(): { entries: number; elements: number } {
  return { entries: cache.size, elements: totalElements }
}

/** Test hook: drop everything. */
export function clearCache(): void {
  cache.clear()
  totalElements = 0
}

import { createHash } from 'crypto'

const GRAPH_PERF_DEBUG = true

interface CacheEntry {
  data: { nodes: any[]; links: any[] }
  etag: string
  timestamp: number
}

const cache = new Map<string, CacheEntry>()
const TTL = 10_000 // 10 seconds

/**
 * Generate a fast ETag from graph data.
 * XOR-hashes all node IDs for O(n) structural fingerprint.
 */
function generateEtag(nodes: any[], links: any[]): string {
  // Fast numeric hash: XOR all node ID chars with position mixing
  let hash = 0
  for (let i = 0; i < nodes.length; i++) {
    const id = nodes[i].id as string
    for (let j = 0; j < id.length; j++) {
      hash = ((hash << 5) - hash + id.charCodeAt(j)) | 0
    }
    hash = (hash ^ (i * 2654435761)) | 0 // mix with position
  }

  const raw = `${nodes.length}:${links.length}:${hash >>> 0}`
  return createHash('md5').update(raw).digest('hex').slice(0, 16)
}

export function getCached(projectId: string): CacheEntry | null {
  const entry = cache.get(projectId)
  if (!entry) return null

  const age = Date.now() - entry.timestamp
  if (age > TTL) {
    cache.delete(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] EXPIRED projectId=${projectId} (age=${age}ms)`)
    return null
  }

  return entry
}

export function setCached(projectId: string, data: { nodes: any[]; links: any[] }): string {
  const etag = generateEtag(data.nodes, data.links)
  cache.set(projectId, { data, etag, timestamp: Date.now() })
  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] SET projectId=${projectId} etag=${etag} nodes=${data.nodes.length} links=${data.links.length}`)
  return etag
}

export function invalidateCache(projectId: string): void {
  if (cache.has(projectId)) {
    cache.delete(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:Cache] INVALIDATE projectId=${projectId}`)
  }
}

import { useMemo, useRef } from 'react'
import { GraphData, GraphNode, GraphLink } from '../types'

/**
 * Returns a GraphData whose node objects are reused across updates (same reference
 * when id matches) and whose links have source/target already resolved to the
 * matching node objects. Two problems this solves:
 *
 * 1. Position preservation: d3-force mutates x/y/z/vx/vy/vz on node objects. When
 *    a fresh fetch replaces the array with new node objects, positions are lost and
 *    the simulation has to re-seed every node. Reusing objects keeps positions.
 *
 * 2. "Edges to the void" on incremental updates: react-force-graph expects links to
 *    reference node objects (so link.source.x exists during canvas paint). Fresh
 *    fetches deliver links with string ids, and there is a frame where the library
 *    has not yet resolved them — during that frame, link endpoints read as
 *    undefined and the edge is drawn to NaN coords. Pre-resolving here eliminates
 *    the race entirely.
 *
 * New nodes are seeded near a connected neighbor so they don't pop in at origin.
 */
export function useStableGraphData(data: GraphData | undefined): GraphData | undefined {
  const nodeCacheRef = useRef<Map<string, GraphNode>>(new Map())

  return useMemo(() => {
    if (!data) {
      nodeCacheRef.current.clear()
      return undefined
    }

    const cache = nodeCacheRef.current
    const incomingIds = new Set<string>()
    const newlyAdded: GraphNode[] = []

    const stableNodes: GraphNode[] = data.nodes.map(incoming => {
      incomingIds.add(incoming.id)
      const existing = cache.get(incoming.id)
      if (existing) {
        existing.name = incoming.name
        existing.type = incoming.type
        existing.properties = incoming.properties
        existing.isCluster = incoming.isCluster
        existing.clusterChildren = incoming.clusterChildren
        existing.clusterChildType = incoming.clusterChildType
        existing.clusterColor = incoming.clusterColor
        return existing
      }
      const fresh: GraphNode = { ...incoming }
      cache.set(incoming.id, fresh)
      newlyAdded.push(fresh)
      return fresh
    })

    for (const id of Array.from(cache.keys())) {
      if (!incomingIds.has(id)) cache.delete(id)
    }

    if (newlyAdded.length > 0) {
      const newIdSet = new Set(newlyAdded.map(n => n.id))
      for (const link of data.links) {
        const sId = typeof link.source === 'string' ? link.source : link.source.id
        const tId = typeof link.target === 'string' ? link.target : link.target.id
        const sNew = newIdSet.has(sId)
        const tNew = newIdSet.has(tId)
        if (sNew === tNew) continue
        const newNode = cache.get(sNew ? sId : tId)
        const anchor = cache.get(sNew ? tId : sId)
        if (!newNode || !anchor) continue
        if (newNode.x !== undefined) continue
        if (anchor.x === undefined) continue
        const jitter = () => (Math.random() - 0.5) * 30
        newNode.x = anchor.x + jitter()
        newNode.y = (anchor.y ?? 0) + jitter()
        if (anchor.z !== undefined) newNode.z = anchor.z + jitter()
      }
    }

    const stableLinks: GraphLink[] = data.links.map(link => {
      const sId = typeof link.source === 'string' ? link.source : link.source.id
      const tId = typeof link.target === 'string' ? link.target : link.target.id
      const source = cache.get(sId) ?? sId
      const target = cache.get(tId) ?? tId
      return { ...link, source, target }
    })

    return { ...data, nodes: stableNodes, links: stableLinks }
  }, [data])
}

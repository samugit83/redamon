import { useMemo } from 'react'
import type { GraphData, GraphNode, GraphLink } from '../types'

export interface ConnectionInfo {
  nodeId: string
  nodeName: string
  nodeType: string
  relationType: string
}

export interface TableRow {
  node: GraphNode
  connectionsIn: ConnectionInfo[]
  connectionsOut: ConnectionInfo[]
  /** Lazy BFS: computes level-2 connections on first call, cached thereafter */
  getLevel2: () => ConnectionInfo[]
  /** Lazy BFS: computes level-3 connections on first call, cached thereafter */
  getLevel3: () => ConnectionInfo[]
}

function getNodeId(endpoint: string | GraphNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id
}

export function useTableData(data: GraphData | undefined): TableRow[] {
  return useMemo(() => {
    if (!data) return []

    const nodeMap = new Map<string, GraphNode>()
    data.nodes.forEach(n => nodeMap.set(n.id, n))

    // Build directed connection maps
    const connectionsIn = new Map<string, ConnectionInfo[]>()
    const connectionsOut = new Map<string, ConnectionInfo[]>()

    // Build undirected adjacency for BFS (set of neighbor IDs per node)
    const adjacency = new Map<string, Set<string>>()

    data.links.forEach((link: GraphLink) => {
      const sourceId = getNodeId(link.source)
      const targetId = getNodeId(link.target)
      const sourceNode = nodeMap.get(sourceId)
      const targetNode = nodeMap.get(targetId)

      if (!connectionsOut.has(sourceId)) connectionsOut.set(sourceId, [])
      connectionsOut.get(sourceId)!.push({
        nodeId: targetId,
        nodeName: targetNode?.name || targetId,
        nodeType: targetNode?.type || 'Unknown',
        relationType: link.type,
      })

      if (!connectionsIn.has(targetId)) connectionsIn.set(targetId, [])
      connectionsIn.get(targetId)!.push({
        nodeId: sourceId,
        nodeName: sourceNode?.name || sourceId,
        nodeType: sourceNode?.type || 'Unknown',
        relationType: link.type,
      })

      // Undirected adjacency
      if (!adjacency.has(sourceId)) adjacency.set(sourceId, new Set())
      if (!adjacency.has(targetId)) adjacency.set(targetId, new Set())
      adjacency.get(sourceId)!.add(targetId)
      adjacency.get(targetId)!.add(sourceId)
    })

    // BFS to get nodes at exactly depth 2 and 3 (lazy, per-node)
    function getNodesAtDepth(startId: string): { level2: string[]; level3: string[] } {
      const visited = new Set<string>([startId])
      let currentLevel = [startId]
      const levels: string[][] = []

      for (let depth = 0; depth < 3; depth++) {
        const nextLevel: string[] = []
        for (const nodeId of currentLevel) {
          const neighbors = adjacency.get(nodeId)
          if (!neighbors) continue
          for (const neighbor of neighbors) {
            if (!visited.has(neighbor)) {
              visited.add(neighbor)
              nextLevel.push(neighbor)
            }
          }
        }
        levels.push(nextLevel)
        currentLevel = nextLevel
      }

      return { level2: levels[1] || [], level3: levels[2] || [] }
    }

    function toConnectionInfos(ids: string[], hopLabel: string): ConnectionInfo[] {
      return ids.map(id => {
        const n = nodeMap.get(id)
        return {
          nodeId: id,
          nodeName: n?.name || id,
          nodeType: n?.type || 'Unknown',
          relationType: hopLabel,
        }
      })
    }

    const rows = data.nodes.map(node => {
      // Memoized lazy getters: BFS runs only on first call per node
      let cachedLevel2: ConnectionInfo[] | null = null
      let cachedLevel3: ConnectionInfo[] | null = null

      return {
        node,
        connectionsIn: connectionsIn.get(node.id) || [],
        connectionsOut: connectionsOut.get(node.id) || [],
        getLevel2: () => {
          if (cachedLevel2 !== null) return cachedLevel2
          const { level2, level3 } = getNodesAtDepth(node.id)
          cachedLevel2 = toConnectionInfos(level2, '2 hops')
          cachedLevel3 = toConnectionInfos(level3, '3 hops')
          return cachedLevel2
        },
        getLevel3: () => {
          if (cachedLevel3 !== null) return cachedLevel3
          const { level2, level3 } = getNodesAtDepth(node.id)
          cachedLevel2 = toConnectionInfos(level2, '2 hops')
          cachedLevel3 = toConnectionInfos(level3, '3 hops')
          return cachedLevel3
        },
      }
    })

    return rows
  }, [data])
}

import { GraphData, GraphNode, GraphLink } from '../types'
import { CLUSTER_THRESHOLD } from '../config'
import { getNodeColor } from './nodeHelpers'

const CHAIN_TYPES = new Set([
  'AttackChain',
  'ChainStep',
  'ChainFinding',
  'ChainDecision',
  'ChainFailure',
])

function linkEndpointId(endpoint: string | GraphNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id
}

/**
 * Collapse >threshold same-type leaf neighbors of a shared parent into synthetic cluster nodes.
 *
 * A neighbor qualifies only when its sole connection in the whole graph is to the parent
 * (leaf-only rule). Chain-family nodes are never clustered.
 *
 * Cluster id is deterministic: `cluster:<parentId>:<childType>` — stable across re-renders
 * so the force simulation keeps its position.
 */
export function clusterGraphData(
  data: GraphData,
  threshold: number = CLUSTER_THRESHOLD,
): GraphData {
  const { nodes, links } = data

  // Degree map for the leaf check
  const degree = new Map<string, number>()
  for (const l of links) {
    const s = linkEndpointId(l.source)
    const t = linkEndpointId(l.target)
    degree.set(s, (degree.get(s) ?? 0) + 1)
    degree.set(t, (degree.get(t) ?? 0) + 1)
  }

  const nodeById = new Map(nodes.map(n => [n.id, n]))

  // Group (parentId, childType) -> child nodes, but only when child is a leaf (degree === 1)
  // and child type is not a chain type.
  const groups = new Map<string, { parentId: string; type: string; children: GraphNode[] }>()
  for (const l of links) {
    const sId = linkEndpointId(l.source)
    const tId = linkEndpointId(l.target)
    const s = nodeById.get(sId)
    const t = nodeById.get(tId)
    if (!s || !t) continue

    // Try both directions: a leaf can be either the source or the target
    const candidates: Array<[GraphNode, GraphNode]> = [[s, t], [t, s]]
    for (const [child, parent] of candidates) {
      if ((degree.get(child.id) ?? 0) !== 1) continue
      if (CHAIN_TYPES.has(child.type)) continue
      const key = `${parent.id}::${child.type}`
      let g = groups.get(key)
      if (!g) {
        g = { parentId: parent.id, type: child.type, children: [] }
        groups.set(key, g)
      }
      g.children.push(child)
    }
  }

  // Collect child ids that will be hidden, keyed to their cluster
  const childToCluster = new Map<string, string>()
  const clusterNodes: GraphNode[] = []
  for (const { parentId, type, children } of groups.values()) {
    if (children.length <= threshold) continue
    const clusterId = `cluster:${parentId}:${type}`
    for (const child of children) childToCluster.set(child.id, clusterId)

    // Resolve a representative color from the first child (handles severity-colored types)
    const representative = children[0]
    const color = getNodeColor(representative)

    const cluster: GraphNode = {
      id: clusterId,
      name: `${children.length} ${type}${children.length === 1 ? '' : 's'}`,
      type: `Cluster:${type}`,
      isCluster: true,
      clusterChildren: children,
      clusterChildType: type,
      clusterColor: color,
      properties: {
        cluster_parent_id: parentId,
        cluster_child_type: type,
        cluster_size: children.length,
      },
    }
    clusterNodes.push(cluster)
  }

  if (clusterNodes.length === 0) return data

  const removedChildIds = new Set(childToCluster.keys())
  const clusterIds = new Set(clusterNodes.map(c => c.id))

  const newNodes: GraphNode[] = []
  for (const n of nodes) {
    if (removedChildIds.has(n.id)) continue
    newNodes.push(n)
  }
  newNodes.push(...clusterNodes)

  const seenLinks = new Set<string>()
  const newLinks: GraphLink[] = []
  for (const l of links) {
    const sId = linkEndpointId(l.source)
    const tId = linkEndpointId(l.target)
    const sCluster = childToCluster.get(sId)
    const tCluster = childToCluster.get(tId)

    // If both endpoints are in the same cluster, drop (intra-cluster, can't happen under leaf-rule but safe).
    const newSource = sCluster ?? sId
    const newTarget = tCluster ?? tId
    if (newSource === newTarget) continue

    // Deduplicate multi-edges between parent and cluster
    if (clusterIds.has(newSource) || clusterIds.has(newTarget)) {
      const dedupeKey = `${newSource}->${newTarget}::${l.type}`
      if (seenLinks.has(dedupeKey)) continue
      seenLinks.add(dedupeKey)
      newLinks.push({ source: newSource, target: newTarget, type: l.type })
    } else {
      newLinks.push(l)
    }
  }

  return { ...data, nodes: newNodes, links: newLinks }
}

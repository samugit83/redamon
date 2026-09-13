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

/**
 * Edges that are "decorative" / "structural" - they connect a hub to a leafy detail
 * node (headers, parameters, technologies, endpoints, certificates). A node whose
 * edges are ALL in this set is treated as structurally leafy for Pass 2 clustering,
 * even if its degree is > 1.
 *
 * Curated from the project's actual Cypher schema (see docs/readmes/GRAPH.SCHEMA.md).
 * Do NOT include attack-chain or vulnerability-link edges here - those carry
 * semantic meaning and should never be collapsed.
 */
const STRUCTURAL_EDGE_TYPES = new Set([
  'HAS_ENDPOINT',
  'HAS_HEADER',
  'HAS_PARAMETER',
  'HAS_DNS_RECORD',
  'HAS_CERTIFICATE',
  // One wildcard cert can cover every Subdomain it names; without this, that
  // high-degree fan-out never collapses and /graph degrades on the first
  // wildcard cert.
  'COVERS_HOST',
  'HAS_SECRET',
  'HAS_PORT',
  'HAS_TRACEROUTE',
  'USES_TECHNOLOGY',
  'HAS_TECHNOLOGY',
  'POWERED_BY',
  'RUNS_SERVICE',
  'SERVES_URL',
  'HAS_BASE_URL',
  // Legacy spelling still on disk until vhost/AI-surface data ages out; the
  // writers now emit HAS_BASE_URL (Phase 0.4) but keep this for old graphs.
  'HAS_BASEURL',
  'RESOLVES_TO',
  'HAS_SUBDOMAIN',
  // Multiscanner asset hubs: a namespace scan can hang hundreds of findings off
  // one image or bucket. Leaf findings already collapse through the generic
  // degree-1 passes, but pass-2 hub clustering is NOT generic — without its edge
  // types here an asset hub with many children never collapses at all.
  'HAS_ASSET',
  'HAS_FINDING',
])

function linkEndpointId(endpoint: string | GraphNode): string {
  return typeof endpoint === 'string' ? endpoint : endpoint.id
}

/**
 * Pick an adaptive clustering threshold that scales down as the graph grows.
 * Tuned on real RedAmon graphs where 700 Endpoints × 4 Headers each fail the
 * default threshold of 30 but explode the node count.
 */
function adaptiveThreshold(nodeCount: number): number {
  if (nodeCount > 6000) return 3
  if (nodeCount > 3000) return 3
  if (nodeCount > 1000) return 8
  return CLUSTER_THRESHOLD
}

/**
 * Pass 1: collapse same-type leaf neighbors (degree === 1) of a shared parent into
 * synthetic cluster nodes. Identical to the legacy behavior but configurable
 * threshold. Cluster id is deterministic: `cluster:<parentId>:<childType>`.
 */
function clusterLeafGroups(data: GraphData, threshold: number): GraphData {
  const { nodes, links } = data

  const degree = new Map<string, number>()
  for (const l of links) {
    const s = linkEndpointId(l.source)
    const t = linkEndpointId(l.target)
    degree.set(s, (degree.get(s) ?? 0) + 1)
    degree.set(t, (degree.get(t) ?? 0) + 1)
  }

  const nodeById = new Map(nodes.map(n => [n.id, n]))

  const groups = new Map<string, { parentId: string; type: string; children: GraphNode[] }>()
  for (const l of links) {
    const sId = linkEndpointId(l.source)
    const tId = linkEndpointId(l.target)
    const s = nodeById.get(sId)
    const t = nodeById.get(tId)
    if (!s || !t) continue

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

  return buildClusteredGraph(data, groups, threshold, 'cluster')
}

/**
 * Pass 2: structural-edge clustering. A node is "structurally leafy" if ALL its
 * edges are in STRUCTURAL_EDGE_TYPES and it has exactly one incoming non-structural
 * anchor (the parent - typically BaseURL → Endpoint). Group such nodes by the
 * anchor + type, and collapse if group size ≥ threshold.
 *
 * Cluster id: `struct:<parentId>:<childType>`.
 *
 * Why this matters: Endpoints have degree 5-7 (BaseURL parent + 4 Header children
 * + 1 Technology) so they fail the leaf-only rule. But all their edges are
 * structural - they're decorator hubs, not graph waypoints - so collapsing them
 * loses no topology that matters.
 */
function clusterStructuralHubs(data: GraphData, threshold: number): GraphData {
  const { nodes, links } = data
  const nodeById = new Map(nodes.map(n => [n.id, n]))

  // Build adjacency with edge type info
  const adjacency = new Map<string, Array<{ neighborId: string; edgeType: string; outgoing: boolean }>>()
  for (const l of links) {
    const sId = linkEndpointId(l.source)
    const tId = linkEndpointId(l.target)
    if (!adjacency.has(sId)) adjacency.set(sId, [])
    if (!adjacency.has(tId)) adjacency.set(tId, [])
    adjacency.get(sId)!.push({ neighborId: tId, edgeType: l.type, outgoing: true })
    adjacency.get(tId)!.push({ neighborId: sId, edgeType: l.type, outgoing: false })
  }

  const groups = new Map<string, { parentId: string; type: string; children: GraphNode[] }>()
  for (const node of nodes) {
    if (CHAIN_TYPES.has(node.type)) continue
    if (node.isCluster) continue // don't recluster already-clustered nodes

    const edges = adjacency.get(node.id) ?? []
    if (edges.length === 0) continue

    // Every edge must be structural
    const allStructural = edges.every(e => STRUCTURAL_EDGE_TYPES.has(e.edgeType))
    if (!allStructural) continue

    // The "parent" anchor: the single incoming structural edge from a non-leaf hub.
    // For Endpoints this is BaseURL via HAS_ENDPOINT. For nodes with multiple
    // incoming structural edges, skip - we can't pick an unambiguous parent.
    const incoming = edges.filter(e => !e.outgoing)
    if (incoming.length !== 1) continue
    const parentId = incoming[0].neighborId
    const parent = nodeById.get(parentId)
    if (!parent) continue

    const key = `${parentId}::${node.type}`
    let g = groups.get(key)
    if (!g) {
      g = { parentId, type: node.type, children: [] }
      groups.set(key, g)
    }
    g.children.push(node)
  }

  return buildClusteredGraph(data, groups, threshold, 'struct')
}

/**
 * Shared cluster materialization: given groups, build the new node/link arrays
 * with collapsed children replaced by synthetic cluster nodes and edges re-routed.
 */
function buildClusteredGraph(
  data: GraphData,
  groups: Map<string, { parentId: string; type: string; children: GraphNode[] }>,
  threshold: number,
  idPrefix: string,
): GraphData {
  const { nodes, links } = data

  const childToCluster = new Map<string, string>()
  const clusterNodes: GraphNode[] = []
  for (const { parentId, type, children } of groups.values()) {
    if (children.length <= threshold) continue

    // Flatten: if all children being clustered are themselves clusters of the
    // same inner type, merge their grandchildren into one flat super-cluster
    // instead of a cluster-of-clusters. Keeps the drawer drill-down at 2 levels
    // (cluster → leaf) rather than 3 (cluster → cluster → leaf).
    let effectiveChildren = children
    let effectiveType = type
    const allClustersOfSameInner =
      children.length > 0 &&
      children.every(c => c.isCluster && (c.clusterChildren?.length ?? 0) > 0)
    if (allClustersOfSameInner) {
      const innerTypes = new Set(children.map(c => c.clusterChildType ?? ''))
      if (innerTypes.size === 1) {
        effectiveType = children[0].clusterChildType ?? type
        effectiveChildren = children.flatMap(c => c.clusterChildren ?? [])
      }
    }

    const clusterId = `${idPrefix}:${parentId}:${effectiveType}`
    for (const child of children) childToCluster.set(child.id, clusterId)

    const representative = effectiveChildren[0] ?? children[0]
    const color = getNodeColor(representative)

    const cluster: GraphNode = {
      id: clusterId,
      name: `${effectiveChildren.length} ${effectiveType}${effectiveChildren.length === 1 ? '' : 's'}`,
      type: `Cluster:${effectiveType}`,
      isCluster: true,
      clusterChildren: effectiveChildren,
      clusterChildType: effectiveType,
      clusterColor: color,
      properties: {
        cluster_parent_id: parentId,
        cluster_child_type: effectiveType,
        cluster_size: effectiveChildren.length,
        cluster_origin: idPrefix,
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

    const newSource = sCluster ?? sId
    const newTarget = tCluster ?? tId
    if (newSource === newTarget) continue

    if (clusterIds.has(newSource) || clusterIds.has(newTarget) || sCluster || tCluster) {
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

/**
 * Main entry: run the clustering pipeline.
 *
 * Strategy (calibrated on real RedAmon graphs):
 *   1. Adaptive-threshold leaf clustering, cascaded until stable. Catches
 *      Headers-per-Endpoint, Parameters-per-Endpoint, DNS records, etc.
 *      Cascading matters: after Headers cluster, their parent Endpoints lose
 *      degree (5→2) but still don't become pure leaves.
 *   2. Structural-edge clustering. Catches "decorator hub" nodes like Endpoints
 *      whose every edge is structural. Groups by single non-structural anchor.
 *   3. One more leaf-cluster cascade in case Pass 2 turned remaining nodes into
 *      pure leaves.
 *
 * Override the threshold if explicitly passed; otherwise it adapts to graph size.
 */
export function clusterGraphData(
  data: GraphData,
  thresholdOverride?: number,
): GraphData {
  const threshold = thresholdOverride ?? adaptiveThreshold(data.nodes.length)

  // Pass 1: cascading leaf clustering. Each iteration collapses one "fringe layer".
  // Bounded to a handful of passes - graphs rarely have more than 3-4 nested fringes.
  let result = data
  for (let i = 0; i < 5; i++) {
    const next = clusterLeafGroups(result, threshold)
    if (next.nodes.length === result.nodes.length) break
    result = next
  }

  // Pass 2: structural-hub clustering (Endpoints, etc.)
  result = clusterStructuralHubs(result, threshold)

  // Pass 3: one more leaf cascade in case structural clustering turned more
  // nodes into pure leaves (e.g. Technology nodes attached only to a now-clustered
  // Endpoint group)
  for (let i = 0; i < 3; i++) {
    const next = clusterLeafGroups(result, threshold)
    if (next.nodes.length === result.nodes.length) break
    result = next
  }

  return result
}

export interface GraphNode {
  id: string
  name: string
  type: string
  properties: Record<string, unknown>
  x?: number
  y?: number
  z?: number
  // Synthetic cluster flag: set by clusterGraphData when this node represents
  // a collapsed group of same-type leaf neighbors sharing a common parent.
  isCluster?: boolean
  clusterChildren?: GraphNode[]
  clusterChildType?: string
  clusterColor?: string
}

export interface GraphLink {
  source: string | GraphNode
  target: string | GraphNode
  type: string
}

export interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
  projectId: string
}

export type GlowLevel = 'critical' | 'high' | false

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

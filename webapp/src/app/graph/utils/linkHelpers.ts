import { GraphLink, GraphNode } from '../types'
import { LINK_COLORS, LINK_SIZES, CHAIN_SESSION_COLORS } from '../config'

/** Sequential flow links — animated directional particles */
const CHAIN_FLOW_TYPES = new Set([
  'HAS_STEP', 'NEXT_STEP', 'PRODUCED', 'FAILED_WITH', 'LED_TO', 'DECISION_PRECEDED',
  'CHAIN_TARGETS',
])

/** Bridge links to recon graph — static, no animation */
const CHAIN_BRIDGE_TYPES = new Set([
  'STEP_TARGETED', 'STEP_EXPLOITED', 'STEP_IDENTIFIED',
  'FOUND_ON', 'FINDING_RELATES_CVE', 'CREDENTIAL_FOR',
])

/**
 * Check if a link is an attack chain relationship (flow or bridge)
 */
export const isChainLink = (link: GraphLink): boolean =>
  CHAIN_FLOW_TYPES.has(link.type) || CHAIN_BRIDGE_TYPES.has(link.type)

/**
 * Check if a link is a sequential flow link (should be animated)
 */
export const isChainFlowLink = (link: GraphLink): boolean =>
  CHAIN_FLOW_TYPES.has(link.type)

/**
 * Check if a link is a bridge link to the recon graph (static, thinner)
 */
export const isChainBridgeLink = (link: GraphLink): boolean =>
  CHAIN_BRIDGE_TYPES.has(link.type)

/**
 * Extract node ID from a link endpoint (handles both string and GraphNode types)
 */
export const getNodeId = (node: string | GraphNode): string =>
  typeof node === 'string' ? node : node.id

/**
 * Check if a link is connected to a specific node
 */
export const isLinkConnectedToNode = (link: GraphLink, nodeId: string): boolean => {
  const sourceId = getNodeId(link.source)
  const targetId = getNodeId(link.target)
  return sourceId === nodeId || targetId === nodeId
}

/**
 * Get link color based on selection state
 */
export const getLinkColor = (link: GraphLink, selectedNodeId?: string): string => {
  if (!selectedNodeId) return LINK_COLORS.default
  return isLinkConnectedToNode(link, selectedNodeId)
    ? LINK_COLORS.highlighted
    : LINK_COLORS.default
}

/**
 * Get link width based on selection state (2D)
 */
export const getLinkWidth2D = (link: GraphLink, selectedNodeId?: string): number => {
  if (isChainBridgeLink(link)) return 0.1
  if (!selectedNodeId) return LINK_SIZES.defaultWidth2D
  return isLinkConnectedToNode(link, selectedNodeId)
    ? LINK_SIZES.highlightedWidth2D
    : LINK_SIZES.defaultWidth2D
}

/**
 * Get link width based on selection state (3D)
 */
export const getLinkWidth3D = (link: GraphLink, selectedNodeId?: string): number => {
  if (isChainBridgeLink(link)) return 0.2
  if (!selectedNodeId) return LINK_SIZES.defaultWidth3D
  return isLinkConnectedToNode(link, selectedNodeId)
    ? LINK_SIZES.highlightedWidth3D
    : LINK_SIZES.defaultWidth3D
}

/**
 * Get particle width based on selection state and chain flow membership
 */
export const getParticleWidth = (link: GraphLink, selectedNodeId?: string): number => {
  if (!selectedNodeId) return 0
  if (!isLinkConnectedToNode(link, selectedNodeId)) return 0
  return isChainFlowLink(link) ? 3 : LINK_SIZES.particleWidth
}

/**
 * Get particle count based on selection state and chain flow membership
 */
export const getParticleCount = (link: GraphLink, selectedNodeId?: string): number => {
  if (!selectedNodeId) return 0
  if (!isLinkConnectedToNode(link, selectedNodeId)) return 0
  return isChainFlowLink(link) ? 4 : LINK_SIZES.particleCount
}

/**
 * Get particle speed — faster for chain flow links
 */
export const getParticleSpeed = (link: GraphLink): number => {
  return isChainFlowLink(link) ? 0.012 : 0.004
}

/**
 * Check if a chain link belongs to the active chain (by inspecting its source/target nodes)
 */
const isLinkInActiveChain = (link: GraphLink, activeChainId?: string): boolean => {
  if (!activeChainId) return false
  const source = typeof link.source === 'string' ? null : link.source
  const target = typeof link.target === 'string' ? null : link.target
  return (source?.properties?.chain_id === activeChainId) || (target?.properties?.chain_id === activeChainId)
}

/**
 * Get particle color — bright grey for active chain, dark grey for inactive, blue for selection highlights
 */
export const getParticleColor = (link: GraphLink, activeChainId?: string): string => {
  if (isChainFlowLink(link)) {
    return isLinkInActiveChain(link, activeChainId) ? '#9ca3af' : '#2d3748'
  }
  return LINK_COLORS.particle
}

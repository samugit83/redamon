'use client'

import { useRef, useEffect, useMemo } from 'react'
import dynamic from 'next/dynamic'
import { GraphData, GraphNode, GraphLink } from '../../types'
import { getNodeColor, getNodeSize, getGlowLevel } from '../../utils'
import { getLinkColor, getLinkWidth2D, getParticleWidth, getParticleColor, getParticleCount, getParticleSpeed } from '../../utils/linkHelpers'
import {
  LINK_SIZES,
  BASE_SIZES,
  BACKGROUND_COLORS,
  SELECTION_COLORS,
  CHAIN_SESSION_COLORS,
  GOAL_FINDING_COLORS,
  FORCE_CONFIG,
  ANIMATION_CONFIG,
  ZOOM_CONFIG,
} from '../../config'
import { getPerformanceTier, TIER_CONFIG, getAdaptiveForceConfig } from '../../config/graph'
import { hasHighSeverityNodes, isGoalFinding } from '../../utils/nodeHelpers'
import { useAnimationFrame } from '../../hooks'

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
})

interface GraphCanvas2DProps {
  data: GraphData
  width: number
  height: number
  showLabels: boolean
  selectedNode: GraphNode | null
  onNodeClick: (node: GraphNode) => void
  isDark?: boolean
  activeChainId?: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  externalGraphRef?: React.MutableRefObject<any>
}

export function GraphCanvas2D({
  data,
  width,
  height,
  showLabels,
  selectedNode,
  onNodeClick,
  isDark = true,
  activeChainId,
  externalGraphRef,
}: GraphCanvas2DProps) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null)

  // Sync internal ref to external ref (for parent component access)
  useEffect(() => {
    if (externalGraphRef) externalGraphRef.current = graphRef.current
  })
  const animationTimeRef = useRef<number>(0)
  const prevNodeCountRef = useRef<number>(0)

  // Performance tier + adaptive force config
  const tier = useMemo(() => getPerformanceTier(data.nodes.length), [data.nodes.length])
  const tierConfig = useMemo(() => TIER_CONFIG[tier], [tier])
  const forceConfig = useMemo(() => getAdaptiveForceConfig(data.nodes.length), [data.nodes.length])

  // Configure forces (runs on mount and when data changes)
  useEffect(() => {
    const timer = setTimeout(() => {
      const fg = graphRef.current
      if (!fg) return

      const d3 = require('d3-force')
      fg.d3Force(
        'collide',
        d3
          .forceCollide()
          .radius(FORCE_CONFIG.collisionRadius)
          .strength(FORCE_CONFIG.collisionStrength)
          .iterations(forceConfig.collisionIterations)
      )
      // Spread connected nodes further apart within clusters
      const linkForce = fg.d3Force('link')
      if (linkForce) linkForce.distance(80)
      // Reduce repulsion so distant clusters don't fly apart
      const chargeForce = fg.d3Force('charge')
      if (chargeForce) chargeForce.strength(-40).distanceMax(250)
    }, ANIMATION_CONFIG.initDelay)

    return () => clearTimeout(timer)
  }, [forceConfig.collisionIterations])

  // Reheat on structural changes (new/removed nodes or links). Deferred via
  // setTimeout so graphRef.current is attached on first mount (ForceGraph2D is
  // next/dynamic-loaded — forwardRef isn't committed on the first render pass).
  const prevLinkCountRef = useRef<number>(0)
  useEffect(() => {
    const prevNodeCount = prevNodeCountRef.current
    const prevLinkCount = prevLinkCountRef.current
    const newNodeCount = data.nodes.length
    const newLinkCount = data.links.length
    const structureChanged = newNodeCount !== prevNodeCount || newLinkCount !== prevLinkCount
    prevNodeCountRef.current = newNodeCount
    prevLinkCountRef.current = newLinkCount

    if (structureChanged) {
      const timer = setTimeout(() => {
        graphRef.current?.d3ReheatSimulation()
      }, ANIMATION_CONFIG.initDelay)
      return () => clearTimeout(timer)
    }
  }, [data])

  // Slow down zoom speed for smoother navigation
  useEffect(() => {
    const applyZoom = () => {
      const fg = graphRef.current
      if (!fg) return false
      // d3-zoom: reduce wheel delta for slower zoom (default multiplier is ~1.0)
      const zoom = fg.zoom()
      if (zoom?.wheelDelta) {
        zoom.wheelDelta((event: WheelEvent) => {
          return -event.deltaY * (event.deltaMode === 1 ? 0.03 : event.deltaMode ? 1 : 0.0006)
        })
        return true
      }
      return false
    }
    if (!applyZoom()) {
      const timer = setTimeout(applyZoom, 500)
      return () => clearTimeout(timer)
    }
  }, [data])

  // Animation loop for pulsing glow effect (only when glow is enabled by tier)
  const hasHighSeverity = hasHighSeverityNodes(data.nodes)
  const enableGlowAnim = hasHighSeverity && tierConfig.enableGlow

  useAnimationFrame(
    (time) => {
      animationTimeRef.current = time
      const fg = graphRef.current
      if (fg) {
        if (typeof fg._rerender === 'function') {
          fg._rerender()
        } else if (typeof fg.refresh === 'function') {
          fg.refresh()
        }
      }
    },
    enableGlowAnim
  )

  const selectedNodeId = selectedNode?.id

  return (
    <ForceGraph2D
      ref={graphRef}
      graphData={data}
      nodeLabel={(node) => `${(node as GraphNode).name} (${(node as GraphNode).type})`}
      nodeRelSize={BASE_SIZES.node2D}
      linkLabel={(link) => (link as GraphLink).type}
      linkColor={(link) => getLinkColor(link as GraphLink, selectedNodeId)}
      linkDirectionalArrowColor={(link) => getLinkColor(link as GraphLink, selectedNodeId)}
      linkWidth={(link) => getLinkWidth2D(link as GraphLink, selectedNodeId)}
      linkDirectionalParticles={tierConfig.enableParticles
        ? (link) => getParticleCount(link as GraphLink, selectedNodeId)
        : 0
      }
      linkDirectionalParticleWidth={tierConfig.enableParticles
        ? (link) => getParticleWidth(link as GraphLink, selectedNodeId)
        : undefined
      }
      linkDirectionalParticleColor={tierConfig.enableParticles
        ? (link) => getParticleColor(link as GraphLink, activeChainId)
        : undefined
      }
      linkDirectionalParticleSpeed={tierConfig.enableParticles
        ? (link) => getParticleSpeed(link as GraphLink)
        : undefined
      }
      linkDirectionalArrowLength={LINK_SIZES.arrowLength}
      linkDirectionalArrowRelPos={1}
      backgroundColor={isDark ? BACKGROUND_COLORS.dark.graph : BACKGROUND_COLORS.light.graph}
      width={width}
      height={height}
      d3AlphaDecay={FORCE_CONFIG.alphaDecay}
      d3VelocityDecay={FORCE_CONFIG.velocityDecay}
      cooldownTime={forceConfig.cooldownTime}
      cooldownTicks={forceConfig.cooldownTicks}
      warmupTicks={forceConfig.warmupTicks}
      onNodeClick={(node) => onNodeClick(node as GraphNode)}
      nodeCanvasObject={(node, ctx, globalScale) => {
        const graphNode = node as GraphNode & { x: number; y: number }
        if (!isFinite(graphNode.x) || !isFinite(graphNode.y)) return
        const nodeSize = BASE_SIZES.node2D * getNodeSize(graphNode)
        const color = getNodeColor(graphNode)
        const isSelected = selectedNodeId === graphNode.id

        const isChainNode = graphNode.type === 'AttackChain' || graphNode.type === 'ChainStep' || graphNode.type === 'ChainDecision' || graphNode.type === 'ChainFailure'
        const isInActiveChain = isChainNode && !!activeChainId && graphNode.properties?.chain_id === activeChainId
        const isActiveChain = graphNode.type === 'AttackChain' && isInActiveChain
        const isExploit = graphNode.type === 'ExploitGvm' || graphNode.type === 'ChainFinding'
        const isExploitInActiveChain = isExploit && !!activeChainId && graphNode.properties?.chain_id === activeChainId
        const isGoal = isGoalFinding(graphNode)
        // Inactive chain nodes: grey (dark yellow for diamonds, dark green for goal findings)
        let effectiveColor: string
        if ((isChainNode || isExploit) && !isInActiveChain && !isExploitInActiveChain) {
          if (isGoal) {
            effectiveColor = isSelected ? GOAL_FINDING_COLORS.active : GOAL_FINDING_COLORS.inactive
          } else if (isExploit) {
            effectiveColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactiveFinding
          } else {
            effectiveColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactive
          }
        } else {
          effectiveColor = color
        }

        // Helper: draw hexagon path centered at (cx, cy) with given radius
        const drawHexagon = (cx: number, cy: number, r: number) => {
          ctx.beginPath()
          for (let i = 0; i < 6; i++) {
            const angle = (Math.PI / 3) * i - Math.PI / 2
            const px = cx + r * Math.cos(angle)
            const py = cy + r * Math.sin(angle)
            if (i === 0) ctx.moveTo(px, py)
            else ctx.lineTo(px, py)
          }
          ctx.closePath()
        }

        // Cluster node: torus / donut ring with centered count
        if (graphNode.isCluster) {
          const clusterColor = graphNode.clusterColor ?? color
          const outerR = nodeSize * 1.35
          const thickness = outerR * 0.42
          const midR = outerR - thickness / 2
          const innerR = outerR - thickness

          // Selection ring (outer bounding circle)
          if (isSelected) {
            ctx.beginPath()
            ctx.arc(graphNode.x, graphNode.y, outerR + 5, 0, 2 * Math.PI)
            ctx.strokeStyle = SELECTION_COLORS.ring
            ctx.lineWidth = 3
            ctx.stroke()
          }

          // Thick stroked circle renders as a donut
          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, midR, 0, 2 * Math.PI)
          ctx.strokeStyle = clusterColor
          ctx.lineWidth = thickness
          ctx.stroke()

          // Subtle inner edge highlight for depth
          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, innerR, 0, 2 * Math.PI)
          ctx.strokeStyle = 'rgba(0,0,0,0.25)'
          ctx.lineWidth = 0.5
          ctx.stroke()

          // Count text inside the hole (theme-aware for contrast)
          const count = graphNode.clusterChildren?.length ?? 0
          const text = count >= 1000 ? `${Math.floor(count / 100) / 10}k` : `${count}`
          const fontSize = Math.max(innerR * 0.78, 4)
          ctx.font = `bold ${fontSize}px Sans-Serif`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillStyle = isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label
          ctx.fillText(text, graphNode.x, graphNode.y)

          // Label below (respects label tier + zoom threshold)
          if (tierConfig.enableLabels && ((showLabels && globalScale > ZOOM_CONFIG.labelVisibilityThreshold) || isSelected)) {
            const childType = graphNode.clusterChildType ?? ''
            const labelFont = Math.max(6 / globalScale, BASE_SIZES.label2D.min)
            ctx.font = `${labelFont}px Sans-Serif`
            ctx.textAlign = 'center'
            ctx.textBaseline = 'top'
            ctx.fillStyle = isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label
            ctx.fillText(`${count} ${childType}`, graphNode.x, graphNode.y + outerR + 2)
          }
          return
        }

        // Draw selection marker (outer ring) for selected node
        if (isSelected) {
          if (graphNode.type === 'ExploitGvm' || graphNode.type === 'ChainFinding') {
            // Diamond selection ring
            const sd = nodeSize * 1.2 + 6
            ctx.beginPath()
            ctx.moveTo(graphNode.x, graphNode.y - sd)
            ctx.lineTo(graphNode.x + sd, graphNode.y)
            ctx.lineTo(graphNode.x, graphNode.y + sd)
            ctx.lineTo(graphNode.x - sd, graphNode.y)
            ctx.closePath()
            ctx.strokeStyle = SELECTION_COLORS.ring
            ctx.lineWidth = 3
            ctx.stroke()
          } else if (isChainNode) {
            // Hexagon selection ring
            drawHexagon(graphNode.x, graphNode.y, nodeSize * 1.2 + 6)
            ctx.strokeStyle = SELECTION_COLORS.ring
            ctx.lineWidth = 3
            ctx.stroke()
          } else {
            ctx.beginPath()
            ctx.arc(graphNode.x, graphNode.y, nodeSize + 6, 0, 2 * Math.PI)
            ctx.strokeStyle = SELECTION_COLORS.ring
            ctx.lineWidth = 3
            ctx.stroke()
          }
        }

        // Draw active-session marker on the matching AttackChain node
        if (isActiveChain) {
          const time = animationTimeRef.current || Date.now() / 1000
          const pulse = Math.sin(time * 3) * 0.5 + 0.5
          const ringRadius = nodeSize * 1.2 + 8 + pulse * 3
          ctx.save()
          ctx.setLineDash([4, 4])
          ctx.lineDashOffset = -time * 20 // rotating dash
          drawHexagon(graphNode.x, graphNode.y, ringRadius)
          ctx.strokeStyle = `rgba(250, 204, 21, ${0.7 + pulse * 0.3})` // yellow
          ctx.lineWidth = 2
          ctx.stroke()
          ctx.setLineDash([])
          ctx.restore()
        }

        // Glow effect (skip when tier disables it)
        const glowLevel = getGlowLevel(graphNode)
        const glowColor = (isChainNode || isExploit) ? effectiveColor : color
        if (tierConfig.enableGlow && glowLevel) {
          const time = animationTimeRef.current || Date.now() / 1000
          const speed = glowLevel === 'critical' ? ANIMATION_CONFIG.criticalSpeed : ANIMATION_CONFIG.highSpeed
          const pulse = Math.sin(time * speed) * 0.5 + 0.5
          const glowRadius = nodeSize + ANIMATION_CONFIG.glow2DRadiusExtra.base + pulse * ANIMATION_CONFIG.glow2DRadiusExtra.pulse

          const gradient = ctx.createRadialGradient(
            graphNode.x,
            graphNode.y,
            nodeSize,
            graphNode.x,
            graphNode.y,
            glowRadius
          )
          gradient.addColorStop(0, glowColor)
          gradient.addColorStop(0.5, `${glowColor}88`)
          gradient.addColorStop(1, `${glowColor}00`)

          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, glowRadius, 0, 2 * Math.PI)
          ctx.fillStyle = gradient
          ctx.fill()
        }

        // Draw main shape
        if (isExploit) {
          // Diamond shape for Exploit nodes (rotated square)
          const d = nodeSize * 1.2 // diamond half-diagonal
          ctx.beginPath()
          ctx.moveTo(graphNode.x, graphNode.y - d)       // top
          ctx.lineTo(graphNode.x + d, graphNode.y)       // right
          ctx.lineTo(graphNode.x, graphNode.y + d)       // bottom
          ctx.lineTo(graphNode.x - d, graphNode.y)       // left
          ctx.closePath()
          ctx.fillStyle = effectiveColor.replace(')', ', 0.12)').replace('rgb(', 'rgba(')
          ctx.fill()
          ctx.strokeStyle = effectiveColor
          ctx.lineWidth = 1.5
          ctx.stroke()

          // Lightning bolt icon inside diamond
          const iconSize = Math.max(d * 0.7, 4)
          ctx.font = `${iconSize}px Sans-Serif`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillStyle = effectiveColor
          ctx.fillText('\u26A1', graphNode.x, graphNode.y)
        } else if (isChainNode) {
          // Hexagon shape for attack chain nodes
          const r = nodeSize * 1.1
          drawHexagon(graphNode.x, graphNode.y, r)
          ctx.fillStyle = effectiveColor.replace(')', ', 0.15)').replace('rgb(', 'rgba(')
          ctx.fill()
          ctx.strokeStyle = effectiveColor
          ctx.lineWidth = 1.5
          ctx.stroke()
        } else if (graphNode.type === 'ExternalDomain') {
          // Dashed circle
          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, nodeSize, 0, 2 * Math.PI)
          ctx.save()
          ctx.globalAlpha = 0.15
          ctx.fillStyle = color
          ctx.fill()
          ctx.globalAlpha = 1
          ctx.setLineDash([3, 3])
          ctx.strokeStyle = color
          ctx.lineWidth = 1.5
          ctx.stroke()
          ctx.setLineDash([])
          ctx.restore()
        } else {
          // Standard circle
          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, nodeSize, 0, 2 * Math.PI)
          ctx.fillStyle = color
          ctx.fill()
        }

        // Draw label (skip when tier disables it)
        if (tierConfig.enableLabels && ((showLabels && globalScale > ZOOM_CONFIG.labelVisibilityThreshold) || isSelected)) {
          const label = graphNode.name
          const fontSize = Math.max(6 / globalScale, BASE_SIZES.label2D.min)
          ctx.font = `${fontSize}px Sans-Serif`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'top'
          ctx.fillStyle = isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label
          ctx.fillText(label, graphNode.x, graphNode.y + nodeSize + 2)
        }
      }}
      nodePointerAreaPaint={(node, color, ctx) => {
        const graphNode = node as GraphNode & { x: number; y: number }
        if (graphNode.isCluster) {
          const outerR = BASE_SIZES.node2D * getNodeSize(graphNode) * 1.35
          ctx.beginPath()
          ctx.arc(graphNode.x, graphNode.y, Math.max(outerR, 10), 0, 2 * Math.PI)
          ctx.fillStyle = color
          ctx.fill()
          return
        }
        ctx.beginPath()
        ctx.arc(graphNode.x, graphNode.y, 10, 0, 2 * Math.PI)
        ctx.fillStyle = color
        ctx.fill()
      }}
    />
  )
}

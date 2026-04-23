'use client'

import { useRef, useEffect, useCallback, useMemo } from 'react'
import dynamic from 'next/dynamic'
import { GraphData, GraphNode, GraphLink } from '../../types'
import { getNodeColor, getNodeSize, getGlowLevel } from '../../utils'
import { getLinkColor, getLinkWidth3D, getParticleCount, getParticleWidth, getParticleColor, getParticleSpeed } from '../../utils/linkHelpers'
import {
  LINK_SIZES,
  BASE_SIZES,
  BACKGROUND_COLORS,
  SELECTION_COLORS,
  CHAIN_SESSION_COLORS,
  GOAL_FINDING_COLORS,
  ANIMATION_CONFIG,
  THREE_CONFIG,
} from '../../config'
import { TIER_CONFIG, getAdaptiveForceConfig } from '../../config/graph'
import { hasHighSeverityNodes, isGoalFinding } from '../../utils/nodeHelpers'
import { useAnimationFrame } from '../../hooks'

const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), {
  ssr: false,
})

interface GraphCanvas3DProps {
  data: GraphData
  width: number
  height: number
  showLabels: boolean
  selectedNode: GraphNode | null
  onNodeClick: (node: GraphNode) => void
  isDark?: boolean
  activeChainId?: string
  themeVersion?: number
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  externalGraphRef?: React.MutableRefObject<any>
}

// ── Dispose all geometries + materials in a group ──
function disposeGroup(group: any) {
  group.traverse((child: any) => {
    if (child.geometry) {
      child.geometry.dispose()
    }
    if (child.material) {
      if (Array.isArray(child.material)) {
        child.material.forEach((m: any) => m.dispose())
      } else {
        child.material.dispose()
      }
    }
    // SpriteText has a dispose method for its canvas texture
    if (typeof child.dispose === 'function' && child !== group) {
      child.dispose()
    }
  })
}

// ── Build a full-detail node group ──
function buildFullDetail(
  graphNode: GraphNode,
  sphereSegments: number,
  ringSegments: number,
  enableGlow: boolean,
  enableWireframe: boolean,
  enableLabels: boolean,
  labelColor: string,
): any {
  const THREE = require('three')
  const SpriteText = require('three-spritetext').default

  const group = new THREE.Group()
  const sphereSize = BASE_SIZES.node3D * getNodeSize(graphNode)
  const nodeColor = getNodeColor(graphNode)

  const isExploit = graphNode.type === 'ExploitGvm' || graphNode.type === 'ChainFinding'
  const isChainNode = graphNode.type === 'AttackChain' || graphNode.type === 'ChainStep' || graphNode.type === 'ChainDecision' || graphNode.type === 'ChainFailure'
  const isGoal = isGoalFinding(graphNode)
  const isCluster = !!graphNode.isCluster

  // Effective color for chain/exploit nodes (inactive state by default)
  let effectiveColor: string
  if (isChainNode || isExploit) {
    if (isGoal) {
      effectiveColor = GOAL_FINDING_COLORS.inactive
    } else if (isExploit) {
      effectiveColor = CHAIN_SESSION_COLORS.inactiveFinding
    } else {
      effectiveColor = CHAIN_SESSION_COLORS.inactive
    }
  } else {
    effectiveColor = nodeColor
  }

  // Selection ring (always created, hidden by default -- toggled via mutation)
  // Clusters render as a torus extending to ~sphereSize * 1.7, so the default
  // selection ring would be hidden inside it — scale it out for clusters.
  const selectInner = isCluster ? 1.85 : THREE_CONFIG.selectionRingScale.inner
  const selectOuter = isCluster ? 2.05 : THREE_CONFIG.selectionRingScale.outer
  const selectGeometry = new THREE.RingGeometry(
    sphereSize * selectInner,
    sphereSize * selectOuter,
    ringSegments
  )
  const selectMaterial = new THREE.MeshBasicMaterial({
    color: SELECTION_COLORS.ring,
    transparent: true,
    opacity: THREE_CONFIG.selectionRingOpacity,
    side: THREE.DoubleSide,
  })
  const selectRing = new THREE.Mesh(selectGeometry, selectMaterial)
  selectRing.lookAt(0, 0, 1)
  selectRing.name = 'selectionRing'
  selectRing.visible = false
  group.add(selectRing)

  // Active chain ring (always created for chain/exploit nodes, hidden by default)
  if (isChainNode || isExploit) {
    const activeGeometry = new THREE.RingGeometry(
      sphereSize * 1.8,
      sphereSize * 2.0,
      6
    )
    const activeMaterial = new THREE.MeshBasicMaterial({
      color: CHAIN_SESSION_COLORS.activeRing,
      transparent: true,
      opacity: 0.7,
      side: THREE.DoubleSide,
    })
    const activeRing = new THREE.Mesh(activeGeometry, activeMaterial)
    activeRing.lookAt(0, 0, 1)
    activeRing.name = 'chainRing'
    activeRing.visible = false
    activeRing.userData.glowLevel = 'high'
    group.add(activeRing)
  }

  // Glow ring for high/critical severity
  const glowLevel = getGlowLevel(graphNode)
  if (enableGlow && glowLevel) {
    const glowColor = (isChainNode || isExploit) ? effectiveColor : nodeColor
    const glowGeometry = new THREE.RingGeometry(
      sphereSize * THREE_CONFIG.glowRingScale.inner,
      sphereSize * THREE_CONFIG.glowRingScale.outer,
      ringSegments
    )
    const glowMaterial = new THREE.MeshBasicMaterial({
      color: glowColor,
      transparent: true,
      opacity: THREE_CONFIG.glowRingOpacity,
      side: THREE.DoubleSide,
    })
    const glowRing = new THREE.Mesh(glowGeometry, glowMaterial)
    glowRing.lookAt(0, 0, 1)
    glowRing.name = 'glowRing'
    glowRing.userData.glowLevel = glowLevel
    group.add(glowRing)
  }

  // Main geometry
  let geometry: any
  if (isCluster) {
    // Torus: ring of radius torusRadius, tube thickness tubeRadius
    geometry = new THREE.TorusGeometry(sphereSize * 1.25, sphereSize * 0.45, 12, 32)
  } else if (isExploit) {
    geometry = new THREE.OctahedronGeometry(sphereSize * 1.2)
  } else if (isChainNode) {
    geometry = new THREE.DodecahedronGeometry(sphereSize * 1.1)
  } else {
    geometry = new THREE.SphereGeometry(sphereSize, sphereSegments, sphereSegments)
  }

  const isSpecialNode = isExploit || isChainNode
  const material = isCluster
    ? new THREE.MeshLambertMaterial({
        color: nodeColor,
        transparent: false,
        opacity: 1,
        emissive: nodeColor,
        emissiveIntensity: 0.2,
      })
    : isSpecialNode
    ? new THREE.MeshLambertMaterial({
        color: effectiveColor,
        transparent: true,
        opacity: 0.12,
        emissive: effectiveColor,
        emissiveIntensity: 0.3,
        side: THREE.DoubleSide,
      })
    : new THREE.MeshLambertMaterial({
        color: nodeColor,
        transparent: true,
        opacity: THREE_CONFIG.nodeOpacity,
      })
  const mesh = new THREE.Mesh(geometry, material)
  mesh.name = 'mainMesh'
  group.add(mesh)

  // Cluster: big count sprite at the center of the torus (always faces camera)
  if (isCluster) {
    const count = graphNode.clusterChildren?.length ?? 0
    const countText = count >= 1000 ? `${Math.floor(count / 100) / 10}k` : `${count}`
    const countSprite = new SpriteText(countText)
    countSprite.color = labelColor
    countSprite.fontWeight = 'bold'
    countSprite.textHeight = sphereSize * 0.6
    countSprite.name = 'countSprite'
    group.add(countSprite)
  }

  // Wireframe for exploit nodes
  if (enableWireframe && isExploit) {
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: effectiveColor,
      wireframe: true,
      transparent: true,
      opacity: 0.6,
    })
    const wireMesh = new THREE.Mesh(geometry, wireMaterial)
    wireMesh.name = 'wireframe'
    group.add(wireMesh)
  }

  // Wireframe for external domain nodes
  if (enableWireframe && graphNode.type === 'ExternalDomain') {
    const wireMaterial = new THREE.MeshBasicMaterial({
      color: nodeColor,
      wireframe: true,
      transparent: true,
      opacity: 0.5,
    })
    const wireMesh = new THREE.Mesh(geometry, wireMaterial)
    wireMesh.name = 'wireframe'
    group.add(wireMesh)
  }

  // Edge outline for chain nodes
  if (enableWireframe && isChainNode) {
    const edges = new THREE.EdgesGeometry(geometry, 15)
    const lineMaterial = new THREE.LineBasicMaterial({
      color: effectiveColor,
      transparent: true,
      opacity: 0.7,
    })
    const lineSegments = new THREE.LineSegments(edges, lineMaterial)
    lineSegments.name = 'edgeOutline'
    group.add(lineSegments)
  }

  // Label (always created, visibility toggled via mutation)
  if (enableLabels) {
    const labelText = isCluster
      ? `${graphNode.clusterChildren?.length ?? 0} ${graphNode.clusterChildType ?? ''}`
      : graphNode.name
    const sprite = new SpriteText(labelText)
    sprite.color = labelColor
    sprite.textHeight = BASE_SIZES.label3D * (isCluster ? 1.3 : 1)
    sprite.position.y = sphereSize + BASE_SIZES.label3D
    sprite.name = 'label'
    sprite.visible = true // toggled by showLabels mutation
    group.add(sprite)
  }

  // Store node metadata for mutation lookups
  group.userData.nodeId = graphNode.id
  group.userData.nodeType = graphNode.type
  group.userData.chainId = graphNode.properties?.chain_id
  group.userData.isChainNode = isChainNode
  group.userData.isExploit = isExploit
  group.userData.isGoal = isGoal
  group.userData.nodeColor = nodeColor
  group.userData.effectiveColor = effectiveColor

  return group
}

export function GraphCanvas3D({
  data,
  width,
  height,
  showLabels,
  selectedNode,
  onNodeClick,
  isDark = true,
  activeChainId,
  themeVersion = 0,
  externalGraphRef,
}: GraphCanvas3DProps) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null)

  // Sync internal ref to external ref (for parent component access)
  useEffect(() => {
    if (externalGraphRef) externalGraphRef.current = graphRef.current
  })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const nodeCache = useRef<Map<string, any>>(new Map())
  const prevThemeVersion = useRef(themeVersion)

  // Always use full quality -- no LOD, no tier degradation
  const forceConfig = useMemo(() => getAdaptiveForceConfig(data.nodes.length), [data.nodes.length])
  // Use ref for labelColor so nodeThreeObject callback doesn't change ref on theme toggle
  // (theme change is handled by the themeVersion effect which disposes + refresh())
  const labelColorRef = useRef(isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label)
  labelColorRef.current = isDark ? BACKGROUND_COLORS.dark.label : BACKGROUND_COLORS.light.label

  // Slow down zoom and rotation speed for smoother navigation
  useEffect(() => {
    const applyControls = () => {
      const controls = graphRef.current?.controls()
      if (controls) {
        controls.zoomSpeed = 0.25   // default is 1.2
        controls.rotateSpeed = 0.5  // default is 1.0
        return true
      }
      return false
    }
    if (!applyControls()) {
      // ForceGraph3D loads dynamically -- retry after it mounts
      const timer = setTimeout(applyControls, 500)
      return () => clearTimeout(timer)
    }
  }, [data])

  // ── Dispose all cached nodes on unmount ──
  useEffect(() => {
    return () => {
      nodeCache.current.forEach(disposeGroup)
      nodeCache.current.clear()
    }
  }, [])

  // ── Theme change: clear cache + refresh to rebuild all nodes ──
  useEffect(() => {
    if (themeVersion === prevThemeVersion.current) return
    prevThemeVersion.current = themeVersion
    nodeCache.current.forEach(disposeGroup)
    nodeCache.current.clear()
    graphRef.current?.refresh()
  }, [themeVersion])

  // ── Memoized nodeThreeObject -- always full quality, no LOD ──
  const fullTier = TIER_CONFIG['full']
  const nodeThreeObject = useCallback((node: object) => {
    const graphNode = node as GraphNode

    const group = buildFullDetail(
      graphNode,
      fullTier.sphereSegments,
      fullTier.ringSegments,
      fullTier.enableGlow,
      fullTier.enableWireframe,
      fullTier.enableLabels,
      labelColorRef.current,
    )

    nodeCache.current.set(graphNode.id, group)
    return group
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fullTier])


  // ── Selection + active chain: direct Three.js mutation (NO nodeThreeObject rebuild) ──
  const selectedNodeId = selectedNode?.id
  useEffect(() => {
    nodeCache.current.forEach((group, nodeId) => {
      const ud = group.userData
      const isSelected = nodeId === selectedNodeId

      const selRing = group.getObjectByName('selectionRing')
      if (selRing) selRing.visible = isSelected

      const chainRing = group.getObjectByName('chainRing')
      if (chainRing) {
        chainRing.visible = !!(activeChainId && ud.chainId === activeChainId)
      }

      if (ud.isChainNode || ud.isExploit) {
        const isInActiveChain = !!(activeChainId && ud.chainId === activeChainId)
        let newColor: string
        if (!isInActiveChain) {
          if (ud.isGoal) {
            newColor = isSelected ? GOAL_FINDING_COLORS.active : GOAL_FINDING_COLORS.inactive
          } else if (ud.isExploit) {
            newColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactiveFinding
          } else {
            newColor = isSelected ? CHAIN_SESSION_COLORS.inactiveSelected : CHAIN_SESSION_COLORS.inactive
          }
        } else {
          newColor = ud.nodeColor
        }
        const mainMesh = group.getObjectByName('mainMesh')
        if (mainMesh?.material) {
          mainMesh.material.color.set(newColor)
          if (mainMesh.material.emissive) mainMesh.material.emissive.set(newColor)
        }
      }
    })
  }, [selectedNodeId, activeChainId])

  // Labels are toggled per-frame based on camera distance (see useAnimationFrame below).
  // The showLabels flag is read there via ref so the callback identity stays stable.
  const showLabelsRef = useRef(showLabels)
  showLabelsRef.current = showLabels

  // ── Glow animation: iterate nodeCache, find rings by name ──
  const hasHighSeverity = hasHighSeverityNodes(data.nodes)

  // Distance threshold for label visibility in 3D (world units from camera)
  const LABEL_DISTANCE_THRESHOLD = 300

  useAnimationFrame(
    (time) => {
      const camera = graphRef.current?.camera()
      const cameraPos = camera?.position

      nodeCache.current.forEach((group) => {
        // Zoom-based label visibility: hide labels when camera is far away
        const label = group.getObjectByName('label')
        if (label) {
          if (!showLabelsRef.current) {
            label.visible = false
          } else if (cameraPos && group.position) {
            const dist = cameraPos.distanceTo(group.position)
            label.visible = dist < LABEL_DISTANCE_THRESHOLD
          }
        }

        // Glow ring animation
        const glowRing = group.getObjectByName('glowRing')
        if (glowRing) {
          const level = glowRing.userData.glowLevel || 'high'
          const speed = level === 'critical' ? ANIMATION_CONFIG.criticalSpeed : ANIMATION_CONFIG.highSpeed
          const pulse = Math.sin(time * speed) * 0.15 + 1
          const opacity = Math.sin(time * speed) * 0.2 + 0.4
          glowRing.scale.set(pulse, pulse, 1)
          if (glowRing.material) glowRing.material.opacity = opacity
        }

        // Chain ring animation (if visible)
        const chainRing = group.getObjectByName('chainRing')
        if (chainRing?.visible) {
          const speed = ANIMATION_CONFIG.highSpeed
          const pulse = Math.sin(time * speed) * 0.15 + 1
          const opacity = Math.sin(time * speed) * 0.2 + 0.4
          chainRing.scale.set(pulse, pulse, 1)
          if (chainRing.material) chainRing.material.opacity = opacity
        }
      })
    },
    true // always run: handles label visibility + glow animations
  )

  // ── Reheat simulation + clean cache when data changes ──
  const prevNodeCount3DRef = useRef(0)
  const prevLinkCount3DRef = useRef(0)
  useEffect(() => {
    const prevNodeCount = prevNodeCount3DRef.current
    const prevLinkCount = prevLinkCount3DRef.current
    const newNodeCount = data.nodes.length
    const newLinkCount = data.links.length
    const structureChanged = newNodeCount !== prevNodeCount || newLinkCount !== prevLinkCount
    prevNodeCount3DRef.current = newNodeCount
    prevLinkCount3DRef.current = newLinkCount

    // Clean up removed nodes from cache
    const currentIds = new Set(data.nodes.map(n => n.id))
    nodeCache.current.forEach((_, id) => {
      if (!currentIds.has(id)) {
        nodeCache.current.delete(id)
      }
    })
    if (structureChanged) {
      const timer = setTimeout(() => {
        graphRef.current?.d3ReheatSimulation()
      }, ANIMATION_CONFIG.initDelay)
      return () => clearTimeout(timer)
    }
  }, [data])

  return (
    <ForceGraph3D
      ref={graphRef}
      graphData={data}
      nodeLabel={(node) => `${(node as GraphNode).name} (${(node as GraphNode).type})`}
      nodeColor={(node) => getNodeColor(node as GraphNode)}
      nodeRelSize={BASE_SIZES.node3D}
      nodeOpacity={THREE_CONFIG.nodeOpacity}
      linkLabel={(link) => (link as GraphLink).type}
      linkColor={(link) => getLinkColor(link as GraphLink, selectedNodeId)}
      linkWidth={(link) => getLinkWidth3D(link as GraphLink, selectedNodeId)}
      linkDirectionalParticles={(link) => getParticleCount(link as GraphLink, selectedNodeId)}
      linkDirectionalParticleWidth={(link) => getParticleWidth(link as GraphLink, selectedNodeId)}
      linkDirectionalParticleColor={(link) => getParticleColor(link as GraphLink, activeChainId)}
      linkDirectionalParticleSpeed={(link) => getParticleSpeed(link as GraphLink)}
      linkDirectionalArrowLength={LINK_SIZES.arrowLength3D}
      linkDirectionalArrowRelPos={1}
      backgroundColor={isDark ? BACKGROUND_COLORS.dark.graph : BACKGROUND_COLORS.light.graph}
      width={width}
      height={height}
      cooldownTime={forceConfig.cooldownTime}
      cooldownTicks={forceConfig.cooldownTicks}
      warmupTicks={forceConfig.warmupTicks}
      onNodeClick={(node) => onNodeClick(node as GraphNode)}
      nodeThreeObject={nodeThreeObject}
    />
  )
}

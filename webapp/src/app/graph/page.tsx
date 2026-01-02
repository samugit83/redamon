'use client'

import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useState, useCallback, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import styles from './page.module.css'

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
})

const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), {
  ssr: false,
})

interface GraphNode {
  id: string
  name: string
  type: string
  properties: Record<string, unknown>
  x?: number
  y?: number
  z?: number
}

interface GraphLink {
  source: string | GraphNode
  target: string | GraphNode
  type: string
}

interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
  projectId: string
}

const NODE_COLORS: Record<string, string> = {
  Domain: '#3b82f6',
  Subdomain: '#8b5cf6',
  IP: '#22c55e',
  Host: '#f59e0b',
  Port: '#ef4444',
  Service: '#06b6d4',
  Vulnerability: '#dc2626',
  Technology: '#84cc16',
  CVE: '#e11d48',        // Rose/Red - Known CVEs from technology lookup
  MitreData: '#0ea5e9',  // Sky blue - CWE weakness data
  Capec: '#f97316',      // Orange - Attack patterns
  Certificate: '#fb923c',
  Email: '#ec4899',
  ASN: '#14b8a6',
  CIDR: '#a855f7',
  URL: '#6366f1',
  BaseURL: '#6366f1',    // Same as URL
  Endpoint: '#818cf8',   // Lighter indigo for endpoints
  Parameter: '#c084fc',  // Purple for parameters
  Header: '#f472b6',
  Project: '#fbbf24',
  Default: '#6b7280',
}

// Node size multipliers (1x = default size)
const NODE_SIZES: Record<string, number> = {
  Domain: 4,
  Subdomain: 3,
  IP: 2,
  Port: 2,
  BaseURL: 3,
  Technology: 2,
  Default: 1,
}

async function fetchGraphData(projectId: string): Promise<GraphData> {
  const response = await fetch(`/api/graph?projectId=${projectId}`)
  if (!response.ok) {
    throw new Error('Failed to fetch graph data')
  }
  return response.json()
}

export default function GraphPage() {
  const projectId = 'project_testphp.vulnweb.com'
  const [is3D, setIs3D] = useState(true)
  const [showLabels, setShowLabels] = useState(false)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null)

  const drawerWidth = 400

  const { data, isLoading, error } = useQuery({
    queryKey: ['graph', projectId],
    queryFn: () => fetchGraphData(projectId),
  })

  useEffect(() => {
    const updateDimensions = () => {
      setDimensions({
        width: window.innerWidth - (drawerOpen ? drawerWidth : 0),
        height: window.innerHeight - 140,
      })
    }

    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [drawerOpen])

  useEffect(() => {
    if (!data || is3D) return

    // Wait for graph to be fully mounted
    const timer = setTimeout(() => {
      const fg = graphRef.current
      if (!fg) return

      const d3 = require('d3-force')

      // Only add collision detection to prevent circles from overlapping
      fg.d3Force('collide', d3.forceCollide().radius(20).strength(1).iterations(3))

      // Reheat the simulation to apply changes
      fg.d3ReheatSimulation()
    }, 300)

    return () => clearTimeout(timer)
  }, [data, is3D])

  const getNodeColor = useCallback((node: GraphNode) => {
    return NODE_COLORS[node.type] || NODE_COLORS.Default
  }, [])

  const getNodeSize = useCallback((node: GraphNode) => {
    return NODE_SIZES[node.type] || NODE_SIZES.Default
  }, [])

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node)
    setDrawerOpen(true)
  }, [])

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false)
    setSelectedNode(null)
  }, [])

  return (
    <main className={styles.main}>
      <header className={styles.header}>
        <Link href="/" className={styles.backLink}>
          ← Back
        </Link>
        <h1 className={styles.title}>Graph View</h1>

        <div className={styles.toggleContainer}>
          <span className={!is3D ? styles.toggleActive : styles.toggleInactive}>2D</span>
          <button
            className={styles.toggleSwitch}
            onClick={() => setIs3D(!is3D)}
            aria-label="Toggle 2D/3D view"
          >
            <span className={`${styles.toggleKnob} ${is3D ? styles.toggleKnobRight : ''}`} />
          </button>
          <span className={is3D ? styles.toggleActive : styles.toggleInactive}>3D</span>
        </div>

        <div className={styles.toggleContainer}>
          <span className={styles.toggleLabel}>Labels</span>
          <button
            className={styles.toggleSwitch}
            onClick={() => setShowLabels(!showLabels)}
            aria-label="Toggle labels"
          >
            <span className={`${styles.toggleKnob} ${showLabels ? styles.toggleKnobRight : ''}`} />
          </button>
        </div>

        <span className={styles.projectId}>Project: {projectId}</span>
      </header>

      <div className={styles.legend}>
        {Object.entries(NODE_COLORS)
          .filter(([key]) => key !== 'Default')
          .map(([type, color]) => (
            <div key={type} className={styles.legendItem}>
              <span
                className={styles.legendColor}
                style={{ backgroundColor: color }}
              />
              <span>{type}</span>
            </div>
          ))}
      </div>

      <div className={styles.contentWrapper}>
        <div className={styles.graphContainer}>
          {isLoading && (
            <div className={styles.loading}>Loading graph data...</div>
          )}

          {error && (
            <div className={styles.error}>
              Error: {error instanceof Error ? error.message : 'Unknown error'}
            </div>
          )}

          {data && data.nodes.length === 0 && (
            <div className={styles.empty}>
              No data found for project: {projectId}
            </div>
          )}

          {data && data.nodes.length > 0 && !is3D && (
            <ForceGraph2D
              ref={graphRef}
              graphData={data}
              nodeLabel={(node) => `${(node as GraphNode).name} (${(node as GraphNode).type})`}
              nodeRelSize={6}
              linkLabel={(link) => (link as GraphLink).type}
              linkColor={() => '#4b5563'}
              linkWidth={1}
              linkDirectionalArrowLength={4}
              linkDirectionalArrowRelPos={1}
              backgroundColor="#0a0a0a"
              width={dimensions.width}
              height={dimensions.height}
              d3AlphaDecay={0.02}
              d3VelocityDecay={0.4}
              cooldownTime={5000}
              onNodeClick={(node) => handleNodeClick(node as GraphNode)}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const graphNode = node as GraphNode & { x: number; y: number }
                const baseSize = 6
                const nodeSize = baseSize * getNodeSize(graphNode)
                const color = getNodeColor(graphNode)

                // Draw circle
                ctx.beginPath()
                ctx.arc(graphNode.x, graphNode.y, nodeSize, 0, 2 * Math.PI)
                ctx.fillStyle = color
                ctx.fill()

                // Draw label if enabled
                if (showLabels && globalScale > 0.4) {
                  const label = graphNode.name
                  const fontSize = Math.max(6 / globalScale, 2)
                  ctx.font = `${fontSize}px Sans-Serif`
                  ctx.textAlign = 'center'
                  ctx.textBaseline = 'top'
                  ctx.fillStyle = '#ffffff'
                  ctx.fillText(label, graphNode.x, graphNode.y + nodeSize + 2)
                }
              }}
              nodePointerAreaPaint={(node, color, ctx) => {
                const graphNode = node as GraphNode & { x: number; y: number }
                ctx.beginPath()
                ctx.arc(graphNode.x, graphNode.y, 10, 0, 2 * Math.PI)
                ctx.fillStyle = color
                ctx.fill()
              }}
            />
          )}

          {data && data.nodes.length > 0 && is3D && (
            <ForceGraph3D
              graphData={data}
              nodeLabel={(node) => `${(node as GraphNode).name} (${(node as GraphNode).type})`}
              nodeColor={(node) => getNodeColor(node as GraphNode)}
              nodeRelSize={6}
              nodeOpacity={1}
              linkLabel={(link) => (link as GraphLink).type}
              linkColor={() => '#4b5563'}
              linkWidth={1}
              linkDirectionalArrowLength={3}
              linkDirectionalArrowRelPos={1}
              backgroundColor="#0a0a0a"
              width={dimensions.width}
              height={dimensions.height}
              onNodeClick={(node) => handleNodeClick(node as GraphNode)}
              nodeThreeObject={(node: object) => {
                const graphNode = node as GraphNode
                const THREE = require('three')
                const SpriteText = require('three-spritetext').default

                const group = new THREE.Group()

                // Create sphere with size multiplier
                const baseSize = 5
                const sphereSize = baseSize * getNodeSize(graphNode)
                const geometry = new THREE.SphereGeometry(sphereSize, 16, 16)
                const material = new THREE.MeshLambertMaterial({
                  color: getNodeColor(graphNode),
                  transparent: true,
                  opacity: 0.9,
                })
                const sphere = new THREE.Mesh(geometry, material)
                group.add(sphere)

                // Create label if enabled
                if (showLabels) {
                  const sprite = new SpriteText(graphNode.name)
                  sprite.color = '#ffffff'
                  sprite.textHeight = 3
                  sprite.position.y = sphereSize + 3
                  group.add(sprite)
                }

                return group
              }}
            />
          )}
        </div>

        {/* Drawer */}
        <div className={`${styles.drawer} ${drawerOpen ? styles.drawerOpen : ''}`}>
          <div className={styles.drawerHeader}>
            <h2 className={styles.drawerTitle}>
              {selectedNode?.type}: {selectedNode?.name}
            </h2>
            <button className={styles.drawerClose} onClick={closeDrawer}>
              ×
            </button>
          </div>
          <div className={styles.drawerContent}>
            {selectedNode && (
              <>
                <div className={styles.drawerSection}>
                  <h3 className={styles.drawerSectionTitle}>Basic Info</h3>
                  <div className={styles.propertyRow}>
                    <span className={styles.propertyKey}>ID</span>
                    <span className={styles.propertyValue}>{selectedNode.id}</span>
                  </div>
                  <div className={styles.propertyRow}>
                    <span className={styles.propertyKey}>Type</span>
                    <span
                      className={styles.propertyBadge}
                      style={{ backgroundColor: getNodeColor(selectedNode) }}
                    >
                      {selectedNode.type}
                    </span>
                  </div>
                  <div className={styles.propertyRow}>
                    <span className={styles.propertyKey}>Name</span>
                    <span className={styles.propertyValue}>{selectedNode.name}</span>
                  </div>
                </div>

                <div className={styles.drawerSection}>
                  <h3 className={styles.drawerSectionTitle}>Properties</h3>
                  {Object.entries(selectedNode.properties || {}).map(([key, value]) => (
                    <div key={key} className={styles.propertyRow}>
                      <span className={styles.propertyKey}>{key}</span>
                      <span className={styles.propertyValue}>
                        {typeof value === 'object'
                          ? JSON.stringify(value, null, 2)
                          : String(value)}
                      </span>
                    </div>
                  ))}
                  {Object.keys(selectedNode.properties || {}).length === 0 && (
                    <p className={styles.emptyProperties}>No additional properties</p>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {data && (
        <div className={styles.stats}>
          <span>Nodes: {data.nodes.length}</span>
          <span>Links: {data.links.length}</span>
          <span>View: {is3D ? '3D' : '2D'}</span>
          <span>Labels: {showLabels ? 'On' : 'Off'}</span>
        </div>
      )}
    </main>
  )
}

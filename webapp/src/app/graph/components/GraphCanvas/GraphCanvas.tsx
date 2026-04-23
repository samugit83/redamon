'use client'

import { memo, useRef } from 'react'
import { GraphData, GraphNode } from '../../types'
import { GraphCanvas2D } from './GraphCanvas2D'
import { GraphCanvas3D } from './GraphCanvas3D'
import { GraphNavControls } from './GraphNavControls'
import { GraphEmptyState } from './GraphEmptyState'
import styles from './GraphCanvas.module.css'

export const AUTO_2D_THRESHOLD = 1500

interface GraphCanvasProps {
  data: GraphData | undefined
  isLoading: boolean
  error: Error | null
  projectId: string
  is3D: boolean
  width: number
  height: number
  showLabels: boolean
  selectedNode: GraphNode | null
  onNodeClick: (node: GraphNode) => void
  isDark?: boolean
  activeChainId?: string
}

export const GraphCanvas = memo(function GraphCanvas({
  data,
  isLoading,
  error,
  projectId,
  is3D,
  width,
  height,
  showLabels,
  selectedNode,
  onNodeClick,
  isDark = true,
  activeChainId,
}: GraphCanvasProps) {
  // Track theme changes as a version counter (for 3D node cache invalidation)
  const themeVersionRef = useRef(0)
  const prevIsDarkRef = useRef(isDark)
  // Shared ref for nav controls to access the ForceGraph instance
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sharedGraphRef = useRef<any>(null)

  if (isDark !== prevIsDarkRef.current) {
    prevIsDarkRef.current = isDark
    themeVersionRef.current++
  }

  const themeVersion = themeVersionRef.current

  // Auto-switch to 2D for large graphs
  const nodeCount = data?.nodes.length ?? 0
  const effective3D = is3D && nodeCount <= AUTO_2D_THRESHOLD

  if (isLoading) {
    return <div className={styles.loading}>Loading graph data...</div>
  }

  if (error) {
    return (
      <div className={styles.error}>
        Error: {error instanceof Error ? error.message : 'Unknown error'}
      </div>
    )
  }

  if (!data || data.nodes.length === 0) {
    return <GraphEmptyState />
  }

  if (effective3D) {
    return (
      <div className={styles.wrapper}>
        <GraphCanvas3D
          data={data}
          width={width}
          height={height}
          showLabels={showLabels}
          selectedNode={selectedNode}
          onNodeClick={onNodeClick}
          isDark={isDark}
          activeChainId={activeChainId}
          themeVersion={themeVersion}
          externalGraphRef={sharedGraphRef}
        />
        <GraphNavControls graphRef={sharedGraphRef} is3D />
      </div>
    )
  }

  return (
    <div className={styles.wrapper}>
      <GraphCanvas2D
        data={data}
        width={width}
        height={height}
        showLabels={showLabels}
        selectedNode={selectedNode}
        onNodeClick={onNodeClick}
        isDark={isDark}
        activeChainId={activeChainId}
        externalGraphRef={sharedGraphRef}
      />
      <GraphNavControls graphRef={sharedGraphRef} is3D={false} />
    </div>
  )
})

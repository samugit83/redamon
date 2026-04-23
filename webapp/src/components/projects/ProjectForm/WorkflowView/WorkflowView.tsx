'use client'

import { useState, useCallback, useMemo } from 'react'
import { useTheme } from '@/hooks/useTheme'
import {
  ReactFlow,
  Controls,
  MiniMap,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { Project } from '@prisma/client'
import { useWorkflowGraph } from './useWorkflowGraph'
import { ToolNode } from './ToolNode'
import { DataNode } from './DataNode'
import { InputNode } from './InputNode'
import { CustomEdge } from './CustomEdge'
import { WorkflowNodeModal } from './WorkflowNodeModal'
import { NodeListOverlay } from './NodeListOverlay'
import { useDataNodeCounts } from './useToolNodeCounts'
import { PARTIAL_RECON_SUPPORTED_TOOLS } from '@/lib/recon-types'
import styles from './WorkflowView.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface WorkflowViewProps {
  formData: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode: 'create' | 'edit'
  onSave?: () => Promise<void>
  onRunPartial?: (toolId: string) => void
  runningPartialToolIds?: Set<string>
  onAutoSaveField?: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const nodeTypes = {
  toolNode: ToolNode,
  dataNode: DataNode,
  inputNode: InputNode,
}

const edgeTypes = {
  custom: CustomEdge,
}

export function WorkflowView({ formData, updateField, projectId, mode, onSave, onRunPartial, runningPartialToolIds, onAutoSaveField }: WorkflowViewProps) {
  const [selectedToolId, setSelectedToolId] = useState<string | null>(mode === 'create' ? 'input' : null)
  const [highlightedNodeId, setHighlightedNodeId] = useState<string | null>(null)
  const [badgeNodeType, setBadgeNodeType] = useState<string | null>(null)
  const { resolvedTheme } = useTheme()
  const isLight = resolvedTheme === 'light'

  const { nodes: rawNodes, edges: graphEdges } = useWorkflowGraph(formData as unknown as Record<string, unknown>)
  const { dataNodeCounts } = useDataNodeCounts(projectId)

  // Inject callbacks into tool node data
  const handleToggle = useCallback((field: string, value: boolean) => {
    updateField(field as keyof FormData, value as FormData[keyof FormData])
    if (onAutoSaveField) {
      onAutoSaveField(field as keyof FormData, value as FormData[keyof FormData])
    }
  }, [updateField, onAutoSaveField])

  const handleOpenSettings = useCallback((toolId: string) => {
    setSelectedToolId(toolId)
  }, [])

  const handleNodeClick = useCallback((nodeId: string) => {
    setHighlightedNodeId(prev => prev === nodeId ? null : nodeId)
  }, [])

  const handleBadgeClick = useCallback((nodeType: string) => {
    setBadgeNodeType(nodeType)
  }, [])

  const handlePaneClick = useCallback(() => {
    setHighlightedNodeId(null)
  }, [])

  // Compute which nodes and edges are directly connected to the highlighted node
  const { connectedNodeIds, connectedEdgeIds } = useMemo(() => {
    if (!highlightedNodeId) return { connectedNodeIds: new Set<string>(), connectedEdgeIds: new Set<string>() }

    const edgeIds = new Set<string>()
    const nodeIds = new Set<string>([highlightedNodeId])

    for (const edge of graphEdges) {
      if (edge.source === highlightedNodeId || edge.target === highlightedNodeId) {
        edgeIds.add(edge.id)
        nodeIds.add(edge.source)
        nodeIds.add(edge.target)
      }
    }

    return { connectedNodeIds: nodeIds, connectedEdgeIds: edgeIds }
  }, [highlightedNodeId, graphEdges])

  const hasHighlight = highlightedNodeId !== null

  const nodes = useMemo(() => {
    return rawNodes.map(node => {
      const isHighlighted = connectedNodeIds.has(node.id)
      const dimmed = hasHighlight && !isHighlighted

      if (node.type === 'toolNode') {
        const toolId = (node.data as { toolId?: string }).toolId || ''
        return {
          ...node,
          data: {
            ...node.data,
            onToggle: handleToggle,
            onOpenSettings: handleOpenSettings,
            onRunPartial: mode === 'edit' && projectId ? onRunPartial : undefined,
            partialReconSupported: PARTIAL_RECON_SUPPORTED_TOOLS.has(toolId),
            isRunningPartial: runningPartialToolIds?.has(toolId) ?? false,
            onNodeClick: handleNodeClick,
            highlighted: isHighlighted,
            dimmed,
          },
        }
      }
      if (node.type === 'dataNode') {
        const dataNodeType = (node.data as { nodeType?: string }).nodeType || ''
        return {
          ...node,
          data: {
            ...node.data,
            onNodeClick: handleNodeClick,
            highlighted: isHighlighted,
            dimmed,
            nodeCount: dataNodeCounts.get(dataNodeType)?.count,
            onBadgeClick: projectId ? handleBadgeClick : undefined,
          },
        }
      }
      // inputNode
      return {
        ...node,
        data: {
          ...node.data,
          onNodeClick: handleNodeClick,
          onOpenSettings: handleOpenSettings,
          highlighted: isHighlighted,
          dimmed,
        },
      }
    })
  }, [rawNodes, handleToggle, handleOpenSettings, onRunPartial, handleNodeClick, connectedNodeIds, hasHighlight, mode, projectId, dataNodeCounts, handleBadgeClick])

  const edges = useMemo(() => {
    if (!hasHighlight) return graphEdges

    return graphEdges.map(edge => {
      const isConnected = connectedEdgeIds.has(edge.id)
      return {
        ...edge,
        style: {
          ...edge.style,
          opacity: isConnected ? 1 : 0.08,
          strokeWidth: isConnected ? 2.5 : (edge.style?.strokeWidth ?? 2),
        },
      }
    })
  }, [graphEdges, connectedEdgeIds, hasHighlight])

  return (
    <div className={styles.canvas}>
      {/* React Flow base CSS is not loaded by Turbopack from node_modules.
          Inject the critical rules for edges SVG rendering. */}
      <style dangerouslySetInnerHTML={{ __html: `
        .react-flow {
          background: #0a0a0a !important;
        }
        [data-theme="light"] .react-flow {
          background: #ffffff !important;
        }
        .react-flow__edges svg {
          overflow: visible !important;
          position: absolute !important;
          pointer-events: none !important;
          width: 100% !important;
          height: 100% !important;
          top: 0 !important;
          left: 0 !important;
        }
        .react-flow__edges {
          position: absolute !important;
          width: 100% !important;
          height: 100% !important;
          top: 0 !important;
          left: 0 !important;
        }
        .react-flow__edge-path {
          fill: none;
        }
        .react-flow__nodes {
          z-index: 10 !important;
        }
        .react-flow__viewport {
          transform-origin: 0 0;
        }
        @keyframes dashFlow {
          to { stroke-dashoffset: -18; }
        }
        @keyframes dotFlow {
          to { stroke-dashoffset: -12; }
        }
        .workflow-edge-animated {
          animation: dashFlow 0.8s linear infinite;
        }
        .workflow-edge-animated-dot {
          animation: dotFlow 0.6s linear infinite;
        }
      `}} />
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.3}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        colorMode={resolvedTheme === 'light' ? 'light' : 'dark'}
        onPaneClick={handlePaneClick}
      >
        {/* Background removed: it rendered as an opaque layer covering edges */}
        <Controls
          showInteractive={false}
          className={styles.controls}
        />
        <MiniMap
          className={styles.minimap}
          nodeColor={(node) => {
            if (node.type === 'inputNode') return isLight ? '#9ca3af' : '#6b7280'
            if (node.type === 'dataNode') {
              const d = node.data as { color?: string; status?: string }
              return d.status === 'starved' ? '#ef4444' : (d.color ?? '#22c55e')
            }
            const d = node.data as { enabled?: boolean; groupColor?: string }
            return d.enabled ? (d.groupColor ?? '#22c55e') : (isLight ? '#d1d5db' : '#374151')
          }}
          maskColor={isLight ? 'rgba(0, 0, 0, 0.15)' : 'rgba(0, 0, 0, 0.7)'}
          pannable
          zoomable
        />
      </ReactFlow>

      <WorkflowNodeModal
        toolId={selectedToolId}
        onClose={() => setSelectedToolId(null)}
        onSave={onSave}
        data={formData}
        updateField={updateField}
        projectId={projectId}
        mode={mode}
      />

      {badgeNodeType && (
        <NodeListOverlay
          isOpen={true}
          onClose={() => setBadgeNodeType(null)}
          toolLabel={badgeNodeType}
          nodes={dataNodeCounts.get(badgeNodeType)?.nodes ?? []}
        />
      )}

    </div>
  )
}

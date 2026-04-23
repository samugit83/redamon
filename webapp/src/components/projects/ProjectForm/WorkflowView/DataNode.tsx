'use client'

import { memo, useCallback } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import styles from './WorkflowView.module.css'

interface DataNodeData {
  nodeType: string
  isUniversal: boolean
  status: 'active' | 'starved'
  category: string
  color: string
  producers: string[]
  consumers: string[]
  enrichers: string[]
  onNodeClick?: (nodeId: string) => void
  highlighted?: boolean
  dimmed?: boolean
  nodeCount?: number
  onBadgeClick?: (nodeType: string) => void
}

function DataNodeComponent({ data }: NodeProps) {
  const { nodeType, isUniversal, status, color, producers, consumers, enrichers, onNodeClick, highlighted, dimmed, nodeCount, onBadgeClick } = data as unknown as DataNodeData

  const tooltipLines = []
  if (producers.length > 0) tooltipLines.push(`Produced by: ${producers.join(', ')}`)
  if (enrichers?.length > 0) tooltipLines.push(`Enriched by: ${enrichers.join(', ')}`)
  if (consumers.length > 0) tooltipLines.push(`Consumed by: ${consumers.join(', ')}`)
  const tooltip = tooltipLines.join('\n')

  const handleBadgeClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onBadgeClick?.(nodeType)
  }, [onBadgeClick, nodeType])

  const handleClick = useCallback(() => {
    onNodeClick?.(`data-${nodeType}`)
  }, [onNodeClick, nodeType])

  return (
    <div
      className={`${styles.dataNode} ${status === 'starved' ? styles.dataNodeStarved : ''} ${isUniversal ? styles.dataNodeUniversal : ''} ${highlighted ? styles.dataNodeHighlighted : ''} ${dimmed ? styles.dataNodeDimmed : ''}`}
      style={{
        borderColor: highlighted ? 'var(--text-primary)' : status === 'starved' ? '#ef4444' : color,
        backgroundColor: status === 'starved'
          ? 'color-mix(in srgb, #ef4444 10%, var(--bg-secondary))'
          : `color-mix(in srgb, ${color} 15%, var(--bg-secondary))`,
      }}
      title={tooltip}
      onClick={handleClick}
    >
      <Handle type="target" position={Position.Left} className={styles.handleSmall} />

      <span
        className={styles.dataNodeLabel}
        style={{ color: status === 'starved' ? '#ef4444' : color }}
      >
        {nodeType}
      </span>

      {nodeCount != null && nodeCount > 0 && (
        <span className={styles.nodeCountBadge} onClick={handleBadgeClick}>
          {nodeCount}
        </span>
      )}

      <Handle type="source" position={Position.Right} className={styles.handleSmall} />
    </div>
  )
}

export const DataNode = memo(DataNodeComponent)

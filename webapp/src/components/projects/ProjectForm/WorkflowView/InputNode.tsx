'use client'

import { memo, useCallback } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Globe, Settings } from 'lucide-react'
import styles from './WorkflowView.module.css'

function InputNodeComponent({ data }: NodeProps) {
  const { label, onNodeClick, onOpenSettings, highlighted, dimmed } = data as unknown as {
    label: string
    onNodeClick?: (nodeId: string) => void
    onOpenSettings?: (toolId: string) => void
    highlighted?: boolean
    dimmed?: boolean
  }

  const handleClick = useCallback(() => {
    onOpenSettings?.('input')
  }, [onOpenSettings])

  return (
    <div
      className={`${styles.inputNode} ${highlighted ? styles.inputNodeHighlighted : ''} ${dimmed ? styles.inputNodeDimmed : ''}`}
      onClick={handleClick}
    >
      <Globe size={16} className={styles.inputNodeIcon} />
      <div className={styles.inputNodeRow}>
        <span className={styles.inputNodeLabel}>{label}</span>
        <Settings size={10} className={styles.inputNodeSettingsIcon} />
      </div>
      <Handle type="source" position={Position.Right} className={styles.handle} />
    </div>
  )
}

export const InputNode = memo(InputNodeComponent)

'use client'

import { Modal } from '@/components/ui/Modal'
import styles from './NodeListOverlay.module.css'

interface NodeSlice {
  id: string
  name: string
  type: string
}

interface NodeListOverlayProps {
  isOpen: boolean
  onClose: () => void
  toolLabel: string
  nodes: NodeSlice[]
}

const MAX_ITEMS = 200

export function NodeListOverlay({ isOpen, onClose, toolLabel, nodes }: NodeListOverlayProps) {
  const capped = nodes.length > MAX_ITEMS
  const visible = capped ? nodes.slice(0, MAX_ITEMS) : nodes

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`${toolLabel} -- ${nodes.length}`}
      size="small"
      closeOnOverlayClick={false}
      closeOnEscape={false}
    >
      <div className={styles.nodeList}>
        {visible.map(node => (
          <div key={node.id} className={styles.nodeItem} title={node.name}>
            {node.name}
          </div>
        ))}
        {capped && (
          <div className={styles.moreIndicator}>
            and {nodes.length - MAX_ITEMS} more...
          </div>
        )}
      </div>
    </Modal>
  )
}

'use client'

import { useState } from 'react'
import { AlertTriangle, ArrowLeft } from 'lucide-react'
import { Drawer } from '@/components/ui'
import { GraphNode } from '../../types'
import { getNodeColor } from '../../utils'
import { renderPropertyValue } from '../../utils/renderPropertyValue'
import { ClusterNodeList } from './ClusterNodeList'
import styles from './NodeDrawer.module.css'
import clusterStyles from './ClusterNodeList.module.css'

interface NodeDrawerProps {
  node: GraphNode | null
  isOpen: boolean
  onClose: () => void
  onDeleteNode?: (nodeId: string) => Promise<void>
  expandedChild?: GraphNode | null
  onExpandChild?: (child: GraphNode) => void
  onCollapseChild?: () => void
}

export function NodeDrawer({
  node,
  isOpen,
  onClose,
  onDeleteNode,
  expandedChild,
  onExpandChild,
  onCollapseChild,
}: NodeDrawerProps) {
  const [isDeleting, setIsDeleting] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const handleDeleteClick = () => {
    setShowDeleteConfirm(true)
  }

  const isCluster = !!node?.isCluster
  const displayNode: GraphNode | null = isCluster ? (expandedChild ?? null) : node
  const showList = isCluster && !expandedChild

  const handleDeleteConfirm = async () => {
    if (!displayNode || !onDeleteNode) return
    setIsDeleting(true)
    try {
      await onDeleteNode(displayNode.id)
      setShowDeleteConfirm(false)
      onClose()
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDeleteCancel = () => {
    setShowDeleteConfirm(false)
  }

  const hiddenKeys = ['project_id', 'user_id']
  const sortedProperties = displayNode
    ? Object.entries(displayNode.properties || {})
        .filter(([key]) => !hiddenKeys.includes(key))
        .sort(([a], [b]) => {
          const bottomKeys = ['created_at', 'updated_at']
          const aIsBottom = bottomKeys.includes(a)
          const bIsBottom = bottomKeys.includes(b)
          if (aIsBottom && !bIsBottom) return 1
          if (!aIsBottom && bIsBottom) return -1
          if (aIsBottom && bIsBottom) return bottomKeys.indexOf(a) - bottomKeys.indexOf(b)
          return 0
        })
    : []

  const drawerTitle = node
    ? isCluster
      ? expandedChild
        ? `${expandedChild.type}: ${expandedChild.name}`
        : `Cluster: ${node.clusterChildType ?? ''}`
      : `${node.type}: ${node.name}`
    : undefined

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="overlay"
      title={drawerTitle}
    >
      {node && showList && (
        <ClusterNodeList
          cluster={node}
          onSelectChild={(child) => onExpandChild?.(child)}
        />
      )}

      {displayNode && !showList && (
        <>
          {isCluster && onCollapseChild && (
            <button
              className={clusterStyles.backBtn}
              onClick={onCollapseChild}
            >
              <ArrowLeft size={14} />
              Back to list
            </button>
          )}

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <h3 className={styles.sectionTitleBasicInfo}>Basic Info</h3>
              {displayNode.type !== 'Domain' && displayNode.type !== 'Subdomain' && onDeleteNode && (
                <button
                  className={styles.deleteButton}
                  onClick={handleDeleteClick}
                  disabled={isDeleting}
                  title="Delete node"
                >
                  {isDeleting ? '...' : '\uD83D\uDDD1'}
                </button>
              )}
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Type</span>
              <span
                className={styles.propertyBadge}
                style={{ backgroundColor: getNodeColor(displayNode) }}
              >
                {displayNode.type}
              </span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>ID</span>
              <span className={styles.propertyValue}>{displayNode.id}</span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Name</span>
              <span className={styles.propertyValue}>{displayNode.name}</span>
            </div>
          </div>

          <div className={styles.section}>
            <h3 className={styles.sectionTitleProperties}>Properties</h3>
            {sortedProperties.map(([key, value]) => (
              <div key={key} className={styles.propertyRow}>
                <span className={styles.propertyKey}>{key}</span>
                <span className={styles.propertyValue}>
                  {renderPropertyValue(value)}
                </span>
              </div>
            ))}
            {sortedProperties.length === 0 && (
              <p className={styles.emptyProperties}>No additional properties</p>
            )}
          </div>

          {/* Delete confirmation modal */}
          {showDeleteConfirm && (
            <div className={styles.confirmOverlay} onClick={handleDeleteCancel}>
              <div className={styles.confirmModal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.confirmIcon}>
                  <AlertTriangle size={28} />
                </div>
                <h4 className={styles.confirmTitle}>Delete Node</h4>
                <p className={styles.confirmText}>
                  Deleting <strong>{displayNode.type}: {displayNode.name}</strong> will permanently remove
                  this node and all its relationships from the graph.
                </p>
                <p className={styles.confirmWarning}>
                  This may break the connectivity of the graph and affect
                  the agent&apos;s ability to interpret the attack chain context.
                </p>
                <div className={styles.confirmActions}>
                  <button
                    className={styles.confirmCancelBtn}
                    onClick={handleDeleteCancel}
                  >
                    Cancel
                  </button>
                  <button
                    className={styles.confirmDeleteBtn}
                    onClick={handleDeleteConfirm}
                    disabled={isDeleting}
                  >
                    {isDeleting ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </Drawer>
  )
}

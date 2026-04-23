import { useState, useCallback } from 'react'
import { GraphNode } from '../types'

interface UseNodeSelectionReturn {
  selectedNode: GraphNode | null
  drawerOpen: boolean
  expandedChild: GraphNode | null
  selectNode: (node: GraphNode) => void
  clearSelection: () => void
  expandChild: (node: GraphNode) => void
  collapseChild: () => void
}

/**
 * Custom hook for managing node selection state.
 *
 * When a cluster node is selected, `expandedChild` tracks which child the user
 * drilled into from the cluster list. Selecting a new primary node always resets
 * `expandedChild` to null.
 */
export function useNodeSelection(): UseNodeSelectionReturn {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [expandedChild, setExpandedChild] = useState<GraphNode | null>(null)

  const selectNode = useCallback((node: GraphNode) => {
    setSelectedNode(node)
    setExpandedChild(null)
    setDrawerOpen(true)
  }, [])

  const clearSelection = useCallback(() => {
    setDrawerOpen(false)
    setSelectedNode(null)
    setExpandedChild(null)
  }, [])

  const expandChild = useCallback((node: GraphNode) => {
    setExpandedChild(node)
  }, [])

  const collapseChild = useCallback(() => {
    setExpandedChild(null)
  }, [])

  return {
    selectedNode,
    drawerOpen,
    expandedChild,
    selectNode,
    clearSelection,
    expandChild,
    collapseChild,
  }
}

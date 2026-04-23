'use client'

import { useState, useEffect, useCallback } from 'react'

export interface GraphView {
  id: string
  projectId: string
  name: string
  description: string
  cypherQuery: string
  createdAt: string
  updatedAt: string
}

interface GraphViewsState {
  views: GraphView[]
  isLoading: boolean
  error: string | null
}

export function useGraphViews(projectId: string | null) {
  const [state, setState] = useState<GraphViewsState>({
    views: [],
    isLoading: false,
    error: null,
  })

  const fetchViews = useCallback(async () => {
    if (!projectId) return
    setState(prev => ({ ...prev, isLoading: true, error: null }))
    try {
      const res = await fetch(`/api/graph-views?projectId=${projectId}`)
      if (!res.ok) throw new Error('Failed to fetch graph views')
      const views = await res.json()
      setState({ views, isLoading: false, error: null })
    } catch (err) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: err instanceof Error ? err.message : 'Failed to fetch',
      }))
    }
  }, [projectId])

  useEffect(() => {
    fetchViews()
  }, [fetchViews])

  const createView = useCallback(async (
    name: string,
    description: string,
    cypherQuery: string,
  ): Promise<GraphView | null> => {
    if (!projectId) return null
    try {
      const res = await fetch('/api/graph-views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, name, description, cypherQuery }),
      })
      if (!res.ok) throw new Error('Failed to create graph view')
      const view = await res.json()
      setState(prev => ({
        ...prev,
        views: [view, ...prev.views.filter(v => v.id !== view.id)],
      }))
      return view
    } catch (err) {
      console.error('Failed to create graph view:', err)
      return null
    }
  }, [projectId])

  const deleteView = useCallback(async (id: string): Promise<boolean> => {
    if (!projectId) return false
    try {
      const res = await fetch(`/api/graph-views/${id}?projectId=${projectId}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete')
      setState(prev => ({
        ...prev,
        views: prev.views.filter(v => v.id !== id),
      }))
      return true
    } catch (err) {
      console.error('Failed to delete graph view:', err)
      return false
    }
  }, [projectId])

  const generateCypher = useCallback(async (
    question: string,
    userId: string,
  ): Promise<{ cypher: string } | { error: string }> => {
    if (!projectId) return { error: 'No project selected' }
    try {
      const res = await fetch('/api/agent/text-to-cypher', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, user_id: userId, project_id: projectId }),
      })
      const data = await res.json()
      if (!res.ok) return { error: data.error || 'Failed to generate cypher' }
      return { cypher: data.cypher }
    } catch (err) {
      return { error: err instanceof Error ? err.message : 'Failed to generate cypher' }
    }
  }, [projectId])

  const executeCypher = useCallback(async (
    cypherQuery: string,
  ): Promise<{ nodes: any[]; links: any[] } | { error: string }> => {
    if (!projectId) return { error: 'No project selected' }
    try {
      const res = await fetch('/api/graph-views/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cypherQuery, projectId }),
      })
      const data = await res.json()
      if (!res.ok) return { error: data.error || 'Failed to execute query' }
      return { nodes: data.nodes, links: data.links }
    } catch (err) {
      return { error: err instanceof Error ? err.message : 'Failed to execute query' }
    }
  }, [projectId])

  return {
    views: state.views,
    isLoading: state.isLoading,
    error: state.error,
    fetchViews,
    createView,
    deleteView,
    generateCypher,
    executeCypher,
  }
}

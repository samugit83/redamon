'use client'

import { useState, useEffect, useCallback } from 'react'
import { readApiError, toApiError, type ApiError } from '@/lib/apiError'
import { providerFailureDetail } from '@/lib/llmFeatures'
import type { GraphLink, GraphNode } from '../types'

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
  /** Why the last save or delete failed; those calls answer only null / false. */
  actionError: string | null
}

/** A failed call as the shown text plus its status and code, for callers that branch on them. */
type Failure = { error: string; status: number; code?: string }

function failure(err: ApiError): Failure {
  // A failed model call also says which provider answer it was (a 401, a 429).
  const provider = providerFailureDetail(err.body)
  return {
    error: provider ? `${err.message} [${provider}]` : err.message,
    status: err.status,
    ...(err.code ? { code: err.code } : {}),
  }
}

async function failureOf(res: Response, fallback: string): Promise<Failure> {
  return failure(await readApiError(res, fallback))
}

export function useGraphViews(projectId: string | null) {
  const [state, setState] = useState<GraphViewsState>({
    views: [],
    isLoading: false,
    error: null,
    actionError: null,
  })

  const fetchViews = useCallback(async () => {
    if (!projectId) return
    setState(prev => ({ ...prev, isLoading: true, error: null }))
    try {
      const res = await fetch(`/api/graph-views?projectId=${projectId}`)
      if (!res.ok) throw await readApiError(res, 'Failed to fetch graph views')
      const views = await res.json()
      setState(prev => ({ ...prev, views, isLoading: false, error: null }))
    } catch (err) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: toApiError(err, 'Failed to fetch graph views').message,
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
      if (!res.ok) throw await readApiError(res, 'Failed to create graph view')
      const view = await res.json()
      setState(prev => ({
        ...prev,
        actionError: null,
        views: [view, ...prev.views.filter(v => v.id !== view.id)],
      }))
      return view
    } catch (err) {
      console.error('Failed to create graph view:', err)
      setState(prev => ({ ...prev, actionError: toApiError(err, 'Failed to create graph view').message }))
      return null
    }
  }, [projectId])

  const deleteView = useCallback(async (id: string): Promise<boolean> => {
    if (!projectId) return false
    try {
      const res = await fetch(`/api/graph-views/${id}?projectId=${projectId}`, { method: 'DELETE' })
      if (!res.ok) throw await readApiError(res, 'Failed to delete graph view')
      setState(prev => ({
        ...prev,
        actionError: null,
        views: prev.views.filter(v => v.id !== id),
      }))
      return true
    } catch (err) {
      console.error('Failed to delete graph view:', err)
      setState(prev => ({ ...prev, actionError: toApiError(err, 'Failed to delete graph view').message }))
      return false
    }
  }, [projectId])

  const generateCypher = useCallback(async (
    question: string,
    userId: string,
  ): Promise<{ cypher: string } | Failure> => {
    if (!projectId) return { error: 'No project selected', status: 0 }
    try {
      const res = await fetch('/api/agent/text-to-cypher', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, user_id: userId, project_id: projectId }),
      })
      if (!res.ok) return failureOf(res, 'Failed to generate cypher')
      const data = await res.json()
      return { cypher: data.cypher }
    } catch (err) {
      return failure(toApiError(err, 'Failed to generate cypher'))
    }
  }, [projectId])

  const executeCypher = useCallback(async (
    cypherQuery: string,
  ): Promise<{ nodes: GraphNode[]; links: GraphLink[] } | Failure> => {
    if (!projectId) return { error: 'No project selected', status: 0 }
    try {
      const res = await fetch('/api/graph-views/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cypherQuery, projectId }),
      })
      if (!res.ok) return failureOf(res, 'Failed to execute query')
      const data = await res.json()
      return { nodes: data.nodes, links: data.links }
    } catch (err) {
      return failure(toApiError(err, 'Failed to execute query'))
    }
  }, [projectId])

  const clearActionError = useCallback(() => {
    setState(prev => (prev.actionError ? { ...prev, actionError: null } : prev))
  }, [])

  return {
    views: state.views,
    isLoading: state.isLoading,
    error: state.error,
    actionError: state.actionError,
    clearActionError,
    fetchViews,
    createView,
    deleteView,
    generateCypher,
    executeCypher,
  }
}

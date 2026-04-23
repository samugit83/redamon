import { useState, useEffect, useCallback, useRef } from 'react'
import type { ModelOption } from '../modelUtils'

export function useModelPicker(userId: string, onModelChange?: (modelId: string) => void) {
  const [showModelModal, setShowModelModal] = useState(false)
  const [modelSearch, setModelSearch] = useState('')
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState(false)
  const modelSearchRef = useRef<HTMLInputElement>(null)

  // Fetch models when modal opens
  useEffect(() => {
    if (!showModelModal) return
    let cancelled = false
    setModelsLoading(true)
    setModelsError(false)
    const params = userId ? `?userId=${userId}` : ''
    fetch(`/api/models${params}`)
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => {
        if (cancelled) return
        if (data && typeof data === 'object' && !data.error) {
          setAllModels(data)
        } else {
          setModelsError(true)
        }
      })
      .catch(() => { if (!cancelled) setModelsError(true) })
      .finally(() => { if (!cancelled) setModelsLoading(false) })
    return () => { cancelled = true }
  }, [showModelModal, userId])

  // Auto-focus search when modal opens
  useEffect(() => {
    if (showModelModal) {
      setTimeout(() => modelSearchRef.current?.focus(), 0)
    } else {
      setModelSearch('')
    }
  }, [showModelModal])

  // Filter models by search
  const filteredModels: Record<string, ModelOption[]> = {}
  if (showModelModal) {
    const lowerSearch = modelSearch.toLowerCase()
    for (const [provider, models] of Object.entries(allModels)) {
      const filtered = models.filter(m =>
        m.id.toLowerCase().includes(lowerSearch) ||
        m.name.toLowerCase().includes(lowerSearch) ||
        m.description.toLowerCase().includes(lowerSearch)
      )
      if (filtered.length > 0) filteredModels[provider] = filtered
    }
  }

  const handleSelectModel = useCallback((id: string) => {
    onModelChange?.(id)
    setShowModelModal(false)
  }, [onModelChange])

  return {
    showModelModal,
    setShowModelModal,
    modelSearch,
    setModelSearch,
    modelsLoading,
    modelsError,
    filteredModels,
    handleSelectModel,
    modelSearchRef,
  }
}

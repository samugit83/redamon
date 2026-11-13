import { useState, useEffect, useCallback, useRef } from 'react'
import { formatApiError, toApiError } from '@/lib/apiError'
import { MODELS_LOAD_FAILED, fetchModelOptions } from '@/components/shared/modelOptions'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import type { ModelOption } from '../modelUtils'

const NO_MODELS: Record<string, ModelOption[]> = {}

/**
 * The drawer's "Change Model" picker. On a project the person does not own (step 5.7) the agent runs
 * on the OWNER's providers: the picker lists the owner's models from the owner catalog (read at
 * Manage only) and, below Manage, does not open: `modelRefusal` says why. Otherwise the person's own
 * models, read each time the picker opens, as before.
 */
export function useModelPicker(userId: string, onModelChange?: (modelId: string) => void) {
  const owner = useOwnerCatalogSource()
  const fromOwner = owner !== null
  const modelRefusal = owner?.pickRefusal ?? null
  const [showModelModal, setShowModelModalState] = useState(false)
  const [modelSearch, setModelSearch] = useState('')
  const [ownModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [ownModelsLoading, setModelsLoading] = useState(false)
  // Null, or the failure with its cause, e.g. "Failed to load models (agent_unreachable · HTTP 503)".
  const [ownModelsError, setModelsError] = useState<string | null>(null)
  const modelSearchRef = useRef<HTMLInputElement>(null)

  const setShowModelModal = useCallback((show: boolean) => {
    if (show && modelRefusal) return
    setShowModelModalState(show)
  }, [modelRefusal])

  const allModels = fromOwner ? owner.models ?? NO_MODELS : ownModels
  const modelsLoading = fromOwner ? owner.modelsStatus === 'loading' : ownModelsLoading
  const modelsError = fromOwner
    ? (owner.modelsStatus === 'error' ? owner.modelsError ?? MODELS_LOAD_FAILED : null)
    : ownModelsError

  // Fetch models when modal opens
  useEffect(() => {
    if (!showModelModal || fromOwner) return
    let cancelled = false
    setModelsLoading(true)
    setModelsError(null)
    fetchModelOptions(userId)
      .then(data => { if (!cancelled) setAllModels(data) })
      .catch(err => {
        if (!cancelled) setModelsError(formatApiError({ ...toApiError(err, MODELS_LOAD_FAILED), reason: MODELS_LOAD_FAILED }))
      })
      .finally(() => { if (!cancelled) setModelsLoading(false) })
    return () => { cancelled = true }
  }, [showModelModal, userId, fromOwner])

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
  }, [onModelChange, setShowModelModal])

  return {
    showModelModal,
    setShowModelModal,
    modelRefusal,
    modelSearch,
    setModelSearch,
    modelsLoading,
    modelsError,
    filteredModels,
    handleSelectModel,
    modelSearchRef,
  }
}

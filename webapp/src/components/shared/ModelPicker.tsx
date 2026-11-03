'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { Search, Loader2 } from 'lucide-react'
import {
  type ModelOption,
  formatContextLength,
  getDisplayName,
} from '@/app/graph/components/AIAssistantDrawer/modelUtils'
import { LOOP_WIKI_URL } from '@/app/graph/components/AIAssistantDrawer/hooks/loopStatus'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { formatApiError, toApiError } from '@/lib/apiError'
import styles from '@/components/projects/ProjectForm/ProjectForm.module.css'
import { MODELS_LOAD_FAILED, fetchModelOptions } from './modelOptions'

interface ModelPickerProps {
  userId?: string | null
  value: string
  onChange: (modelId: string) => void
  placeholder?: string
  /**
   * Models already fetched by the caller. When given, the picker does not
   * fetch: a screen showing many pickers makes one /api/models call, not one
   * per picker (each call makes the agent list every provider's models).
   */
  models?: Record<string, ModelOption[]>
  /** Hide the free-text input offered when the model list failed to load. */
  hideManualFallback?: boolean
  /** Only models this accepts are listed. */
  filter?: (modelId: string) => boolean
  disabled?: boolean
  /** Shown in the closed picker while `value` is empty. */
  emptyLabel?: string
}

/**
 * Reusable model picker that mirrors the AgentBehaviourSection LLM selector.
 * Fetches the user's available models from /api/models?userId=, groups by
 * provider, supports search-as-you-type, and falls back to a manual text
 * input when /api/models fails. Shared by AgentBehaviourSection (agent
 * conversational model) and TargetSection (recon AI hook model).
 */
export function ModelPicker({
  userId,
  value,
  onChange,
  placeholder,
  models,
  hideManualFallback,
  filter,
  disabled,
  emptyLabel,
}: ModelPickerProps) {
  const [fetchedModels, setFetchedModels] = useState<Record<string, ModelOption[]>>({})
  const [fetchLoading, setFetchLoading] = useState(true)
  // The failure's cause, e.g. "Failed to load models (agent_unreachable · HTTP 503)".
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const provided = models !== undefined

  useEffect(() => {
    if (provided) return
    fetchModelOptions(userId)
      .then(setFetchedModels)
      .catch(err => setFetchError(formatApiError({ ...toApiError(err, MODELS_LOAD_FAILED), reason: MODELS_LOAD_FAILED })))
      .finally(() => setFetchLoading(false))
  }, [userId, provided])

  const allModels = models ?? fetchedModels
  const modelsLoading = provided ? false : fetchLoading
  const modelsError = provided ? null : fetchError

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false)
        setSearch('')
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const selectModel = useCallback((id: string) => {
    onChange(id)
    setDropdownOpen(false)
    setSearch('')
  }, [onChange])

  const open = dropdownOpen && !disabled

  const filteredModels: Record<string, ModelOption[]> = {}
  const lowerSearch = search.toLowerCase()
  for (const [provider, list] of Object.entries(allModels)) {
    const filtered = list.filter(m =>
      (!filter || filter(m.id)) && (
        m.id.toLowerCase().includes(lowerSearch) ||
        m.name.toLowerCase().includes(lowerSearch) ||
        m.description.toLowerCase().includes(lowerSearch)
      )
    )
    if (filtered.length > 0) filteredModels[provider] = filtered
  }

  return (
    <div className={styles.modelSelector} ref={dropdownRef}>
      <div
        className={`${styles.modelSelectorInput} ${open ? styles.modelSelectorInputFocused : ''}`}
        aria-disabled={disabled || undefined}
        style={disabled ? { opacity: 0.6, cursor: 'not-allowed' } : undefined}
        onClick={() => {
          if (disabled) return
          setDropdownOpen(true)
          setTimeout(() => inputRef.current?.focus(), 0)
        }}
      >
        {open ? (
          <input
            ref={inputRef}
            className={styles.modelSearchInput}
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={placeholder || 'Search models...'}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setDropdownOpen(false)
                setSearch('')
              }
            }}
          />
        ) : (
          <span className={styles.modelSelectedText}>
            {modelsLoading
              ? 'Loading models...'
              : value ? getDisplayName(value, allModels) : (emptyLabel ?? '')}
          </span>
        )}
        {modelsLoading ? (
          <Loader2 size={12} className={styles.modelSelectorSpinner} />
        ) : (
          <Search size={12} className={styles.modelSelectorIcon} />
        )}
      </div>

      {open && (
        <div className={styles.modelDropdown}>
          {modelsError ? (
            <div className={styles.modelDropdownEmpty}>
              {hideManualFallback ? (
                <span>{modelsError}.</span>
              ) : (
                <>
                  <span>{modelsError}. Type a model ID manually:</span>
                  <input
                    className="textInput"
                    type="text"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    placeholder="e.g. claude-opus-4-6, gpt-5.2, openrouter/meta-llama/llama-4-maverick"
                    style={{ marginTop: 'var(--space-1)' }}
                  />
                </>
              )}
            </div>
          ) : Object.keys(filteredModels).length === 0 ? (
            <div className={styles.modelDropdownEmpty}>
              {search ? `No models matching "${search}"` : 'No providers configured'}
            </div>
          ) : (
            Object.entries(filteredModels).map(([provider, list]) => (
              <div key={provider} className={styles.modelGroup}>
                <div className={styles.modelGroupHeader}>{provider}</div>
                {list.map(model => (
                  <div
                    key={model.id}
                    className={`${styles.modelOption} ${model.id === value ? styles.modelOptionSelected : ''}`}
                    onClick={() => selectModel(model.id)}
                  >
                    <div className={styles.modelOptionMain}>
                      <span className={styles.modelOptionName}>{model.name}</span>
                      {model.context_length && (
                        <span className={styles.modelOptionCtx}>{formatContextLength(model.context_length)}</span>
                      )}
                      {isLoopModel(model.id) && (
                        <WikiInfoButton target={LOOP_WIKI_URL} className={styles.modelOptionWiki} />
                      )}
                    </div>
                    {model.description && (
                      <span className={styles.modelOptionDesc}>{model.description}</span>
                    )}
                  </div>
                ))}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

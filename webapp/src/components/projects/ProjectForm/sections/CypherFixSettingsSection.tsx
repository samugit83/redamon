'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { ChevronDown, Shield, Search, Loader2, X } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface CypherFixSettingsSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

interface ModelOption {
  id: string
  name: string
  context_length: number | null
  description: string
}

function formatContextLength(ctx: number | null): string {
  if (!ctx) return ''
  if (ctx >= 1_000_000) return `${(ctx / 1_000_000).toFixed(1)}M`
  if (ctx >= 1_000) return `${Math.round(ctx / 1_000)}K`
  return String(ctx)
}

function getDisplayName(modelId: string, allModels: Record<string, ModelOption[]>): string {
  for (const models of Object.values(allModels)) {
    const found = models.find(m => m.id === modelId)
    if (found) return found.name
  }
  return modelId
}

export function CypherFixSettingsSection({ data, updateField }: CypherFixSettingsSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  // Model selector state
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(true)
  const [modelsError, setModelsError] = useState(false)
  const [search, setSearch] = useState('')
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Fetch models on mount
  useEffect(() => {
    fetch('/api/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      cache: 'no-store',
    })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => {
        if (data && typeof data === 'object' && !data.error) {
          setAllModels(data)
        } else {
          setModelsError(true)
        }
      })
      .catch(() => setModelsError(true))
      .finally(() => setModelsLoading(false))
  }, [])

  // Close dropdown on outside click
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
    updateField('cypherfixLlmModel', id)
    setDropdownOpen(false)
    setSearch('')
  }, [updateField])

  const clearModel = useCallback(() => {
    updateField('cypherfixLlmModel', '')
    setDropdownOpen(false)
    setSearch('')
  }, [updateField])

  // Filter models by search
  const filteredModels: Record<string, ModelOption[]> = {}
  const lowerSearch = search.toLowerCase()
  for (const [provider, models] of Object.entries(allModels)) {
    const filtered = models.filter(m =>
      m.id.toLowerCase().includes(lowerSearch) ||
      m.name.toLowerCase().includes(lowerSearch) ||
      m.description.toLowerCase().includes(lowerSearch)
    )
    if (filtered.length > 0) filteredModels[provider] = filtered
  }

  const hasOverride = !!data.cypherfixLlmModel

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Shield size={16} />
          CypherFix Settings
          <WikiInfoButton target="CypherFixSettings" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Configure finding prioritisation and automated code remediation. CypherFix analyzes your
            Neo4j graph, ranks each finding by exploitability and exposure (the Priority Board), then
            generates code fixes via pull requests to your GitHub repository. The model chosen below
            runs the Priority Board ranking as well as the fixes.
          </p>

          {/* GitHub Token */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Token (CypherFix)</label>
            <input
              type="password"
              className="textInput"
              value={data.cypherfixGithubToken}
              onChange={(e) => updateField('cypherfixGithubToken', e.target.value)}
              placeholder="ghp_xxxxxxxxxxxx"
            />
            <span className={styles.fieldHint}>
              Personal access token with <code>repo</code> scope. Used for cloning, pushing branches, and creating PRs.
            </span>
          </div>

          {/* Default Repository */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Default Repository</label>
            <input
              type="text"
              className="textInput"
              value={data.cypherfixDefaultRepo}
              onChange={(e) => updateField('cypherfixDefaultRepo', e.target.value)}
              placeholder="owner/repo"
            />
            <span className={styles.fieldHint}>
              GitHub repository to fix (owner/repo format). Can be overridden per remediation.
            </span>
          </div>

          {/* Default Branch */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Default Branch</label>
            <input
              type="text"
              className="textInput"
              value={data.cypherfixDefaultBranch}
              onChange={(e) => updateField('cypherfixDefaultBranch', e.target.value)}
              placeholder="main"
            />
            <span className={styles.fieldHint}>
              Base branch for creating fix branches (default: main).
            </span>
          </div>

          {/* Branch Prefix */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Branch Prefix</label>
            <input
              type="text"
              className="textInput"
              value={data.cypherfixBranchPrefix}
              onChange={(e) => updateField('cypherfixBranchPrefix', e.target.value)}
              placeholder="cypherfix/"
            />
            <span className={styles.fieldHint}>
              Prefix for fix branch names (e.g., cypherfix/rem-abc123).
            </span>
          </div>

          {/* Require Approval */}
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Require Approval</span>
              <p className={styles.toggleDescription}>
                Pause and wait for user approval before applying each code edit. Recommended for production repositories.
              </p>
            </div>
            <Toggle
              checked={data.cypherfixRequireApproval}
              onChange={(checked) => updateField('cypherfixRequireApproval', checked)}
            />
          </div>

          {/* LLM Model Override - searchable dropdown */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>CypherFix &amp; Priority Board LLM Model</label>
            <div className={styles.modelSelector} ref={dropdownRef}>
              <div
                className={`${styles.modelSelectorInput} ${dropdownOpen ? styles.modelSelectorInputFocused : ''}`}
                onClick={() => {
                  setDropdownOpen(true)
                  setTimeout(() => inputRef.current?.focus(), 0)
                }}
              >
                {dropdownOpen ? (
                  <input
                    ref={inputRef}
                    className={styles.modelSearchInput}
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search models..."
                    onKeyDown={(e) => {
                      if (e.key === 'Escape') {
                        setDropdownOpen(false)
                        setSearch('')
                      }
                    }}
                  />
                ) : (
                  <span className={styles.modelSelectedText} style={!hasOverride ? { opacity: 0.5 } : undefined}>
                    {modelsLoading
                      ? 'Loading models...'
                      : hasOverride
                        ? getDisplayName(data.cypherfixLlmModel, allModels)
                        : `Using Agent Behaviour model (${getDisplayName(data.agentOpenaiModel, allModels)})`
                    }
                  </span>
                )}
                {modelsLoading ? (
                  <Loader2 size={12} className={styles.modelSelectorSpinner} />
                ) : hasOverride && !dropdownOpen ? (
                  <X
                    size={12}
                    className={styles.modelSelectorIcon}
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => {
                      e.stopPropagation()
                      clearModel()
                    }}
                  />
                ) : (
                  <Search size={12} className={styles.modelSelectorIcon} />
                )}
              </div>

              {dropdownOpen && (
                <div className={styles.modelDropdown}>
                  {/* Use default option */}
                  <div
                    className={`${styles.modelOption} ${!hasOverride ? styles.modelOptionSelected : ''}`}
                    onClick={clearModel}
                  >
                    <div className={styles.modelOptionMain}>
                      <span className={styles.modelOptionName} style={{ fontStyle: 'italic' }}>
                        Use Agent Behaviour model ({getDisplayName(data.agentOpenaiModel, allModels)})
                      </span>
                    </div>
                  </div>

                  {modelsError ? (
                    <div className={styles.modelDropdownEmpty}>
                      <span>Failed to load models. Type a model ID manually:</span>
                      <input
                        className="textInput"
                        type="text"
                        value={data.cypherfixLlmModel}
                        onChange={(e) => updateField('cypherfixLlmModel', e.target.value)}
                        placeholder="e.g. claude-opus-4-6, gpt-5.2, openrouter/meta-llama/llama-4-maverick"
                        style={{ marginTop: 'var(--space-1)' }}
                      />
                    </div>
                  ) : Object.keys(filteredModels).length === 0 ? (
                    <div className={styles.modelDropdownEmpty}>
                      {search ? `No models matching "${search}"` : 'No providers configured'}
                    </div>
                  ) : (
                    Object.entries(filteredModels).map(([provider, models]) => (
                      <div key={provider} className={styles.modelGroup}>
                        <div className={styles.modelGroupHeader}>{provider}</div>
                        {models.map(model => (
                          <div
                            key={model.id}
                            className={`${styles.modelOption} ${model.id === data.cypherfixLlmModel ? styles.modelOptionSelected : ''}`}
                            onClick={() => selectModel(model.id)}
                          >
                            <div className={styles.modelOptionMain}>
                              <span className={styles.modelOptionName}>{model.name}</span>
                              {model.context_length && (
                                <span className={styles.modelOptionCtx}>{formatContextLength(model.context_length)}</span>
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
            <span className={styles.fieldHint}>
              Override the LLM model for CypherFix agents, including the Priority Board pass that
              explains and groups the top-ranked findings. Leave empty to use the model selected in
              Agent Behaviour.
            </span>
          </div>

          {/* How much a triage run may spend on the AI review */}
          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Priority Board: findings the AI reviews</label>
            <input
              type="number"
              min={0}
              max={1000}
              step={10}
              className={styles.input}
              value={data.triageReviewBudget ?? 150}
              onChange={(e) =>
                updateField('triageReviewBudget', parseInt(e.target.value, 10) || 0)
              }
            />
            <span className={styles.fieldHint}>
              Every finding is scored and ranked in code, for free. This caps how
              many of them the AI also reviews against their evidence, which is
              what a run costs. Set it to 0 for a ranked board with no AI at all.
              Findings whose evidence has not changed since the last review cost
              nothing, and findings the AI cannot usefully judge (missing headers,
              dependency advisories) are never sent.
            </span>
          </div>

        </div>
      )}
    </div>
  )
}

'use client'

import { useEffect, useState } from 'react'
import { ChevronDown, Shield, X } from 'lucide-react'
import { Toggle, WikiInfoButton, useToast } from '@/components/ui'
import { ModelPicker } from '@/components/shared/ModelPicker'
import {
  fetchModelOptions,
  fetchSavedFeatureModels,
  saveFeatureModel,
  useFeatureModelGate,
  type ModelsByProvider,
} from '@/components/shared/FeatureModelGate'
import { getLlmFeature, modelAllowedForFeature, type FeatureId } from '@/lib/llmFeatures'
import type { Project } from '@prisma/client'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface CypherFixSettingsSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const ACCOUNT_MODEL_FEATURES: FeatureId[] = ['triage', 'codefix']

/**
 * The Triage review and CodeFix models. They belong to the user, not to this
 * project: the same value is edited in Global Settings → LLM Providers →
 * Models by feature, and every project of this user runs on it. Each change is
 * saved at once, outside the project form's own Save.
 */
function AccountFeatureModels() {
  const toast = useToast()
  const { userId } = useFeatureModelGate()
  const [models, setModels] = useState<ModelsByProvider | null>(null)
  const [modelsFailed, setModelsFailed] = useState(false)
  const [saved, setSaved] = useState<Record<string, string> | null>(null)
  const [saving, setSaving] = useState<FeatureId | null>(null)

  useEffect(() => {
    if (!userId) return
    let live = true
    fetchModelOptions(userId)
      .then(m => { if (live) setModels(m) })
      .catch(() => { if (live) setModelsFailed(true) })
    fetchSavedFeatureModels(userId)
      .then(m => { if (live) setSaved(m) })
      .catch(() => { if (live) setSaved({}) })
    return () => { live = false }
  }, [userId])

  const save = async (featureId: FeatureId, model: string) => {
    if (!userId || saving || model === (saved?.[featureId] ?? '')) return
    const label = getLlmFeature(featureId).label
    setSaving(featureId)
    try {
      setSaved(await saveFeatureModel(userId, featureId, model))
      toast.success(model ? `${label} now uses ${model}, in all your projects` : `${label} has no model now`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Could not save the ${label} model`)
    } finally {
      setSaving(null)
    }
  }

  return (
    <>
      {ACCOUNT_MODEL_FEATURES.map(featureId => {
        const feature = getLlmFeature(featureId)
        const value = saved?.[featureId] ?? ''
        return (
          <div key={featureId} className={styles.fieldGroup} data-feature-model-field={featureId}>
            <label className={styles.fieldLabel}>{feature.label} model</label>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                {modelsFailed ? (
                  <input className="textInput" value={value || 'Not set'} readOnly aria-label={`${feature.label} model`} />
                ) : (
                  <ModelPicker
                    userId={userId}
                    value={value}
                    onChange={id => void save(featureId, id)}
                    models={models ?? {}}
                    hideManualFallback
                    filter={id => modelAllowedForFeature(featureId, id)}
                    disabled={!userId || !models || saved === null || saving === featureId}
                    emptyLabel={models && saved ? 'Choose a model' : 'Loading models...'}
                  />
                )}
              </div>
              {value && !modelsFailed && (
                <button
                  type="button"
                  className="iconButton"
                  onClick={() => void save(featureId, '')}
                  disabled={saving === featureId}
                  title={`Clear the ${feature.label} model`}
                  aria-label={`Clear the ${feature.label} model`}
                >
                  <X size={12} />
                </button>
              )}
            </div>
            <span className={styles.fieldHint}>
              {feature.description} {feature.hint}
              <br />
              Applies to all your projects · also in Global Settings → LLM Providers
            </span>
          </div>
        )
      })}
    </>
  )
}

export function CypherFixSettingsSection({ data, updateField }: CypherFixSettingsSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  // A collaborator's form (step 5.7): the two models are the OWNER's account settings, which the
  // owner's runs use; the collaborator's own account settings would mean nothing here.
  const ownerForm = useOwnerCatalogSource() !== null

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
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
            generates code fixes via pull requests to your GitHub repository. The two models below are
            yours, not this project&apos;s: Triage review checks the ranked findings&apos; evidence and
            words the fix list, CodeFix writes the fixes.
          </p>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>GitHub Token (CypherFix)</label>
              <input
                type="password"
                className="textInput"
                value={data.cypherfixGithubToken ?? ''}
                onChange={(e) => updateField('cypherfixGithubToken', e.target.value)}
                placeholder="ghp_xxxxxxxxxxxx"
              />
              <span className={styles.fieldHint}>
                Personal access token with <code>repo</code> scope. Used for cloning, pushing branches, and creating PRs.
              </span>
            </div>
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
          </div>

          <div className={styles.fieldRow}>
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
          </div>

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

          <div className={styles.fieldRow}>
            {ownerForm ? (
              <p className={styles.fieldHint} data-testid="owner-feature-models">
                The Triage review and CodeFix models are the project owner&apos;s account settings: this
                project&apos;s runs use the owner&apos;s, and only the owner changes them, in their Global Settings.
              </p>
            ) : (
              <AccountFeatureModels />
            )}
          </div>

          {/* How much a triage run may spend on the AI review */}
          <div className={`${styles.fieldRow} ${styles.fieldRowHalf}`}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Priority Board: findings the AI reviews</label>
              <input
                type="number"
                min={0}
                max={1000}
                step={10}
                className="textInput"
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

        </div>
      )}
    </div>
  )
}

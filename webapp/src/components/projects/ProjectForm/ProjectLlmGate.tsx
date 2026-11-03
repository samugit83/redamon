'use client'

import { useRouter } from 'next/navigation'
import { Cpu, Bot, Sparkles, ArrowRight } from 'lucide-react'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { bothModelsSelected } from './projectLlmGate.logic'
import styles from './ProjectForm.module.css'

/**
 * Blocking modal shown when a user tries to create a project without any
 * LLM provider configured. Both the agent and the AI recon pipeline need one,
 * so creation cannot continue until a provider is added in Global Settings.
 */
export function ProviderRequiredModal({
  onCancel,
  onUseLoop,
}: {
  onCancel: () => void
  /** Offered while Agent in the Loop is on: it needs no provider. */
  onUseLoop?: () => void
}) {
  const router = useRouter()
  return (
    <div className={styles.guardrailOverlay}>
      <div className={styles.gateModal}>
        <div className={styles.gateIconWrapper}>
          <Cpu size={28} />
        </div>
        <h2 className={styles.gateTitle}>Configure an LLM provider first</h2>
        <p className={styles.gateMessage}>
          RedAmon needs at least one LLM provider (DeepSeek, Anthropic, OpenAI, ...) before
          you can create a project. The autonomous agent and the AI recon pipeline both rely on it.
        </p>
        <div className={styles.gateActions}>
          <button type="button" className="secondaryButton" onClick={onCancel}>
            Back to Projects
          </button>
          {onUseLoop && (
            <button
              type="button"
              className="secondaryButton"
              onClick={onUseLoop}
              title="Your own Claude Code or Codex answers each step; no API key needed"
            >
              Use Agent in the Loop instead
            </button>
          )}
          <button
            type="button"
            className="primaryButton"
            onClick={() => router.push('/settings')}
          >
            Configure Provider
            <ArrowRight size={14} />
          </button>
        </div>
        {onUseLoop && (
          <p className={styles.gateHint}>
            With Agent in the Loop the recon AI features need a provider model too. They stay off
            until you add one in Global Settings.
          </p>
        )}
      </div>
    </div>
  )
}

interface ModelSelectionModalProps {
  userId?: string | null
  agentModel: string
  aiPipelineModel: string
  onChangeAgent: (id: string) => void
  onChangeAiPipeline: (id: string) => void
  onConfirm: () => void
  onCancel: () => void
  /** Agent in the Loop with no provider: the pipeline model may stay unset. */
  pipelineOptional?: boolean
}

/**
 * Forced model-selection modal shown on save when either the agent model or the
 * AI pipeline model is unset. Both must be picked before the project is saved.
 * The chosen models are remembered as per-user defaults for the next project.
 */
export function ModelSelectionModal({
  userId,
  agentModel,
  aiPipelineModel,
  onChangeAgent,
  onChangeAiPipeline,
  onConfirm,
  onCancel,
  pipelineOptional = false,
}: ModelSelectionModalProps) {
  const ready = bothModelsSelected(agentModel, aiPipelineModel, pipelineOptional)
  return (
    <div className={styles.guardrailOverlay}>
      <div className={styles.gateModalWide}>
        <div className={styles.gateIconWrapper}>
          <Sparkles size={28} />
        </div>
        <h2 className={styles.gateTitle}>Select the AI models</h2>
        <p className={styles.gateMessage}>
          Choose the models RedAmon will use for this project. We&apos;ll remember them as the
          default for your next project.
        </p>

        <div className={styles.gateField}>
          <label className={styles.gateLabel}>
            <Bot size={14} /> Agent model
          </label>
          <span className={styles.gateHint}>
            Used by the autonomous agent (chat, graph NL-to-Cypher queries).
          </span>
          <ModelPicker
            userId={userId}
            value={agentModel}
            onChange={onChangeAgent}
            placeholder="Search agent models..."
          />
        </div>

        <div className={styles.gateField}>
          <label className={styles.gateLabel}>
            <Cpu size={14} /> AI recon pipeline model
          </label>
          <span className={styles.gateHint}>
            Used by recon AI hooks: Nuclei tag cascade, FP filter, WAF and takeover classifiers,
            FFuf extensions.
          </span>
          {pipelineOptional && (
            <span className={styles.gateHint} role="note">
              Recon AI features need a provider model. They stay off until you add one in Global
              Settings.
            </span>
          )}
          <ModelPicker
            userId={userId}
            value={aiPipelineModel}
            onChange={onChangeAiPipeline}
            placeholder="Search pipeline models..."
            filter={excludeLoop}
          />
        </div>

        <div className={styles.gateActions}>
          <button type="button" className="secondaryButton" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className="primaryButton"
            disabled={!ready}
            onClick={onConfirm}
            title={ready ? 'Save the project with the selected models' : 'Select both models to continue'}
          >
            Save Project
          </button>
        </div>
      </div>
    </div>
  )
}

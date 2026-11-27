'use client'

import { useState } from 'react'
import { ChevronDown, Brain, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ResourceEnumAiSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function ResourceEnumAiSection({ data, updateField, onRun }: ResourceEnumAiSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const masterOn = data.resourceEnumAiClassifierEnabled ?? true
  const jevStatus = useHasJevProvider()

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Brain size={16} />
          Endpoint AI Classifier
          <NodeInfoTooltip section="EndpointAiClassifier" />
          <WikiInfoButton target="EndpointAiClassifier" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && masterOn && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Endpoint AI Classifier"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={masterOn}
              onChange={(checked) => updateField('resourceEnumAiClassifierEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Classifies every Endpoint and Parameter discovered by Katana / Hakrawler / GAU / FFuf / ParamSpider / Arjun / Kiterunner / jsluice, or declared in an OpenAPI document, against an AI-shape catalogue. Tags chat / completion / embedding / tool-call / SSE / MCP / GraphQL endpoints, flags RAG ingestion paths, and marks parameters likely to carry prompt-injection vectors. Pure regex over data already in the graph; no extra traffic is sent to the target.
          </p>

          {masterOn && (
            <div className={styles.subSection}>
              <h3 className={styles.subSectionTitle}>AI Surface Classifiers</h3>
              <p className={styles.fieldHint}>
                All sub-classifiers default on. Master toggle above gates the whole pass. Each sub-classifier can be flipped independently when a specific annotation produces too much noise on a given target.
              </p>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>AI Path Classifier</span>
                  <p className={styles.toggleDescription}>
                    Matches the URL path against the LLM / completion / embedding / tool-call / SSE / MCP / GraphQL catalogue (OpenAI /v1/chat/completions, Anthropic /v1/messages, Ollama /api/chat, Gemini :generateContent, Cohere /v2/chat, MCP /mcp, LangServe /stream, ...) and stamps Endpoint.ai_interface_type.
                  </p>
                </div>
                <Toggle
                  checked={data.resourceEnumAiPathClassifierEnabled ?? true}
                  onChange={(checked) => updateField('resourceEnumAiPathClassifierEnabled', checked)}
                />
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>AI RAG Path Flag</span>
                  <p className={styles.toggleDescription}>
                    Flags endpoints that look like RAG ingestion or retrieval (OpenAI Vector Stores, Pinecone /vectors/upsert, Weaviate /v1/objects, Qdrant /collections/.../points). Ambiguous paths (/upload, /search, /query) only fire when the parent host is already AI-tagged, to avoid flagging every e-commerce search bar.
                  </p>
                </div>
                <Toggle
                  checked={data.resourceEnumAiRagPathFlagEnabled ?? true}
                  onChange={(checked) => updateField('resourceEnumAiRagPathFlagEnabled', checked)}
                />
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>AI Prompt-Injectable Param Flag</span>
                  <p className={styles.toggleDescription}>
                    Marks Parameter nodes whose name is a known prompt-injection field (prompt, messages, system, contents, inputs, arguments, ...) when the parent Endpoint is AI-classified. Sets Parameter.is_ai_prompt_injectable=true.
                  </p>
                </div>
                <Toggle
                  checked={data.resourceEnumAiParamInjectableFlagEnabled ?? true}
                  onChange={(checked) => updateField('resourceEnumAiParamInjectableFlagEnabled', checked)}
                />
              </div>
            </div>
          )}

          {/* Not part of the classifier above, so outside its master toggle. */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Tool Health (Jev)</h3>
            <p className={styles.fieldHint}>
              Every empty result from a crawler or collector is checked from its exit code and error output, and one that looks like a failure is recorded as a coverage gap. That check always runs.
            </p>
            <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
              <AiToggleLabel
                label="Read unexplained tool errors with Jev"
                tooltip={
                  'When an empty result\'s error output fits neither a routine line nor a known ' +
                  'failure, Jev is asked whether it describes a transient failure a second run could ' +
                  'fix. At most 20 questions per run, with header values redacted. The verdict is ' +
                  'kept in the recon output next to the coverage gap; no tool is re-run. Same switch ' +
                  'as in the Target tab AI panel. ' +
                  (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                }
              />
              <JevEngineControl
                variant="jevOnly"
                value={data.resourceEnumJevToolHealth}
                enabled={data.aiInPipeline}
                jevStatus={jevStatus}
                disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
                onSelect={(on) => updateField('resourceEnumJevToolHealth', on)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

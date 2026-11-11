'use client'

import { useState } from 'react'
import { ChevronDown, Radar, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AiSurfaceReconSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

export function AiSurfaceReconSection({ data, updateField, onRun }: AiSurfaceReconSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const masterOn = data.aiSurfaceReconEnabled ?? true

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Radar size={16} />
          AI Surface Recon
          <NodeInfoTooltip section="AiSurfaceRecon" />
          <WikiInfoButton target="AiSurfaceRecon" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && masterOn && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run AI Surface Recon"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={masterOn}
              onChange={(checked) => updateField('aiSurfaceReconEnabled', checked)}
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
            Active, protocol-aware fingerprinting of AI / LLM / MCP surfaces. Runs after Resource Enumeration and probes only hosts that already show an AI signal. Sends benign shape-probes only (a 1-token chat ping, a protocol handshake, read-only GETs) and detects MCP tool poisoning statically. No jailbreaks, no payloads, no LLM judging.
          </p>

          {masterOn && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Per-probe Timeout (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.aiSurfaceReconTimeout ?? 10}
                    onChange={(e) => updateField('aiSurfaceReconTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>HTTP timeout for each probe</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Workers</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.aiSurfaceReconMaxWorkers ?? 5}
                    onChange={(e) => updateField('aiSurfaceReconMaxWorkers', parseInt(e.target.value) || 5)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Per-host probe concurrency</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>User-Agent</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.aiSurfaceReconUserAgent ?? 'RedAmon-AISurfaceRecon/1.0'}
                    onChange={(e) => updateField('aiSurfaceReconUserAgent', e.target.value)}
                  />
                  <span className={styles.fieldHint}>UA string sent on every probe</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Probe-pack Version</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.aiSurfaceReconProbePackVersion ?? 'latest'}
                    onChange={(e) => updateField('aiSurfaceReconProbePackVersion', e.target.value)}
                  />
                  <span className={styles.fieldHint}>Recorded on every annotation</span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Workloads</h3>
                <p className={styles.fieldHint}>
                  Each workload defaults on. The master toggle gates the whole pass. Stealth mode keeps the passive workloads on but disables MCP tools/list and the vector-DB read and halves concurrency.
                </p>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Chat-shape Probes</span>
                    <p className={styles.toggleDescription}>POSTs a 1-token &quot;ping&quot; to candidate chat paths and classifies the response shape (OpenAI / Anthropic / Ollama / Gemini / LangServe / SSE). Confirms Endpoint.ai_interface_type and streaming support.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconChatShapeProbeEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconChatShapeProbeEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>MCP Handshake</span>
                    <p className={styles.toggleDescription}>Runs the Model Context Protocol initialize handshake (Streamable HTTP + legacy SSE). Captures server name/version, protocol version, advertised capabilities, and auth requirement.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconMcpHandshakeEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconMcpHandshakeEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>MCP tools/list Enumeration</span>
                    <p className={styles.toggleDescription}>After a successful handshake, lists the MCP server tools / resources / prompts and creates a Parameter per tool argument. Off in stealth mode (extra JSON-RPC calls).</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconMcpListToolsEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconMcpListToolsEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>MCP Tool-Poisoning Scan (YARA)</span>
                    <p className={styles.toggleDescription}>Statically scans every MCP tool description, input schema, and server instructions with YARA rules for tool poisoning, prompt injection, and data-exfiltration hints. Deterministic, no LLM. Writes Vulnerability findings.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconMcpYaraEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconMcpYaraEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>OpenAPI / Manifest Discovery</span>
                    <p className={styles.toggleDescription}>Fetches and parses openapi.json / ai-plugin.json / swagger to extract tool-call schemas and capability flags (tools / vision / streaming). Populates Endpoint.ai_tool_schema_ref and Parameter.ai_tool_arg_path.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconOpenapiDiscoveryEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconOpenapiDiscoveryEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Model-family Guess</span>
                    <p className={styles.toggleDescription}>Reads /v1/models and /api/tags to infer the served model family (gpt / claude / llama / mistral / qwen / gemini ...). Sets Endpoint.ai_model_family_guess.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconModelListEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconModelListEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Julius Fingerprint Pack</span>
                    <p className={styles.toggleDescription}>Runs the vendored Julius HTTP fingerprint packs to identify the AI service software (Ollama, vLLM, LiteLLM, ...) and promote it to a confirmed Technology node.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconJuliusProbePackEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconJuliusProbePackEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Vector-DB Confirmation Read</span>
                    <p className={styles.toggleDescription}>Sends one benign read to candidate vector-DB ports (Chroma / Qdrant / Weaviate / Milvus) and promotes the Service to a confirmed Technology(category=ai-vector-db). Off in stealth mode.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconVectorDbReadEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconVectorDbReadEnabled', c)} />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Latency Baseline</span>
                    <p className={styles.toggleDescription}>Records the p50 latency of the chat-shape ping on each LLM endpoint (piggybacks on the chat probe). Cheap signal for later model fingerprinting.</p>
                  </div>
                  <Toggle checked={data.aiSurfaceReconLatencyBaselineEnabled ?? true}
                    onChange={(c) => updateField('aiSurfaceReconLatencyBaselineEnabled', c)} />
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

'use client'

import { useState } from 'react'
import { ChevronDown, Bot } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AgentBehaviourSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function AgentBehaviourSection({ data, updateField }: AgentBehaviourSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bot size={16} />
          Agent Behaviour
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Configure the AI agent orchestrator that performs autonomous pentesting. Controls LLM model, phase transitions, payload settings, tool access, and safety gates.
          </p>

          {/* LLM & Phase Configuration */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>LLM & Phase Configuration</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>LLM Model</label>
                <select
                  className="select"
                  value={data.agentOpenaiModel}
                  onChange={(e) => updateField('agentOpenaiModel', e.target.value)}
                >
                  <optgroup label="Anthropic Claude">
                    <option value="claude-opus-4-6">Claude Opus 4.6 — Most capable model</option>
                    <option value="claude-sonnet-4-5-20250929">Claude Sonnet 4.5 — Balanced performance</option>
                    <option value="claude-haiku-4-5-20251001">Claude Haiku 4.5 — Fast and efficient</option>
                  </optgroup>
                  <optgroup label="GPT-5.2">
                    <option value="gpt-5.2">gpt-5.2 — Flagship reasoning model</option>
                    <option value="gpt-5.2-pro">gpt-5.2-pro — Smarter, more precise (Responses API)</option>
                  </optgroup>
                  <optgroup label="GPT-5">
                    <option value="gpt-5">gpt-5 — Previous reasoning model</option>
                    <option value="gpt-5-mini">gpt-5-mini — Faster, cost-efficient GPT-5</option>
                    <option value="gpt-5-nano">gpt-5-nano — Fastest, cheapest GPT-5</option>
                  </optgroup>
                  <optgroup label="GPT-4.1">
                    <option value="gpt-4.1">gpt-4.1 — Smartest non-reasoning model</option>
                    <option value="gpt-4.1-mini">gpt-4.1-mini — Fast, cost-efficient</option>
                    <option value="gpt-4.1-nano">gpt-4.1-nano — Fastest, cheapest</option>
                  </optgroup>
                </select>
                <span className={styles.fieldHint}>Model used by the agent. Anthropic models require ANTHROPIC_API_KEY in the agent .env file.</span>
              </div>
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Activate Post-Exploitation Phase</span>
                <p className={styles.toggleDescription}>Enable post-exploitation after successful exploitation. When disabled, the agent stops after exploitation.</p>
              </div>
              <Toggle
                checked={data.agentActivatePostExplPhase}
                onChange={(checked) => updateField('agentActivatePostExplPhase', checked)}
              />
            </div>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Post-Exploitation Type</label>
                <select
                  className="select"
                  value={data.agentPostExplPhaseType}
                  onChange={(e) => updateField('agentPostExplPhaseType', e.target.value)}
                >
                  <option value="statefull">Stateful</option>
                  <option value="stateless">Stateless</option>
                </select>
                <span className={styles.fieldHint}>Stateful keeps Meterpreter/shell sessions between turns</span>
              </div>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Informational Phase System Prompt</label>
              <textarea
                className="textInput"
                value={data.agentInformationalSystemPrompt}
                onChange={(e) => updateField('agentInformationalSystemPrompt', e.target.value)}
                placeholder="Custom system prompt for the informational/recon phase..."
                rows={2}
              />
              <span className={styles.fieldHint}>Injected during the informational phase. Leave empty for default.</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Exploitation Phase System Prompt</label>
              <textarea
                className="textInput"
                value={data.agentExplSystemPrompt}
                onChange={(e) => updateField('agentExplSystemPrompt', e.target.value)}
                placeholder="Custom system prompt for the exploitation phase..."
                rows={2}
              />
              <span className={styles.fieldHint}>Injected during the exploitation phase. Leave empty for default.</span>
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Post-Exploitation Phase System Prompt</label>
              <textarea
                className="textInput"
                value={data.agentPostExplSystemPrompt}
                onChange={(e) => updateField('agentPostExplSystemPrompt', e.target.value)}
                placeholder="Custom system prompt for the post-exploitation phase..."
                rows={2}
              />
              <span className={styles.fieldHint}>Injected during the post-exploitation phase. Leave empty for default.</span>
            </div>
          </div>

          {/* Payload Direction */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Payload Direction</h3>
            <p className={styles.toggleDescription} style={{ marginBottom: 'var(--space-2)' }}>
              <strong>Reverse</strong>: target connects back to you (LHOST + LPORT). <strong>Bind</strong>: you connect to the target (leave LPORT empty).
            </p>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>LHOST (Attacker IP)</label>
                <input
                  type="text"
                  className="textInput"
                  value={data.agentLhost}
                  onChange={(e) => updateField('agentLhost', e.target.value)}
                  placeholder="e.g. 172.28.0.2"
                />
                <span className={styles.fieldHint}>Leave empty for bind mode</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>LPORT</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentLport || ''}
                  onChange={(e) => updateField('agentLport', e.target.value === '' ? null : parseInt(e.target.value))}
                  min={1}
                  max={65535}
                  placeholder="Empty = bind mode"
                />
                <span className={styles.fieldHint}>Leave empty for bind mode</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Bind Port on Target</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentBindPortOnTarget || ''}
                  onChange={(e) => updateField('agentBindPortOnTarget', e.target.value === '' ? null : parseInt(e.target.value))}
                  min={1}
                  max={65535}
                  placeholder="Empty = ask agent"
                />
                <span className={styles.fieldHint}>Leave empty if unsure (agent will ask)</span>
              </div>
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Payload Use HTTPS</span>
                <p className={styles.toggleDescription}>Use reverse_https instead of reverse_tcp. Only for reverse payloads.</p>
              </div>
              <Toggle
                checked={data.agentPayloadUseHttps}
                onChange={(checked) => updateField('agentPayloadUseHttps', checked)}
              />
            </div>
          </div>

          {/* Agent Limits */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Agent Limits</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Max Iterations</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentMaxIterations}
                  onChange={(e) => updateField('agentMaxIterations', parseInt(e.target.value) || 100)}
                  min={1}
                />
                <span className={styles.fieldHint}>LLM reasoning iterations limit</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Trace Memory Steps</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentExecutionTraceMemorySteps}
                  onChange={(e) => updateField('agentExecutionTraceMemorySteps', parseInt(e.target.value) || 100)}
                  min={1}
                />
                <span className={styles.fieldHint}>Past steps kept in context</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Tool Output Max Chars</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentToolOutputMaxChars}
                  onChange={(e) => updateField('agentToolOutputMaxChars', parseInt(e.target.value) || 20000)}
                  min={1000}
                />
                <span className={styles.fieldHint}>Truncation limit for tool output</span>
              </div>
            </div>
          </div>

          {/* Approval Gates */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Approval Gates</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Require Approval for Exploitation</span>
                <p className={styles.toggleDescription}>User confirmation before transitioning to exploitation phase.</p>
              </div>
              <Toggle
                checked={data.agentRequireApprovalForExploitation}
                onChange={(checked) => updateField('agentRequireApprovalForExploitation', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Require Approval for Post-Exploitation</span>
                <p className={styles.toggleDescription}>User confirmation before transitioning to post-exploitation phase.</p>
              </div>
              <Toggle
                checked={data.agentRequireApprovalForPostExploitation}
                onChange={(checked) => updateField('agentRequireApprovalForPostExploitation', checked)}
              />
            </div>
          </div>

          {/* Retries, Logging & Debug */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Retries, Logging & Debug</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Cypher Max Retries</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentCypherMaxRetries}
                  onChange={(e) => updateField('agentCypherMaxRetries', parseInt(e.target.value) || 3)}
                  min={0}
                  max={10}
                />
                <span className={styles.fieldHint}>Neo4j query retries</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Log Max MB</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentLogMaxMb}
                  onChange={(e) => updateField('agentLogMaxMb', parseInt(e.target.value) || 10)}
                  min={1}
                />
                <span className={styles.fieldHint}>Max log file size</span>
              </div>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Log Backups</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentLogBackupCount}
                  onChange={(e) => updateField('agentLogBackupCount', parseInt(e.target.value) || 5)}
                  min={0}
                />
                <span className={styles.fieldHint}>Rotated backups to keep</span>
              </div>
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Create Graph Image on Init</span>
                <p className={styles.toggleDescription}>Generate a LangGraph visualization when the agent starts. Useful for debugging.</p>
              </div>
              <Toggle
                checked={data.agentCreateGraphImageOnInit}
                onChange={(checked) => updateField('agentCreateGraphImageOnInit', checked)}
              />
            </div>
          </div>

          {/* Tool Phase Restrictions */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Tool Phase Restrictions</h3>
            <span className={styles.fieldHint} style={{ marginBottom: 'var(--space-2)', display: 'block' }}>
              Controls which tools the agent can use in each phase. Check the phases where each tool should be available.
            </span>
            <div className={styles.toolPhaseGrid}>
              <div className={styles.toolPhaseHeader}>
                <span className={styles.toolPhaseHeaderLabel}>Tool</span>
                <span className={styles.toolPhaseHeaderLabel}>Informational</span>
                <span className={styles.toolPhaseHeaderLabel}>Exploitation</span>
                <span className={styles.toolPhaseHeaderLabel}>Post-Exploitation</span>
              </div>
              {[
                { id: 'query_graph', label: 'query_graph' },
                { id: 'web_search', label: 'web_search' },
                { id: 'execute_curl', label: 'execute_curl' },
                { id: 'execute_naabu', label: 'execute_naabu' },
                { id: 'metasploit_console', label: 'metasploit_console' },
                { id: 'msf_restart', label: 'msf_restart' },
              ].map(tool => {
                const phaseMap = (typeof data.agentToolPhaseMap === 'string'
                  ? JSON.parse(data.agentToolPhaseMap)
                  : data.agentToolPhaseMap) as Record<string, string[]>
                const toolPhases = phaseMap[tool.id] || []

                const togglePhase = (phase: string) => {
                  const newMap = { ...phaseMap }
                  const current = newMap[tool.id] || []
                  if (current.includes(phase)) {
                    newMap[tool.id] = current.filter((p: string) => p !== phase)
                  } else {
                    newMap[tool.id] = [...current, phase]
                  }
                  updateField('agentToolPhaseMap', newMap as typeof data.agentToolPhaseMap)
                }

                return (
                  <div key={tool.id} className={styles.toolPhaseRow}>
                    <span className={styles.toolPhaseName}>{tool.label}</span>
                    {['informational', 'exploitation', 'post_exploitation'].map(phase => (
                      <label key={phase} className={styles.phaseCheck}>
                        <input
                          type="checkbox"
                          checked={toolPhases.includes(phase)}
                          onChange={() => togglePhase(phase)}
                        />
                      </label>
                    ))}
                  </div>
                )
              })}
            </div>
          </div>

        </div>
      )}
    </div>
  )
}

'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { ChevronDown, Bot, Search, Loader2, AlertTriangle } from 'lucide-react'
import { Toggle } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { type ModelOption, formatContextLength, getDisplayName } from '@/app/graph/components/AIAssistantDrawer/modelUtils'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AgentBehaviourSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function AgentBehaviourSection({ data, updateField }: AgentBehaviourSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()

  // Model selector state
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(true)
  const [modelsError, setModelsError] = useState(false)
  const [search, setSearch] = useState('')
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)


  // Fetch models on mount (pass userId for user-specific providers)
  useEffect(() => {
    const params = userId ? `?userId=${userId}` : ''
    fetch(`/api/models${params}`)
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
  }, [userId])

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
    updateField('agentOpenaiModel', id)
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

  const totalFiltered = Object.values(filteredModels).reduce((sum, arr) => sum + arr.length, 0)

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
            Configure the AI agent orchestrator that performs autonomous pentesting. Controls LLM model, phase transitions, payload settings, and safety gates. Tool access per phase is configured in the Tool Matrix tab.
          </p>

          {/* LLM & Phase Configuration */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>LLM & Phase Configuration</h3>
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>LLM Model</label>
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
                      <span className={styles.modelSelectedText}>
                        {modelsLoading ? 'Loading models...' : getDisplayName(data.agentOpenaiModel, allModels)}
                      </span>
                    )}
                    {modelsLoading ? (
                      <Loader2 size={12} className={styles.modelSelectorSpinner} />
                    ) : (
                      <Search size={12} className={styles.modelSelectorIcon} />
                    )}
                  </div>

                  {dropdownOpen && (
                    <div className={styles.modelDropdown}>
                      {modelsError ? (
                        <div className={styles.modelDropdownEmpty}>
                          <span>Failed to load models. Type a model ID manually:</span>
                          <input
                            className="textInput"
                            type="text"
                            value={data.agentOpenaiModel}
                            onChange={(e) => updateField('agentOpenaiModel', e.target.value)}
                            placeholder="e.g. claude-opus-4-6, gpt-5.2, openrouter/meta-llama/llama-4-maverick, openai_compat/llama3.1"
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
                                className={`${styles.modelOption} ${model.id === data.agentOpenaiModel ? styles.modelOptionSelected : ''}`}
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
                  Model used by the agent. Configure providers in Global Settings.
                </span>
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
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Deep Think</span>
                <p className={styles.toggleDescription}>
                  When enabled, the agent performs an explicit deep reasoning step at key decision points
                  (start of session, phase transitions, failure loops) to plan multi-step attack strategies
                  before acting. Adds ~1 extra LLM call at these moments. Recommended for complex targets
                  with multiple services.
                </p>
              </div>
              <Toggle
                checked={data.agentDeepThinkEnabled}
                onChange={(checked) => updateField('agentDeepThinkEnabled', checked)}
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
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Tunnel Provider</label>
              <select
                className="textInput"
                value={data.agentNgrokTunnelEnabled ? 'ngrok' : data.agentChiselTunnelEnabled ? 'chisel' : 'none'}
                onChange={(e) => {
                  const val = e.target.value;
                  updateField('agentNgrokTunnelEnabled', val === 'ngrok');
                  updateField('agentChiselTunnelEnabled', val === 'chisel');
                }}
              >
                <option value="none">None (manual LHOST/LPORT)</option>
                <option value="ngrok">ngrok (single port — free, no VPS needed)</option>
                <option value="chisel">chisel (multi-port — requires VPS)</option>
              </select>
              <span className={styles.fieldHint}>
                {data.agentNgrokTunnelEnabled && 'Configure ngrok auth token in Global Settings → Tunneling. Tunnels port 4444 only (handler). Stageless payloads required. Web delivery / HTA not supported.'}
                {data.agentChiselTunnelEnabled && 'Configure chisel server URL in Global Settings → Tunneling. Requires a chisel server running on your VPS. Tunnels ports 4444 (handler) + 8080 (web delivery). Stageless payloads required.'}
                {!data.agentNgrokTunnelEnabled && !data.agentChiselTunnelEnabled && 'No tunnel — configure LHOST/LPORT manually below.'}
              </span>
            </div>
            {(data.agentNgrokTunnelEnabled || data.agentChiselTunnelEnabled) ? (
              <p className={styles.toggleDescription} style={{ marginTop: 'var(--space-2)', padding: 'var(--space-2)', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-1)' }}>
                {data.agentNgrokTunnelEnabled && 'LHOST and LPORT are auto-detected from the ngrok tunnel. No manual configuration needed.'}
                {data.agentChiselTunnelEnabled && 'LHOST is derived from the VPS hostname. Both handler (4444) and web delivery (8080) ports are tunneled. No manual configuration needed.'}
              </p>
            ) : (
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
            )}
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

          {/* Fireteam (multi-agent) */}
          {(() => {
            const fireteamEnabled = (data as any).fireteamEnabled ?? true
            const maxConcurrent = (data as any).fireteamMaxConcurrent ?? 5
            const maxMembers = (data as any).fireteamMaxMembers ?? 5
            const memberMaxIter = (data as any).fireteamMemberMaxIterations ?? 20
            const timeoutSec = (data as any).fireteamTimeoutSec ?? 3600
            const propensity = (data as any).fireteamPropensity ?? 3
            const allowedPhasesRaw = (data as any).fireteamAllowedPhases ?? ['informational', 'exploitation', 'post_exploitation']
            const allowedPhases: string[] = Array.isArray(allowedPhasesRaw)
              ? allowedPhasesRaw
              : String(allowedPhasesRaw || '').split(',').map(s => s.trim()).filter(Boolean)
            const togglePhase = (phase: string) => {
              const next = allowedPhases.includes(phase)
                ? allowedPhases.filter(p => p !== phase)
                : [...allowedPhases, phase]
              if (next.length === 0) return // at least one phase required
              updateField('fireteamAllowedPhases' as any, next as any)
            }
            const crossError =
              fireteamEnabled && maxConcurrent > maxMembers
                ? 'Max concurrent cannot exceed max members'
                : null
            return (
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Fireteam (multi-agent)</h3>
                <div className={styles.fieldHint} style={{ marginBottom: 8 }}>
                  When on, the agent can deploy up to N specialist sub-agents in parallel on independent attack surfaces.
                  Parent stays in charge of safety approvals and phase transitions.
                </div>
                <div className={styles.toggleRow}>
                  <Toggle
                    checked={fireteamEnabled}
                    onChange={(v) => updateField('fireteamEnabled' as any, v as any)}
                    labelOn="Fireteam enabled"
                    labelOff="Fireteam disabled"
                  />
                </div>
                {fireteamEnabled && (
                  <>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Max concurrent members</label>
                        <input
                          type="number"
                          className="textInput"
                          value={maxConcurrent}
                          min={1}
                          max={8}
                          onChange={(e) => {
                            const v = Math.max(1, Math.min(8, parseInt(e.target.value) || 5))
                            updateField('fireteamMaxConcurrent' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>1-8. Upper limit on members in-flight at once.</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Max members per fireteam</label>
                        <input
                          type="number"
                          className="textInput"
                          value={maxMembers}
                          min={2}
                          max={8}
                          onChange={(e) => {
                            const v = Math.max(2, Math.min(8, parseInt(e.target.value) || 5))
                            updateField('fireteamMaxMembers' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>2-8. Hard cap on fireteam size the LLM can request.</span>
                      </div>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Per-member max iterations</label>
                        <input
                          type="number"
                          className="textInput"
                          value={memberMaxIter}
                          min={5}
                          max={50}
                          onChange={(e) => {
                            const v = Math.max(5, Math.min(50, parseInt(e.target.value) || 20))
                            updateField('fireteamMemberMaxIterations' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>5-50. Each member's ReAct budget before it exits.</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Wave timeout (seconds)</label>
                        <input
                          type="number"
                          className="textInput"
                          value={timeoutSec}
                          min={60}
                          max={7200}
                          onChange={(e) => {
                            const v = Math.max(60, Math.min(7200, parseInt(e.target.value) || 1800))
                            updateField('fireteamTimeoutSec' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>60-7200. Hard wall-clock ceiling for the whole fireteam.</span>
                      </div>
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Allowed phases</label>
                      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                        {(['informational', 'exploitation', 'post_exploitation'] as const).map(p => (
                          <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <input
                              type="checkbox"
                              checked={allowedPhases.includes(p)}
                              onChange={() => togglePhase(p)}
                            />
                            <span style={{ fontSize: '0.85rem' }}>{p}</span>
                          </label>
                        ))}
                      </div>
                      <span className={styles.fieldHint}>
                        Phases in which the agent may deploy fireteams. Recon (informational) is safe; exploitation/post-exploitation are deeper and usually serial.
                      </span>
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>
                        Fireteam propensity: <strong>{propensity}/5</strong>
                      </label>
                      <input
                        type="range"
                        min={1}
                        max={5}
                        step={1}
                        value={propensity}
                        onChange={(e) => {
                          const v = Math.max(1, Math.min(5, parseInt(e.target.value) || 3))
                          updateField('fireteamPropensity' as any, v as any)
                        }}
                        style={{ width: '100%' }}
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted, #888)', marginTop: 2 }}>
                        <span>1 - only very complex tasks</span>
                        <span>3 - balanced (default)</span>
                        <span>5 - deploy aggressively</span>
                      </div>
                      <span className={styles.fieldHint}>
                        How strongly the agent leans toward deploying a fireteam over single-agent or plan_tools. Injected into the system prompt as a directive the LLM must follow.
                      </span>
                    </div>
                    {crossError && (
                      <div className={styles.shodanWarning} style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)' }}>
                        <AlertTriangle size={14} style={{ color: '#ef4444' }} />
                        <span>{crossError}</span>
                      </div>
                    )}
                  </>
                )}
              </div>
            )
          })()}

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
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Plan Max Parallel Tools</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.agentPlanMaxParallelTools ?? 10}
                  onChange={(e) => updateField('agentPlanMaxParallelTools', parseInt(e.target.value) || 10)}
                  min={1}
                  max={50}
                />
                <span className={styles.fieldHint}>Concurrent tools per plan wave (root + fireteam); extras queue</span>
              </div>
            </div>
          </div>

          {/* Approval Gates */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Approval Gates</h3>

            {(!data.agentRequireApprovalForExploitation || !data.agentRequireApprovalForPostExploitation || !(data.agentGuardrailEnabled ?? true) || !(data.agentRequireToolConfirmation ?? true)) && (
              <div className={styles.shodanWarning} style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)' }}>
                <AlertTriangle size={14} style={{ color: '#ef4444' }} />
                <span>
                  <strong>Autonomous operation risk:</strong> One or more safety gates are disabled.
                  The AI agent may perform exploitation, post-exploitation, dangerous tool executions, or out-of-scope actions without human approval.
                  This significantly increases the risk of unintended damage to target systems.
                  You assume full responsibility for all autonomous agent actions.
                  See <a href="https://github.com/samugit83/redamon/blob/master/DISCLAIMER.md" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit', textDecoration: 'underline' }}>DISCLAIMER.md</a> for details.
                </span>
              </div>
            )}

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
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Require Tool Confirmation</span>
                <p className={styles.toggleDescription}>
                  Manual confirmation before executing dangerous tools
                  (nmap, nuclei, metasploit, hydra, kali shell, etc.).
                </p>
              </div>
              <Toggle
                checked={data.agentRequireToolConfirmation ?? true}
                onChange={(checked) => updateField('agentRequireToolConfirmation', checked)}
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Agent Guardrail</span>
                <p className={styles.toggleDescription}>
                  Verify target authorization on session start and enforce scope restrictions
                  in the agent&apos;s prompt. Blocks the agent from operating against well-known
                  public targets and prevents out-of-scope actions.
                  Government, military, educational, and international organization domains
                  (.gov, .mil, .edu, .int) are always blocked regardless of this setting.
                </p>
              </div>
              <Toggle
                checked={data.agentGuardrailEnabled ?? true}
                onChange={(checked) => updateField('agentGuardrailEnabled', checked)}
              />
            </div>
          </div>

          {/* Kali Shell — Library Installation */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Kali Shell — Library Installation</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Allow Library Installation</span>
                <p className={styles.toggleDescription}>Let the agent install packages (pip/apt) in kali_shell during a pentest. Installed packages are ephemeral — lost on container restart.</p>
              </div>
              <Toggle
                checked={data.agentKaliInstallEnabled}
                onChange={(checked) => updateField('agentKaliInstallEnabled', checked)}
              />
            </div>
            {data.agentKaliInstallEnabled && (
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Authorized Packages</label>
                  <textarea
                    className="textInput"
                    value={data.agentKaliInstallAllowedPackages}
                    onChange={(e) => updateField('agentKaliInstallAllowedPackages', e.target.value)}
                    rows={2}
                    placeholder="e.g. pyftpdlib, scapy, droopescan"
                  />
                  <span className={styles.fieldHint}>Comma-separated whitelist. If non-empty, ONLY these packages can be installed.</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Forbidden Packages</label>
                  <textarea
                    className="textInput"
                    value={data.agentKaliInstallForbiddenPackages}
                    onChange={(e) => updateField('agentKaliInstallForbiddenPackages', e.target.value)}
                    rows={2}
                    placeholder="e.g. metasploit-framework, cobalt-strike"
                  />
                  <span className={styles.fieldHint}>Comma-separated blacklist. These packages must NEVER be installed.</span>
                </div>
              </div>
            )}
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

        </div>
      )}
    </div>
  )
}

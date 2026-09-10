'use client'

import { useState } from 'react'
import { ChevronDown, Bot, AlertTriangle } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { REGEX_IPV4 } from '@/lib/validation'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface AgentBehaviourSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  /** Docker host's LAN IP (from useDetectedHostIp), suggested as LHOST. Issue #180. */
  detectedHostIp?: string
}

export function AgentBehaviourSection({ data, updateField, detectedHostIp }: AgentBehaviourSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Bot size={16} />
          Agent Behaviour
          <WikiInfoButton target="AgentBehaviour" />
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
                <ModelPicker
                  userId={userId}
                  value={data.agentOpenaiModel}
                  onChange={(id) => updateField('agentOpenaiModel', id)}
                />
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
                <option value="ngrok">ngrok (single port - free, no VPS needed)</option>
                <option value="chisel">chisel (multi-port - requires VPS)</option>
              </select>
              <span className={styles.fieldHint}>
                {data.agentNgrokTunnelEnabled && 'Configure ngrok auth token in Global Settings → Tunneling. Tunnels port 4444 only (handler). Stageless payloads required. Web delivery / HTA not supported.'}
                {data.agentChiselTunnelEnabled && 'Configure chisel server URL in Global Settings → Tunneling. Requires a chisel server running on your VPS. Tunnels ports 4444 (handler) + 8080 (web delivery). Stageless payloads required.'}
                {!data.agentNgrokTunnelEnabled && !data.agentChiselTunnelEnabled && 'No tunnel - configure LHOST/LPORT manually below.'}
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
                    placeholder="e.g. 192.168.1.50"
                  />
                  <span className={styles.fieldHint}>Your host machine&apos;s LAN IP that the target can reach (not the container&apos;s 172.x address). Leave empty for bind mode.</span>
                  {detectedHostIp && REGEX_IPV4.test(detectedHostIp) && detectedHostIp !== data.agentLhost && (
                    <span className={styles.suggestionRow}>
                      Detected (default route): {detectedHostIp}
                      <button
                        type="button"
                        className={styles.suggestionButton}
                        onClick={() => updateField('agentLhost', detectedHostIp)}
                      >
                        Use this
                      </button>
                    </span>
                  )}
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
            const memberMaxIter = (data as any).fireteamMemberMaxIterations ?? 10
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
                            // Pass raw value (string or NaN) through during typing.
                            // Clamping on every keystroke makes it impossible to enter
                            // multi-digit numbers - e.g. typing `15` clamps `1` to `2`
                            // before the user can finish.
                            const raw = e.target.value
                            updateField('fireteamMaxConcurrent' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(1, Math.min(8, n)) : 5
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
                            const raw = e.target.value
                            updateField('fireteamMaxMembers' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(2, Math.min(8, n)) : 5
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
                            const raw = e.target.value
                            updateField('fireteamMemberMaxIterations' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(5, Math.min(50, n)) : 10
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
                            const raw = e.target.value
                            updateField('fireteamTimeoutSec' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(60, Math.min(7200, n)) : 1800
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

          {/* Exploit-Path Search (LATS) */}
          {(() => {
            const latsEnabled = (data as any).agentLatsEnabled ?? false
            const shadowMode = (data as any).agentLatsShadowMode ?? false
            const phaseExpl = (data as any).agentLatsPhaseExploitation ?? true
            const phasePostExpl = (data as any).agentLatsPhasePostExpl ?? false
            const maxRollouts = (data as any).agentLatsMaxRollouts ?? 50
            const maxDepth = (data as any).agentLatsMaxDepth ?? 6
            const branching = (data as any).agentLatsBranching ?? 6
            const minHypotheses = (data as any).agentLatsMinHypotheses ?? 2
            const maxTreeNodes = (data as any).agentLatsMaxTreeNodes ?? 120
            const uctC = (data as any).agentLatsUctC ?? 1.4
            const pruneFloor = (data as any).agentLatsPruneFloor ?? 0.15
            const noPhase = latsEnabled && !phaseExpl && !phasePostExpl
            return (
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>
                  Exploit-Path Search (LATS)
                  <WikiInfoButton target="Lats" />
                </h3>
                <div className={styles.fieldHint} style={{ marginBottom: 8 }}>
                  Systematic tree search over exploit probes. Turns on only when the agent finds &gt;= 2 credible
                  attack paths on a discovered surface, then concentrates the budget on the highest-value line and
                  backs out of WAF/403 dead ends.
                </div>
                <div className={styles.toggleRow}>
                  <Toggle
                    checked={latsEnabled}
                    onChange={(v) => updateField('agentLatsEnabled' as any, v as any)}
                    labelOn="Exploit-Path Search enabled"
                    labelOff="Exploit-Path Search disabled"
                  />
                </div>
                {latsEnabled && (
                  <>
                    {shadowMode && (
                      <div className={styles.shodanWarning} style={{ borderColor: 'rgba(59, 130, 246, 0.4)', background: 'rgba(59, 130, 246, 0.08)' }}>
                        <span>Observe-only mode: the search tree is built and visualized but the normal agent drives the actual probes.</span>
                      </div>
                    )}
                    <div className={styles.toggleRow}>
                      <Toggle
                        checked={shadowMode}
                        onChange={(v) => updateField('agentLatsShadowMode' as any, v as any)}
                        labelOn="Shadow mode (observe only)"
                        labelOff="Shadow mode off (search drives)"
                      />
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Search in phases</label>
                      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <input
                            type="checkbox"
                            checked={phaseExpl}
                            onChange={(e) => updateField('agentLatsPhaseExploitation' as any, e.target.checked as any)}
                          />
                          <span style={{ fontSize: '0.85rem' }}>exploitation</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <input
                            type="checkbox"
                            checked={phasePostExpl}
                            onChange={(e) => updateField('agentLatsPhasePostExpl' as any, e.target.checked as any)}
                          />
                          <span style={{ fontSize: '0.85rem' }}>post-exploitation <em>(experimental)</em></span>
                        </label>
                      </div>
                      <span className={styles.fieldHint}>At least one phase required. Post-exploitation scoring is experimental (§6.1).</span>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Search budget (max live probes)</label>
                        <input
                          type="number"
                          className="textInput"
                          value={maxRollouts}
                          min={4}
                          max={300}
                          onChange={(e) => {
                            const raw = e.target.value
                            updateField('agentLatsMaxRollouts' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(4, Math.min(300, n)) : 50
                            updateField('agentLatsMaxRollouts' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>
                          4-300. Hard cap on real requests one search fires. Worst case: up to {maxRollouts} live probes, chains up to {maxDepth} deep.
                        </span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Max chain depth</label>
                        <input
                          type="number"
                          className="textInput"
                          value={maxDepth}
                          min={2}
                          max={10}
                          onChange={(e) => {
                            const raw = e.target.value
                            updateField('agentLatsMaxDepth' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(2, Math.min(10, n)) : 6
                            updateField('agentLatsMaxDepth' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>2-10. Longest attack chain from the entry point (a ceiling, not the typical depth).</span>
                      </div>
                    </div>
                    <div className={styles.fieldRow}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Branch width (probes per step)</label>
                        <input
                          type="number"
                          className="textInput"
                          value={branching}
                          min={2}
                          max={10}
                          onChange={(e) => {
                            const raw = e.target.value
                            updateField('agentLatsBranching' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(2, Math.min(10, n)) : 6
                            updateField('agentLatsBranching' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>2-10. Candidate probes weighed at each node.</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Activation sensitivity</label>
                        <input
                          type="number"
                          className="textInput"
                          value={minHypotheses}
                          min={2}
                          max={4}
                          onChange={(e) => {
                            const raw = e.target.value
                            updateField('agentLatsMinHypotheses' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(2, Math.min(4, n)) : 2
                            updateField('agentLatsMinHypotheses' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>2-4. Competing hypotheses needed before the search turns on. Higher = more selective.</span>
                      </div>
                    </div>
                    <details className={styles.fieldGroup}>
                      <summary style={{ cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>Advanced</summary>
                      <div className={styles.fieldGroup} style={{ marginTop: 8 }}>
                        <label className={styles.fieldLabel}>Exploration vs focus: <strong>{Number(uctC).toFixed(1)}</strong></label>
                        <input
                          type="range"
                          min={0.5}
                          max={2.5}
                          step={0.1}
                          value={uctC}
                          onChange={(e) => updateField('agentLatsUctC' as any, parseFloat(e.target.value) as any)}
                          style={{ width: '100%' }}
                        />
                        <span className={styles.fieldHint}>Low = laser-focus the single best line. High = also develop secondary footholds.</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Prune aggressiveness: <strong>{Number(pruneFloor).toFixed(2)}</strong></label>
                        <input
                          type="range"
                          min={0.0}
                          max={0.5}
                          step={0.05}
                          value={pruneFloor}
                          onChange={(e) => updateField('agentLatsPruneFloor' as any, parseFloat(e.target.value) as any)}
                          style={{ width: '100%' }}
                        />
                        <span className={styles.fieldHint}>Value below which a branch is abandoned. Higher = give up on weak branches sooner.</span>
                      </div>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>Hard node cap</label>
                        <input
                          type="number"
                          className="textInput"
                          value={maxTreeNodes}
                          min={10}
                          max={1000}
                          onChange={(e) => {
                            const raw = e.target.value
                            updateField('agentLatsMaxTreeNodes' as any, (raw === '' ? '' : parseInt(raw)) as any)
                          }}
                          onBlur={(e) => {
                            const n = parseInt(e.target.value)
                            const v = Number.isFinite(n) ? Math.max(10, Math.min(1000, n)) : 120
                            updateField('agentLatsMaxTreeNodes' as any, v as any)
                          }}
                        />
                        <span className={styles.fieldHint}>10-1000. Hard tree-size cap.</span>
                      </div>
                    </details>
                    {noPhase && (
                      <div className={styles.shodanWarning} style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)' }}>
                        <AlertTriangle size={14} style={{ color: '#ef4444' }} />
                        <span>Select at least one phase for the search to run.</span>
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

          {/* Kali Shell - Library Installation */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Kali Shell - Library Installation</h3>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Allow Library Installation</span>
                <p className={styles.toggleDescription}>Let the agent install packages (pip/apt) in kali_shell during a pentest. Installed packages are ephemeral - lost on container restart.</p>
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

'use client'

import React, { useEffect, useState } from 'react'
import { Wrench, Swords, Check, Settings, Server } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { useProject } from '@/providers/ProjectProvider'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import { PluginIcon } from '@/components/plugins/pluginIcons'
import { usePluginContributions } from '@/hooks/usePluginContributions'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import { errorMessage } from '@/lib/apiError'
import type { ChatSessionActionContribution } from '@/lib/plugins/contributions'
import type { ActionContext } from '@/components/plugins/host/actionClient'
import { PHASE_CONFIG, getAttackPathConfig, formatModelDisplay } from './phaseConfig'
import type { Phase } from './types'
import styles from './AIAssistantDrawer.module.css'

const ALL_PHASES = ['informational', 'exploitation', 'post_exploitation'] as const

interface SkillData {
  builtIn: Array<{ id: string; name: string }>
  user: Array<{ id: string; name: string }>
  config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}

interface UserMcpServer {
  id: string
  name?: string
  enabled?: boolean
  default_phases?: string[]
  tools?: Array<{ name: string; default_phases?: string[] | null }>
}

interface PhaseIndicatorBarProps {
  currentPhase: Phase
  toolPhaseMap?: Record<string, string[]>
  attackPathType: string
  skillData: SkillData | null
  iterationCount: number
  stealthMode: boolean
  onToggleStealth?: (v: boolean) => void
  settingsDropdownRef: React.RefObject<HTMLDivElement | null>
  showSettingsDropdown: boolean
  setShowSettingsDropdown: React.Dispatch<React.SetStateAction<boolean>>
  setSettingsModal: (v: 'agent' | 'toolmatrix' | 'attack' | null) => void
  modelName?: string
  setShowModelModal: (v: boolean) => void
  // Plugin chat-session actions (design §6.7). Nullable until the first message creates the
  // conversation; the items are disabled until then.
  projectId?: string | null
  sessionId?: string | null
  conversationId?: string | null
  onRunPluginAction?: (
    plugin: { pluginId: string; displayName: string },
    item: ChatSessionActionContribution,
    context: ActionContext,
  ) => void
}

export function PhaseIndicatorBar({
  currentPhase,
  toolPhaseMap,
  attackPathType,
  skillData,
  iterationCount,
  stealthMode,
  onToggleStealth,
  settingsDropdownRef,
  showSettingsDropdown,
  setShowSettingsDropdown,
  setSettingsModal,
  modelName,
  setShowModelModal,
  projectId,
  sessionId,
  conversationId,
  onRunPluginAction,
}: PhaseIndicatorBarProps) {
  const PhaseIcon = PHASE_CONFIG[currentPhase].icon
  const { userId } = useProject()
  // On a project the person does not own (step 5.7) the agent runs on the OWNER's MCP servers and
  // models: the tools tooltip lists the owner's servers, and the model badge needs Manage to open.
  const owner = useOwnerCatalogSource()
  const fromOwner = owner !== null
  const modelRefusal = owner?.pickRefusal ?? null
  const [ownMcpServers, setUserMcpServers] = useState<UserMcpServer[]>([])
  // The catalog answers a server stored without default phases as [], which means every phase there
  // (as in the tool matrix), so it is read here as a missing field.
  const userMcpServers: UserMcpServer[] = fromOwner
    ? (owner.catalog?.mcpServers ?? []).map(srv => ({ ...srv, default_phases: srv.default_phases.length ? srv.default_phases : undefined }))
    : ownMcpServers
  const { data: contributions, error: contributionsError, refetch: refetchContributions } = usePluginContributions()
  // Only plugins with a gear-menu action; a nav-only plugin adds nothing here.
  const pluginGroups = (contributions ?? []).filter((c) => c.chatSessionActions.length > 0)

  // Pull the user's saved MCP servers from the DB so MCP tools always
  // appear in the wrench tooltip - even when the user hasn't explicitly
  // toggled their phase checkboxes (in which case they're not in
  // toolPhaseMap and would otherwise be invisible).
  useEffect(() => {
    if (!userId || fromOwner) return
    fetch(`/api/users/${userId}/mcp`)
      .then(r => r.ok ? r.json() : null)
      .then((d: { servers?: UserMcpServer[] } | null) => {
        if (d?.servers && Array.isArray(d.servers)) {
          setUserMcpServers(d.servers)
        }
      })
      .catch(() => {})
  }, [userId, fromOwner])

  return (
    <div className={styles.phaseIndicator}>
      <div
        className={styles.phaseBadge}
        style={{
          backgroundColor: PHASE_CONFIG[currentPhase].bgColor,
          borderColor: PHASE_CONFIG[currentPhase].color,
        }}
      >
        <PhaseIcon size={14} style={{ color: PHASE_CONFIG[currentPhase].color }} />
        <span style={{ color: PHASE_CONFIG[currentPhase].color }}>
          {PHASE_CONFIG[currentPhase].label}
        </span>
      </div>

      {(() => {
        // Built-in (and explicitly toggled) tools - same logic as before.
        const builtInTools: string[] = toolPhaseMap
          ? Object.entries(toolPhaseMap)
              .filter(([, phases]) => phases.includes(currentPhase))
              .map(([name]) => name)
          : []

        // User MCP tools whose default_phases (with per-tool override) include
        // the current phase AND are NOT already in toolPhaseMap (which would
        // mean the user explicitly toggled them - project override wins).
        const explicitlyToggled = new Set(Object.keys(toolPhaseMap || {}))
        const mcpTools: Array<{ name: string; serverName: string }> = []
        for (const srv of userMcpServers) {
          if (srv.enabled === false) continue
          const serverDefault = srv.default_phases ?? [...ALL_PHASES]
          for (const t of (srv.tools || [])) {
            if (explicitlyToggled.has(t.name)) continue  // shown above
            const phases = (t.default_phases && t.default_phases.length > 0)
              ? t.default_phases
              : serverDefault
            if (phases.includes(currentPhase)) {
              mcpTools.push({ name: t.name, serverName: srv.name || srv.id })
            }
          }
        }

        if (builtInTools.length === 0 && mcpTools.length === 0) return null

        return (
          <Tooltip
            position="bottom"
            interactive
            content={
              <div className={styles.phaseToolsTooltip}>
                <div className={styles.phaseToolsHeader}>Phase Tools</div>
                {builtInTools.map(t => (
                  <div key={t} className={styles.phaseToolsItem}>{t}</div>
                ))}
                {mcpTools.length > 0 && (
                  <>
                    <div className={styles.phaseToolsHeader} style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid rgba(255,255,255,0.12)', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <Server size={10} /> MCP Tool Plugins
                    </div>
                    {mcpTools.map(t => (
                      <div key={t.name} className={styles.phaseToolsItem}>
                        {t.name}
                        <span style={{ marginLeft: 6, opacity: 0.55, fontSize: '10px' }}>{t.serverName}</span>
                      </div>
                    ))}
                  </>
                )}
              </div>
            }
          >
            <Wrench size={13} className={styles.phaseToolsIcon} />
          </Tooltip>
        )
      })()}

      {attackPathType && (currentPhase === 'informational' || currentPhase === 'exploitation' || currentPhase === 'post_exploitation') && (
        <Tooltip
          position="bottom"
          interactive
          content={
            <div className={styles.skillTooltip}>
              <div className={styles.skillTooltipHeader}>
                <Swords size={11} />
                Agent Skills
              </div>
              {skillData && (
                <>
                  <div className={styles.skillTooltipGroup}>
                    <div className={styles.skillTooltipGroupLabel}>Built-in</div>
                    {skillData.builtIn.map(s => {
                      // The agent's rule: a built-in skill is on only when its key says so.
                      const enabled = skillData.config.builtIn[s.id] === true
                      const isActive = attackPathType === s.id
                      return (
                        <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                          <span className={styles.skillTooltipName}>{s.name}</span>
                          {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                          {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
                        </div>
                      )
                    })}
                  </div>
                  {/* Only the skills this project turned on (a missing toggle is off, as the
                      agent reads it): a user may have hundreds. */}
                  {skillData.user.some(s => skillData.config.user[s.id] === true) && (
                    <div className={styles.skillTooltipGroup}>
                      <div className={styles.skillTooltipGroupLabel}>User Skills</div>
                      {skillData.user.filter(s => skillData.config.user[s.id] === true).map(s => {
                        const isActive = attackPathType === `user_skill:${s.id}`
                        return (
                          <div key={s.id} className={`${styles.skillTooltipItem} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                            <span className={styles.skillTooltipName}>{s.name}</span>
                            {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </>
              )}
            </div>
          }
        >
          <div
            className={styles.phaseBadge}
            style={{
              backgroundColor: getAttackPathConfig(attackPathType).bgColor,
              borderColor: getAttackPathConfig(attackPathType).color,
            }}
          >
            <span style={{ color: getAttackPathConfig(attackPathType).color }}>
              {getAttackPathConfig(attackPathType).shortLabel}
            </span>
          </div>
        </Tooltip>
      )}

      {iterationCount > 0 && (
        <span className={styles.iterationCount}>Step {iterationCount}</span>
      )}

      {onToggleStealth ? (
        <button
          className={`${styles.stealthToggle} ${stealthMode ? styles.stealthToggleActive : ''}`}
          onClick={() => onToggleStealth(!stealthMode)}
          title={stealthMode
            ? 'Stealth Mode ON - click to disable'
            : 'Stealth Mode OFF - click to enable passive-only techniques'
          }
        >
          <StealthIcon size={11} />
        </button>
      ) : stealthMode ? (
        <span className={styles.stealthBadge} title="Stealth Mode - passive/low-noise techniques only">
          <StealthIcon size={11} />
        </span>
      ) : null}

      <div className={styles.settingsWrapper} ref={settingsDropdownRef}>
        <button
          className={styles.settingsButton}
          onClick={() => setShowSettingsDropdown(prev => !prev)}
          title="Agent settings"
        >
          <Settings size={12} />
        </button>
        {showSettingsDropdown && (
          <div className={styles.settingsDropdown}>
            <button
              className={styles.settingsDropdownItem}
              onClick={() => { setSettingsModal('agent'); setShowSettingsDropdown(false) }}
            >
              Agent Behaviour
            </button>
            <button
              className={styles.settingsDropdownItem}
              onClick={() => { setSettingsModal('toolmatrix'); setShowSettingsDropdown(false) }}
            >
              Tool Matrix
            </button>
            <button
              className={styles.settingsDropdownItem}
              onClick={() => { setSettingsModal('attack'); setShowSettingsDropdown(false) }}
            >
              Agent Skills
            </button>

            {!contributions && contributionsError && (
              <div className={styles.pluginGroup} role="status" data-testid="plugin-items-error">
                <div className={styles.pluginGroupLabel}>
                  <span className={styles.pluginUpdating}>{errorMessage(contributionsError, 'Plugin items could not be loaded')}</span>
                </div>
                <button
                  className={`${styles.settingsDropdownItem} ${styles.pluginItem}`}
                  onClick={() => void refetchContributions()}
                >
                  Retry
                </button>
              </div>
            )}

            {pluginGroups.map((plugin) => (
              <div key={plugin.pluginId} className={styles.pluginGroup}>
                <div className={styles.pluginGroupLabel}>
                  <PluginBadge label={plugin.displayName} />
                  {plugin.updating && <span className={styles.pluginUpdating}>updating</span>}
                </div>
                {plugin.chatSessionActions.map((item) => (
                  <button
                    key={item.key}
                    className={`${styles.settingsDropdownItem} ${styles.pluginItem}`}
                    disabled={!conversationId}
                    title={conversationId ? undefined : 'Send a message first'}
                    onClick={() => {
                      onRunPluginAction?.(
                        { pluginId: plugin.pluginId, displayName: plugin.displayName },
                        item,
                        { projectId: projectId ?? null, sessionId: sessionId ?? null },
                      )
                      setShowSettingsDropdown(false)
                    }}
                  >
                    <PluginIcon name={item.icon} size={12} aria-hidden className={styles.pluginItemIcon} />
                    {item.label}
                  </button>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>

      {modelName && (
        <button
          className={styles.modelBadge}
          onClick={() => { if (!modelRefusal) setShowModelModal(true) }}
          aria-disabled={modelRefusal ? true : undefined}
          title={modelRefusal ?? undefined}
          style={modelRefusal ? { cursor: 'not-allowed', opacity: 0.7 } : undefined}
        >
          {formatModelDisplay(modelName)}
        </button>
      )}
    </div>
  )
}

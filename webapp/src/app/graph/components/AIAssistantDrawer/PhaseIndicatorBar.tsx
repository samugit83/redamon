'use client'

import React from 'react'
import { Wrench, Swords, Check, Settings, Lightbulb } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { PHASE_CONFIG, getAttackPathConfig, formatModelDisplay } from './phaseConfig'
import type { Phase } from './types'
import styles from './AIAssistantDrawer.module.css'

interface SkillData {
  builtIn: Array<{ id: string; name: string }>
  user: Array<{ id: string; name: string }>
  config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}

interface PhaseIndicatorBarProps {
  currentPhase: Phase
  toolPhaseMap?: Record<string, string[]>
  attackPathType: string
  skillData: SkillData | null
  iterationCount: number
  stealthMode: boolean
  onToggleStealth?: (v: boolean) => void
  deepThinkEnabled: boolean
  onToggleDeepThink?: (v: boolean) => void
  settingsDropdownRef: React.RefObject<HTMLDivElement | null>
  showSettingsDropdown: boolean
  setShowSettingsDropdown: React.Dispatch<React.SetStateAction<boolean>>
  setSettingsModal: (v: 'agent' | 'toolmatrix' | 'attack' | null) => void
  modelName?: string
  setShowModelModal: (v: boolean) => void
}

export function PhaseIndicatorBar({
  currentPhase,
  toolPhaseMap,
  attackPathType,
  skillData,
  iterationCount,
  stealthMode,
  onToggleStealth,
  deepThinkEnabled,
  onToggleDeepThink,
  settingsDropdownRef,
  showSettingsDropdown,
  setShowSettingsDropdown,
  setSettingsModal,
  modelName,
  setShowModelModal,
}: PhaseIndicatorBarProps) {
  const PhaseIcon = PHASE_CONFIG[currentPhase].icon

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

      {toolPhaseMap && (() => {
        const phaseTools = Object.entries(toolPhaseMap)
          .filter(([, phases]) => phases.includes(currentPhase))
          .map(([name]) => name)
        return phaseTools.length > 0 ? (
          <Tooltip
            position="bottom"
            content={
              <div className={styles.phaseToolsTooltip}>
                <div className={styles.phaseToolsHeader}>Phase Tools</div>
                {phaseTools.map(t => (
                  <div key={t} className={styles.phaseToolsItem}>{t}</div>
                ))}
              </div>
            }
          >
            <Wrench size={13} className={styles.phaseToolsIcon} />
          </Tooltip>
        ) : null
      })()}

      {attackPathType && (currentPhase === 'informational' || currentPhase === 'exploitation' || currentPhase === 'post_exploitation') && (
        <Tooltip
          position="bottom"
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
                      const enabled = skillData.config.builtIn[s.id] !== false
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
                  {skillData.user.length > 0 && (
                    <div className={styles.skillTooltipGroup}>
                      <div className={styles.skillTooltipGroupLabel}>User Skills</div>
                      {skillData.user.map(s => {
                        const enabled = skillData.config.user[s.id] !== false
                        const isActive = attackPathType === `user_skill:${s.id}`
                        return (
                          <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                            <span className={styles.skillTooltipName}>{s.name}</span>
                            {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                            {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
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
            ? 'Stealth Mode ON — click to disable'
            : 'Stealth Mode OFF — click to enable passive-only techniques'
          }
        >
          <StealthIcon size={11} />
        </button>
      ) : stealthMode ? (
        <span className={styles.stealthBadge} title="Stealth Mode — passive/low-noise techniques only">
          <StealthIcon size={11} />
        </span>
      ) : null}

      {onToggleDeepThink ? (
        <button
          className={`${styles.deepThinkToggle} ${deepThinkEnabled ? styles.deepThinkToggleActive : ''}`}
          onClick={() => onToggleDeepThink(!deepThinkEnabled)}
          title={deepThinkEnabled
            ? 'Deep Think ON — the agent performs strategic reasoning at key decision points (start, phase transitions, failure loops) before acting. Click to disable.'
            : 'Deep Think OFF — click to enable strategic reasoning at key decision points. Adds ~1 extra LLM call at start, phase transitions, and failure loops to plan multi-step strategies.'
          }
        >
          <Lightbulb size={11} />
        </button>
      ) : deepThinkEnabled ? (
        <span className={styles.deepThinkBadge} title="Deep Think — strategic reasoning at key decision points">
          <Lightbulb size={11} />
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
          </div>
        )}
      </div>

      {modelName && (
        <button className={styles.modelBadge} onClick={() => setShowModelModal(true)}>
          {formatModelDisplay(modelName)}
        </button>
      )}
    </div>
  )
}

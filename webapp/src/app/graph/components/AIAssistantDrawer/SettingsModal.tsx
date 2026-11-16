'use client'

import React from 'react'
import { X, Loader2, AlertCircle } from 'lucide-react'
import { AgentBehaviourSection } from '@/components/projects/ProjectForm/sections/AgentBehaviourSection'
import { AttackSkillsSection } from '@/components/projects/ProjectForm/sections/AttackSkillsSection'
import { ToolMatrixSection } from '@/components/projects/ProjectForm/sections/ToolMatrixSection'
import { TAB_LABEL_V2, useTradecraftV2 } from '@/components/projects/ProjectForm/sections/TradecraftResourcesAccordion'
import type { ProjectFormData } from './hooks/useSettingsModal'
import { useDetectedHostIp } from '@/hooks/useDetectedHostIp'
import styles from './AIAssistantDrawer.module.css'

interface SettingsModalProps {
  settingsModal: 'agent' | 'toolmatrix' | 'attack' | null
  setSettingsModal: (v: 'agent' | 'toolmatrix' | 'attack' | null) => void
  projectFormData: ProjectFormData | null
  updateProjectField: (field: any, value: any) => void
  /** The chat is always for a saved project; passed so Agent Skills shows plugin version controls. */
  projectId?: string | null
  /** The project could not be read; shown in place of the spinner. */
  loadError?: string | null
}

export function SettingsModal({
  settingsModal,
  setSettingsModal,
  projectFormData,
  updateProjectField,
  projectId,
  loadError,
}: SettingsModalProps) {
  // Suggested LHOST for the Agent Behaviour form (issue #180). Fetch only while the
  // agent modal is open; refetches each open so it tracks the last `redamon.sh up`.
  const detectedHostIp = useDetectedHostIp(settingsModal === 'agent')
  // The window takes the new name only when the project owner has Tradecraft 2.0 on (§3.4).
  const tradecraftV2 = useTradecraftV2(settingsModal === 'attack' ? projectId ?? null : null)
  if (!settingsModal) return null

  return (
    <div className={styles.settingsModalOverlay} onClick={() => setSettingsModal(null)}>
      <div className={styles.settingsModal} onClick={e => e.stopPropagation()}>
        <div className={styles.settingsModalHeader}>
          <h2 className={styles.settingsModalTitle}>
            {settingsModal === 'agent' ? 'Agent Behaviour' : settingsModal === 'toolmatrix' ? 'Tool Matrix' : tradecraftV2 ? TAB_LABEL_V2 : 'Agent Skills'}
          </h2>
          <button className={styles.settingsModalClose} onClick={() => setSettingsModal(null)}>
            <X size={16} />
          </button>
        </div>
        <div className={styles.settingsModalBody}>
          {projectFormData ? (
            settingsModal === 'agent' ? (
              <AgentBehaviourSection data={projectFormData} updateField={updateProjectField} detectedHostIp={detectedHostIp} />
            ) : settingsModal === 'toolmatrix' ? (
              <ToolMatrixSection data={projectFormData} updateField={updateProjectField} />
            ) : (
              <AttackSkillsSection data={projectFormData} updateField={updateProjectField} projectId={projectId} inDrawer />
            )
          ) : loadError ? (
            <div role="alert" style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', padding: '2rem', color: 'var(--status-error, #ef4444)' }}>
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
              <span>{loadError}</span>
            </div>
          ) : (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
              <Loader2 size={24} className={styles.spinner} />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

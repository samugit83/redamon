'use client'

import React from 'react'
import { X, Loader2 } from 'lucide-react'
import { AgentBehaviourSection } from '@/components/projects/ProjectForm/sections/AgentBehaviourSection'
import { AttackSkillsSection } from '@/components/projects/ProjectForm/sections/AttackSkillsSection'
import { ToolMatrixSection } from '@/components/projects/ProjectForm/sections/ToolMatrixSection'
import type { ProjectFormData } from './hooks/useSettingsModal'
import styles from './AIAssistantDrawer.module.css'

interface SettingsModalProps {
  settingsModal: 'agent' | 'toolmatrix' | 'attack' | null
  setSettingsModal: (v: 'agent' | 'toolmatrix' | 'attack' | null) => void
  projectFormData: ProjectFormData | null
  updateProjectField: (field: any, value: any) => void
}

export function SettingsModal({
  settingsModal,
  setSettingsModal,
  projectFormData,
  updateProjectField,
}: SettingsModalProps) {
  if (!settingsModal) return null

  return (
    <div className={styles.settingsModalOverlay} onClick={() => setSettingsModal(null)}>
      <div className={styles.settingsModal} onClick={e => e.stopPropagation()}>
        <div className={styles.settingsModalHeader}>
          <h2 className={styles.settingsModalTitle}>
            {settingsModal === 'agent' ? 'Agent Behaviour' : settingsModal === 'toolmatrix' ? 'Tool Matrix' : 'Agent Skills'}
          </h2>
          <button className={styles.settingsModalClose} onClick={() => setSettingsModal(null)}>
            <X size={16} />
          </button>
        </div>
        <div className={styles.settingsModalBody}>
          {projectFormData ? (
            settingsModal === 'agent' ? (
              <AgentBehaviourSection data={projectFormData} updateField={updateProjectField} />
            ) : settingsModal === 'toolmatrix' ? (
              <ToolMatrixSection data={projectFormData} updateField={updateProjectField} />
            ) : (
              <AttackSkillsSection data={projectFormData} updateField={updateProjectField} />
            )
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

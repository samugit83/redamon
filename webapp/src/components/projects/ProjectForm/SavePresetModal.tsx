'use client'

import { useState, useEffect } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { extractPresetSettings } from '@/lib/project-preset-utils'
import { useToast } from '@/components/ui'
import styles from './ProjectForm.module.css'

interface SavePresetModalProps {
  isOpen: boolean
  onClose: () => void
  formData: Record<string, unknown>
  userId: string | null | undefined
}

export function SavePresetModal({ isOpen, onClose, formData, userId }: SavePresetModalProps) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Reset fields when modal opens
  useEffect(() => {
    if (isOpen) {
      setName('')
      setDescription('')
    }
  }, [isOpen])

  const handleSave = async () => {
    if (!name.trim()) return
    if (!userId) {
      toast.error('User not found')
      return
    }

    setIsSaving(true)
    try {
      const settings = extractPresetSettings(formData)

      const res = await fetch('/api/presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, name, description, settings }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save preset')
      }

      toast.success(`Preset "${name.trim()}" saved`, 'Preset Saved')
      onClose()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to save preset')
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Save as Preset"
      closeOnOverlayClick={false}
      closeOnEscape={false}
      footer={
        <>
          <button
            type="button"
            className="secondaryButton"
            onClick={onClose}
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            type="button"
            className="primaryButton"
            onClick={handleSave}
            disabled={isSaving || !name.trim()}
          >
            {isSaving ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Saving...
              </>
            ) : (
              'Save Preset'
            )}
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <div>
          <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
            Name
          </label>
          <input
            type="text"
            className="textInput"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. My aggressive scan config"
            autoFocus
          />
        </div>
        <div>
          <label className={styles.fieldLabel}>
            Description
          </label>
          <textarea
            className="textarea"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description for this preset"
            rows={3}
          />
        </div>
      </div>
    </Modal>
  )
}

'use client'

import { useEffect, useRef, useState } from 'react'
import { Modal } from '@/components/ui'
import styles from './NodeAgentModal.module.css'

interface NodeAgentModalProps {
  isOpen: boolean
  nodeLabel: string
  onClose: () => void
  onSubmit: (request: string) => void
}

export function NodeAgentModal({ isOpen, nodeLabel, onClose, onSubmit }: NodeAgentModalProps) {
  const [request, setRequest] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Each opening starts from an empty request.
  const [wasOpen, setWasOpen] = useState(isOpen)
  if (wasOpen !== isOpen) {
    setWasOpen(isOpen)
    if (isOpen) setRequest('')
  }

  useEffect(() => {
    if (isOpen) {
      // Modal mounts via portal; focus after it paints.
      const t = setTimeout(() => textareaRef.current?.focus(), 50)
      return () => clearTimeout(t)
    }
  }, [isOpen])

  const trimmed = request.trim()

  const submit = () => {
    if (!trimmed) return
    onSubmit(trimmed)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault()
      submit()
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Start an agent session from this node"
      size="default"
      closeOnOverlayClick={false}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={onClose}>Cancel</button>
          <button type="button" className="primaryButton" onClick={submit} disabled={!trimmed}>
            Start session
          </button>
        </>
      }
    >
      <p className={styles.intro}>
        Opens a fresh agent session focused on{' '}
        <span className={styles.nodeLabel}>{nodeLabel}</span>. Your request is sent as
        the first message, together with the node&apos;s full context and its
        relationships in the graph.
      </p>
      <label className={styles.fieldLabel} htmlFor="node-agent-request">
        What should the agent do?
      </label>
      <textarea
        id="node-agent-request"
        ref={textareaRef}
        className="textarea"
        value={request}
        onChange={(e) => setRequest(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="e.g. Assess whether this endpoint is exploitable and suggest next steps"
        rows={5}
      />
      <p className={styles.hint}>Ctrl/⌘ + Enter to start</p>
    </Modal>
  )
}

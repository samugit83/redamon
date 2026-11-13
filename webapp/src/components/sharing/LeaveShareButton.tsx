'use client'

import { useState } from 'react'
import { LogOut } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { errorMessage, fetchOk } from '@/lib/apiError'

interface LeaveShareButtonProps {
  project: { id: string; name: string }
  /** After the share is gone: read the list again, or ask the open project's access at once. */
  onLeft: () => void
  /** A toast of its own; off for the open project, whose access check then says the access ended. */
  announce?: boolean
  className?: string
}

/**
 * Leave (step 4.12, SH-10): a collaborator gives up their own share of a project, after confirming
 * through useAlertModal, with POST .../leave (4.4: same-origin JSON, refused under act-as). Its click
 * never reaches a clickable card around it.
 */
export function LeaveShareButton({ project, onLeft, announce = true, className = 'iconButton' }: LeaveShareButtonProps) {
  const { dangerConfirm, alertError } = useAlertModal()
  const toast = useToast()
  const [pending, setPending] = useState(false)

  const leave = async () => {
    if (pending) return
    const ok = await dangerConfirm(
      `You lose access to "${project.name}" now. Only its owner can share it with you again.`,
      'Leave project',
      { confirmLabel: 'Leave' },
    )
    if (!ok) return
    setPending(true)
    try {
      await fetchOk(`/api/projects/${encodeURIComponent(project.id)}/leave`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, 'Could not leave the project')
    } catch (err) {
      setPending(false)
      await alertError(errorMessage(err, 'Could not leave the project'))
      return
    }
    setPending(false)
    if (announce) toast.success(`You left "${project.name}".`)
    onLeft()
  }

  return (
    <button
      type="button"
      className={className}
      title="Leave this project"
      aria-label={`Leave ${project.name}`}
      disabled={pending}
      onClick={(e) => {
        e.stopPropagation()
        void leave()
      }}
    >
      <LogOut size={14} />
    </button>
  )
}

export default LeaveShareButton

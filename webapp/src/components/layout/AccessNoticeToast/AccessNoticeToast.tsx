'use client'

import { useEffect } from 'react'
import { useToast } from '@/components/ui'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { accessBadge } from '@/lib/sharedProjects'

/**
 * Shows what the stale-access poll found (ProjectProvider, step 4.11) as a toast, once: the provider
 * sits above the toast layer, so this sits under it. Renders nothing.
 */
export function AccessNoticeToast() {
  const project = useOptionalProject()
  const toast = useToast()
  const notice = project?.accessNotice ?? null
  const dismiss = project?.dismissAccessNotice

  useEffect(() => {
    if (!notice || !dismiss) return
    if (notice.kind === 'ended') {
      toast.warning(
        `Your access to "${notice.projectName}" has ended: the share was revoked or expired, or you left it.`,
        'Access ended',
      )
    } else if (notice.myAccess) {
      toast.info(`Your access to "${notice.projectName}" is now ${accessBadge(notice.myAccess)}.`, 'Access changed')
    }
    dismiss()
  }, [notice, dismiss, toast])

  return null
}

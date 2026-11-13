'use client'

import { useCallback } from 'react'
import { useToast } from '@/components/ui'
import { toApiError } from '@/lib/apiError'
import { STALE_FIELD_NOTICE, reloadProjectRow, saveProjectFields } from '@/lib/projectFieldSave'
import { toProjectSummary, type ProjectRead, type ProjectSummary } from '@/lib/projectSummary'

/** The project fields the graph page saves one at a time. */
export type HeaderProjectField = 'stealthMode' | 'agentOpenaiModel'

/**
 * One field of the open project saved from the graph page (stealth mode, the agent model), with the
 * row's version as the header last read it (step 5.2, SH-40): a value someone else changed since is
 * refused, and the header then takes the row as it is now instead of overwriting it. A saved field
 * moves the header's version forward, so the next save is not refused for this one.
 */
export function useProjectFieldSave(
  projectId: string | null | undefined,
  currentProject: ProjectSummary | null,
  setCurrentProject: (project: ProjectSummary | null) => void,
): (field: HeaderProjectField, value: boolean | string, failure: string) => Promise<void> {
  const toast = useToast()
  return useCallback(async (field, value, failure) => {
    if (!projectId) return
    try {
      const saved = await saveProjectFields(projectId, { [field]: value }, currentProject?.updatedAt, failure)
      if (!saved.ok) {
        toast.warning(STALE_FIELD_NOTICE)
        const row = await reloadProjectRow(projectId)
        if (row) setCurrentProject(toProjectSummary(row as unknown as ProjectRead))
        return
      }
      if (currentProject) {
        setCurrentProject({ ...currentProject, [field]: value, ...(saved.version ? { updatedAt: saved.version } : {}) })
      }
    } catch (error) {
      console.error(`Failed to save ${field}:`, error)
      toast.error(toApiError(error, failure).message)
    }
  }, [projectId, currentProject, setCurrentProject, toast])
}

import { useState, useEffect, useCallback, useMemo } from 'react'
import { useUserSkillsChanged } from '@/lib/userSkillsChannel'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'

interface SkillData {
  builtIn: { id: string; name: string }[]
  user: { id: string; name: string }[]
  config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}

/**
 * The skills and this project's toggles for the chat drawer's tooltip. Refetched when a
 * skill version is saved anywhere in the browser, and on demand (`refetch`). A failed read
 * keeps the data it had and sets `error`.
 *
 * On a project the person does not own (step 5.7) the toggles name the OWNER's skills, so the user
 * skills are the owner catalog's, by name; the built-in list is the same for everyone.
 */
export function useAttackSkillData(userId: string, projectId: string) {
  const [fetched, setSkillData] = useState<SkillData | null>(null)
  const owner = useOwnerCatalogSource()
  const ownerCatalog = owner?.catalog ?? null
  const fromOwner = owner !== null
  const skillData = useMemo<SkillData | null>(() => {
    if (!fetched || !fromOwner) return fetched
    return { ...fetched, user: (ownerCatalog?.attackSkills ?? []).map(s => ({ id: s.id, name: s.name })) }
  }, [fetched, fromOwner, ownerCatalog])
  const [error, setError] = useState<ApiError | null>(null)
  const [generation, setGeneration] = useState(0)
  const refetch = useCallback(() => setGeneration(g => g + 1), [])

  useEffect(() => {
    if (!userId || !projectId) return
    let cancelled = false
    async function fetchSkills() {
      try {
        const [availRes, projRes] = await Promise.all([
          fetch(`/api/users/${userId}/attack-skills/available`),
          fetch(`/api/projects/${projectId}`),
        ])
        if (cancelled) return
        if (!availRes.ok) throw await readApiError(availRes, 'Failed to load the attack skills')
        if (!projRes.ok) throw await readApiError(projRes, 'Failed to load the project skill toggles')
        const avail = await availRes.json()
        const proj = await projRes.json()
        const cfg = proj.attackSkillConfig || { builtIn: {}, user: {} }
        setSkillData({
          builtIn: avail.builtIn,
          user: avail.user,
          config: {
            builtIn: cfg.builtIn || {},
            user: cfg.user || {},
          },
        })
        setError(null)
      } catch (err) {
        if (cancelled) return
        const failure = toApiError(err, 'Failed to load the attack skills')
        console.warn('Attack skill data for the chat drawer:', failure.message)
        setError(failure)
      }
    }
    fetchSkills()
    return () => { cancelled = true }
  }, [userId, projectId, generation])

  useUserSkillsChanged(change => {
    if (!change.projectId || change.projectId === projectId) refetch()
  })

  return { skillData, refetch, error }
}

import { useState, useEffect } from 'react'

interface SkillData {
  builtIn: { id: string; name: string }[]
  user: { id: string; name: string }[]
  config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}

export function useAttackSkillData(userId: string, projectId: string) {
  const [skillData, setSkillData] = useState<SkillData | null>(null)

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
        if (availRes.ok && projRes.ok) {
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
        }
      } catch { /* silent */ }
    }
    fetchSkills()
    return () => { cancelled = true }
  }, [userId, projectId])

  return { skillData }
}

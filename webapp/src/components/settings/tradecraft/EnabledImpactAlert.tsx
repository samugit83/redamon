'use client'

import { useCallback } from 'react'
import { useOptionalAlertModal } from '@/components/ui'
import { tradecraftClient } from '@/lib/tradecraft/client'

export const ENABLED_ALERT_TITLE = 'Every project follows'

/**
 * The alert of a change of Enabled (§3.4, R-062, R-140): the global switch clears every project's
 * own choice, so all of them take the new value.
 */
export function enabledImpactText(name: string, next: boolean, impact: { projects: number; turnedOffIn: number } | null): string {
  if (!impact) return `${name} will be ${next ? 'enabled' : 'disabled'} in all your projects.`
  const where = impact.projects === 1 ? 'your 1 project' : `all your ${impact.projects} projects`
  if (!next) return `${name} will be disabled in ${where}.`
  if (impact.turnedOffIn === 0) return `${name} will be enabled in ${where}.`
  return `${name} will be enabled in ${where}, including the ${impact.turnedOffIn} where it was turned off.`
}

/**
 * Asks before a change of Enabled is saved: reads the numbers, shows the alert, answers whether
 * the person confirmed. Numbers that cannot be read leave the alert without them, never skip it.
 */
export function useEnabledImpactConfirm(userId: string): (resource: { id: string; name: string }, next: boolean) => Promise<boolean> {
  const alerts = useOptionalAlertModal()
  return useCallback(async (resource, next) => {
    // Without a way to ask, nothing changes: the alert is never skipped.
    if (!alerts) return false
    let impact: { projects: number; turnedOffIn: number } | null = null
    try {
      impact = await tradecraftClient.enabledImpact(userId, resource.id, next)
    } catch {
      impact = null
    }
    return alerts.confirm(enabledImpactText(resource.name, next, impact), ENABLED_ALERT_TITLE)
  }, [userId, alerts])
}

'use client'

import { useState } from 'react'
import { Toggle, useAlertModal, useToast } from '@/components/ui'
import { actionFailedText } from '@/components/settings/failureText'
import { tradecraftClient } from '@/lib/tradecraft/client'
import css from './tradecraft.module.css'

export const TURN_ON_TEXT =
  'Tradecraft 2.0 changes how your resources are ingested: a Refresh runs in the background and the card shows ' +
  'its stage, each resource is Live (read from the site at every read) or Stored (a copy kept in your RedAmon ' +
  'database), editing a URL ingests the resource again, and deleting a resource deletes everything it holds. ' +
  'You can turn it off at any time: Tradecraft returns to today\'s behaviour and your resources stay.'

export const TURN_OFF_TEXT =
  'Tradecraft returns to today\'s behaviour. Your resources and their maps stay; what 2.0 stored stays unused ' +
  'until you turn it on again.'

/** The account's Tradecraft 2.0 (preview) switch, at the top of the tab, asked for before each change. */
export function V2Switch({ userId, enabled, onChange }: { userId: string; enabled: boolean; onChange: (enabled: boolean) => void }) {
  const { confirm } = useAlertModal()
  const toast = useToast()
  const [saving, setSaving] = useState(false)

  const change = async (next: boolean) => {
    const ok = await confirm(
      next ? TURN_ON_TEXT : TURN_OFF_TEXT,
      next ? 'Turn on Tradecraft 2.0 (preview)?' : 'Turn off Tradecraft 2.0 (preview)?',
    )
    if (!ok) return
    setSaving(true)
    try {
      const saved = await tradecraftClient.setSwitch(userId, next)
      onChange(saved.v2Enabled)
    } catch (e) {
      toast.error(actionFailedText(next ? 'Turning on Tradecraft 2.0' : 'Turning off Tradecraft 2.0', e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className={css.switchBar}>
      <Toggle checked={enabled} onChange={change} disabled={saving} aria-label="Tradecraft 2.0 (preview)" />
      <div className={css.switchText}>
        <span className={css.switchTitle}>Tradecraft 2.0 (preview)</span>
        <span className={css.hint}>
          {enabled
            ? 'On for your account: background ingestion, Live or Stored resources.'
            : 'Off: Tradecraft works as it does today. Turn it on to try background ingestion and stored pages.'}
        </span>
      </div>
    </div>
  )
}

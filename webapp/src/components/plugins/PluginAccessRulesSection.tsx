'use client'

import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useAlertModal } from '@/components/ui'
import { errorMessage, fetchJson } from '@/lib/apiError'
import type { AccessRulesView } from '@/lib/plugins/accessRuleAdmin'
import styles from './plugins.module.css'

interface PluginAccessRulesSectionProps {
  pluginId: string
  displayName: string
}

const sameSets = (a: readonly string[], b: readonly string[]) => [...a].sort().join('\n') === [...b].sort().join('\n')

/**
 * Who may use the plugin (GV-16), on its details drawer for whoever manages plugins, shown only with
 * RBAC_GOVERNANCE_ENABLED on (off, the rules are ignored and the route does not exist). No set
 * ticked = everyone holding plugins:use; ticked sets = only their holders, and plugin admins.
 */
export function PluginAccessRulesSection({ pluginId, displayName }: PluginAccessRulesSectionProps) {
  const queryClient = useQueryClient()
  const { confirm } = useAlertModal()
  const url = `/api/plugins/${pluginId}/access-rules`
  const rules = useQuery<AccessRulesView>({
    queryKey: ['plugins', 'access-rules', pluginId],
    queryFn: () => fetchJson<AccessRulesView>(url, { cache: 'no-store' }, 'The access rules could not be loaded'),
  })
  const [chosen, setChosen] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  useEffect(() => {
    if (rules.data) setChosen(rules.data.setIds)
  }, [rules.data])

  const stored = rules.data?.setIds ?? []
  const known = new Set((rules.data?.sets ?? []).map((s) => s.id))
  // A rule naming a set that is gone (deleteSet refuses that, but a row may predate it) is still shown.
  const gone = stored.filter((id) => !known.has(id))
  const changed = !!rules.data && !sameSets(chosen, stored)

  const toggle = (id: string) => {
    setSaved(false)
    setChosen((now) => (now.includes(id) ? now.filter((x) => x !== id) : [...now, id]))
  }

  const save = async () => {
    const message = chosen.length === 0
      ? `Everyone who can use plugins will be able to use ${displayName}.`
      : `Only holders of the ${chosen.length} chosen set${chosen.length === 1 ? '' : 's'}, and plugin admins, will be able to use ${displayName}. Anyone else loses it at once: an action already running stops at its next call.`
    if (!(await confirm(message, 'Change who may use this plugin?', { confirmLabel: 'Save' }))) return
    setSaving(true)
    setSaveError(null)
    try {
      const out = await fetchJson<{ setIds: string[] }>(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ setIds: chosen }),
      }, 'The access rules could not be saved')
      queryClient.setQueryData<AccessRulesView>(['plugins', 'access-rules', pluginId], (old) => (old ? { ...old, setIds: out.setIds } : old))
      setSaved(true)
    } catch (e) {
      setSaveError(errorMessage(e, 'The access rules could not be saved'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <section data-testid="plugin-access-rules">
      <h4>Who may use it</h4>
      {rules.isLoading && <div className="skeleton skeletonCard" aria-label="Loading the access rules" />}
      {rules.isError && (
        <div className={styles.error} role="alert">
          {errorMessage(rules.error, 'The access rules could not be loaded')}{' '}
          <button type="button" className="secondaryButton" onClick={() => void rules.refetch()}>
            Retry
          </button>
        </div>
      )}
      {rules.data && (
        <fieldset disabled={saving}>
          <legend className={styles.notice}>
            {stored.length === 0
              ? 'Everyone who can use plugins can use it. Tick permission sets to limit it to their holders.'
              : 'Only holders of the ticked sets can use it; plugin admins always can. Untick every set to open it to everyone.'}
          </legend>
          {[...rules.data.sets.map((s) => ({ id: s.id, label: s.builtin ? `${s.name} (built-in)` : s.name })),
            ...gone.map((id) => ({ id, label: `${id} (this set no longer exists)` }))].map((s) => (
            <label key={s.id} style={{ display: 'block' }}>
              <input type="checkbox" checked={chosen.includes(s.id)} onChange={() => toggle(s.id)} /> {s.label}
            </label>
          ))}
          <button type="button" className="secondaryButton" disabled={!changed || saving} onClick={() => void save()}>
            Save who may use it
          </button>
        </fieldset>
      )}
      {saveError && (
        <p className={styles.error} role="alert">
          {saveError}
        </p>
      )}
      {saved && !changed && (
        <p className={styles.notice} role="status">
          Saved.
        </p>
      )}
    </section>
  )
}

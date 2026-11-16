'use client'

import type { SettingDef } from '@/lib/tradecraft/settingsSpec'
import { SectionFields, type SectionFieldsProps } from './SettingsSection'
import css from './dialog.module.css'

/**
 * Known site types: the per-type map limits first, then the language, GitHub and PDF settings.
 * Real page titles arrive with their feature (phase 6) and are not shown before.
 */
export function KnownTypesFields(props: SectionFieldsProps) {
  const maps = props.defs.filter(d => d.key.startsWith('knownTypes.maxMapEntries.'))
  const rest = props.defs.filter(d => !d.key.startsWith('knownTypes.maxMapEntries.'))
  return (
    <>
      <h4 className={css.subhead}>Max map entries per type</h4>
      <SectionFields {...props} defs={maps} />
      <h4 className={css.subhead}>Language, GitHub and PDF</h4>
      <SectionFields {...props} defs={rest as SettingDef[]} />
    </>
  )
}

'use client'

import type { SettingDef } from '@/lib/tradecraft/settingsSpec'
import { SectionFields, type SectionFieldsProps } from './SettingsSection'
import css from './dialog.module.css'

const TITLE_KEYS: ReadonlySet<string> = new Set(['knownTypes.realTitles', 'knownTypes.maxTitleFetches'])

/**
 * Known site types: the per-type map limits first, then real page titles (§4.3: fetch each page's
 * title on wikis, docs sites, GitBooks and repositories, up to a limit), then the language, GitHub
 * and PDF settings.
 */
export function KnownTypesFields(props: SectionFieldsProps) {
  const maps = props.defs.filter(d => d.key.startsWith('knownTypes.maxMapEntries.'))
  const titles = props.defs.filter(d => TITLE_KEYS.has(d.key))
  const rest = props.defs.filter(d => !d.key.startsWith('knownTypes.maxMapEntries.') && !TITLE_KEYS.has(d.key))
  const titlesOff = props.draft['knownTypes.realTitles'] !== true
  return (
    <>
      <h4 className={css.subhead}>Max map entries per type</h4>
      <SectionFields {...props} defs={maps} />
      {titles.length > 0 && (
        <>
          <h4 className={css.subhead}>Real page titles</h4>
          <SectionFields
            {...props} defs={titles}
            inactive={key => (key === 'knownTypes.maxTitleFetches' && titlesOff ? 'Used only when "Use real page titles" is on.' : props.inactive(key))}
          />
        </>
      )}
      <h4 className={css.subhead}>Language, GitHub and PDF</h4>
      <SectionFields {...props} defs={rest as SettingDef[]} />
    </>
  )
}

'use client'

import { RotateCcw } from 'lucide-react'
import type { SettingDef } from '@/lib/tradecraft/settingsSpec'
import { SettingField } from './SettingField'
import type { Draft } from './draft'
import css from './dialog.module.css'

export interface SectionFieldsProps {
  defs: SettingDef[]
  draft: Draft
  errors: Record<string, string>
  inactive: (key: string) => string | undefined
  userId: string
  onChange: (key: string, value: unknown) => void
}

export function SectionFields({ defs, draft, errors, inactive, userId, onChange }: SectionFieldsProps) {
  return (
    <>
      {defs.map(def => (
        <SettingField
          key={def.key} def={def} value={draft[def.key]} error={errors[def.key]} inactiveHint={inactive(def.key)}
          userId={userId} onChange={v => onChange(def.key, v)}
        />
      ))}
    </>
  )
}

/** One section of a settings dialog: its title, its own reset and its fields. */
export function SettingsSection({ label, onReset, children }: { label: string; onReset: () => void; children: React.ReactNode }) {
  return (
    <section className={css.pane} aria-label={label}>
      <div className={css.paneHead}>
        <h3 className={css.paneTitle}>{label}</h3>
        <button type="button" className="secondaryButton" onClick={onReset} aria-label={`Reset ${label} to defaults`}>
          <RotateCcw size={12} /> Reset section
        </button>
      </div>
      {children}
    </section>
  )
}

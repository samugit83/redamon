'use client'

import type { ReactNode } from 'react'
import type { SettingDef, SettingValue } from '@/lib/tradecraft/settingsSpec'
import { OverrideField } from './OverrideField'
import { FormSection } from './FormSection'
import { SECTION_KEYS, defsOf, overrideStatus } from './sections'

/** What every section of the resource form reads and writes. */
export interface FormContext {
  userId: string
  /** The value each setting has without an override: the account's effective value or the spec default. */
  inherited: Record<string, SettingValue>
  /** The resource's overrides as the form holds them (a number field keeps its raw text). */
  overrides: Record<string, unknown>
  setOverride: (key: string, value: unknown) => void
  errors: Record<string, string>
}

export function inheritedOf(ctx: FormContext, def: SettingDef): SettingValue {
  return Object.hasOwn(ctx.inherited, def.key) ? ctx.inherited[def.key] : def.default
}

export function OverrideList({ ctx, defs, hints = {} }: { ctx: FormContext; defs: SettingDef[]; hints?: Record<string, ReactNode> }) {
  return (
    <>
      {defs.map(def => (
        <OverrideField
          key={def.key} def={def} inherited={inheritedOf(ctx, def)} value={ctx.overrides[def.key]}
          onChange={v => ctx.setOverride(def.key, v)} userId={ctx.userId} error={ctx.errors[def.key]} hint={hints[def.key]}
        />
      ))}
    </>
  )
}

/** A section that is only its settings, with the "Inherit" / "N overrides" status. */
export function SettingsOnlySection({ ctx, title, section, hide = [], hints, children }: {
  ctx: FormContext
  title: string
  section: keyof typeof SECTION_KEYS
  hide?: string[]
  hints?: Record<string, ReactNode>
  children?: ReactNode
}) {
  const defs = defsOf(section).filter(d => !hide.includes(d.key))
  return (
    <FormSection title={title} status={overrideStatus(defs.map(d => d.key), ctx.overrides)}>
      {children}
      <OverrideList ctx={ctx} defs={defs} hints={hints} />
    </FormSection>
  )
}

/** A Check URL suggestion: one click writes it as the override. */
export function Suggest({ label, onUse }: { label: string; onUse: () => void }) {
  return <button type="button" className="textButton" onClick={onUse}>{label}</button>
}

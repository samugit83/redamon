/** A stateful FormContext for the resource form's section tests: the overrides a section writes are kept. */
import { useEffect, useState, type ReactNode } from 'react'
import { SETTINGS, type SettingValue } from '@/lib/tradecraft/settingsSpec'
import type { FormContext } from '../form/OverrideList'

/** The account's values as the settings route answers them: the spec's defaults, with a few changed. */
export const ACCOUNT: Record<string, SettingValue> = {
  ...Object.fromEntries(SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource').map(s => [s.key, s.default])),
  'crawl.maxPages': 120,
  'knownTypes.githubFileTypes': ['.md', '.txt'],
}

export const latest: { overrides: Record<string, unknown> } = { overrides: {} }

export function Harness({ initial = {}, children }: { initial?: Record<string, unknown>; children: (ctx: FormContext) => ReactNode }) {
  const [overrides, setOverrides] = useState<Record<string, unknown>>(initial)
  useEffect(() => { latest.overrides = overrides })
  const ctx: FormContext = {
    userId: 'user-1',
    inherited: ACCOUNT,
    overrides,
    setOverride: (key, value) => setOverrides(prev => {
      const next = { ...prev }
      if (value === undefined) delete next[key]
      else next[key] = value
      return next
    }),
    errors: {},
  }
  return <>{children(ctx)}</>
}

'use client'

import { SettingsOnlySection, type FormContext } from './OverrideList'

/** Refreshing (§6.11): what a failed or empty refresh does. Nothing refreshes on its own. */
export function RefreshingSection({ ctx }: { ctx: FormContext }) {
  return <SettingsOnlySection ctx={ctx} title="Refreshing" section="refreshing" />
}

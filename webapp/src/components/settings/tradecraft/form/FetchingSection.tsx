'use client'

import { SettingsOnlySection, type FormContext } from './OverrideList'

/** Fetching (§6.7). "Always use the browser" is not offered on a resource with a login (§5). */
export function FetchingSection({ ctx, hasLogin }: { ctx: FormContext; hasLogin: boolean }) {
  return <SettingsOnlySection ctx={ctx} title="Fetching" section="fetching" hide={hasLogin ? ['fetching.alwaysBrowser'] : []} />
}

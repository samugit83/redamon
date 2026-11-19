'use client'

import { SettingsOnlySection, type FormContext } from './OverrideList'

/** Content (§6.8): the body selector and the elements removed, used by storage and live reads alike; storage limits. */
export function ContentSection({ ctx }: { ctx: FormContext }) {
  return <SettingsOnlySection ctx={ctx} title="Content" section="content" />
}

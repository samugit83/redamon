'use client'

import { SettingsOnlySection, type FormContext } from './OverrideList'
import css from './form.module.css'

/** PDF (§6.5): page range, map by pages or bookmarks, pages to skip. A PDF is always Stored. */
export function PdfSection({ ctx, pages }: { ctx: FormContext; pages: number | null }) {
  return (
    <SettingsOnlySection ctx={ctx} title="PDF" section="pdf">
      {pages !== null && <span className={css.inherited}>The document has {pages.toLocaleString('en-US')} pages.</span>}
    </SettingsOnlySection>
  )
}

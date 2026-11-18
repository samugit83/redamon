'use client'

import { SettingsOnlySection, Suggest, type FormContext } from './OverrideList'

/** Docs site (§6.5): its search index URL, which versioned docs keep under their version. */
export function DocsSection({ ctx, indexFound }: { ctx: FormContext; indexFound: string | null }) {
  const hints = indexFound ? {
    'type.docs.searchIndexUrl': <Suggest label={`Use the index Check URL found: ${indexFound}`} onUse={() => ctx.setOverride('type.docs.searchIndexUrl', indexFound)} />,
  } : {}
  return <SettingsOnlySection ctx={ctx} title="Docs site" section="docs" hints={hints} />
}

'use client'

import { SettingsOnlySection, Suggest, type FormContext } from './OverrideList'

/** CVE archive (§6.5): the path patterns a CVE is looked up by, the branch, the README fallback. */
export function CveSection({ ctx, foundPattern }: { ctx: FormContext; foundPattern: string | null }) {
  const hints = foundPattern ? {
    'type.cve.pathPatterns': <Suggest label={`Use the pattern Check URL found: ${foundPattern}`} onUse={() => ctx.setOverride('type.cve.pathPatterns', [foundPattern])} />,
  } : {}
  return <SettingsOnlySection ctx={ctx} title="CVE archive" section="cve" hints={hints} />
}

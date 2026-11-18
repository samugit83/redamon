'use client'

import { SettingsOnlySection, Suggest, type FormContext } from './OverrideList'

/**
 * Wiki (MkDocs/mdBook) or GitBook (§6.5): sitemap URLs, menu selector, language, map size, and the
 * "Use real page titles" override with its fetch limit.
 */
export function WikiSection({ ctx, variant, sitemapFound }: { ctx: FormContext; variant: 'wiki' | 'gitbook'; sitemapFound: string | null }) {
  const key = `type.${variant}.sitemapUrls`
  const hints = sitemapFound ? { [key]: <Suggest label={`Use the sitemap Check URL found: ${sitemapFound}`} onUse={() => ctx.setOverride(key, [sitemapFound])} /> } : {}
  return <SettingsOnlySection ctx={ctx} title={variant === 'wiki' ? 'Wiki' : 'GitBook'} section={variant} hints={hints} />
}

'use client'

import { SettingsOnlySection, Suggest, type FormContext } from './OverrideList'

/** Website (§6.5, §4.4): start pages, a sitemap for Auto, pagination, and every crawl setting. */
export function WebsiteSection({ ctx, sitemapFound }: { ctx: FormContext; sitemapFound: string | null }) {
  const hints = sitemapFound ? {
    'type.website.sitemapUrls': <Suggest label={`Use the sitemap Check URL found: ${sitemapFound}`} onUse={() => ctx.setOverride('type.website.sitemapUrls', [sitemapFound])} />,
  } : {}
  return <SettingsOnlySection ctx={ctx} title="Website crawl" section="website" hints={hints} />
}

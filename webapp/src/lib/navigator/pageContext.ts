/**
 * The page the person asked from, as a hint for the docs route. Only a pathname of a known app
 * screen is kept, without its query string; anything else is dropped. Never trusted for access.
 */
import { PAGE_WIKI } from '@/components/ui/WikiInfoButton/wiki-links'

const SCREENS: ReadonlyArray<[RegExp, string | null]> = [
  [/^\/graph$/, PAGE_WIKI.graph.page],
  [/^\/insights$/, PAGE_WIKI.insights.page],
  [/^\/projects$/, PAGE_WIKI.projects.page],
  [/^\/projects\/new$/, PAGE_WIKI.projectsNew.page],
  [/^\/projects\/[A-Za-z0-9_-]{1,64}\/settings$/, PAGE_WIKI.projectSettings.page],
  [/^\/reports$/, PAGE_WIKI.reports.page],
  [/^\/settings$/, PAGE_WIKI.settings.page],
  [/^\/cypherfix$/, PAGE_WIKI.cypherfix.page],
  [/^\/plugins(\/[A-Za-z0-9_-]{1,64})?$/, PAGE_WIKI.plugins.page],
  [/^\/admin(\/[a-z-]{1,40})?$/, PAGE_WIKI.settingsUsers.page],
  [/^\/traffic$/, 'TrafficMind'],
  [/^\/ai-attack-surface$/, 'Adversarial-AI-Recon'],
  [/^\/account$/, null],
  [/^\/$/, null],
]

export interface PageContext {
  path: string
  wiki_hint: string | null
}

export function pageContextOf(raw: unknown): PageContext | null {
  if (!raw || typeof raw !== 'object') return null
  const path = (raw as { path?: unknown }).path
  if (typeof path !== 'string' || path.length > 120) return null
  const clean = path.split(/[?#]/)[0]
  // A project id in the path is the person's own data; the agent needs only the screen.
  for (const [re, hint] of SCREENS) {
    if (re.test(clean)) {
      const shown = clean.replace(/^\/projects\/[A-Za-z0-9_-]+\/settings$/, '/projects/<id>/settings')
        .replace(/^\/plugins\/[A-Za-z0-9_-]+$/, '/plugins/<id>')
      return { path: shown, wiki_hint: hint }
    }
  }
  return null
}

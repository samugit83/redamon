/**
 * The AI Navigator stream events (plan Appendix B) and their validator. The agent's NDJSON and the
 * browser's SSE carry the same objects; the webapp is the last boundary before the browser, so
 * every agent event is rebuilt here from its known fields with their caps, and anything unknown is
 * dropped. Agent text never reaches the browser outside a validated field.
 */
import { NAVIGATOR_ROUTES, type NavigatorRoute } from './constants'

export const CITATION_URL_PATTERNS: readonly RegExp[] = [
  /^https:\/\/www\.redamon\.org\/docs(\/[a-z0-9-]+)?(#[a-z0-9\-_]+)?$/,
  /^https:\/\/github\.com\/samugit83\/redamon\/wiki(\/[A-Za-z0-9-]+)?(#[a-z0-9\-_]+)?$/,
]

export function citationUrlAllowed(url: unknown): url is string {
  return typeof url === 'string' && CITATION_URL_PATTERNS.some((re) => re.test(url))
}

export interface Citation {
  id: string
  title: string
  heading: string
  url: string
  mirror_url: string
}

export type NavigatorEvent =
  | { type: 'thread'; thread_id: string; user_message_id: string }
  | { type: 'meta'; run_id: string; model_used: string }
  | { type: 'route'; routes: NavigatorRoute[] }
  | { type: 'refused_route'; route: NavigatorRoute; reason_code: string }
  | { type: 'tool'; route: NavigatorRoute; name: string; status: 'start' | 'end' | 'error'; summary: string; detail?: string }
  | { type: 'delta'; text: string }
  | { type: 'citations'; items: Citation[] }
  | { type: 'handoff'; target: 'ai_agent' }
  | { type: 'done'; status: 'complete' }
  | { type: 'error'; code: string; message: string }

const CODE_RE = /^[a-z_]{1,40}$/
const TOOL_NAME_RE = /^[a-z_]{1,60}$/
const CITE_ID_RE = /^S\d{1,3}$/

const str = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max
const isRoute = (v: unknown): v is NavigatorRoute => typeof v === 'string' && (NAVIGATOR_ROUTES as readonly string[]).includes(v)

function citation(raw: unknown): Citation | null {
  if (!raw || typeof raw !== 'object') return null
  const c = raw as Record<string, unknown>
  if (typeof c.id !== 'string' || !CITE_ID_RE.test(c.id)) return null
  if (!str(c.title, 200) || !str(c.heading, 200)) return null
  if (!citationUrlAllowed(c.url) || !citationUrlAllowed(c.mirror_url)) return null
  return { id: c.id, title: c.title, heading: c.heading, url: c.url, mirror_url: c.mirror_url }
}

/** The validated copy of one agent event, or null to drop it. The agent may not send `thread`. */
export function validateAgentEvent(raw: unknown): NavigatorEvent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const e = raw as Record<string, unknown>
  switch (e.type) {
    case 'meta':
      return str(e.run_id, 80) && str(e.model_used, 200) ? { type: 'meta', run_id: e.run_id, model_used: e.model_used } : null
    case 'route': {
      if (!Array.isArray(e.routes) || e.routes.length > NAVIGATOR_ROUTES.length) return null
      const routes = [...new Set(e.routes.filter(isRoute))]
      return routes.length === e.routes.length ? { type: 'route', routes } : null
    }
    case 'refused_route':
      return isRoute(e.route) && typeof e.reason_code === 'string' && CODE_RE.test(e.reason_code)
        ? { type: 'refused_route', route: e.route, reason_code: e.reason_code } : null
    case 'tool': {
      if (!isRoute(e.route) || typeof e.name !== 'string' || !TOOL_NAME_RE.test(e.name)) return null
      if (e.status !== 'start' && e.status !== 'end' && e.status !== 'error') return null
      if (!str(e.summary, 200)) return null
      if (e.detail !== undefined && !str(e.detail, 8000)) return null
      return { type: 'tool', route: e.route, name: e.name, status: e.status, summary: e.summary,
        ...(typeof e.detail === 'string' ? { detail: e.detail } : {}) }
    }
    case 'delta':
      return str(e.text, 4000) ? { type: 'delta', text: e.text } : null
    case 'citations': {
      if (!Array.isArray(e.items)) return null
      const items = e.items.slice(0, 20).map(citation).filter((c): c is Citation => c !== null)
      return { type: 'citations', items }
    }
    case 'handoff':
      return e.target === 'ai_agent' ? { type: 'handoff', target: 'ai_agent' } : null
    case 'done':
      return e.status === 'complete' ? { type: 'done', status: 'complete' } : null
    case 'error':
      return typeof e.code === 'string' && CODE_RE.test(e.code) && str(e.message, 300)
        ? { type: 'error', code: e.code, message: e.message } : null
    default:
      return null
  }
}

export function sse(event: NavigatorEvent): string {
  return `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`
}

/** `[S#]` markers whose id is not among the citations, removed. */
export function stripUnknownMarkers(text: string, citations: readonly Citation[]): string {
  const known = new Set(citations.map((c) => c.id))
  return text.replace(/\[(S\d{1,3})\]/g, (m, id: string) => (known.has(id) ? m : ''))
}

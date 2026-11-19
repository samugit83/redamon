/**
 * One AI Navigator message, rendered safely (plan §9.9): react-markdown + remark-gfm only, no raw
 * HTML and no dangerouslySetInnerHTML. A link becomes clickable only when it is one of this
 * answer's citations (an allowlisted RedAmon docs or GitHub wiki URL), or the app's own AI Agent
 * deep link; any other URL (target data can carry links) shows as plain text. Images are never
 * loaded. `[S#]` markers become chips that open their citation; an unknown id stays plain text.
 */
'use client'

import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { citationUrlAllowed } from '@/lib/navigator/events'
import { CopyButton } from '@/components/ui/CopyButton'
import type { ChatMessage, CitationView } from './useNavigatorChat'
import { RouteBadges } from './RouteBadges'
import { TraceDisclosure } from './TraceDisclosure'
import { SourcesList } from './CitationChips'
import { navigatorMessage, REFUSED_REASON_TEXT, ROUTE_BADGES } from './messages'
import styles from './Navigator.module.css'

const AGENT_LINK = /^\/graph\?project=[A-Za-z0-9_-]{1,64}&agent=open$/

/** `[S3]` → a fragment link the `a` override turns into a chip. */
export function linkCitationMarkers(text: string): string {
  return text.replace(/\[(S\d{1,3})\](?!\()/g, (_m, id: string) => `[${id}](#cite-${id})`)
}

function textOf(children: React.ReactNode): string {
  if (typeof children === 'string') return children
  if (Array.isArray(children)) return children.map(textOf).join('')
  return ''
}

export function markdownComponents(citations: readonly CitationView[]): Components {
  const byId = new Map(citations.map((c) => [c.id, c]))
  // The allowlist covers any GitHub wiki page name, pages anyone with wiki access can write: a
  // link is clickable only at a URL the server built from the index for this answer.
  const backed = new Set(citations.flatMap((c) => [c.url, c.mirror_url]).filter((u) => citationUrlAllowed(u)))
  return {
    a: ({ href, children }) => {
      const to = typeof href === 'string' ? href : ''
      if (to.startsWith('#cite-')) {
        const cit = byId.get(to.slice(6))
        if (!cit || !citationUrlAllowed(cit.url)) return <span>[{textOf(children)}]</span>
        return (
          <a className={styles.citeChip} href={cit.url} target="_blank" rel="noopener noreferrer" title={`${cit.title} › ${cit.heading}`}>
            {cit.id}
          </a>
        )
      }
      if (backed.has(to)) {
        return <a href={to} target="_blank" rel="noopener noreferrer">{children}</a>
      }
      if (AGENT_LINK.test(to)) return <a href={to}>{children}</a>
      const label = textOf(children)
      return <span className={styles.plainLink}>{label && label !== to ? `${label} (${to})` : to}</span>
    },
    img: ({ alt }) => <span className={styles.plainLink}>[image: {alt || 'no description'}]</span>,
    pre: ({ children }) => {
      const code = textOf((children as { props?: { children?: React.ReactNode } })?.props?.children ?? children)
      return (
        <div className={styles.codeBlock}>
          <CopyButton text={code} title="Copy" />
          <pre>{children}</pre>
        </div>
      )
    },
    table: ({ children }) => (
      <div className={styles.tableWrap}><table>{children}</table></div>
    ),
  }
}

export function SafeNavigatorMarkdown({ text, citations }: { text: string; citations: readonly CitationView[] }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml disallowedElements={['iframe', 'script', 'style']}
      components={markdownComponents(citations)}>
      {linkCitationMarkers(text)}
    </ReactMarkdown>
  )
}

export function MessageBubble({ message, last, onRetry, onOpenAgent, agentAllowed }: {
  message: ChatMessage
  last: boolean
  onRetry?: () => void
  onOpenAgent?: () => void
  agentAllowed: boolean
}) {
  if (message.role === 'user') {
    return (
      <div className={styles.userRow}>
        <div className={styles.userBubble}>{message.content}</div>
        {message.actedByAdmin && <div className={styles.actedBy}>Sent by an administrator acting as you</div>}
      </div>
    )
  }
  const refused = message.trace.filter((t) => t.tool === 'refused_route')
  const offeredAgent = message.trace.some((t) => t.tool === 'handoff')
  const running = message.status === 'streaming'
  const live = running ? message.trace.filter((t) => t.status === 'start').at(-1) : undefined
  return (
    <div className={styles.answerRow} aria-busy={running}>
      <RouteBadges routes={message.routes} />
      {live && <div className={styles.liveTool}><span className={styles.spinner} aria-hidden /> {live.summary}…</div>}
      {running && !message.content && !live && <div className={styles.liveTool}><span className={styles.spinner} aria-hidden /> Thinking…</div>}
      {message.content && (
        <div className={styles.answerBody}>
          <SafeNavigatorMarkdown text={message.content} citations={message.citations} />
        </div>
      )}
      {refused.length > 0 && (
        <ul className={styles.refused}>
          {refused.map((r, i) => (
            <li key={i}>{ROUTE_BADGES[r.route]?.label ?? r.route}: {REFUSED_REASON_TEXT[r.summary] ?? REFUSED_REASON_TEXT.not_allowed}</li>
          ))}
        </ul>
      )}
      <SourcesList citations={message.citations} />
      {(offeredAgent && onOpenAgent) && (
        agentAllowed
          ? <button type="button" className={styles.agentButton} onClick={onOpenAgent}>Open the AI Agent →</button>
          : <p className={styles.muted}>You don&apos;t have access to the AI Agent on this project.</p>
      )}
      {message.status === 'stopped' && <span className={styles.tagStopped}>Stopped</span>}
      {message.status === 'failed' && (
        <p className={styles.failed}>Failed: {navigatorMessage(message.errorCode)}</p>
      )}
      {!running && <TraceDisclosure trace={message.trace} />}
      {last && !running && (message.status === 'failed' || message.status === 'stopped') && onRetry && (
        <button type="button" className={styles.linkButton} onClick={onRetry}>Retry</button>
      )}
    </div>
  )
}

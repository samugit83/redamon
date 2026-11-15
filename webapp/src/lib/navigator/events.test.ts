/**
 * The AI Navigator event contract (plan Appendix B): every agent event rebuilt from its known fields,
 * anything else dropped, citations only to the two allowlisted sites.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { citationUrlAllowed, stripUnknownMarkers, validateAgentEvent } from './events'

const cite = (over: Record<string, unknown> = {}) => ({
  id: 'S1', title: 'Scan Timeline', heading: 'Scans', url: 'https://www.redamon.org/docs/scan-timeline#scans',
  mirror_url: 'https://github.com/samugit83/redamon/wiki/Scan-Timeline#scans', ...over,
})

describe('validateAgentEvent', () => {
  test('known events keep only their fields', () => {
    expect(validateAgentEvent({ type: 'delta', text: 'hi', extra: '<script>' })).toEqual({ type: 'delta', text: 'hi' })
    expect(validateAgentEvent({ type: 'meta', run_id: 'r', model_used: 'm', x: 1 })).toEqual({ type: 'meta', run_id: 'r', model_used: 'm' })
    expect(validateAgentEvent({ type: 'tool', route: 'graph', name: 'run_cypher', status: 'end', summary: 'Ran', detail: 'MATCH (n:IP) RETURN n' }))
      .toEqual({ type: 'tool', route: 'graph', name: 'run_cypher', status: 'end', summary: 'Ran', detail: 'MATCH (n:IP) RETURN n' })
  })

  test.each([
    [{ type: 'thread', thread_id: 't', user_message_id: 'm' }],
    [{ type: 'unknown' }],
    [{ type: 'delta', text: 'x'.repeat(4001) }],
    [{ type: 'route', routes: ['graph', 'shell'] }],
    [{ type: 'tool', route: 'graph', name: 'Bad Name', status: 'end', summary: 's' }],
    [{ type: 'tool', route: 'graph', name: 'x', status: 'end', summary: 's'.repeat(201) }],
    [{ type: 'error', code: 'Bad-Code', message: 'm' }],
    [{ type: 'handoff', target: 'evil' }],
    [{ type: 'done', status: 'maybe' }],
    [null], ['text'], [[1, 2]],
  ])('drops %j', (raw) => {
    expect(validateAgentEvent(raw)).toBeNull()
  })

  test('citations: a bad URL drops that item only', () => {
    const ev = validateAgentEvent({ type: 'citations', items: [cite(), cite({ id: 'S2', url: 'https://evil.example/x' }),
      cite({ id: 'S3', mirror_url: 'javascript:alert(1)' })] })
    expect(ev).toEqual({ type: 'citations', items: [cite()] })
  })
})

describe('citation URLs', () => {
  test.each([
    ['https://www.redamon.org/docs', true],
    ['https://www.redamon.org/docs/scan-timeline#creating-a-schedule', true],
    ['https://github.com/samugit83/redamon/wiki/Scan-Timeline', true],
    ['https://www.redamon.org.evil.example/docs', false],
    ['http://www.redamon.org/docs', false],
    ['https://github.com/someone/redamon/wiki', false],
    ['https://www.redamon.org/docs/x?q=1', false],
  ])('%s → %s', (url, ok) => {
    expect(citationUrlAllowed(url)).toBe(ok)
  })

  test('unknown markers are removed from the saved text', () => {
    expect(stripUnknownMarkers('A [S1] B [S2] C', [cite()])).toBe('A [S1] B  C')
  })
})

/**
 * PAUSE ALL on the graph page (HD-07): a member's press stops only their own agent runs,
 * an admin's every user's. The page asks the route which scope a press has (GET), hands it
 * to the toolbar's tooltip, and after a press reports what the route answered: the scope
 * and the count, or a failure labelled with whose runs it was about.
 *
 * Source-level, like scanErrorWiring.test.ts: rendering /graph needs providers, a router
 * and live scan data, none of which is what is checked. The texts themselves are tested
 * in GraphToolbar/GraphToolbar.emergencyScope.test.tsx.
 *
 * Run: npx vitest run src/app/graph/emergencyStopWiring.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const pageSrc = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')

function handler(name: string): string {
  const start = pageSrc.indexOf(`const ${name} = useCallback(`)
  expect(start, `${name} not found in page.tsx`).toBeGreaterThan(-1)
  const next = pageSrc.indexOf('\n  const ', start + 1)
  return pageSrc.slice(start, next === -1 ? undefined : next)
}

function toolbarElement(): string {
  const at = pageSrc.indexOf('<GraphToolbar\n')
  expect(at).toBeGreaterThan(-1)
  return pageSrc.slice(at, pageSrc.indexOf('/>', at))
}

describe('the emergency stop scope on the graph page', () => {
  test('the page asks the route for the scope and keeps only a known one', () => {
    expect(pageSrc).toContain("fetch('/api/agent/emergency-stop-all')")
    expect(pageSrc).toMatch(/isEmergencyStopScope\(\w+(\?\.)?\.?scope\)/)
  })

  test('the toolbar gets the scope for its tooltip', () => {
    expect(toolbarElement()).toContain('emergencyStopScope={emergencyStopScope}')
  })

  test('a press reports the scope and count the route answered', () => {
    const body = handler('handleEmergencyPauseAll')
    expect(body).toContain("fetch('/api/agent/emergency-stop-all', { method: 'POST' })")
    expect(body).toContain('agentStopSummary(')
    expect(body).toMatch(/toast\.info\(\w+\)/)
  })

  test('a failed press names whose runs it was about, with the route\'s reason', () => {
    const body = handler('handleEmergencyPauseAll')
    expect(body).toContain('agentStopFailureLabel(emergencyStopScope)')
    expect(body).toContain("readApiError(res, 'Failed to stop agents')")
    expect(body).toContain("toApiError(err, 'Failed to stop agents')")
    expect(body).not.toContain('`AI agents: ')
  })

  test('the answer also corrects the scope the tooltip shows', () => {
    const body = handler('handleEmergencyPauseAll')
    expect(body).toMatch(/setEmergencyStopScope\(/)
  })
})

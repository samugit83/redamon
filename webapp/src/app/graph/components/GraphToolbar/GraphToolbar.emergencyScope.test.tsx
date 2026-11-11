/**
 * PAUSE ALL stops agent runs as well as this project's scans, and since HD-07 a member's
 * press stops only their own agent runs while an admin's stops every user's. The tooltip
 * must say which before the press, and the page's message after it; neither reaches the
 * CypherFix triage or CodeFix runs, which the text says too.
 *
 * Run: npx vitest run src/app/graph/components/GraphToolbar/GraphToolbar.emergencyScope.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { GraphToolbar } from './GraphToolbar'
import {
  agentStopFailureLabel, agentStopSummary, emergencyPauseTitle, isEmergencyStopScope,
} from './emergencyStopScope'

afterEach(cleanup)

const base = {
  projectId: 'p1', is3D: false, showLabels: true, onToggle3D: () => {}, onToggleLabels: () => {},
  onStartRecon: () => {}, hasReconData: true, isAnyPipelineRunning: true,
}

function pauseButton(): HTMLButtonElement {
  return screen.getAllByRole('button').find(b => b.textContent?.includes('PAUSE ALL')) as HTMLButtonElement
}

describe('PAUSE ALL tooltip by scope', () => {
  test('a member is told it stops their own agent runs only', () => {
    render(<GraphToolbar {...base} emergencyStopScope="own" />)
    const title = pauseButton().title
    expect(title).toContain('Stop your own agent runs')
    expect(title).toMatch(/other users' runs keep going/)
    expect(title).not.toMatch(/every user/)
  })

  test('an admin is told it stops every user\'s agent runs', () => {
    render(<GraphToolbar {...base} emergencyStopScope="all" />)
    const title = pauseButton().title
    expect(title).toContain("Stop every user's agent runs")
    expect(title).not.toMatch(/your own/)
  })

  test('before the scope is known the tooltip claims neither', () => {
    render(<GraphToolbar {...base} />)
    const title = pauseButton().title
    expect(title).toMatch(/every user's for an administrator, otherwise only your own/)
  })

  test.each(['own', 'all', undefined] as const)('scope %s: scans of this project, and CypherFix runs are not stopped', scope => {
    render(<GraphToolbar {...base} emergencyStopScope={scope} />)
    const title = pauseButton().title
    expect(title).toMatch(/^EMERGENCY PAUSE - /)
    expect(title).toContain("freeze this project's running scans")
    expect(title).toContain('CypherFix triage and CodeFix runs are not stopped')
  })

  test('the button itself still reads PAUSE ALL and stays enabled while something runs', () => {
    render(<GraphToolbar {...base} emergencyStopScope="own" />)
    expect(pauseButton().disabled).toBe(false)
    expect(pauseButton().textContent).toContain('PAUSE ALL')
  })
})

describe('the page\'s message after a press', () => {
  test('own: how many of the person\'s runs stopped, and that others keep going', () => {
    expect(agentStopSummary({ scope: 'own', stopped: 1 })).toBe("AI agents: stopped 1 of your own runs. Other users' runs keep going.")
    expect(agentStopSummary({ scope: 'own', stopped: 0 })).toBe("AI agents: you had no run to stop. Other users' runs keep going.")
  })

  test('all: how many runs of every user stopped', () => {
    expect(agentStopSummary({ scope: 'all', stopped: 3 })).toBe("AI agents: stopped 3 runs of every user.")
    expect(agentStopSummary({ scope: 'all', stopped: 1 })).toBe("AI agents: stopped 1 run of every user.")
  })

  test('an answer without a known scope gives no message', () => {
    expect(agentStopSummary(null)).toBeNull()
    expect(agentStopSummary({ scope: 'everyone', stopped: 2 })).toBeNull()
    expect(agentStopSummary({ stopped: 2 })).toBeNull()
  })

  test('a failure names whose runs it was about', () => {
    expect(agentStopFailureLabel('own')).toBe('Your AI agents')
    expect(agentStopFailureLabel('all')).toBe('AI agents')
    expect(agentStopFailureLabel(undefined)).toBe('AI agents')
  })

  test('only the two scopes are scopes', () => {
    expect(isEmergencyStopScope('own')).toBe(true)
    expect(isEmergencyStopScope('all')).toBe(true)
    expect(isEmergencyStopScope('ALL')).toBe(false)
    expect(isEmergencyStopScope(undefined)).toBe(false)
    expect(emergencyPauseTitle('own')).not.toBe(emergencyPauseTitle('all'))
  })
})

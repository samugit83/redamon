/**
 * Fireteam step content in a report (4.9 review): a deployment's plan rationale and each member's
 * task, completion reason and error are the agent's own reasoning and output. A report is one
 * stored file every `reports:read` holder (R) opens, so it records whether it holds any, and a
 * reader below R* opens only one that records it holds none.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { reportHoldsStepContent, reportMayHoldStepContent } from './stepContent'

const member = (over: Record<string, unknown> = {}) => ({
  memberIdKey: 'm-1', name: 'recon', task: '', skills: [], status: 'success', completionReason: null,
  iterationsUsed: 3, tokensUsed: 100, findingsCount: 1, wallClockSeconds: 2, errorMessage: null, ...over,
})
const fireteams = (deployment: Record<string, unknown> = {}, members = [member()]) => ({
  totalFireteams: 1, totalMembers: members.length, totalFindings: 1,
  deployments: [{
    fireteamIdKey: 'ft-1', iteration: 2, planRationale: '', startedAt: '2026-11-01T00:00:00Z', completedAt: null,
    wallClockSeconds: null, statusCounts: null, status: 'completed', members, ...deployment,
  }],
})

describe('reportHoldsStepContent', () => {
  test('no fireteam, or fireteams whose rationale, tasks, reasons and errors are all empty: none', () => {
    expect(reportHoldsStepContent({})).toBe(false)
    expect(reportHoldsStepContent({ fireteams: undefined })).toBe(false)
    expect(reportHoldsStepContent({ fireteams: fireteams() })).toBe(false)
    expect(reportHoldsStepContent({ fireteams: fireteams({}, []) })).toBe(false)
  })

  test.each([
    ['a plan rationale', fireteams({ planRationale: 'split the hosts: web first' })],
    ['a member task', fireteams({}, [member({ task: 'log in with admin:rbac-fake-pass' })])],
    ['a completion reason', fireteams({}, [member({ completionReason: 'got a shell on 10.0.0.5' })])],
    ['an error', fireteams({}, [member({ errorMessage: 'stderr: denied' })])],
  ])('%s: holds step content', (_what, f) => {
    expect(reportHoldsStepContent({ fireteams: f as never })).toBe(true)
  })
})

describe('reportMayHoldStepContent (what a stored report recorded)', () => {
  test('only a report that recorded none opens below R*', () => {
    expect(reportMayHoldStepContent({ riskScore: 3, stepContent: false })).toBe(false)
  })

  test.each([
    ['recorded some', { stepContent: true }],
    ['generated before the record existed', { riskScore: 3 }],
    ['no metrics', null],
    ['a malformed record', { stepContent: 'false' }],
    ['metrics that are not an object', 'x'],
  ])('a report that %s may hold it (fails closed)', (_what, metrics) => {
    expect(reportMayHoldStepContent(metrics)).toBe(true)
  })
})

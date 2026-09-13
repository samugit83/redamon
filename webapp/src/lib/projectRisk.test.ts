/**
 * One number for the project's risk, computed one way (K15, Phase 8).
 *
 * There were three separate scoring systems: the Priority Board's, the
 * report's, and the Insights gauge's. The last two shared a weighted sum with a
 * log squash, and its real problem was its SHAPE rather than its weights: a
 * term per finding meant it measured how big a project is at least as much as
 * how exposed it is. Scanning more hosts raised the risk score even when every
 * new finding was a missing header.
 *
 * These tests pin the properties that make the replacement meaningful, because
 * a risk number nobody can reason about is worse than no number.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { projectRisk, riskLabel, RISK_TOP_N } from './projectRisk'

const open = (risk: number) => ({ triage_risk: risk, triage_state: 'open' })

describe('projectRisk', () => {
  test('one finding with risk r gives 100r', () => {
    expect(projectRisk([open(0.5)]).score).toBe(50)
  })

  test('two independent findings combine, they do not add', () => {
    // 1 - (1-0.5)(1-0.5) = 0.75, not 1.0. Two coin flips are not a certainty.
    expect(projectRisk([open(0.5), open(0.5)]).score).toBe(75)
  })

  test('it never exceeds 100, however many findings there are', () => {
    const many = Array.from({ length: 500 }, () => open(0.9))
    expect(projectRisk(many).score).toBeLessThanOrEqual(100)
  })

  test('more low-value findings barely move it', () => {
    // THE POINT. Fifty missing headers must not outweigh one real problem: the
    // old sum-and-log said the opposite, so a bigger scan looked riskier.
    const noise = Array.from({ length: 50 }, () => open(0.01))
    const oneRealProblem = [open(0.8)]
    expect(projectRisk(noise).score).toBeLessThan(
      projectRisk(oneRealProblem).score)
  })

  test('one dangerous finding raises it more than many trivial ones', () => {
    const before = projectRisk([open(0.1), open(0.1), open(0.1)])
    const after = projectRisk([open(0.1), open(0.1), open(0.1), open(0.9)])
    expect(after.score - before.score).toBeGreaterThan(50)
  })

  test('adding a finding never lowers the score', () => {
    let previous = 0
    for (let n = 1; n <= 30; n++) {
      const score = projectRisk(Array.from({ length: n }, () => open(0.2))).score
      expect(score).toBeGreaterThanOrEqual(previous)
      previous = score
    }
  })

  test('only the worst findings contribute, and it says how many', () => {
    const risks = Array.from({ length: 100 }, (_, i) => open(i / 200))
    const result = projectRisk(risks)
    expect(result.contributing).toBe(RISK_TOP_N)
  })

  test('the order the findings arrive in does not matter', () => {
    const risks = [open(0.1), open(0.7), open(0.3)]
    expect(projectRisk(risks).score).toBe(projectRisk([...risks].reverse()).score)
  })
})

describe('what does not count', () => {
  test('a fixed finding stops contributing', () => {
    const result = projectRisk([
      { triage_risk: 0.9, triage_state: 'fixed' },
      open(0.1),
    ])
    expect(result.score).toBe(10)
  })

  test('a finding judged a false positive stops contributing', () => {
    const result = projectRisk([
      { triage_risk: 0.9, triage_state: 'open', triage_status: 'likely_noise' },
      open(0.1),
    ])
    expect(result.score).toBe(10)
  })

  test('a finding with no risk yet is skipped rather than counted as zero', () => {
    expect(projectRisk([{ triage_risk: null }, open(0.5)]).score).toBe(50)
  })

  test('a nonsense risk value does not produce a nonsense score', () => {
    const result = projectRisk([
      { triage_risk: NaN, triage_state: 'open' },
      { triage_risk: 99, triage_state: 'open' },
      { triage_risk: -5, triage_state: 'open' },
    ])
    expect(result.score).toBeGreaterThanOrEqual(0)
    expect(result.score).toBeLessThanOrEqual(100)
  })
})

describe('an untriaged project is UNMEASURED, not safe', () => {
  // The trap this guards: rendering `unmeasured` as 0 would tell an operator
  // their project is risk-free purely because nobody has looked at it.
  test('no findings at all is unmeasured', () => {
    expect(projectRisk([]).unmeasured).toBe(true)
  })

  test('findings with no risk value are unmeasured', () => {
    expect(projectRisk([{ triage_risk: null }, { triage_risk: undefined }])
      .unmeasured).toBe(true)
  })

  test('a single triaged finding is measured', () => {
    expect(projectRisk([open(0.1)]).unmeasured).toBe(false)
  })

  test('undefined input does not throw', () => {
    expect(projectRisk(undefined as never).unmeasured).toBe(true)
  })
})

describe('labels', () => {
  test('the bands are contiguous and ordered', () => {
    expect(riskLabel(100)).toBe('Critical')
    expect(riskLabel(80)).toBe('Critical')
    expect(riskLabel(79)).toBe('High')
    expect(riskLabel(60)).toBe('High')
    expect(riskLabel(59)).toBe('Medium')
    expect(riskLabel(40)).toBe('Medium')
    expect(riskLabel(39)).toBe('Low')
    expect(riskLabel(20)).toBe('Low')
    expect(riskLabel(19)).toBe('Minimal')
    expect(riskLabel(0)).toBe('Minimal')
  })
})

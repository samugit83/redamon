/**
 * The log drawers' phase lists equal the orchestrator's phase patterns.
 *
 * Each drawer shows "Phase N/M": N is the number the orchestrator's
 * *_PHASE_PATTERNS entry carries (recon_orchestrator/container_manager.py), M
 * is the length of the TS list. The GVM drawer hard-coded M = 4 against five
 * patterns and showed "Phase 5/4" (drift-map #22). A partial run's count was a
 * per-tool list of names nothing printed (drift-map #64); the orchestrator pins
 * every partial event to phase 1. The Python source is parsed, so a pattern
 * added or a pin changed there fails here.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { GITHUB_HUNT_PHASES, GVM_PHASES, PARTIAL_RECON_TOTAL_PHASES, RECON_TOTAL_PHASES, TRUFFLEHOG_PHASES } from './recon-types'

const CONTAINER_MANAGER = join(__dirname, '../../../recon_orchestrator/container_manager.py')
const available = existsSync(CONTAINER_MANAGER)

/** [name, number] per entry of the Python list literal `name = [...]`. */
function pythonPhases(name: string): Array<[string, number]> {
  const src = readFileSync(CONTAINER_MANAGER, 'utf8')
  const body = new RegExp(`^${name} = \\[\\n([\\s\\S]*?)\\n\\]`, 'm').exec(src)
  expect(body, `${name} not found in container_manager.py`).toBeTruthy()
  return body![1].split('\n')
    .map(line => /,\s*"([^"]+)",\s*([\d.]+)\),?\s*$/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null)
    .map(m => [m[1], Number(m[2])])
}

describe.skipIf(!available)('drawer phase lists equal the orchestrator patterns', () => {
  test.each([
    ['GVM_PHASE_PATTERNS', GVM_PHASES],
    ['GITHUB_HUNT_PHASE_PATTERNS', GITHUB_HUNT_PHASES],
    ['TRUFFLEHOG_PHASE_PATTERNS', TRUFFLEHOG_PHASES],
  ] as const)('%s', (name, ts) => {
    const py = pythonPhases(name)
    expect(py.length).toBeGreaterThan(0)
    // Same names in the same order, numbered 1..n, so N never exceeds M.
    expect([...ts]).toEqual(py.map(([phase]) => phase))
    expect(py.map(([, n]) => n)).toEqual(py.map((_, i) => i + 1))
  })
})

describe.skipIf(!available)('the full pipeline is RECON_TOTAL_PHASES phases', () => {
  test('the last PHASE_PATTERNS number, which ReconState.total_phases also says', () => {
    expect(RECON_TOTAL_PHASES).toBe(Math.max(...pythonPhases('PHASE_PATTERNS').map(([, n]) => n)))
  })
})

describe.skipIf(!available)('a partial run is phase 1 of PARTIAL_RECON_TOTAL_PHASES', () => {
  test('stream_partial_logs reports every event as PARTIAL_RECON_PHASE_NUMBER, which is that count', () => {
    const src = readFileSync(CONTAINER_MANAGER, 'utf8')
    const constant = /^PARTIAL_RECON_PHASE_NUMBER = (\d+)$/m.exec(src)
    expect(constant, 'PARTIAL_RECON_PHASE_NUMBER not found in container_manager.py').toBeTruthy()
    expect(Number(constant![1])).toBe(PARTIAL_RECON_TOTAL_PHASES)
    const fn = /\n    async def stream_partial_logs\([\s\S]*?(?=\n    (?:async )?def )/.exec(src)
    expect(fn, 'stream_partial_logs not found in container_manager.py').toBeTruthy()
    expect(fn![0]).toContain('PARTIAL_RECON_PHASE_NUMBER')
    // The pipeline's phase parser would name and number a line from its text.
    expect(fn![0]).not.toMatch(/_parse_log_line|PhaseTracker/)
  })
})

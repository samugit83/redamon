/**
 * The webapp's scanning-window copy against the vectors the scan container
 * (recon/tests/test_roe_time_window_vectors.py) and the orchestrator
 * (recon_orchestrator/tests/test_roe_time_window_vectors.py) also run, so a
 * schedule is never judged by a window the scan reads differently.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { insideScanWindow } from './scanWindow'

const VECTORS = join(process.cwd(), '..', 'recon', 'tests', 'fixtures', 'roe_time_window_vectors.json')

interface Vector {
  name: string
  enabled?: boolean
  days: string[]
  start: string
  end: string
  timezone: string
  now: string
  result: 'allowed' | 'refused' | 'invalid_timezone'
}

describe.skipIf(!existsSync(VECTORS))('RoE scanning window: shared vectors', () => {
  const vectors: Vector[] = existsSync(VECTORS) ? JSON.parse(readFileSync(VECTORS, 'utf8')).vectors : []

  test('the table is a real set', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(20)
  })

  test.each(vectors.map(v => [v.name, v] as const))('%s', (_name, v) => {
    const row = {
      roeTimeWindowEnabled: v.enabled ?? true,
      roeTimeWindowDays: v.days,
      roeTimeWindowStartTime: v.start,
      roeTimeWindowEndTime: v.end,
      roeTimeWindowTimezone: v.timezone,
    }
    const at = new Date(v.now)
    if (v.result === 'invalid_timezone') {
      expect(() => insideScanWindow(at, row)).toThrow()
    } else {
      expect(insideScanWindow(at, row)).toBe(v.result === 'allowed')
    }
  })
})

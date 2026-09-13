/** @vitest-environment node */
/**
 * Regression G7: a preset that sends no active packets must not start
 * opening TLS handshakes.
 *
 * tlsx ships DEFAULT ON, so every "passive" / "zero active probing" preset has
 * to opt OUT explicitly. The first review checked only the three presets the
 * plan happened to name and missed dns-email-security, which disables naabu,
 * masscan, nmap, httpx and nuclei -- every active scanner -- and would still
 * have run tlsx.
 *
 * This asserts the INVARIANT rather than a list, so a preset added tomorrow
 * cannot reintroduce the same hole.
 */
import { describe, test, expect } from 'vitest'
import { RECON_PRESETS } from './index'

type Settings = Record<string, unknown>

/** A preset's toggles live under `parameters` (ReconPreset in types.ts). */
function settingsOf(preset: unknown): Settings {
  return ((preset as { parameters?: Settings }).parameters ?? {}) as Settings
}

describe('tlsx preset guard', () => {
  test('there are presets to check', () => {
    expect(RECON_PRESETS.length).toBeGreaterThan(10)
  })

  test('every preset that disables the HTTP probe also disables tlsx', () => {
    const offenders: string[] = []
    for (const preset of RECON_PRESETS) {
      const s = settingsOf(preset)
      if (s.httpxEnabled === false && s.tlsxEnabled !== false) {
        offenders.push((preset as { id?: string }).id ?? 'unknown')
      }
    }
    expect(offenders, 'these presets send no HTTP but would still handshake with tlsx')
      .toEqual([])
  })

  test('a preset that disables every active scanner disables tlsx too', () => {
    const ACTIVE = ['naabuEnabled', 'masscanEnabled', 'nmapEnabled', 'httpxEnabled', 'nucleiEnabled']
    const offenders: string[] = []
    for (const preset of RECON_PRESETS) {
      const s = settingsOf(preset)
      const declared = ACTIVE.filter(k => k in s)
      const allOff = declared.length >= 3 && declared.every(k => s[k] === false)
      if (allOff && s.tlsxEnabled !== false) {
        offenders.push((preset as { id?: string }).id ?? 'unknown')
      }
    }
    expect(offenders).toEqual([])
  })

  test('active presets are NOT forced to disable tlsx (the guard is not blanket)', () => {
    // Control: if this were empty the invariant above would be vacuous.
    const active = RECON_PRESETS.filter(p => settingsOf(p).httpxEnabled === true)
    expect(active.length).toBeGreaterThan(0)
    expect(active.some(p => settingsOf(p).tlsxEnabled !== false)).toBe(true)
  })
})

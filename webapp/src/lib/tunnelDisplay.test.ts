/**
 * How a tunnel indicator reads one tunnel of the /tunnel-status answer (round 2): `status` decides,
 * and an answer without it (a sandbox image older than the field) falls back to `active`.
 *
 * Run: npx vitest run src/lib/tunnelDisplay.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { tunnelDisplay } from './tunnelDisplay'

describe('tunnelDisplay', () => {
  // The agent's shapes: host and port only with "on"; connecting and error while the process runs.
  test('status decides: only "on" is on, though the process runs while connecting or failing', () => {
    expect(tunnelDisplay({ active: true, status: 'on', host: '0.tcp.ngrok.example', port: 12345 })).toEqual({ state: 'on' })
    expect(tunnelDisplay({ active: true, status: 'connecting' })).toEqual({ state: 'connecting' })
    expect(tunnelDisplay({ active: true, status: 'error: auth failed' })).toEqual({ state: 'error', reason: 'auth failed' })
    expect(tunnelDisplay({ active: false, status: 'off' })).toEqual({ state: 'off' })
    // A chisel client that exited on its error (tunnel_manager.py `_chisel_status`) still says why.
    expect(tunnelDisplay({ active: false, status: 'error: exited' })).toEqual({ state: 'error', reason: 'exited' })
    // A status this webapp does not know yet is never shown as on.
    expect(tunnelDisplay({ active: true, status: 'something new' })).toEqual({ state: 'off' })
  })

  test('an error with no reason still says failed; a long reason is cut', () => {
    expect(tunnelDisplay({ status: 'error' })).toEqual({ state: 'error', reason: 'unknown error' })
    const long = tunnelDisplay({ status: `error: ${'x'.repeat(500)}` })
    expect(long.state === 'error' && long.reason.length).toBe(200)
  })

  test('no status (an older sandbox image): active as before; nothing usable is off', () => {
    expect(tunnelDisplay({ active: true })).toEqual({ state: 'on' })
    expect(tunnelDisplay({ active: false })).toEqual({ state: 'off' })
    for (const v of [undefined, null, 'on', 7, {}]) expect(tunnelDisplay(v)).toEqual({ state: 'off' })
  })
})

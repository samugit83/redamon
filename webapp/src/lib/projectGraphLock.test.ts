/**
 * The per-project graph-operation lock (S-4): starts queue behind starts, a
 * save or an activation never waits, and each refuses while the other kind
 * holds it. The interleavings of the real start, save and activation paths are
 * in startFullScan.versionLock.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { graphLockHolder, tryWithGraphLock, withGraphStartLock } from './projectGraphLock'

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(r => { resolve = r })
  return { promise, resolve }
}

const tick = () => new Promise(r => setTimeout(r, 0))

describe('starts', () => {
  test('run one at a time per project, in arrival order', async () => {
    const order: string[] = []
    const first = deferred()
    const a = withGraphStartLock('p1', async () => { order.push('a:in'); await first.promise; order.push('a:out'); return 'a' })
    const b = withGraphStartLock('p1', async () => { order.push('b:in'); return 'b' })
    await tick()
    expect(order).toEqual(['a:in'])
    first.resolve()
    expect(await a).toEqual({ acquired: true, value: 'a' })
    expect(await b).toEqual({ acquired: true, value: 'b' })
    expect(order).toEqual(['a:in', 'a:out', 'b:in'])
    expect(graphLockHolder('p1')).toBeNull()
  })

  test('a rejected start passes its error on and the next start still runs', async () => {
    const a = withGraphStartLock('p1', async () => { throw new Error('programming error') })
    const b = withGraphStartLock('p1', async () => 'b')
    await expect(a).rejects.toThrow('programming error')
    expect(await b).toEqual({ acquired: true, value: 'b' })
    expect(graphLockHolder('p1')).toBeNull()
  })

  test('on different projects do not wait for each other', async () => {
    const gate = deferred()
    const p1 = withGraphStartLock('p1', () => gate.promise)
    expect(await withGraphStartLock('p2', async () => 'p2')).toEqual({ acquired: true, value: 'p2' })
    gate.resolve()
    await p1
  })

  test.each(['version-save', 'activation'] as const)('are refused while a %s holds the lock, without running', async op => {
    const gate = deferred()
    const held = tryWithGraphLock('p1', op, () => gate.promise)
    let ran = false
    expect(await withGraphStartLock('p1', async () => { ran = true })).toEqual({ acquired: false, heldBy: op })
    expect(ran).toBe(false)
    gate.resolve()
    await held
    expect(await withGraphStartLock('p1', async () => 'after')).toEqual({ acquired: true, value: 'after' })
  })
})

describe('a version save or an activation', () => {
  test.each(['version-save', 'activation'] as const)('a %s is refused at once while a start runs or waits', async op => {
    const gate = deferred()
    const a = withGraphStartLock('p1', () => gate.promise)
    const b = withGraphStartLock('p1', async () => undefined)
    let ran = false
    expect(await tryWithGraphLock('p1', op, async () => { ran = true })).toEqual({ acquired: false, heldBy: 'scan-start' })
    gate.resolve()
    await a
    // The queued start still holds the lock until it has run.
    await b
    expect(ran).toBe(false)
    expect(graphLockHolder('p1')).toBeNull()
  })

  test('is refused while another one holds the lock, which it names', async () => {
    const gate = deferred()
    const save = tryWithGraphLock('p1', 'version-save', () => gate.promise)
    expect(graphLockHolder('p1')).toBe('version-save')
    expect(await tryWithGraphLock('p1', 'activation', async () => 'x')).toEqual({ acquired: false, heldBy: 'version-save' })
    expect(await tryWithGraphLock('p1', 'version-save', async () => 'x')).toEqual({ acquired: false, heldBy: 'version-save' })
    gate.resolve()
    await save
    expect(await tryWithGraphLock('p1', 'activation', async () => 'x')).toEqual({ acquired: true, value: 'x' })
  })

  test('releases the lock when it throws, and passes the error on', async () => {
    await expect(tryWithGraphLock('p1', 'activation', async () => { throw new Error('restore failed') }))
      .rejects.toThrow('restore failed')
    expect(graphLockHolder('p1')).toBeNull()
    expect(await withGraphStartLock('p1', async () => 'start')).toEqual({ acquired: true, value: 'start' })
  })
})

// Step 5.12: an ownership transfer holds the lock alone, like a save or an activation.
describe('the ownership transfer (step 5.12)', () => {
  test('a start waiting or running refuses the transfer, and a transfer refuses every start and activation', async () => {
    const gate = deferred()
    const start = withGraphStartLock('p-transfer', () => gate.promise)
    expect(await tryWithGraphLock('p-transfer', 'transfer', async () => 'moved')).toEqual({ acquired: false, heldBy: 'scan-start' })
    gate.resolve()
    await start
    const moving = deferred()
    const transfer = tryWithGraphLock('p-transfer', 'transfer', () => moving.promise)
    expect(graphLockHolder('p-transfer')).toBe('transfer')
    expect(await withGraphStartLock('p-transfer', async () => 'started')).toEqual({ acquired: false, heldBy: 'transfer' })
    expect(await tryWithGraphLock('p-transfer', 'activation', async () => 'swapped')).toEqual({ acquired: false, heldBy: 'transfer' })
    moving.resolve()
    await transfer
    expect(graphLockHolder('p-transfer')).toBeNull()
  })
})

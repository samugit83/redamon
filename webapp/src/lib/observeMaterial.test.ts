import { describe, test, expect } from 'vitest'
import { parseObservedMaterial } from './observeMaterial'

describe('parseObservedMaterial', () => {
  test('keeps clean cookie/authorization/extra + host', () => {
    const m = parseObservedMaterial(
      { cookie: 'sid=a', authorization: 'Bearer x', extra: { 'X-CSRF-Token': 'c' } },
      'App.Target.test',
    )
    expect(m).toEqual({
      cookie: 'sid=a', authorization: 'Bearer x',
      extra: { 'X-CSRF-Token': 'c' }, host: 'app.target.test',
    })
  })

  test('rejects header-injection values (defense in depth)', () => {
    expect(parseObservedMaterial({ cookie: 'sid=a\r\nX-Evil: 1' }, 'h')).toBeNull()
    expect(parseObservedMaterial({ authorization: 'a;;b' }, 'h')).toBeNull()
  })

  test('drops a bad extra header but keeps good material', () => {
    const m = parseObservedMaterial(
      { cookie: 'sid=a', extra: { 'X-Ok': 'v', 'Bad Name': 'v', 'x-redamon-ctx': 'x' } }, 'h')
    expect(m?.cookie).toBe('sid=a')
    expect(m?.extra).toEqual({ 'X-Ok': 'v' })
  })

  test('null when nothing usable', () => {
    expect(parseObservedMaterial({}, undefined)).toBeNull()
    expect(parseObservedMaterial(null, undefined)).toBeNull()
    expect(parseObservedMaterial('nope', undefined)).toBeNull()
  })

  test('host hint used when material has no host', () => {
    expect(parseObservedMaterial({ cookie: 'sid=a' }, 'h.test')?.host).toBe('h.test')
  })
})

/**
 * The webapp's copy of the settings an IP project's hostname mode forces
 * (decision D-20). recon/tests/test_ip_hostname_overrides.py holds the table equal
 * to recon's `_IP_HOSTNAME_FORCED`; this pins what readers get from a row.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { field } from '@/lib/reconSettings/registry'
import { IP_HOSTNAME_FORCED, ipHostnameOverrides } from './ipHostnameOverrides'

describe('ipHostnameOverrides', () => {
  test('nothing outside IP mode', () => {
    expect(ipHostnameOverrides({ ipMode: false, ipHostnameMode: 'ip_only' })).toEqual([])
    expect(ipHostnameOverrides({ ipHostnameMode: 'ip_only' })).toEqual([])
  })

  test('an unknown or absent mode reads as ip_only, the strictest row', () => {
    for (const raw of [undefined, null, '', 'SCAN_ALL', 7]) {
      expect(ipHostnameOverrides({ ipMode: true, ipHostnameMode: raw }).map(o => o.key))
        .toEqual(['tlsxRevPtrSni', 'shodanReverseDns', 'vhostSniUseGraphCandidates'])
    }
  })

  test('each override names its value and the mode that forces it', () => {
    expect(ipHostnameOverrides({ ipMode: true, ipHostnameMode: 'scan_all' })).toEqual([
      { key: 'tlsxRevPtrSni', value: false, reason: 'forced by Hostnames on target IPs: scan_all' },
    ])
  })

  test('every key is a real boolean column, and every forced value is false', () => {
    for (const row of Object.values(IP_HOSTNAME_FORCED)) {
      for (const [key, value] of Object.entries(row)) {
        expect(field(key)?.type, key).toBe('boolean')
        expect(value, key).toBe(false)
      }
    }
  })
})

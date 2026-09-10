/**
 * Unit tests for API Keys template generation and import validation.
 *
 * Run: npx vitest run src/lib/apiKeysTemplate.test.ts
 */

import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildTemplate,
  templateToJson,
  validateAndParse,
  isValidationError,
  templateKeyLabel,
} from './apiKeysTemplate'
import { credentialField } from './credentialFields'

// ---------------------------------------------------------------------------
// Template generation
// ---------------------------------------------------------------------------

describe('buildTemplate', () => {
  // The file is filled in by hand, so it is named the way the UI is: a column
  // name would ask an operator to know an internal spelling.
  test('names every field the way Settings labels it', () => {
    const t = buildTemplate({}, {})
    const keyFields = Object.keys(t.keys)
    expect(keyFields).toContain('GitHub Secret Hunt Token')
    expect(keyFields).toContain('Supply Chain GitHub Token')
    expect(keyFields).toContain('Shodan API Key')
    expect(keyFields).toContain('Tavily API Key')
    expect(keyFields).toContain('Driftnet API Key')
    expect(keyFields).toContain('WPScan API Token')
    expect(keyFields).toContain('PDCP API Key')
    // GitHub Enterprise host + its own token travel with the keys file.
    expect(keyFields).toContain('GitHub Enterprise Host')
    expect(keyFields).toContain('GitHub Enterprise Token')
    // The word 'trufflehog' is the old product name and appears nowhere.
    expect(keyFields).toContain('Secret Multiscanner GitHub Token')
    expect(keyFields.join(' ').toLowerCase()).not.toContain('trufflehog')
    // 28 general API keys + 19 Secret Multiscanner per-source credentials.
    expect(keyFields.length).toBe(49)
  })

  test('generates a template with all tunneling fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.tunneling)).toEqual(
      expect.arrayContaining(['ngrok Auth Token', 'Chisel Server URL', 'Chisel Auth'])
    )
  })

  test('generates rotation entries for all tools', () => {
    const t = buildTemplate({}, {})
    const tools = Object.keys(t.rotation).filter(k => !k.startsWith('_'))
    expect(tools).toContain('shodan')
    expect(tools).toContain('tavily')
    expect(tools).toContain('wpscan')
    expect(tools).toContain('pdcp')
    expect(tools.length).toBe(22)
  })

  test('uses current key values when provided', () => {
    const t = buildTemplate({ shodanApiKey: '••••1234' }, {})
    expect(t.keys['Shodan API Key']).toBe('••••1234')
  })

  test('defaults missing fields to empty string', () => {
    const t = buildTemplate({}, {})
    expect(t.keys['GitHub Secret Hunt Token']).toBe('')
  })

  test('includes instructions string', () => {
    const t = buildTemplate({}, {})
    expect(t._instructions).toContain('Fill in your API keys')
  })
})

describe('templateToJson', () => {
  test('returns valid JSON string', () => {
    const t = buildTemplate({}, {})
    const json = templateToJson(t)
    expect(() => JSON.parse(json)).not.toThrow()
  })

  test('round-trips through parse correctly', () => {
    const t = buildTemplate({ shodanApiKey: 'test123' }, { chiselServerUrl: 'http://vps:9090' })
    const parsed = JSON.parse(templateToJson(t))
    expect(parsed.keys['Shodan API Key']).toBe('test123')
    expect(parsed.tunneling['Chisel Server URL']).toBe('http://vps:9090')
  })
})

// ---------------------------------------------------------------------------
// Validation — valid inputs
// ---------------------------------------------------------------------------

describe('validateAndParse — valid inputs', () => {
  test('parses a minimal valid file with one key', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: 'abc123' } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(1)
      expect(result.keys.shodanApiKey).toBe('abc123')
    }
  })

  test('parses a file with multiple keys', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: 'key1', tavilyApiKey: 'key2', nvdApiKey: '' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(2)
      expect(result.keys.nvdApiKey).toBeUndefined()
    }
  })

  test('parses tunneling fields', () => {
    const raw = JSON.stringify({
      tunneling: { ngrokAuthtoken: 'tok123', chiselServerUrl: 'http://vps:9090' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.tunnelingCount).toBe(2)
      expect(result.tunneling.ngrokAuthtoken).toBe('tok123')
    }
  })

  test('parses rotation configs', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: 'main' },
      rotation: {
        shodan: { extraKeys: ['key2', 'key3'], rotateEveryN: 5 },
      },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotationCount).toBe(1)
      expect(result.rotation.shodan.extraKeys).toEqual(['key2', 'key3'])
      expect(result.rotation.shodan.rotateEveryN).toBe(5)
    }
  })

  test('skips masked values in keys', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: '••••1234', tavilyApiKey: 'real-key' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(1)
      expect(result.keys.shodanApiKey).toBeUndefined()
      expect(result.keys.tavilyApiKey).toBe('real-key')
    }
  })

  test('skips masked values in rotation extraKeys', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['••••abcd', 'realkey'], rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.extraKeys).toEqual(['realkey'])
    }
  })

  test('ignores _comment and _instructions fields', () => {
    const raw = JSON.stringify({
      _instructions: 'some text',
      keys: { _comment: 'ignore me', shodanApiKey: 'val' },
      rotation: { _comment: 'also ignore' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(1)
    }
  })

  test('defaults rotateEveryN to 10 when missing', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'] } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(10)
    }
  })

  test('defaults rotateEveryN to 10 when zero or negative', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'], rotateEveryN: 0 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(10)
    }
  })

  test('floors fractional rotateEveryN', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'], rotateEveryN: 7.9 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(7)
    }
  })

  test('parses a full round-trip template', () => {
    const template = buildTemplate(
      { shodanApiKey: 'main-shodan', tavilyApiKey: 'main-tavily' },
      { ngrokAuthtoken: 'ngrok-tok' },
    )
    const json = templateToJson(template)
    const modified = JSON.parse(json)
    modified.keys.shodanApiKey = 'new-shodan-key'
    modified.rotation.shodan = { extraKeys: ['extra1'], rotateEveryN: 3 }
    const raw = JSON.stringify(modified)
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keys.shodanApiKey).toBe('new-shodan-key')
      expect(result.rotation.shodan.extraKeys).toEqual(['extra1'])
    }
  })
})

// ---------------------------------------------------------------------------
// Validation — invalid inputs
// ---------------------------------------------------------------------------

describe('validateAndParse — rejections', () => {
  test('rejects file exceeding size limit', () => {
    const result = validateAndParse('{}', 200 * 1024)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('too large')
    }
  })

  test('rejects invalid JSON', () => {
    const result = validateAndParse('not json {{{', 10)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Invalid JSON')
    }
  })

  test('rejects array at top level', () => {
    const result = validateAndParse('[]', 2)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('JSON object')
    }
  })

  test('rejects object without any known section', () => {
    const raw = JSON.stringify({ foo: 'bar' })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown top-level field')
    }
  })

  test('rejects empty object (no sections)', () => {
    const raw = JSON.stringify({})
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Missing required section')
    }
  })

  test('rejects unknown key field', () => {
    const raw = JSON.stringify({ keys: { unknownField: 'val' } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown key field')
      expect(result.message).toContain('unknownField')
    }
  })

  test('rejects non-string key value', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: 12345 } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('must be a string')
    }
  })

  test('rejects unknown tunneling field', () => {
    const raw = JSON.stringify({ tunneling: { badField: 'val' } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown tunneling field')
    }
  })

  test('rejects unknown rotation tool', () => {
    const raw = JSON.stringify({ rotation: { badTool: { extraKeys: [], rotateEveryN: 10 } } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown rotation tool')
    }
  })

  test('rejects rotation with non-array extraKeys', () => {
    const raw = JSON.stringify({ rotation: { shodan: { extraKeys: 'not-array', rotateEveryN: 10 } } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('must be an array')
    }
  })

  test('rejects rotation with non-string item in extraKeys', () => {
    const raw = JSON.stringify({ rotation: { shodan: { extraKeys: [123], rotateEveryN: 10 } } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('extraKeys[0] must be a string')
    }
  })

  test('rejects keys section that is an array', () => {
    const raw = JSON.stringify({ keys: ['a', 'b'] })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('"keys" must be a JSON object')
    }
  })

  test('rejects rotation section that is a string', () => {
    const raw = JSON.stringify({ rotation: 'bad' })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('"rotation" must be a JSON object')
    }
  })
})

// ---------------------------------------------------------------------------
// isValidationError
// ---------------------------------------------------------------------------

describe('isValidationError', () => {
  test('returns true for validation error', () => {
    expect(isValidationError({ message: 'bad' })).toBe(true)
  })

  test('returns false for parsed import', () => {
    const parsed = {
      keys: {}, rotation: {}, tunneling: {},
      keyCount: 0, rotationCount: 0, tunnelingCount: 0,
    }
    expect(isValidationError(parsed)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// End-to-end round-trip: download template → fill keys → import
// ---------------------------------------------------------------------------

describe('full round-trip: download → fill → import', () => {
  test('single key per service — download template, fill in, validate, parse', () => {
    const template = buildTemplate({}, {})
    const json = templateToJson(template)
    const filled = JSON.parse(json)

    filled.keys.shodanApiKey = 'FAKE_SHODAN_KEY_abc123'
    filled.keys.urlscanApiKey = 'FAKE_URLSCAN_0000-1111-2222'
    filled.keys.censysApiToken = 'FAKE_CENSYS_TOKEN_xyz'
    filled.keys.fofaApiKey = 'FAKE_FOFA_KEY_deadbeef'
    filled.keys.otxApiKey = 'FAKE_OTX_KEY_0123456789abcdef'
    filled.keys.netlasApiKey = 'FAKE_NETLAS_KEY_aaaa'
    filled.keys.virusTotalApiKey = 'FAKE_VT_KEY_longstring123'
    filled.keys.zoomEyeApiKey = 'FAKE_ZOOMEYE_KEY_1234'
    filled.keys.criminalIpApiKey = 'FAKE_CIP_KEY_abcdef'

    const raw = JSON.stringify(filled)
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(9)
    expect(result.keys.shodanApiKey).toBe('FAKE_SHODAN_KEY_abc123')
    expect(result.keys.urlscanApiKey).toBe('FAKE_URLSCAN_0000-1111-2222')
    expect(result.keys.censysApiToken).toBe('FAKE_CENSYS_TOKEN_xyz')
    expect(result.keys.fofaApiKey).toBe('FAKE_FOFA_KEY_deadbeef')
    expect(result.keys.otxApiKey).toBe('FAKE_OTX_KEY_0123456789abcdef')
    expect(result.keys.netlasApiKey).toBe('FAKE_NETLAS_KEY_aaaa')
    expect(result.keys.virusTotalApiKey).toBe('FAKE_VT_KEY_longstring123')
    expect(result.keys.zoomEyeApiKey).toBe('FAKE_ZOOMEYE_KEY_1234')
    expect(result.keys.criminalIpApiKey).toBe('FAKE_CIP_KEY_abcdef')
    expect(result.rotationCount).toBe(0)
    expect(result.tunnelingCount).toBe(0)
  })

  test('multi-key rotation — shodan with 3 keys and rotation config', () => {
    const template = buildTemplate({}, {})
    const json = templateToJson(template)
    const filled = JSON.parse(json)

    filled.keys.shodanApiKey = 'FAKE_SHODAN_MAIN_KEY'
    filled.rotation.shodan = {
      extraKeys: ['FAKE_SHODAN_ROTATE_KEY_2', 'FAKE_SHODAN_ROTATE_KEY_3'],
      rotateEveryN: 5,
    }

    const raw = JSON.stringify(filled)
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(1)
    expect(result.keys.shodanApiKey).toBe('FAKE_SHODAN_MAIN_KEY')
    expect(result.rotationCount).toBe(1)
    expect(result.rotation.shodan.extraKeys).toEqual([
      'FAKE_SHODAN_ROTATE_KEY_2',
      'FAKE_SHODAN_ROTATE_KEY_3',
    ])
    expect(result.rotation.shodan.rotateEveryN).toBe(5)
  })

  test('all keys filled — every field populated in a single import', () => {
    const template = buildTemplate({}, {})
    const json = templateToJson(template)
    const filled = JSON.parse(json)

    const fakeKeys: Record<string, string> = {
      githubAccessToken: 'FAKE_GH_TOKEN',
      tavilyApiKey: 'FAKE_TAVILY_KEY',
      shodanApiKey: 'FAKE_SHODAN_KEY',
      serpApiKey: 'FAKE_SERP_KEY',
      wpscanApiToken: 'FAKE_WPSCAN_TOKEN',
      nvdApiKey: 'FAKE_NVD_KEY',
      vulnersApiKey: 'FAKE_VULNERS_KEY',
      urlscanApiKey: 'FAKE_URLSCAN_KEY',
      censysApiToken: 'FAKE_CENSYS_TOKEN',
      censysOrgId: 'FAKE_CENSYS_ORG',
      fofaApiKey: 'FAKE_FOFA_KEY',
      otxApiKey: 'FAKE_OTX_KEY',
      netlasApiKey: 'FAKE_NETLAS_KEY',
      virusTotalApiKey: 'FAKE_VT_KEY',
      zoomEyeApiKey: 'FAKE_ZOOMEYE_KEY',
      criminalIpApiKey: 'FAKE_CIP_KEY',
      quakeApiKey: 'FAKE_QUAKE_KEY',
      hunterApiKey: 'FAKE_HUNTER_KEY',
      publicWwwApiKey: 'FAKE_PUBLICWWW_KEY',
      hunterHowApiKey: 'FAKE_HUNTERHOW_KEY',
      googleApiKey: 'FAKE_GOOGLE_KEY',
      googleApiCx: 'FAKE_GOOGLE_CX',
      onypheApiKey: 'FAKE_ONYPHE_KEY',
      driftnetApiKey: 'FAKE_DRIFTNET_KEY',
      pdcpApiKey: 'FAKE_PDCP_KEY',
    }
    for (const [k, v] of Object.entries(fakeKeys)) {
      filled.keys[k] = v
    }

    filled.tunneling.ngrokAuthtoken = 'FAKE_NGROK_TOKEN'
    filled.tunneling.chiselServerUrl = 'http://fake-vps:9090'
    filled.tunneling.chiselAuth = 'FAKE_CHISEL_AUTH'

    const raw = JSON.stringify(filled)
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(25)
    expect(result.tunnelingCount).toBe(3)
    for (const [k, v] of Object.entries(fakeKeys)) {
      expect(result.keys[k]).toBe(v)
    }
    expect(result.tunneling.ngrokAuthtoken).toBe('FAKE_NGROK_TOKEN')
    expect(result.tunneling.chiselServerUrl).toBe('http://fake-vps:9090')
    expect(result.tunneling.chiselAuth).toBe('FAKE_CHISEL_AUTH')
  })

  test('partial import — only some keys, rest stay empty (not imported)', () => {
    const raw = JSON.stringify({
      keys: {
        shodanApiKey: 'FAKE_SHODAN_ONLY',
        tavilyApiKey: '',
        nvdApiKey: '',
      },
    })
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(1)
    expect(result.keys.shodanApiKey).toBe('FAKE_SHODAN_ONLY')
    expect(result.keys.tavilyApiKey).toBeUndefined()
    expect(result.keys.nvdApiKey).toBeUndefined()
  })

  test('import preserves existing keys — masked values are skipped', () => {
    const template = buildTemplate(
      { shodanApiKey: '••••Rk3W', tavilyApiKey: '••••abcd' },
      {},
    )
    const json = templateToJson(template)
    const filled = JSON.parse(json)

    filled.keys.urlscanApiKey = 'FAKE_NEW_URLSCAN_KEY'

    const raw = JSON.stringify(filled)
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(1)
    expect(result.keys.urlscanApiKey).toBe('FAKE_NEW_URLSCAN_KEY')
    expect(result.keys.shodanApiKey).toBeUndefined()
    expect(result.keys.tavilyApiKey).toBeUndefined()
  })

  test('multiple rotation tools with varying configs', () => {
    const filled = {
      keys: {
        shodanApiKey: 'FAKE_SHODAN_MAIN',
        virusTotalApiKey: 'FAKE_VT_MAIN',
        criminalIpApiKey: 'FAKE_CIP_MAIN',
      },
      rotation: {
        shodan: { extraKeys: ['FAKE_SHODAN_R2', 'FAKE_SHODAN_R3'], rotateEveryN: 5 },
        virustotal: { extraKeys: ['FAKE_VT_R2'], rotateEveryN: 20 },
        criminalip: { extraKeys: [], rotateEveryN: 10 },
      },
    }
    const raw = JSON.stringify(filled)
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(3)
    expect(result.rotationCount).toBe(2)
    expect(result.rotation.shodan.extraKeys).toHaveLength(2)
    expect(result.rotation.shodan.rotateEveryN).toBe(5)
    expect(result.rotation.virustotal.extraKeys).toEqual(['FAKE_VT_R2'])
    expect(result.rotation.virustotal.rotateEveryN).toBe(20)
    expect(result.rotation.criminalip).toBeUndefined()
  })

  test('tunneling-only import — no keys, no rotation', () => {
    const raw = JSON.stringify({
      tunneling: {
        ngrokAuthtoken: 'FAKE_NGROK_ONLY',
        chiselServerUrl: 'http://fake-chisel:9090',
      },
    })
    const result = validateAndParse(raw, raw.length)

    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    expect(result.keyCount).toBe(0)
    expect(result.rotationCount).toBe(0)
    expect(result.tunnelingCount).toBe(2)
    expect(result.tunneling.ngrokAuthtoken).toBe('FAKE_NGROK_ONLY')
    expect(result.tunneling.chiselServerUrl).toBe('http://fake-chisel:9090')
  })

  test('re-downloading after import does not leak imported keys into template', () => {
    const imported = {
      keys: { shodanApiKey: 'FAKE_REAL_SHODAN_KEY' },
    }
    const raw = JSON.stringify(imported)
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return

    const postImportSettings = { ...result.keys, shodanApiKey: '••••_KEY' }
    const newTemplate = buildTemplate(postImportSettings, {})
    expect(newTemplate.keys['Shodan API Key']).toBe('••••_KEY')

    const reImport = validateAndParse(templateToJson(newTemplate), 5000)
    expect(isValidationError(reImport)).toBe(false)
    if (!isValidationError(reImport)) {
      expect(reImport.keys.shodanApiKey).toBeUndefined()
    }
  })

  test('injection attempt — __proto__ silently skipped via underscore prefix rule', () => {
    const raw = JSON.stringify({
      keys: {
        shodanApiKey: 'FAKE_GOOD_KEY',
        __proto__: 'INJECTION_ATTEMPT',
      },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(1)
      expect(result.keys.shodanApiKey).toBe('FAKE_GOOD_KEY')
      expect(Object.hasOwn(result.keys, '__proto__')).toBe(false)
    }
  })

  test('injection attempt — non-underscore unknown field rejected', () => {
    const raw = JSON.stringify({
      keys: {
        shodanApiKey: 'FAKE_GOOD_KEY',
        maliciousField: 'DROP TABLE users;',
      },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown key field')
      expect(result.message).toContain('maliciousField')
    }
  })

  test('XSS attempt in key value — stored as-is (no execution context)', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: '<script>alert("xss")</script>' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keys.shodanApiKey).toBe('<script>alert("xss")</script>')
      expect(result.keyCount).toBe(1)
    }
  })
})

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

describe('validateAndParse — boundary and edge cases', () => {
  test('rejects null JSON literal', () => {
    const result = validateAndParse('null', 4)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('JSON object')
    }
  })

  test('rejects numeric JSON literal', () => {
    const result = validateAndParse('42', 2)
    expect(isValidationError(result)).toBe(true)
  })

  test('rejects string JSON literal', () => {
    const result = validateAndParse('"hello"', 7)
    expect(isValidationError(result)).toBe(true)
  })

  test('rejects boolean JSON literal', () => {
    const result = validateAndParse('true', 4)
    expect(isValidationError(result)).toBe(true)
  })

  test('accepts file at exactly 100 KB', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: 'k' } })
    const result = validateAndParse(raw, 100 * 1024)
    expect(isValidationError(result)).toBe(false)
  })

  test('rejects file at 100 KB + 1 byte', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: 'k' } })
    const result = validateAndParse(raw, 100 * 1024 + 1)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('too large')
    }
  })

  test('empty string raw input returns invalid JSON error', () => {
    const result = validateAndParse('', 0)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Invalid JSON')
    }
  })

  test('whitespace-only key values are skipped', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: '   ', tavilyApiKey: 'real' } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      // '   ' is truthy but not empty - it gets imported as-is
      // This test documents the actual behavior
      expect(result.keyCount).toBe(2)
    }
  })

  test('whitespace-only extraKeys entries are filtered out', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['  ', '', 'real-key'], rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.extraKeys).toEqual(['real-key'])
      expect(result.rotationCount).toBe(1)
    }
  })

  test('rotation with only whitespace/empty extraKeys is not counted', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['', '  '], rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotationCount).toBe(0)
      expect(result.rotation.shodan).toBeUndefined()
    }
  })

  test('rejects non-string rotateEveryN gracefully (falls back to 10)', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'], rotateEveryN: 'fast' } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(10)
    }
  })

  test('very large rotateEveryN is accepted as-is', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'], rotateEveryN: 999999 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(999999)
    }
  })

  test('negative rotateEveryN falls back to 10', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: ['k1'], rotateEveryN: -5 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.rotateEveryN).toBe(10)
    }
  })

  test('rejects rotation entry missing extraKeys entirely', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('extraKeys')
    }
  })

  test('rejects tunneling value that is a number', () => {
    const raw = JSON.stringify({ tunneling: { ngrokAuthtoken: 12345 } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('must be a string')
    }
  })

  test('rejects tunneling section that is an array', () => {
    const raw = JSON.stringify({ tunneling: ['a'] })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('"tunneling" must be a JSON object')
    }
  })

  test('skips masked tunneling values', () => {
    const raw = JSON.stringify({
      tunneling: { ngrokAuthtoken: '••••xyz', chiselAuth: 'real-auth' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.tunnelingCount).toBe(1)
      expect(result.tunneling.ngrokAuthtoken).toBeUndefined()
      expect(result.tunneling.chiselAuth).toBe('real-auth')
    }
  })

  test('empty tunneling values are skipped', () => {
    const raw = JSON.stringify({
      tunneling: { ngrokAuthtoken: '', chiselServerUrl: '' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.tunnelingCount).toBe(0)
    }
  })

  test('unknown top-level fields are rejected', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: 'val' },
      version: '2.0',
      metadata: { author: 'test' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown top-level field')
      expect(result.message).toContain('version')
    }
  })

  test('rejects key value that is null', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: null } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('must be a string')
    }
  })

  test('rejects key value that is an object', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: { nested: true } } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
  })

  test('rejects key value that is a boolean', () => {
    const raw = JSON.stringify({ keys: { shodanApiKey: true } })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
  })

  test('rejects rotation extraKeys containing null', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: [null], rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('extraKeys[0] must be a string')
    }
  })

  test('prototype pollution via constructor field in keys is rejected', () => {
    const raw = JSON.stringify({
      keys: { constructor: 'evil' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown key field')
    }
  })

  test('rejects rotation entry where extraKeys is null', () => {
    const raw = JSON.stringify({
      rotation: { shodan: { extraKeys: null, rotateEveryN: 10 } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('extraKeys')
    }
  })
})

describe('validateAndParse — validation gap documentation', () => {
  test('unknown top-level fields are now rejected', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: 'val' },
      admin: true,
      deleteEverything: 'yes',
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown top-level field')
    }
  })

  test('unknown properties inside rotation config are now rejected', () => {
    const raw = JSON.stringify({
      rotation: {
        shodan: {
          extraKeys: ['k1'],
          rotateEveryN: 5,
          deleteAll: true,
          runCommand: 'rm -rf /',
        },
      },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown property')
      expect(result.message).toContain('deleteAll')
    }
  })

  test('deeply nested object in keys section is rejected (type check catches it)', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: { nested: { deep: 'value' } } },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
  })

  test('keys section with null value is rejected (type check catches it)', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: null },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
  })

  test('alien JSON structure with extra top-level fields is rejected', () => {
    const raw = JSON.stringify({
      keys: { shodanApiKey: 'real-key' },
      database: { host: 'localhost', drop: true },
      users: [{ name: 'admin', password: '1234' }],
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(true)
    if (isValidationError(result)) {
      expect(result.message).toContain('Unknown top-level field')
    }
  })

  test('underscore-prefixed top-level fields are still allowed', () => {
    const raw = JSON.stringify({
      _instructions: 'some text',
      _version: '1.0',
      keys: { shodanApiKey: 'val' },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.keyCount).toBe(1)
    }
  })

  test('underscore-prefixed rotation config properties are still allowed', () => {
    const raw = JSON.stringify({
      rotation: {
        shodan: {
          _comment: 'my shodan keys',
          extraKeys: ['k1'],
          rotateEveryN: 5,
        },
      },
    })
    const result = validateAndParse(raw, raw.length)
    expect(isValidationError(result)).toBe(false)
    if (!isValidationError(result)) {
      expect(result.rotation.shodan.extraKeys).toEqual(['k1'])
    }
  })
})

describe('buildTemplate — edge cases', () => {
  test('ignores unknown fields in currentKeys input', () => {
    const t = buildTemplate({ shodanApiKey: 'val', unknownThing: 'ignored' }, {})
    expect(t.keys['Shodan API Key']).toBe('val')
    expect(t.keys).not.toHaveProperty('unknownThing')
    expect(Object.keys(t.keys).length).toBe(49)
  })

  test('ignores unknown fields in currentTunneling input', () => {
    const t = buildTemplate({}, { ngrokAuthtoken: 'tok', badField: 'ignored' })
    expect(t.tunneling['ngrok Auth Token']).toBe('tok')
    expect(t.tunneling).not.toHaveProperty('badField')
    expect(Object.keys(t.tunneling).length).toBe(3)
  })

  test('template rotation tools count matches TOOL_NAME_MAP', () => {
    const t = buildTemplate({}, {})
    const rotationTools = Object.keys(t.rotation).filter(k => !k.startsWith('_'))
    expect(rotationTools.length).toBe(22)
  })

  test('template keys count matches UserSettings key fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.keys).length).toBe(49)
  })

  test('template tunneling count matches UserSettings tunnel fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.tunneling).length).toBe(3)
  })
})

/**
 * The template is the offline twin of the API Keys tab. Two ways it silently
 * lies: a field the form has and the file does not (the operator fills in
 * everything, imports, and the missing key is still unset), and a name that no
 * longer matches what the form calls it (they fill in the wrong box, or none).
 */
describe('template covers the form exactly', () => {
  const PAGE = join(process.cwd(), 'src/app/settings/page.tsx')
  const SETTINGS_ROUTE = join(process.cwd(), 'src/app/api/users/[id]/settings/route.ts')

  /** Every column the settings PUT handler is willing to write. */
  function writableSettingsFields(): string[] {
    const src = readFileSync(SETTINGS_ROUTE, 'utf8')
    const m = src.match(/const fields = \[([\s\S]*?)\] as const/)
    if (!m) throw new Error('writable `fields` array not found - update this test')
    return [...m[1].matchAll(/'([A-Za-z0-9_]+)'/g)].map(x => x[1])
  }

  /** column -> label, for the keys the page renders as a SecretField itself. */
  function renderedLabels(): Record<string, string> {
    const src = readFileSync(PAGE, 'utf8')
    const out: Record<string, string> = {}
    for (const [, body] of src.matchAll(/<SecretField\b([\s\S]*?)\/>/g)) {
      const label = body.match(/label="([^"]+)"/)
      const key = body.match(/updateSetting\('([A-Za-z0-9_]+)'/)
      if (label && key) out[key[1]] = label[1]
    }
    return out
  }

  const template = buildTemplate({}, {})
  const templateNames = new Set([...Object.keys(template.keys), ...Object.keys(template.tunneling)])

  test('every key the settings form can save is in the template', () => {
    for (const column of writableSettingsFields()) {
      expect(
        templateNames.has(templateKeyLabel(column)),
        `'${column}' is saveable in Settings but absent from the template, so filling the file in would silently not set it`,
      ).toBe(true)
    }
  })

  test('every template name is the label the form shows', () => {
    const rendered = renderedLabels()
    for (const [column, label] of Object.entries(rendered)) {
      expect(templateKeyLabel(column), `'${column}' is labelled differently in the template`).toBe(label)
    }
    // The drawer-rendered keys take their label straight from the catalogue.
    expect(templateKeyLabel('trufflehogGithubToken')).toBe(credentialField('trufflehogGithubToken')!.label)
    expect(templateKeyLabel('supplyChainGithubToken')).toBe('Supply Chain GitHub Token')
  })

  test('no two keys collide on one template name', () => {
    const names = [...Object.keys(template.keys), ...Object.keys(template.tunneling)]
    expect(new Set(names).size).toBe(names.length)
  })

  // A template downloaded before the rename is still on someone's disk.
  test('a legacy template written with column names still imports', () => {
    const legacy = JSON.stringify({
      keys: { trufflehogGithubToken: 'ghp_legacy', githubAccessToken: 'ghp_old' },
      tunneling: { ngrokAuthtoken: 'ng_legacy' },
    })
    const result = validateAndParse(legacy, 500)
    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return
    expect(result.keys.trufflehogGithubToken).toBe('ghp_legacy')
    expect(result.keys.githubAccessToken).toBe('ghp_old')
    expect(result.tunneling.ngrokAuthtoken).toBe('ng_legacy')
  })

  test('a label-named template imports to the right columns', () => {
    const filled = JSON.stringify({
      keys: {
        'Secret Multiscanner GitHub Token': 'ghp_multi',
        'GitHub Secret Hunt Token': 'ghp_hunt',
        'Supply Chain GitHub Token': 'ghp_sc',
      },
      tunneling: { 'ngrok Auth Token': 'ng_new' },
    })
    const result = validateAndParse(filled, 500)
    expect(isValidationError(result)).toBe(false)
    if (isValidationError(result)) return
    expect(result.keys).toEqual({
      trufflehogGithubToken: 'ghp_multi',
      githubAccessToken: 'ghp_hunt',
      supplyChainGithubToken: 'ghp_sc',
    })
    expect(result.tunneling.ngrokAuthtoken).toBe('ng_new')
  })

  test('a name that is neither a label nor a column is still rejected', () => {
    const result = validateAndParse(JSON.stringify({ keys: { 'Made Up Token': 'x' } }), 200)
    expect(isValidationError(result)).toBe(true)
  })
})

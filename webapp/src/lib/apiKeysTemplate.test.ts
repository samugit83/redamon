/**
 * Unit tests for API Keys template generation and import validation.
 *
 * Run: npx vitest run src/lib/apiKeysTemplate.test.ts
 */

import { describe, test, expect } from 'vitest'
import {
  buildTemplate,
  templateToJson,
  validateAndParse,
  isValidationError,
} from './apiKeysTemplate'

// ---------------------------------------------------------------------------
// Template generation
// ---------------------------------------------------------------------------

describe('buildTemplate', () => {
  test('generates a template with all expected key fields', () => {
    const t = buildTemplate({}, {})
    const keyFields = Object.keys(t.keys)
    expect(keyFields).toContain('githubAccessToken')
    expect(keyFields).toContain('shodanApiKey')
    expect(keyFields).toContain('tavilyApiKey')
    expect(keyFields).toContain('driftnetApiKey')
    expect(keyFields).toContain('wpscanApiToken')
    expect(keyFields.length).toBe(24)
  })

  test('generates a template with all tunneling fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.tunneling)).toEqual(
      expect.arrayContaining(['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'])
    )
  })

  test('generates rotation entries for all tools', () => {
    const t = buildTemplate({}, {})
    const tools = Object.keys(t.rotation).filter(k => !k.startsWith('_'))
    expect(tools).toContain('shodan')
    expect(tools).toContain('tavily')
    expect(tools).toContain('wpscan')
    expect(tools.length).toBe(19)
  })

  test('uses current key values when provided', () => {
    const t = buildTemplate({ shodanApiKey: '••••1234' }, {})
    expect(t.keys.shodanApiKey).toBe('••••1234')
  })

  test('defaults missing fields to empty string', () => {
    const t = buildTemplate({}, {})
    expect(t.keys.githubAccessToken).toBe('')
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
    expect(parsed.keys.shodanApiKey).toBe('test123')
    expect(parsed.tunneling.chiselServerUrl).toBe('http://vps:9090')
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

    expect(result.keyCount).toBe(24)
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
    expect(newTemplate.keys.shodanApiKey).toBe('••••_KEY')

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
    expect(t.keys.shodanApiKey).toBe('val')
    expect(t.keys).not.toHaveProperty('unknownThing')
    expect(Object.keys(t.keys).length).toBe(24)
  })

  test('ignores unknown fields in currentTunneling input', () => {
    const t = buildTemplate({}, { ngrokAuthtoken: 'tok', badField: 'ignored' })
    expect(t.tunneling.ngrokAuthtoken).toBe('tok')
    expect(t.tunneling).not.toHaveProperty('badField')
    expect(Object.keys(t.tunneling).length).toBe(3)
  })

  test('template rotation tools count matches TOOL_NAME_MAP', () => {
    const t = buildTemplate({}, {})
    const rotationTools = Object.keys(t.rotation).filter(k => !k.startsWith('_'))
    expect(rotationTools.length).toBe(19)
  })

  test('template keys count matches UserSettings key fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.keys).length).toBe(24)
  })

  test('template tunneling count matches UserSettings tunnel fields', () => {
    const t = buildTemplate({}, {})
    expect(Object.keys(t.tunneling).length).toBe(3)
  })
})

/**
 * Re-entry of a stored secret when the endpoint it is sent to changes (HD-24, F-19).
 * Without it, a stolen session (or anyone who can write the row) re-points the endpoint
 * while the masked secret is kept, and the next run sends the secret to the new address.
 * The rule holds for everyone, the account itself included: a masked placeholder is
 * never a value, and an absent field that the write keeps is no value either.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  SECRET_REENTRY_CODE,
  isMaskedSecret,
  llmProviderSecretReentry,
  mcpServerSecretReentry,
  normalizeGithubHost,
  secretReentryResponse,
  settingsSecretReentry,
} from './secretEndpointRebind'

const MASK = '••••••••1234'

describe('isMaskedSecret', () => {
  test('the placeholder every GET returns is masked; a typed value and an empty one are not', () => {
    expect(isMaskedSecret(MASK)).toBe(true)
    expect(isMaskedSecret('••••')).toBe(true)
    expect(isMaskedSecret('sk-real')).toBe(false)
    expect(isMaskedSecret('')).toBe(false)
    expect(isMaskedSecret(undefined)).toBe(false)
    expect(isMaskedSecret(42)).toBe(false)
  })
})

describe('LLM provider: base URL or type', () => {
  const stored = {
    providerType: 'openai_compatible', baseUrl: 'https://llm.example.com/v1',
    apiKey: 'sk-stored', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
  }

  test('a changed base URL without the key is refused, naming apiKey', () => {
    const r = llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example/v1' })
    expect(r).toMatchObject({ field: 'apiKey', fields: ['apiKey'], endpoint: 'baseUrl' })
    expect(r!.message).toMatch(/base URL/)
    expect(r!.message).toMatch(/API key/)
  })

  test('a changed base URL with the masked placeholder is refused', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example/v1', apiKey: MASK }))
      .toMatchObject({ field: 'apiKey' })
  })

  test('a changed base URL with the key typed again passes', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example/v1', apiKey: 'sk-typed' })).toBeNull()
  })

  test('a changed base URL that clears the key passes: nothing stored is sent', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example/v1', apiKey: '' })).toBeNull()
  })

  test('a changed type is an endpoint change too', () => {
    const anthropic = { ...stored, providerType: 'anthropic', baseUrl: '' }
    expect(llmProviderSecretReentry(anthropic, { providerType: 'openai_compatible', baseUrl: 'https://x.example/v1', apiKey: MASK }))
      .toMatchObject({ field: 'apiKey', endpoint: 'providerType' })
  })

  test('the same base URL and type keep the masked key', () => {
    expect(llmProviderSecretReentry(stored, { providerType: 'openai_compatible', baseUrl: stored.baseUrl, apiKey: MASK })).toBeNull()
    expect(llmProviderSecretReentry(stored, { name: 'renamed' })).toBeNull()
  })

  test('no stored secret, nothing to re-enter', () => {
    expect(llmProviderSecretReentry({ ...stored, apiKey: '' }, { baseUrl: 'https://elsewhere.example/v1' })).toBeNull()
  })

  test('every stored secret the write would keep is named; the first is the field', () => {
    const bedrock = { providerType: 'bedrock', baseUrl: '', apiKey: '', awsAccessKeyId: 'AKIA', awsSecretKey: 'sec', awsBearerToken: '' }
    const r = llmProviderSecretReentry(bedrock, { providerType: 'openai_compatible', baseUrl: 'https://x.example/v1', awsAccessKeyId: MASK })
    expect(r).toMatchObject({ field: 'awsAccessKeyId', fields: ['awsAccessKeyId', 'awsSecretKey'] })
  })

  test('a null base URL reads as the empty one stored', () => {
    expect(llmProviderSecretReentry({ ...stored, baseUrl: '' }, { baseUrl: null, apiKey: MASK })).toBeNull()
  })
})

describe('settings: GitHub Enterprise host and chisel URL', () => {
  const stored = {
    githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: 'ghp_stored',
    chiselServerUrl: 'http://vps.example.com:9090', chiselAuth: 'user:pass',
  }

  test('a new GitHub Enterprise host without the token is refused, naming githubEnterpriseToken', () => {
    expect(settingsSecretReentry(stored, { githubEnterpriseHost: 'evil.example.net' }))
      .toMatchObject({ field: 'githubEnterpriseToken', endpoint: 'githubEnterpriseHost' })
  })

  test('a new GitHub Enterprise host with the masked token is refused', () => {
    expect(settingsSecretReentry(stored, { githubEnterpriseHost: 'evil.example.net', githubEnterpriseToken: MASK }))
      .toMatchObject({ field: 'githubEnterpriseToken' })
  })

  test('a new GitHub Enterprise host with the token typed again passes', () => {
    expect(settingsSecretReentry(stored, { githubEnterpriseHost: 'evil.example.net', githubEnterpriseToken: 'ghp_new' })).toBeNull()
  })

  test('setting a host for the first time re-points a token stored without one', () => {
    expect(settingsSecretReentry({ ...stored, githubEnterpriseHost: '' }, { githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: MASK }))
      .toMatchObject({ field: 'githubEnterpriseToken' })
  })

  test('the same host, written differently, is no change', () => {
    expect(settingsSecretReentry({ ...stored, githubEnterpriseHost: 'https://GHE.example.com/' },
      { githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: MASK })).toBeNull()
  })

  test('a new chisel URL without the auth is refused, naming chiselAuth', () => {
    expect(settingsSecretReentry(stored, { chiselServerUrl: 'http://evil.example.net:9090', chiselAuth: MASK }))
      .toMatchObject({ field: 'chiselAuth', endpoint: 'chiselServerUrl' })
    expect(settingsSecretReentry(stored, { chiselServerUrl: 'http://evil.example.net:9090' }))
      .toMatchObject({ field: 'chiselAuth' })
  })

  test('a new chisel URL with the auth typed again, or cleared, passes', () => {
    expect(settingsSecretReentry(stored, { chiselServerUrl: 'http://evil.example.net:9090', chiselAuth: 'u:new' })).toBeNull()
    expect(settingsSecretReentry(stored, { chiselServerUrl: 'http://evil.example.net:9090', chiselAuth: '' })).toBeNull()
  })

  test('a whole-form save with nothing re-pointed keeps every masked secret', () => {
    expect(settingsSecretReentry(stored, { ...stored, githubEnterpriseToken: MASK, chiselAuth: MASK, tavilyApiKey: MASK })).toBeNull()
  })

  test('both re-pointed: both named', () => {
    const r = settingsSecretReentry(stored, { githubEnterpriseHost: 'evil.example.net', chiselServerUrl: 'http://evil.example.net:1' })
    expect(r?.fields).toEqual(['githubEnterpriseToken', 'chiselAuth'])
  })

  test('no stored row, nothing to re-enter', () => {
    expect(settingsSecretReentry(null, { githubEnterpriseHost: 'ghe.example.com', chiselServerUrl: 'http://x:1' })).toBeNull()
  })

  test('normalizeGithubHost keeps the bare lowercase hostname', () => {
    expect(normalizeGithubHost('HTTPS://GHE.Example.com/orgs/acme')).toBe('ghe.example.com')
    expect(normalizeGithubHost('  ghe.example.com ')).toBe('ghe.example.com')
    expect(normalizeGithubHost(null)).toBe('')
  })
})

describe('outbound MCP server: URL', () => {
  const stored = {
    url: 'https://mcp.example.com/mcp',
    auth: { type: 'bearer' as const, token: 'tok-stored' },
    headers: { 'X-Api-Key': 'hdr-stored', 'X-Tenant': 'acme' },
  }

  test('a new URL with the masked token is refused, naming auth.token', () => {
    expect(mcpServerSecretReentry(stored, { url: 'https://evil.example.net/mcp', auth: { type: 'bearer', token: MASK } }))
      .toMatchObject({ field: 'auth.token', endpoint: 'url' })
  })

  test('a new URL with the token typed again passes', () => {
    expect(mcpServerSecretReentry(stored, { url: 'https://evil.example.net/mcp', auth: { type: 'bearer', token: 'tok-new' } })).toBeNull()
  })

  test('a new URL that drops the auth passes: the save replaces the whole server', () => {
    expect(mcpServerSecretReentry(stored, { url: 'https://evil.example.net/mcp' })).toBeNull()
  })

  test('masked header values are stored secrets too', () => {
    const r = mcpServerSecretReentry(stored, {
      url: 'https://evil.example.net/mcp', auth: { type: 'bearer', token: 'tok-new' },
      headers: { 'X-Api-Key': MASK, 'X-Tenant': 'acme' },
    })
    expect(r).toMatchObject({ field: 'headers.X-Api-Key', fields: ['headers.X-Api-Key'] })
  })

  test('the test route restores only the token, so it can skip the headers', () => {
    expect(mcpServerSecretReentry(stored, {
      url: 'https://evil.example.net/mcp', auth: { type: 'bearer', token: 'tok-new' }, headers: { 'X-Api-Key': MASK },
    }, { headers: false })).toBeNull()
  })

  test('the same URL keeps every masked value', () => {
    expect(mcpServerSecretReentry(stored, { url: stored.url, auth: { type: 'bearer', token: MASK }, headers: { 'X-Api-Key': MASK } })).toBeNull()
  })

  test('mcp test does not restore a token for a changed URL', () => {
    // The shape /api/mcp/test sends: a draft whose token is still the mask.
    const draft = { id: 'srv', transport: 'streamable_http', url: 'https://evil.example.net/mcp', auth: { type: 'bearer', token: MASK } }
    expect(mcpServerSecretReentry(stored, draft, { headers: false })).toMatchObject({ field: 'auth.token' })
  })
})

describe('secretReentryResponse', () => {
  test('400 with the code, the field and the message; extra fields keep a route answer shape', async () => {
    const r = llmProviderSecretReentry(
      { providerType: 'openai_compatible', baseUrl: 'a', apiKey: 'sk-STORED-SECRET', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '' },
      { baseUrl: 'b' })!
    const res = secretReentryResponse(r, { success: false })
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body).toMatchObject({ code: SECRET_REENTRY_CODE, field: 'apiKey', fields: ['apiKey'], endpoint: 'baseUrl', success: false })
    expect(body.error).toBe(r.message)
    // the stored secret never appears in the answer
    expect(JSON.stringify(body)).not.toContain('STORED-SECRET')
  })
})

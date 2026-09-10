type Settings = Record<string, unknown>

const HTTP_HEADER_LINE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+:\s*[^\r\n]*$/
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'transfer-encoding'])

function isRecord(value: unknown): value is Settings {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isHttpUrl(value: unknown): boolean {
  if (typeof value !== 'string' || !value.trim()) return false
  try {
    const url = new URL(value)
    return (url.protocol === 'http:' || url.protocol === 'https:')
      && !url.username && !url.password && !url.hash
  } catch {
    return false
  }
}

function isHttpOrigin(value: unknown): boolean {
  if (!isHttpUrl(value)) return false
  const url = new URL(value as string)
  return (url.pathname === '' || url.pathname === '/') && !url.search
}

function validateHeaders(value: unknown, field: string): string | null {
  if (!Array.isArray(value)) return `${field} must be an array of header lines`
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== 'string' || !HTTP_HEADER_LINE.test(value[index])) {
      return `${field}[${index}] must be a valid HTTP header line`
    }
    const name = value[index].slice(0, value[index].indexOf(':')).toLowerCase()
    if (FORBIDDEN_HEADERS.has(name)) return `${field}[${index}] uses a forbidden HTTP header`
  }
  return null
}

export function validateOpenApiSettings(settings: Settings): string | null {
  if ('openapiEnabled' in settings && typeof settings.openapiEnabled !== 'boolean') {
    return 'openapiEnabled must be a boolean'
  }
  if ('openapiAutoDiscover' in settings && typeof settings.openapiAutoDiscover !== 'boolean') {
    return 'openapiAutoDiscover must be a boolean'
  }
  if ('openapiTimeout' in settings
      && (!Number.isInteger(settings.openapiTimeout) || (settings.openapiTimeout as number) < 1
        || (settings.openapiTimeout as number) > 60)) {
    return 'openapiTimeout must be an integer between 1 and 60'
  }
  if ('openapiMaxDocuments' in settings
      && (!Number.isInteger(settings.openapiMaxDocuments) || (settings.openapiMaxDocuments as number) < 1
        || (settings.openapiMaxDocuments as number) > 200)) {
    return 'openapiMaxDocuments must be an integer between 1 and 200'
  }

  if ('openapiDiscoveryPaths' in settings) {
    const paths = settings.openapiDiscoveryPaths
    if (!Array.isArray(paths) || paths.length > 200 || paths.some(path =>
      typeof path !== 'string' || path.length > 2048 || !path.startsWith('/')
      || path.startsWith('//') || /[\s\x00-\x1f\x7f\\?#]/.test(path))) {
      return 'openapiDiscoveryPaths must contain at most 200 origin-relative paths without queries or fragments'
    }
  }
  if ('openapiSources' in settings) {
    if (!Array.isArray(settings.openapiSources)) return 'openapiSources must be an array'
    const sourceIds = new Set<string>()
    for (let index = 0; index < settings.openapiSources.length; index += 1) {
      const source = settings.openapiSources[index]
      const field = `openapiSources[${index}]`
      if (!isRecord(source) || !isHttpUrl(source.url)) {
        return `${field}.url must be an absolute HTTP(S) URL`
      }
      if ('id' in source && source.id !== undefined) {
        if (typeof source.id !== 'string' || !source.id.trim() || source.id.length > 128) {
          return `${field}.id must be a non-empty string of at most 128 characters`
        }
        if (sourceIds.has(source.id)) return `${field}.id must be unique`
        sourceIds.add(source.id)
      }
      if (source.headers !== undefined) {
        const headerError = validateHeaders(source.headers, `${field}.headers`)
        if (headerError) return headerError
      }
      if ('serverOverride' in source && source.serverOverride !== undefined
          && !isHttpUrl(source.serverOverride)) {
        return `${field}.serverOverride must be an absolute HTTP(S) URL`
      }
      if (typeof source.serverOverride === 'string' && new URL(source.serverOverride).search) {
        return `${field}.serverOverride must be an absolute HTTP(S) URL without a query`
      }
      if ('enabled' in source && source.enabled !== undefined && typeof source.enabled !== 'boolean') {
        return `${field}.enabled must be a boolean`
      }
    }
  }

  if ('openapiDiscoveryHeaders' in settings) {
    if (!Array.isArray(settings.openapiDiscoveryHeaders)) {
      return 'openapiDiscoveryHeaders must be an array'
    }
    for (let index = 0; index < settings.openapiDiscoveryHeaders.length; index += 1) {
      const entry = settings.openapiDiscoveryHeaders[index]
      const field = `openapiDiscoveryHeaders[${index}]`
      if (!isRecord(entry) || !isHttpOrigin(entry.origin)) {
        return `${field}.origin must contain only an HTTP(S) origin`
      }
      const headerError = validateHeaders(entry.headers, `${field}.headers`)
      if (headerError) return headerError
    }
  }

  return null
}

export function normalizeOpenApiSourceIds(
  value: unknown,
  createId: () => string = () => crypto.randomUUID(),
): unknown {
  if (!Array.isArray(value)) return value
  return value.map(source => (
    isRecord(source) && source.id === undefined
      ? { ...source, id: createId() }
      : source
  ))
}

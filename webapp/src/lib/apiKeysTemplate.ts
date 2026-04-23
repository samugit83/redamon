/**
 * API Keys template generation, validation, and import logic.
 *
 * All functions are pure (no side effects) so they can be unit-tested
 * without a DOM or React environment.
 */

const MAX_FILE_SIZE = 100 * 1024 // 100 KB

const ALLOWED_KEY_FIELDS = [
  'githubAccessToken',
  'tavilyApiKey',
  'shodanApiKey',
  'serpApiKey',
  'wpscanApiToken',
  'nvdApiKey',
  'vulnersApiKey',
  'urlscanApiKey',
  'censysApiToken',
  'censysOrgId',
  'fofaApiKey',
  'otxApiKey',
  'netlasApiKey',
  'virusTotalApiKey',
  'zoomEyeApiKey',
  'criminalIpApiKey',
  'quakeApiKey',
  'hunterApiKey',
  'publicWwwApiKey',
  'hunterHowApiKey',
  'googleApiKey',
  'googleApiCx',
  'onypheApiKey',
  'driftnetApiKey',
] as const

const ALLOWED_TUNNEL_FIELDS = [
  'ngrokAuthtoken',
  'chiselServerUrl',
  'chiselAuth',
] as const

const ALLOWED_ROTATION_TOOLS = [
  'tavily', 'shodan', 'serp', 'nvd', 'vulners', 'urlscan',
  'fofa', 'otx', 'netlas', 'virustotal', 'zoomeye', 'criminalip',
  'quake', 'hunter', 'publicwww', 'hunterhow', 'onyphe', 'driftnet', 'wpscan',
] as const

const ALLOWED_KEY_SET = new Set<string>(ALLOWED_KEY_FIELDS)
const ALLOWED_TUNNEL_SET = new Set<string>(ALLOWED_TUNNEL_FIELDS)
const ALLOWED_ROTATION_SET = new Set<string>(ALLOWED_ROTATION_TOOLS)

// ---------------------------------------------------------------------------
// Template generation
// ---------------------------------------------------------------------------

export interface ApiKeysTemplate {
  _instructions: string
  keys: Record<string, string>
  rotation: Record<string, { extraKeys: string[]; rotateEveryN: number } | { _comment: string }>
  tunneling: Record<string, string>
}

export function buildTemplate(
  currentKeys: Record<string, string>,
  currentTunneling: Record<string, string>,
): ApiKeysTemplate {
  const keys: Record<string, string> = {}
  for (const field of ALLOWED_KEY_FIELDS) {
    keys[field] = currentKeys[field] ?? ''
  }

  const tunneling: Record<string, string> = {}
  for (const field of ALLOWED_TUNNEL_FIELDS) {
    tunneling[field] = currentTunneling[field] ?? ''
  }

  const rotation: Record<string, { extraKeys: string[]; rotateEveryN: number } | { _comment: string }> = {
    _comment: 'Optional. Add extra keys for rotation. rotateEveryN = switch key every N API calls.' as never,
  }
  for (const tool of ALLOWED_ROTATION_TOOLS) {
    rotation[tool] = { extraKeys: [], rotateEveryN: 10 }
  }

  return {
    _instructions: 'Fill in your API keys below. Leave empty strings for keys you don\'t use. For key rotation, add multiple keys to the array. Upload this file back to RedAmon at Settings > API Keys & Tunneling.',
    keys,
    rotation,
    tunneling,
  }
}

export function templateToJson(template: ApiKeysTemplate): string {
  return JSON.stringify(template, null, 2)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface ValidationError {
  message: string
}

export interface ParsedImport {
  keys: Record<string, string>
  rotation: Record<string, { extraKeys: string[]; rotateEveryN: number }>
  tunneling: Record<string, string>
  keyCount: number
  rotationCount: number
  tunnelingCount: number
}

function isMasked(v: string): boolean {
  return v.startsWith('••••')
}

export function validateAndParse(raw: string, fileSize: number): ParsedImport | ValidationError {
  if (fileSize > MAX_FILE_SIZE) {
    return { message: `File too large (${(fileSize / 1024).toFixed(1)} KB). Maximum is ${MAX_FILE_SIZE / 1024} KB.` }
  }

  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return { message: 'Invalid JSON — file could not be parsed.' }
  }

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return { message: 'Invalid format — expected a JSON object at the top level.' }
  }

  const obj = data as Record<string, unknown>

  const hasKeys = 'keys' in obj
  const hasRotation = 'rotation' in obj
  const hasTunneling = 'tunneling' in obj

  // Reject unknown top-level fields
  const ALLOWED_TOP_LEVEL = new Set(['keys', 'rotation', 'tunneling'])
  for (const field of Object.keys(obj)) {
    if (field.startsWith('_')) continue
    if (!ALLOWED_TOP_LEVEL.has(field)) {
      return { message: `Unknown top-level field: "${field}". Only "keys", "rotation", and "tunneling" are accepted.` }
    }
  }

  if (!hasKeys && !hasRotation && !hasTunneling) {
    return { message: 'Missing required section — file must contain at least one of: "keys", "rotation", "tunneling".' }
  }

  const result: ParsedImport = {
    keys: {},
    rotation: {},
    tunneling: {},
    keyCount: 0,
    rotationCount: 0,
    tunnelingCount: 0,
  }

  // Validate keys
  if (hasKeys) {
    if (typeof obj.keys !== 'object' || obj.keys === null || Array.isArray(obj.keys)) {
      return { message: '"keys" must be a JSON object.' }
    }
    const keysObj = obj.keys as Record<string, unknown>
    for (const [field, value] of Object.entries(keysObj)) {
      if (field.startsWith('_')) continue
      if (!ALLOWED_KEY_SET.has(field)) {
        return { message: `Unknown key field: "${field}". Only recognized API key fields are accepted.` }
      }
      if (typeof value !== 'string') {
        return { message: `Key "${field}" must be a string, got ${typeof value}.` }
      }
      if (value && !isMasked(value)) {
        result.keys[field] = value
        result.keyCount++
      }
    }
  }

  // Validate tunneling
  if (hasTunneling) {
    if (typeof obj.tunneling !== 'object' || obj.tunneling === null || Array.isArray(obj.tunneling)) {
      return { message: '"tunneling" must be a JSON object.' }
    }
    const tunObj = obj.tunneling as Record<string, unknown>
    for (const [field, value] of Object.entries(tunObj)) {
      if (field.startsWith('_')) continue
      if (!ALLOWED_TUNNEL_SET.has(field)) {
        return { message: `Unknown tunneling field: "${field}".` }
      }
      if (typeof value !== 'string') {
        return { message: `Tunneling field "${field}" must be a string, got ${typeof value}.` }
      }
      if (value && !isMasked(value)) {
        result.tunneling[field] = value
        result.tunnelingCount++
      }
    }
  }

  // Validate rotation
  if (hasRotation) {
    if (typeof obj.rotation !== 'object' || obj.rotation === null || Array.isArray(obj.rotation)) {
      return { message: '"rotation" must be a JSON object.' }
    }
    const rotObj = obj.rotation as Record<string, unknown>
    for (const [tool, cfg] of Object.entries(rotObj)) {
      if (tool.startsWith('_')) continue
      if (!ALLOWED_ROTATION_SET.has(tool)) {
        return { message: `Unknown rotation tool: "${tool}".` }
      }
      if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) {
        return { message: `Rotation config for "${tool}" must be an object.` }
      }
      const rotCfg = cfg as Record<string, unknown>
      // Reject unknown properties inside rotation config
      const ALLOWED_ROTATION_PROPS = new Set(['extraKeys', 'rotateEveryN'])
      for (const prop of Object.keys(rotCfg)) {
        if (prop.startsWith('_')) continue
        if (!ALLOWED_ROTATION_PROPS.has(prop)) {
          return { message: `Unknown property "${prop}" in rotation config for "${tool}". Only "extraKeys" and "rotateEveryN" are accepted.` }
        }
      }
      if (!('extraKeys' in rotCfg) || !Array.isArray(rotCfg.extraKeys)) {
        return { message: `Rotation "${tool}": "extraKeys" must be an array of strings.` }
      }
      for (let i = 0; i < rotCfg.extraKeys.length; i++) {
        if (typeof rotCfg.extraKeys[i] !== 'string') {
          return { message: `Rotation "${tool}": extraKeys[${i}] must be a string.` }
        }
      }
      const validKeys = (rotCfg.extraKeys as string[]).filter(k => k.trim() && !isMasked(k))
      const rotateEveryN = typeof rotCfg.rotateEveryN === 'number' && rotCfg.rotateEveryN > 0
        ? Math.floor(rotCfg.rotateEveryN)
        : 10
      if (validKeys.length > 0) {
        result.rotation[tool] = { extraKeys: validKeys, rotateEveryN }
        result.rotationCount++
      }
    }
  }

  return result
}

export function isValidationError(result: ParsedImport | ValidationError): result is ValidationError {
  return 'message' in result && !('keys' in result)
}

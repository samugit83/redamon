/**
 * The named validators the registry points at.
 *
 * The recon-settings surface used to control risk by refusing 586 of 712
 * columns BY NAME. That was a crude proxy for "this value could be dangerous",
 * and wrong in both directions: it refused `nucleiTags`, which is a bug-class
 * filter, while permitting `takeoverRateLimit` to run at 500 rps past a 3 rps
 * engagement ceiling.
 *
 * So the allowlist stops being the control and validation at the point of use
 * becomes it. The precedent already shipped: `sanitize_image_settings()` lets
 * any value be written to a `*DockerImage` column and pins it to the shipped
 * default at scan start. The field is open; the VALUE is controlled.
 *
 * Two postures, and the difference is deliberate:
 *
 *   REJECT AT THE WRITE   for anything a caller could have got right. Rejecting
 *                         names the problem while the caller is still there to
 *                         fix it, and a silently rewritten value means the
 *                         caller believes a setting applied when it did not.
 *
 *   PIN AT SCAN START     for `docker_image` and `project_file`, where the
 *                         column is also written by the webapp, a project
 *                         import and a version restore. Those paths do not come
 *                         through here, so the check that has to hold is the one
 *                         in `recon/project_settings.py`. This layer rejects the
 *                         same values early as a courtesy, not as the control.
 */
import type { RegistryField } from './registry'
import { attackSkillConfigShapeError } from '@/lib/userSkills'

/** Pipeline phases, mirroring ScanModulesSection's SCAN_MODULE_OPTIONS. */
export const SCAN_MODULE_VALUES: readonly string[] = Object.freeze([
  'domain_discovery',
  'port_scan',
  'http_probe',
  'resource_enum',
  'vuln_scan',
  'js_recon',
])

/** Nuclei / takeover severity vocabulary. */
export const SEVERITY_VALUES: readonly string[] = Object.freeze([
  'info', 'low', 'medium', 'high', 'critical', 'unknown',
])

/**
 * Headers a caller may not set, whatever the field.
 *
 * Each would change WHERE the request goes or WHAT it carries rather than
 * annotating it: Host re-points a request at a different virtual host,
 * Authorization and Cookie attach a credential the engagement did not
 * authorise, and Proxy-* redirects the whole exchange.
 */
const FORBIDDEN_HEADERS = new Set(['host', 'authorization', 'cookie', 'proxy-authorization'])

/**
 * Directories a path-valued setting may resolve inside.
 *
 * Kept in step with `_PROJECT_FILE_ROOTS` in `recon/project_settings.py`, which
 * is the authoritative copy. This one exists to refuse early rather than to be
 * relied on.
 */
/**
 * The one shared root that also holds per-project uploads, at
 * `<root>/<projectId>/<name>`. Every other root holds shipped or
 * operator-mounted files that any project may read.
 */
const PROJECT_UPLOAD_ROOT = '/app/recon/wordlists'

const PROJECT_FILE_ROOTS: readonly string[] = [
  '/app/recon/wordlists',
  '/app/custom_templates',
  '/custom-templates',
  '/usr/share/seclists',
  '/usr/share/wordlists',
  '/usr/share/dirb',
  '/usr/share/dirbuster',
]

/** Resolve `.` and `..` without touching the filesystem. */
function normalisePath(raw: string): string | null {
  if (raw.includes('\0')) return null
  if (!raw.startsWith('/')) return null
  const out: string[] = []
  for (const part of raw.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (out.length === 0) return null
      out.pop()
      continue
    }
    out.push(part)
  }
  return '/' + out.join('/')
}

/**
 * May this project read this path?
 *
 * Not the same question as "is it inside an allowed root". The upload root is
 * shared, uploads land under `<root>/<projectId>/`, and the tools that read
 * these files report which lines matched, so a path into a neighbouring
 * project's directory reflects that project's file into this scan's output.
 * Inside the upload root a path is allowed only when it is a shipped list
 * sitting directly in it, or under THIS project's own directory. With no
 * projectId no upload directory is readable at all.
 *
 * Kept in step with `_inside_allowed_root` in `recon/project_settings.py`,
 * which is the authoritative copy.
 */
export function isInsideProjectFileRoot(raw: unknown, projectId = ''): boolean {
  if (typeof raw !== 'string' || raw.trim() === '') return false
  const resolved = normalisePath(raw.trim())
  if (resolved === null) return false
  for (const root of PROJECT_FILE_ROOTS) {
    if (resolved === root) return true
    if (!resolved.startsWith(root + '/')) continue
    if (root !== PROJECT_UPLOAD_ROOT) return true
    const relative = resolved.slice(root.length + 1)
    if (!relative.includes('/')) return true // a shipped list, not an upload
    return projectId !== '' && relative.slice(0, relative.indexOf('/')) === projectId
  }
  return false
}

export function isSafeFileName(raw: unknown): boolean {
  if (typeof raw !== 'string') return false
  const name = raw.trim()
  if (name === '' || name.includes('\0')) return false
  if (name.includes('/') || name.includes('\\')) return false
  if (name === '.' || name === '..' || name.startsWith('.')) return false
  return true
}

/** One header line, as `Name: value`. */
export function checkHeader(raw: unknown): string | null {
  if (typeof raw !== 'string') return 'must be a string'
  if (/[\r\n]/.test(raw)) {
    // A CR or LF splits one header into two and lets the caller write the rest
    // of the request, which is request splitting rather than configuration.
    return 'must not contain a carriage return or newline'
  }
  if (raw.includes('\0')) return 'must not contain a NUL byte'
  const colon = raw.indexOf(':')
  if (colon <= 0) return "must be 'Name: value'"
  const name = raw.slice(0, colon).trim().toLowerCase()
  if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) return 'has an invalid header name'
  if (FORBIDDEN_HEADERS.has(name) || name.startsWith('proxy-')) {
    return `may not set the '${name}' header, which changes where the request goes or what it carries`
  }
  // A header with no value is a line the tools will send and the target will
  // ignore, so the caller believes they are identifying their traffic and are
  // not. The length bound is the one most servers enforce anyway: a longer
  // line is rejected by the target, not by us, and looks like a scan failure.
  if (raw.slice(colon + 1).trim() === '') return 'has no value'
  if (raw.length > 4096) return 'is longer than 4096 characters'
  return null
}

const STATUS_CODE_RE = /^[0-9]{3}(-[0-9]{3})?$/

/** A GitHub account (user or organisation) name: GitHub's own rule, 39 characters at most. */
export const REGEX_GITHUB_ORG = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/

/** A GitHub repository name, as the secret hunt compares it with `repo.name`. */
const GITHUB_REPO_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/

/**
 * One line of a pasted hostname list: a bare prefix (`admin`) or a full name.
 * Each line becomes a Host header and an SNI name, so a path, a URL or a space
 * can only produce a candidate no server would answer to.
 */
const HOSTNAME_LIST_LINE_RE = /^[A-Za-z0-9._-]{1,253}$/

/** A 5,000-name list is ~50 KB; this leaves room without letting a row grow unbounded. */
const HOSTNAME_LIST_MAX_CHARS = 1_000_000

/** Lists whose own ceiling is lower than the generic 5000 entries. */
const LIST_MAX_ENTRIES: Record<string, number> = { url_path_list: 200 }

function checkHostnameList(value: unknown): string | null {
  if (typeof value !== 'string') return 'must be a string'
  if (value.length > HOSTNAME_LIST_MAX_CHARS) return `is longer than ${HOSTNAME_LIST_MAX_CHARS} characters`
  const lines = value.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (line === '' || line.startsWith('#')) continue
    if (!HOSTNAME_LIST_LINE_RE.test(line)) {
      return `must be one hostname or prefix per line; line ${i + 1} (${JSON.stringify(line.slice(0, 80))}) is not one`
    }
  }
  return null
}

/**
 * Container images the OPERATOR approved beyond the shipped set.
 *
 * Mirrors `_operator_allowed_images()` in `recon/project_settings.py`, which is
 * the copy that actually holds at scan start. `RECON_EXTRA_ALLOWED_IMAGES` is
 * set on the server, so unlike a project setting it is not something a caller
 * can influence - which is why it may widen a closed list that exists to refuse
 * caller-supplied values.
 *
 * Read per call rather than cached: the value is an env var and a test that
 * stubs it must see the change.
 */
export function operatorAllowedImages(): Set<string> {
  const raw = process.env.RECON_EXTRA_ALLOWED_IMAGES ?? ''
  return new Set(raw.split(',').map(s => s.trim()).filter(Boolean))
}

export interface ValidationContext {
  /** What the field is called, for the message. */
  key: string
  /** Its registry entry. */
  spec: RegistryField
  /** Whose project the write is for. Absent at creation: nothing is uploaded yet. */
  projectId?: string
}

/** Validate one scalar against a named validator. Returns a problem or null. */
function checkScalar(validator: string, value: unknown, ctx: ValidationContext): string | null {
  switch (validator) {
    case 'http_header':
      return checkHeader(value)
    case 'project_file':
      return isInsideProjectFileRoot(value, ctx.projectId ?? '') || value === ''
        ? null
        : 'must be an absolute path inside a shipped wordlist directory or this ' +
          'project\'s own upload directory'
    case 'project_file_name':
      return isSafeFileName(value) ? null : 'must be a plain filename with no directory part'
    case 'status_codes':
      return typeof value === 'string' && STATUS_CODE_RE.test(value)
        ? null
        : 'must be an HTTP status code such as "200" or "200-299"'
    case 'severity':
      return typeof value === 'string' && SEVERITY_VALUES.includes(value)
        ? null
        : `must be one of ${SEVERITY_VALUES.join(', ')}`
    case 'scan_modules':
      return typeof value === 'string' && SCAN_MODULE_VALUES.includes(value)
        ? null
        : `must be one of ${SCAN_MODULE_VALUES.join(', ')}`
    case 'docker_image':
      // Reached only for an image the registry's closed `values:` list did not
      // match, which is the operator-approved extra case below. Everything else
      // is refused by the value set before it gets here.
      return typeof value === 'string' && !/[\s\0]/.test(value)
        ? null
        : 'must be a container image reference with no whitespace'
    case 'json_object':
      return value !== null && typeof value === 'object' ? null : 'must be an object'
    case 'attack_skill_config':
      // The shape only: which user skills exist, and the owner's enabled bound, are
      // checked against the database by every writer (reconSettings/crossField.ts).
      return attackSkillConfigShapeError(value)
    case 'identifier':
      return typeof value === 'string' && /^[A-Za-z0-9._:-]{0,200}$/.test(value)
        ? null
        : 'must be a short identifier'
    case 'hostname':
      return typeof value === 'string' && /^[A-Za-z0-9.*_-]{0,253}$/.test(value)
        ? null
        : 'must be a hostname'
    case 'hostname_list':
      return checkHostnameList(value)
    case 'url':
      return typeof value === 'string' && (value === '' || /^https?:\/\/[^\s]+$/.test(value))
        ? null
        : 'must be an http or https URL'
    case 'url_path_list':
      // One origin-relative path per item, requested on every in-scope origin:
      // a scheme-relative '//', a query or a fragment would change the host or
      // the request the operator asked for.
      return typeof value === 'string' && value.length <= 2048 && value.startsWith('/')
        && !value.startsWith('//') && !/[\s\x00-\x1f\x7f\\?#]/.test(value)
        ? null
        : 'must be an origin-relative path starting with /, without whitespace, a query or a fragment'
    case 'github_name':
      // Empty means "none set"; anything else names one account.
      return typeof value === 'string' && (value === '' || (value.length <= 39 && REGEX_GITHUB_ORG.test(value)))
        ? null
        : 'must be a GitHub account name: letters, digits and single hyphens, at most 39 characters'
    case 'github_repo_list': {
      // Comma-separated, empty for "every repository". Each entry is matched
      // against a repository NAME, so an owner/ prefix or a URL would match nothing.
      if (typeof value !== 'string') return 'must be a string'
      const names = value.split(',').map(n => n.trim()).filter(Boolean)
      return names.every(n => GITHUB_REPO_NAME_RE.test(n) && n !== '.' && n !== '..')
        ? null
        : 'must be a comma-separated list of repository names (no owner/ prefix, no URL)'
    }
    case 'port_spec':
      return typeof value === 'string' && /^[0-9,\s-]{0,2000}$/.test(value)
        ? null
        : 'must be a port list or range such as "80,443,8000-8100"'
    case 'provider_reference':
      return value === null || (typeof value === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(value))
        ? null
        : 'must be null or a Jev provider configuration id'
    case 'free_text':
      if (typeof value !== 'string') return 'must be a string'
      if (value.includes('\0')) return 'must not contain a NUL byte'
      if (value.length > 20000) return 'is longer than 20000 characters'
      return null
    default:
      return `has an unknown validator '${validator}' (a registry bug, not a caller one)`
  }
}

/**
 * Validate one caller-supplied value against its registry entry.
 *
 * Returns a human-readable problem naming the bound or the rule, or null. The
 * message is written for the agent that will read it: an agent refused without
 * being told the bound learns it one call at a time, and because one bad key
 * refuses the whole call, a batch of guesses applies nothing at all.
 */
export function validateValue(
  key: string,
  spec: RegistryField,
  value: unknown,
  projectId?: string
): string | null {
  const ctx: ValidationContext = { key, spec, projectId }

  switch (spec.type) {
    case 'boolean':
      return typeof value === 'boolean' ? null : 'must be true or false'

    case 'int':
    case 'float': {
      if (typeof value !== 'number' || !Number.isFinite(value)) return 'must be a number'
      if (spec.type === 'int' && !Number.isInteger(value)) return 'must be a whole number'
      if (!spec.bounds) return 'has no bound in the registry (a registry bug, not a caller one)'
      if (value < spec.bounds.min || value > spec.bounds.max) {
        const zero =
          spec.zero_means === 'unlimited'
            ? ' Note that 0 means UNLIMITED here, so it is the most aggressive value, not the safest.'
            : ''
        return `must be between ${spec.bounds.min} and ${spec.bounds.max}.${zero}`
      }
      return null
    }

    case 'string': {
      if (spec.values) {
        if (typeof value === 'string' && spec.values.includes(value)) return null
        // An air-gapped or private-registry deployment mirrors the shipped
        // images, and the operator names the mirrors in an env var the SERVER
        // controls. That is not attacker-influenceable the way a project
        // setting is, so it widens the set without re-opening the hole.
        if (spec.validator === 'docker_image' && operatorAllowedImages().has(String(value))) {
          return checkScalar('docker_image', value, ctx)
        }
        return `must be one of ${spec.values.join(', ')}`
      }
      // A single header column's default is "" for "send no header", so clearing
      // it must be writable. An empty ITEM in a header list stays refused.
      if (spec.validator === 'http_header' && value === '') return null
      return checkScalar(spec.validator ?? 'free_text', value, ctx)
    }

    case 'string-list':
    case 'number-list': {
      if (!Array.isArray(value)) return 'must be an array'
      if (value.length > (LIST_MAX_ENTRIES[spec.validator ?? ''] ?? 5000)) {
        return `has more than ${LIST_MAX_ENTRIES[spec.validator ?? ''] ?? 5000} entries`
      }
      for (const item of value) {
        if (spec.type === 'number-list') {
          if (typeof item !== 'number' || !Number.isInteger(item)) {
            return 'must contain only whole numbers'
          }
          continue
        }
        if (spec.values) {
          if (typeof item !== 'string' || !spec.values.includes(item)) {
            return `contains an unknown value. Allowed: ${spec.values.join(', ')}`
          }
          continue
        }
        const problem = checkScalar(spec.validator ?? 'free_text', item, ctx)
        if (problem) return `contains an entry that ${problem}`
      }
      return null
    }

    case 'json':
      return checkScalar(spec.validator ?? 'json_object', value, ctx)

    case 'datetime':
      // Not a pipeline parameter in practice; every datetime column is closed.
      return typeof value === 'string' && !Number.isNaN(Date.parse(value))
        ? null
        : 'must be an ISO 8601 timestamp'

    default:
      return `has an unhandled type '${spec.type}' (a registry bug, not a caller one)`
  }
}

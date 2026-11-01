'use client'

import { useState, useRef, useEffect, useCallback, useId } from 'react'
import { AlertTriangle, ChevronDown, Search, Upload, Trash2, Loader2, FileText, HelpCircle, Play } from 'lucide-react'
import { Toggle, Modal, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { RegistryFields } from '../RegistryFields'
import { announceProjectWrite } from '@/lib/projectVersion'
import { readApiError, toApiError } from '@/lib/apiError'
import { field as registryField } from '@/lib/reconSettings/registry'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface UploadedFile {
  name: string
  size: number
  uploaded_at: string
}

interface CustomFileState {
  [key: string]: { name: string; size: number; uploaded_at: string } | null
}

const CUSTOM_FILE_TYPES: {
  key: string
  label: string
  accept: string
  hint: string
  guide: { title: string; description: string; format: string; example: string; howItWorks: string }
  validate: (content: string, filename: string) => string | null
}[] = [
  {
    key: 'patterns',
    label: 'Custom Secret Patterns',
    accept: '.json,.txt',
    hint: 'JSON array or TXT (name|regex|severity|confidence per line)',
    guide: {
      title: 'Custom Secret Patterns',
      description: 'Add your own regex patterns to detect company-specific secrets, internal API key formats, or custom tokens that the built-in 100 patterns do not cover. These are ADDITIVE -- they run alongside the defaults, never replacing them.',
      format: 'JSON (.json) or plain text (.txt)',
      example: `JSON format:
[
  {
    "name": "MyCompany API Key",
    "regex": "MYCO-[a-f0-9]{32}",
    "severity": "critical",
    "confidence": "high"
  },
  {
    "name": "Internal Service Token",
    "regex": "svc_tok_[A-Za-z0-9]{40}",
    "severity": "high",
    "confidence": "medium"
  }
]

TXT format (one pattern per line):
MyCompany API Key|MYCO-[a-f0-9]{32}|critical|high
Internal Token|svc_tok_[A-Za-z0-9]{40}|high|medium
# Lines starting with # are comments

Fields: name | regex | severity | confidence
- severity: critical, high, medium, low, info
- confidence: high, medium, low
- severity and confidence are optional (default: medium)`,
      howItWorks: 'Each pattern is compiled as a Python regex and applied line-by-line to every downloaded JS file. When a match is found, a finding is created with the specified severity and confidence. The matched text is redacted in the output (first 6 + last 4 chars shown). Patterns with a high false-positive rate should use confidence "low". Note: patterns run in Python (re module), not JavaScript. Avoid JS-only syntax like (?<name>...) named groups -- use (?P<name>...) or plain capture groups instead.',
    },
    validate: (content: string, filename: string) => {
      if (filename.endsWith('.json')) {
        try {
          const parsed = JSON.parse(content)
          if (!Array.isArray(parsed)) return 'JSON must be an array of pattern objects'
          for (let i = 0; i < parsed.length; i++) {
            const p = parsed[i]
            if (!p.name || typeof p.name !== 'string') return `Pattern ${i + 1}: missing "name" (string)`
            if (!p.regex || typeof p.regex !== 'string') return `Pattern ${i + 1}: missing "regex" (string)`
            try { new RegExp(p.regex) } catch { return `Pattern ${i + 1}: invalid regex "${p.regex}"` }
            if (p.severity && !['critical', 'high', 'medium', 'low', 'info'].includes(p.severity))
              return `Pattern ${i + 1}: invalid severity "${p.severity}" (must be critical/high/medium/low/info)`
            if (p.confidence && !['high', 'medium', 'low'].includes(p.confidence))
              return `Pattern ${i + 1}: invalid confidence "${p.confidence}" (must be high/medium/low)`
          }
          if (parsed.length === 0) return 'JSON array is empty -- add at least one pattern'
        } catch { return 'Invalid JSON syntax' }
      } else {
        const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'))
        if (lines.length === 0) return 'File is empty -- add at least one pattern line'
        for (let i = 0; i < lines.length; i++) {
          const parts = lines[i].split('|')
          if (parts.length < 2) return `Line ${i + 1}: expected "name|regex" format, got "${lines[i].trim().substring(0, 40)}"`
          try { new RegExp(parts[1].trim()) } catch { return `Line ${i + 1}: invalid regex "${parts[1].trim()}"` }
        }
      }
      return null
    },
  },
  {
    key: 'sourcemap-paths',
    label: 'Source Map Paths',
    accept: '.txt',
    hint: 'Extra paths to probe for .map files (one per line)',
    guide: {
      title: 'Custom Source Map Probe Paths',
      description: 'Add extra URL path templates to probe when looking for .map source map files. The scanner already tries 8 default paths (like {url}.map, {base}/static/js/{filename}.map). Use this to add paths specific to your target application.',
      format: 'Plain text (.txt), one path template per line',
      example: `{base}/assets/maps/{filename}.map
{base}/sourcemaps/{filename}.map
{base}/build/static/js/{filename}.map
{base}/_assets/{filename}.map
# Lines starting with # are comments

Available variables:
- {url}      = full JS file URL (e.g., https://example.com/js/app.js)
- {base}     = scheme + host (e.g., https://example.com)
- {filename} = JS filename (e.g., app.js)`,
      howItWorks: 'For each downloaded JS file, the scanner first checks for a sourceMappingURL comment and SourceMap HTTP header. If neither found, it probes each path template by replacing {url}, {base}, and {filename} with actual values and making an HTTP GET request. If a valid source map JSON (with "version" and "sources" fields) is returned, the scanner parses it, extracts original source filenames, and scans any embedded sourcesContent for secrets.',
    },
    validate: (content: string) => {
      const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'))
      if (lines.length === 0) return 'File is empty -- add at least one path template'
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim()
        if (!line.includes('{') && !line.includes('/')) return `Line ${i + 1}: expected a URL path template, got "${line.substring(0, 40)}"`
      }
      return null
    },
  },
  {
    key: 'packages',
    label: 'Internal Packages',
    accept: '.txt',
    hint: 'Known internal npm package names to check (one per line)',
    guide: {
      title: 'Internal Package Names',
      description: 'List known internal/private npm package names used by the target organization. These are ALWAYS checked against the public npm registry, even if not found in the JS code via import/require statements. This is useful when minified JS strips import names.',
      format: 'Plain text (.txt), one scoped package name per line',
      example: `@mycompany/auth-sdk
@mycompany/api-client
@mycompany/shared-utils
@internal/config
@targetcorp/payment-lib
# Lines starting with # are comments

Note: packages must use the @scope/name format.
Well-known public scopes (@types, @babel, @angular, @vue, etc.) are automatically skipped.`,
      howItWorks: 'For each package name, the scanner makes a GET request to https://registry.npmjs.org/{package}. If the registry returns 404 (package does not exist), this is flagged as a CRITICAL dependency confusion vulnerability -- an attacker could register the package name on public npm and execute arbitrary code when the target runs npm install. If the package DOES exist on npm but is listed here as "internal," it is flagged as HIGH severity (verify ownership).',
    },
    validate: (content: string) => {
      const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'))
      if (lines.length === 0) return 'File is empty -- add at least one package name'
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim()
        if (!line.startsWith('@') || !line.includes('/'))
          return `Line ${i + 1}: expected @scope/package format, got "${line}". Packages must be scoped (e.g., @myorg/mylib).`
      }
      return null
    },
  },
  {
    key: 'endpoint-keywords',
    label: 'Endpoint Keywords',
    accept: '.txt',
    hint: 'Extra keywords to search for in JS (one per line)',
    guide: {
      title: 'Custom Endpoint Keywords',
      description: 'Add extra keywords to search for in JavaScript content. When a keyword is found inside a quoted string in the JS code, the surrounding URL is extracted as a discovered endpoint. Use this for target-specific API paths that the built-in patterns might miss.',
      format: 'Plain text (.txt), one keyword per line',
      example: `/internal-api/v2/
/backoffice/
mycompany-service
admin-panel
graphql-gateway
/legacy/api/
# Lines starting with # are comments

Tips:
- Use path fragments like /internal-api/ for precision
- Use service names like mycompany-service for broader matching
- Avoid very short keywords (< 4 chars) to reduce false positives`,
      howItWorks: 'For each keyword, the scanner searches all JS file content using a case-insensitive regex. When a match is found, it extracts the surrounding quoted string (the URL/path containing the keyword). Each discovered URL is classified by category (admin, debug, auth, api, etc.) and assigned a severity. Results appear in the Endpoints tab of the JS Recon dashboard.',
    },
    validate: (content: string) => {
      const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'))
      if (lines.length === 0) return 'File is empty -- add at least one keyword'
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].trim().length < 2) return `Line ${i + 1}: keyword too short (minimum 2 characters)`
      }
      return null
    },
  },
  {
    key: 'frameworks',
    label: 'Framework Signatures',
    accept: '.json',
    hint: 'JSON array of {name, patterns[], version_regex}',
    guide: {
      title: 'Custom Framework Signatures',
      description: 'Add detection signatures for custom or internal JavaScript frameworks not covered by the 12 built-in ones (React, Next.js, Vue, Nuxt, Angular, jQuery, Svelte, Ember, Backbone, Lodash, Moment.js, Bootstrap). Each signature defines regex patterns that identify the framework and optionally extract its version.',
      format: 'JSON (.json) array',
      example: `[
  {
    "name": "MyCompanyFramework",
    "patterns": [
      "MyFramework\\.init",
      "__MY_FRAMEWORK__",
      "myfw-version"
    ],
    "version_regex": "MyFramework\\.version\\s*=\\s*[\"']([0-9.]+)[\"']"
  },
  {
    "name": "InternalRouter",
    "patterns": [
      "InternalRouter\\.navigate",
      "__INTERNAL_ROUTER__"
    ],
    "version_regex": null
  }
]

Fields:
- name: display name for the framework
- patterns: array of regex strings -- if ANY matches, framework is detected
- version_regex: regex with capture group 1 for version (null if not needed)

JSON escaping rules:
- Literal dot in regex: \\. (one backslash + dot in JSON)
- Whitespace \\s: \\s (one backslash + s in JSON)
- Quote in regex: use [\"'] or ['"']
The example above is ready to copy-paste into a .json file.`,
      howItWorks: 'Each signature\'s patterns are compiled as Python regexes (re module) and searched in the JS file content. If any pattern matches, the framework is detected. The version_regex (if provided) is then used to extract the version number from capture group 1. Detected frameworks appear in the JS Recon dashboard under Security Patterns. Version information enables targeted CVE lookups. Note: use Python regex syntax -- avoid JS-only features like (?<name>...) named groups.',
    },
    validate: (content: string) => {
      try {
        const parsed = JSON.parse(content)
        if (!Array.isArray(parsed)) return 'JSON must be an array of framework signature objects'
        for (let i = 0; i < parsed.length; i++) {
          const fw = parsed[i]
          if (!fw.name || typeof fw.name !== 'string') return `Signature ${i + 1}: missing "name" (string)`
          if (!Array.isArray(fw.patterns) || fw.patterns.length === 0) return `Signature ${i + 1}: "patterns" must be a non-empty array of regex strings`
          for (let j = 0; j < fw.patterns.length; j++) {
            if (typeof fw.patterns[j] !== 'string') return `Signature ${i + 1}, pattern ${j + 1}: must be a string`
            try { new RegExp(fw.patterns[j]) } catch { return `Signature ${i + 1}, pattern ${j + 1}: invalid regex "${fw.patterns[j]}"` }
          }
          if (fw.version_regex !== null && fw.version_regex !== undefined) {
            if (typeof fw.version_regex !== 'string') return `Signature ${i + 1}: "version_regex" must be a string or null`
            try { new RegExp(fw.version_regex) } catch { return `Signature ${i + 1}: invalid version_regex "${fw.version_regex}"` }
          }
        }
        if (parsed.length === 0) return 'JSON array is empty -- add at least one framework signature'
      } catch { return 'Invalid JSON syntax' }
      return null
    },
  },
]

const DEFAULT_ENDPOINT_ACCEPT_STATUS = [200, 201, 204, 301, 302, 307, 308, 401, 403, 405]

export const TRUFFLEHOG_IMAGE_MISSING = 'TruffleHog image not installed: run ./redamon.sh update'

/** The registry's closed `jsReconTrufflehogResults` values, in its order. */
export const TRUFFLEHOG_RESULT_OPTIONS: { value: string; label: string; hint: string }[] = [
  { value: 'verified', label: 'Verified', hint: 'the provider accepted the key' },
  { value: 'unknown', label: 'Unknown', hint: 'the check errored' },
  { value: 'unverified', label: 'Unverified', hint: 'not shown live, or not checkable' },
]
const DEFAULT_TRUFFLEHOG_RESULTS = TRUFFLEHOG_RESULT_OPTIONS.map(o => o.value)

type TrufflehogAvailability =
  | { state: 'checking' }
  | { state: 'available' }
  | { state: 'image_missing' }
  // The orchestrator did not say: nothing is known about the image.
  | { state: 'unknown'; detail: string }

async function fetchTrufflehogAvailability(): Promise<TrufflehogAvailability> {
  const fallback = 'availability check failed'
  try {
    const res = await fetch('/api/js-recon/trufflehog/available')
    if (!res.ok) return { state: 'unknown', detail: (await readApiError(res, fallback)).message }
    const body = await res.json()
    if (body?.available === true) return { state: 'available' }
    if (body?.reason === 'image_missing') return { state: 'image_missing' }
    return { state: 'unknown', detail: typeof body?.reason === 'string' ? body.reason : fallback }
  } catch (err) {
    return { state: 'unknown', detail: toApiError(err, fallback).message }
  }
}

interface JsReconSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode?: 'create' | 'edit'
  onRun?: () => void
}

export function JsReconSection({ data, updateField, projectId, mode, onRun }: JsReconSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [showCustomFiles, setShowCustomFiles] = useState(false)
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([])
  const [customFiles, setCustomFiles] = useState<CustomFileState>({})
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  // The manual JS upload's own error: uploadError renders inside the custom
  // files panel, which is usually collapsed.
  const [jsFileError, setJsFileError] = useState<string | null>(null)
  const [guideModal, setGuideModal] = useState<string | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const jsFileRef = useRef<HTMLInputElement>(null)
  const customFileRefs = useRef<Record<string, HTMLInputElement | null>>({})
  const [trufflehog, setTrufflehog] = useState<TrufflehogAvailability>({ state: 'checking' })
  const trufflehogResultsLabelId = useId()

  const jsReconEnabled = (data as any).jsReconEnabled ?? false
  useEffect(() => {
    if (!isOpen || !jsReconEnabled) return
    let cancelled = false
    fetchTrufflehogAvailability().then(answer => { if (!cancelled) setTrufflehog(answer) })
    return () => { cancelled = true }
  }, [isOpen, jsReconEnabled])

  // The registry says what stealth does to the field, so the form follows it
  // rather than repeating it.
  const stealthForcesValidationOff = !!data.stealthMode
    && registryField('jsReconValidateKeys')?.stealth?.set === false
  const validateKeysStored = (data as any).jsReconValidateKeys ?? true
  const validateKeysEffective = validateKeysStored && !stealthForcesValidationOff

  const trufflehogEnabled = (data as any).jsReconTrufflehogEnabled ?? false
  const trufflehogMissing = trufflehog.state === 'image_missing'
  const storedResults = (data as any).jsReconTrufflehogResults
  const trufflehogResults: string[] = Array.isArray(storedResults) ? storedResults : DEFAULT_TRUFFLEHOG_RESULTS
  const toggleTrufflehogResult = (value: string) => {
    const next = trufflehogResults.includes(value)
      ? trufflehogResults.filter(v => v !== value)
      : [...trufflehogResults, value]
    // Canonical order, so ticking and unticking never reorders the stored list.
    const ordered = DEFAULT_TRUFFLEHOG_RESULTS.filter(v => next.includes(v))
    updateField('jsReconTrufflehogResults' as any, ordered as any)
  }

  const isEditMode = mode === 'edit' && projectId
  // The upload routes need a saved project they can check ownership of, so a
  // create-mode form, whose id is only pre-generated, cannot upload yet.
  const canUpload = !!projectId && mode === 'edit'

  const fetchUploadedFiles = useCallback(async () => {
    if (!canUpload) return
    try {
      const res = await fetch(`/api/js-recon/${projectId}/upload`)
      if (res.ok) {
        const data = await res.json()
        setUploadedFiles(data.files || [])
      }
    } catch { /* ignore */ }
  }, [canUpload, projectId])

  const fetchCustomFiles = useCallback(async () => {
    if (!canUpload) return
    try {
      const res = await fetch(`/api/js-recon/${projectId}/custom-files`)
      if (res.ok) {
        const data = await res.json()
        setCustomFiles(data.files || {})
      }
    } catch { /* ignore */ }
  }, [canUpload, projectId])

  useEffect(() => {
    if (canUpload && isOpen) {
      fetchUploadedFiles()
      fetchCustomFiles()
    }
  }, [canUpload, isOpen, fetchUploadedFiles, fetchCustomFiles])

  const handleJsFileUpload = async (file: File) => {
    if (!canUpload) return
    setIsUploading(true)
    setJsFileError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch(`/api/js-recon/${projectId}/upload`, { method: 'POST', body: formData })
      if (!res.ok) {
        setJsFileError(`${file.name}: ${(await readApiError(res, 'Upload failed')).message}`)
        return
      }
      announceProjectWrite(projectId, (await res.json()).projectUpdatedAt)
      await fetchUploadedFiles()
    } catch (err) {
      setJsFileError(`${file.name}: ${toApiError(err, 'Upload failed').message}`)
    } finally {
      setIsUploading(false)
      if (jsFileRef.current) jsFileRef.current.value = ''
    }
  }

  const handleJsFileDelete = async (filename: string) => {
    if (!canUpload) return
    setJsFileError(null)
    try {
      const res = await fetch(`/api/js-recon/${projectId}/upload?name=${encodeURIComponent(filename)}`, { method: 'DELETE' })
      if (res.ok) announceProjectWrite(projectId, (await res.json()).projectUpdatedAt)
      else setJsFileError((await readApiError(res, `Could not delete ${filename}`)).message)
      await fetchUploadedFiles()
    } catch (err) {
      setJsFileError(toApiError(err, `Could not delete ${filename}`).message)
    }
  }

  const handleCustomFileUpload = async (fileType: string, file: File) => {
    if (!canUpload) return

    // Client-side validation before upload
    const fileTypeConfig = CUSTOM_FILE_TYPES.find(t => t.key === fileType)
    if (fileTypeConfig) {
      try {
        const content = await file.text()
        const error = fileTypeConfig.validate(content, file.name)
        if (error) {
          setValidationError(`${fileTypeConfig.label}: ${error}`)
          const ref = customFileRefs.current[fileType]
          if (ref) ref.value = ''
          return
        }
      } catch {
        setValidationError(`${fileTypeConfig.label}: Could not read file`)
        const ref = customFileRefs.current[fileType]
        if (ref) ref.value = ''
        return
      }
    }

    setIsUploading(true)
    setUploadError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('type', fileType)
      const res = await fetch(`/api/js-recon/${projectId}/custom-files`, { method: 'POST', body: formData })
      if (!res.ok) {
        setUploadError((await readApiError(res, 'Upload failed')).message)
        return
      }
      announceProjectWrite(projectId, (await res.json()).projectUpdatedAt)
      await fetchCustomFiles()
    } catch (err) {
      setUploadError(toApiError(err, 'Upload failed').message)
    } finally {
      setIsUploading(false)
      const ref = customFileRefs.current[fileType]
      if (ref) ref.value = ''
    }
  }

  const handleCustomFileDelete = async (fileType: string) => {
    if (!canUpload) return
    setUploadError(null)
    try {
      const res = await fetch(`/api/js-recon/${projectId}/custom-files?type=${fileType}`, { method: 'DELETE' })
      if (res.ok) announceProjectWrite(projectId, (await res.json()).projectUpdatedAt)
      else setUploadError((await readApiError(res, 'Could not delete the file')).message)
      await fetchCustomFiles()
    } catch (err) {
      setUploadError(toApiError(err, 'Could not delete the file').message)
    }
  }

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Search size={16} />
          JS Recon Scanner
          <NodeInfoTooltip section="JsRecon" />
          <WikiInfoButton target="JsRecon" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && (data as any).jsReconEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run JS Recon Scanner"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={(data as any).jsReconEnabled ?? false}
              onChange={(checked) => updateField('jsReconEnabled' as any, checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Deep JavaScript reconnaissance beyond jsluice. Scans JS files for secrets with 90+ regex patterns
            (and optionally TruffleHog&apos;s detectors), validates discovered API keys against their providers,
            detects dependency confusion vulnerabilities,
            discovers exposed source maps, extracts hidden API endpoints (REST, GraphQL, WebSocket),
            fingerprints frameworks with versions, and identifies DOM-based XSS sinks.
          </p>

          {(data as any).jsReconEnabled && (
            <>
              {/* Analysis Scope */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Analysis Scope</h3>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Max JS Files</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).jsReconMaxFiles ?? 10000}
                      onChange={(e) => updateField('jsReconMaxFiles' as any, parseInt(e.target.value) || 10000)}
                      min={10}
                      max={10000}
                    />
                    <span className={styles.fieldHint}>Maximum JS files to download and analyze</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Timeout (seconds)</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).jsReconTimeout ?? 900}
                      onChange={(e) => updateField('jsReconTimeout' as any, parseInt(e.target.value) || 900)}
                      min={60}
                    />
                    <span className={styles.fieldHint}>Overall scan timeout</span>
                  </div>
                </div>
                <div className={styles.fieldRow}>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Concurrency</label>
                    <input
                      type="number"
                      className="textInput"
                      value={(data as any).jsReconConcurrency ?? 10}
                      onChange={(e) => updateField('jsReconConcurrency' as any, parseInt(e.target.value) || 10)}
                      min={1}
                      max={30}
                    />
                    <span className={styles.fieldHint}>Parallel file processing threads</span>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label className={styles.fieldLabel}>Min Confidence</label>
                    <select
                      className="textInput"
                      value={(data as any).jsReconMinConfidence ?? 'low'}
                      onChange={(e) => updateField('jsReconMinConfidence' as any, e.target.value)}
                    >
                      <option value="low">Low (show all findings)</option>
                      <option value="medium">Medium (reduce noise)</option>
                      <option value="high">High (minimal false positives)</option>
                    </select>
                    <span className={styles.fieldHint}>Filter findings by confidence level</span>
                  </div>
                </div>
              </div>

              {/* JS File Sources */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>JS File Sources</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Include Webpack Chunks</span>
                    <p className={styles.toggleDescription}>Analyze .chunk.js and .bundle.js files excluded by Katana. These contain application code with embedded secrets.</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconIncludeChunks ?? true}
                    onChange={(checked) => updateField('jsReconIncludeChunks' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Include Framework JS</span>
                    <p className={styles.toggleDescription}>Fetch Next.js (/_next/static/chunks/) and Nuxt.js (/_nuxt/) bundles that Katana excludes. Often contain API keys and Firebase configs.</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconIncludeFrameworkJs ?? true}
                    onChange={(checked) => updateField('jsReconIncludeFrameworkJs' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Include Archived JS</span>
                    <p className={styles.toggleDescription}>Analyze historical JS files from Wayback Machine/GAU. Old builds often contain hardcoded keys removed from production. Requires GAU enabled.</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconIncludeArchivedJs ?? true}
                    onChange={(checked) => updateField('jsReconIncludeArchivedJs' as any, checked)}
                  />
                </div>
              </div>

              {/* Detection Modules */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Detection Modules</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Secret Detection (Regex)</span>
                    <p className={styles.toggleDescription}>90+ patterns for AWS keys, Stripe, Firebase, GitHub tokens, database URIs, JWTs, and more. TruffleHog can run beside them: see Key Validation below.</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconRegexPatterns ?? true}
                    onChange={(checked) => updateField('jsReconRegexPatterns' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Source Map Analysis</span>
                    <p className={styles.toggleDescription}>Discover exposed .map files that leak original unminified source code and scan them for secrets</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconSourceMaps ?? true}
                    onChange={(checked) => updateField('jsReconSourceMaps' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Dependency Confusion</span>
                    <p className={styles.toggleDescription}>Check if scoped npm packages (@org/pkg) exist on public registry. Missing = critical RCE vector</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconDependencyCheck ?? true}
                    onChange={(checked) => updateField('jsReconDependencyCheck' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Endpoint Extraction</span>
                    <p className={styles.toggleDescription}>Extract REST, GraphQL, WebSocket endpoints, admin/debug routes, and API documentation paths</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconExtractEndpoints ?? true}
                    onChange={(checked) => updateField('jsReconExtractEndpoints' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Validate Extracted Endpoints</span>
                    <p className={styles.toggleDescription}>Off by default. When on, each extracted endpoint on an in-scope host is probed and only confirmed-dead ones are dropped before graph write. Third-party hosts named in the JS (analytics, social widgets, CDNs) and RoE-excluded hosts are never contacted. Headers below apply only to endpoint probes.</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconValidateEndpoints ?? false}
                    onChange={(checked) => updateField('jsReconValidateEndpoints' as any, checked)}
                  />
                </div>
                {((data as any).jsReconValidateEndpoints ?? false) && (
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Accepted Status Codes</label>
                      <input
                        type="text"
                        className="textInput"
                        value={((data as any).jsReconEndpointAcceptStatus ?? DEFAULT_ENDPOINT_ACCEPT_STATUS).join(', ')}
                        onChange={(e) => updateField(
                          'jsReconEndpointAcceptStatus' as any,
                          e.target.value
                            .split(',')
                            .map((value) => value.trim())
                            .filter(Boolean)
                            .map((value) => Number(value))
                            .filter(Number.isFinite) as any,
                        )}
                      />
                      <span className={styles.fieldHint}>Comma-separated HTTP status codes accepted as live endpoints</span>
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Endpoint Validation Headers</label>
                      <textarea
                        className="textInput"
                        rows={4}
                        value={((data as any).jsReconEndpointCustomHeaders ?? []).join('\n')}
                        onChange={(e) => updateField(
                          'jsReconEndpointCustomHeaders' as any,
                          e.target.value
                            .split('\n')
                            .map((line) => line.trim())
                            .filter(Boolean) as any,
                        )}
                        placeholder={`Cookie: session=...\nAuthorization: Bearer ...`}
                      />
                      <span className={styles.fieldHint}>One header per line for endpoint validation probes</span>
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Probe Concurrency</label>
                      <input
                        type="number"
                        min={1}
                        max={20}
                        className="textInput"
                        value={(data as any).jsReconEndpointConcurrency ?? 10}
                        onChange={(e) => updateField('jsReconEndpointConcurrency' as any, parseInt(e.target.value) || 10)}
                      />
                      <span className={styles.fieldHint}>Parallel endpoint probes (1-20, default 10)</span>
                    </div>
                  </div>
                )}
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>DOM Sink Detection</span>
                    <p className={styles.toggleDescription}>Find innerHTML, eval(), document.write, prototype pollution, and other XSS/injection vectors</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconDomSinks ?? true}
                    onChange={(checked) => updateField('jsReconDomSinks' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Framework Fingerprinting</span>
                    <p className={styles.toggleDescription}>Detect React, Next.js, Vue, Angular, jQuery and 7 more frameworks with version extraction for CVE targeting</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconFrameworkDetect ?? true}
                    onChange={(checked) => updateField('jsReconFrameworkDetect' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Developer Comments</span>
                    <p className={styles.toggleDescription}>Extract TODO, FIXME, HACK markers and comments containing password/secret/token keywords</p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconDevComments ?? true}
                    onChange={(checked) => updateField('jsReconDevComments' as any, checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>AI SDK Detection</span>
                    <p className={styles.toggleDescription}>
                      Adversarial AI Phase 6. Scan every harvested JS bundle for AI/LLM SDK imports (OpenAI, Anthropic, Gemini, LangChain, LlamaIndex, Vercel AI SDK, MCP, vector DBs), hard-coded provider keys (sk-, sk-ant-, hf_, lsv2_, gsk_, r8_, …), the OpenAI/Anthropic dangerouslyAllowBrowser opt-in, and AI-frontend product markers in async-loaded chunks the httpx Wappalyzer pass cannot see. Writes JsReconFinding nodes with finding_type ai-sdk-* and enriches matching Secret nodes with ai_provider. Pure regex, no extra traffic.
                    </p>
                  </div>
                  <Toggle
                    checked={(data as any).jsReconAiSdkDetectionEnabled ?? true}
                    onChange={(checked) => updateField('jsReconAiSdkDetectionEnabled' as any, checked)}
                  />
                </div>
              </div>

              {/* Key Validation */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Key Validation</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Validate Discovered Keys</span>
                    <p className={styles.toggleDescription}>Make live API calls to verify if discovered keys are active (AWS STS, GitHub /user, Stripe /v1/account, etc.). Generates outbound traffic to third-party services. With TruffleHog on, this also decides whether TruffleHog checks the keys it finds.</p>
                    {stealthForcesValidationOff && (
                      <p className={styles.fieldHint}>Stealth mode turns key validation off for this project&apos;s scans.</p>
                    )}
                  </div>
                  <Toggle
                    checked={(data as any).jsReconValidateKeys ?? true}
                    onChange={(checked) => updateField('jsReconValidateKeys' as any, checked)}
                  />
                </div>
                {(data as any).jsReconValidateKeys && (
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Validation Timeout (seconds)</label>
                      <input
                        type="number"
                        className="textInput"
                        value={(data as any).jsReconValidationTimeout ?? 5}
                        onChange={(e) => updateField('jsReconValidationTimeout' as any, parseInt(e.target.value) || 5)}
                        min={1}
                        max={30}
                      />
                      <span className={styles.fieldHint}>Per-service API call timeout</span>
                    </div>
                  </div>
                )}
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>TruffleHog</span>
                    <p className={styles.toggleDescription}>
                      Also run TruffleHog, in an isolated container, over local copies of the JavaScript JS Recon analyses,
                      and merge its findings with JS Recon&apos;s: one finding per key. It scans those local copies only and
                      never fetches anything from the target. With key validation on, TruffleHog checks the keys it finds
                      with their providers, never with a host named in the JavaScript; with key validation off its
                      container has no network.
                    </p>
                    {trufflehogMissing && trufflehogEnabled && (
                      <div className={`${styles.callout} ${styles.calloutWarning}`} role="alert">
                        <AlertTriangle size={16} />
                        <span>
                          <strong>{TRUFFLEHOG_IMAGE_MISSING}.</strong> TruffleHog stays on for this project, but scans
                          skip it until the image is installed; the regex engine still runs.
                        </span>
                      </div>
                    )}
                    {trufflehog.state === 'unknown' && (
                      <p className={styles.fieldHint}>
                        Could not check whether the TruffleHog image is installed ({trufflehog.detail}). A scan without it skips TruffleHog and says so.
                      </p>
                    )}
                  </div>
                  {/* The tooltip sits on a wrapper: a disabled button gets no hover events. */}
                  <span title={trufflehogMissing ? TRUFFLEHOG_IMAGE_MISSING : undefined}>
                    {/* Missing image: it cannot be turned on, but one already on can still be turned off. */}
                    <Toggle
                      checked={trufflehogEnabled}
                      onChange={(checked) => updateField('jsReconTrufflehogEnabled' as any, checked)}
                      disabled={trufflehogMissing && !trufflehogEnabled}
                      aria-label="Run TruffleHog"
                    />
                  </span>
                </div>
                {trufflehogEnabled && (
                  <div className={styles.fieldGroup}>
                    <span className={styles.fieldLabel} id={trufflehogResultsLabelId}>Keep TruffleHog-only keys that are</span>
                    <div className={styles.checkboxGroup} role="group" aria-labelledby={trufflehogResultsLabelId}>
                      {TRUFFLEHOG_RESULT_OPTIONS.map(option => (
                        <label key={option.value} className="checkboxLabel">
                          <input
                            type="checkbox"
                            className="checkbox"
                            checked={trufflehogResults.includes(option.value)}
                            onChange={() => toggleTrufflehogResult(option.value)}
                            disabled={!validateKeysEffective}
                          />
                          {option.label} <span className={styles.fieldHint}>({option.hint})</span>
                        </label>
                      ))}
                    </div>
                    {!validateKeysEffective ? (
                      <span className={styles.fieldHint}>
                        {stealthForcesValidationOff ? 'Ignored in stealth mode, which turns key validation off' : 'Ignored while Validate Discovered Keys is off'}:
                        {' '}TruffleHog checks no key then, so it keeps every key it finds.
                      </span>
                    ) : (
                      <span className={styles.fieldHint}>
                        A key JS Recon also found is always kept.
                        {trufflehogResults.length === 0 && ' Nothing ticked keeps all three.'}
                      </span>
                    )}
                  </div>
                )}
              </div>

              {!canUpload && (
                <p className={styles.fieldHint}>
                  Save the project first; then you can upload JS files for analysis (max 10MB each) and custom
                  extension files.
                </p>
              )}

              {/* Custom Extension Files */}
              {canUpload && (
                <div className={styles.subSection}>
                  <div
                    className={styles.subSectionTitleCollapsible}
                    onClick={() => setShowCustomFiles(!showCustomFiles)}
                  >
                    Custom Extension Files
                    <ChevronDown
                      size={14}
                      className={`${styles.sectionIcon} ${showCustomFiles ? styles.sectionIconOpen : ''}`}
                    />
                  </div>
                  {showCustomFiles && (
                    <>
                      <p className={styles.sectionDescription} style={{ marginTop: '8px' }}>
                        Upload custom files to extend the built-in detection patterns. These are additive and do not replace defaults.
                        Click the <HelpCircle size={11} style={{ display: 'inline', verticalAlign: 'middle' }} /> icon next to each type for format details and examples.
                      </p>

                      {uploadError && (
                        <p className={styles.inlineError}>{uploadError}</p>
                      )}

                      {CUSTOM_FILE_TYPES.map(({ key, label, accept, hint, guide }) => (
                        <div key={key} className={styles.fieldGroup} style={{ marginBottom: '12px' }}>
                          <label className={styles.fieldLabel} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {label}
                            <button
                              type="button"
                              onClick={() => setGuideModal(key)}
                              className={styles.helpButton}
                              title={`Format guide for ${label}`}
                            >
                              <HelpCircle size={13} />
                            </button>
                          </label>
                          <span className={styles.fieldHint}>{hint}</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                            <input
                              ref={(el) => { customFileRefs.current[key] = el }}
                              type="file"
                              accept={accept}
                              style={{ display: 'none' }}
                              onChange={(e) => {
                                const file = e.target.files?.[0]
                                if (file) handleCustomFileUpload(key, file)
                              }}
                            />
                            <button
                              type="button"
                              className="secondaryButton"
                              onClick={() => customFileRefs.current[key]?.click()}
                              disabled={isUploading}
                              style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
                            >
                              {isUploading ? <Loader2 size={12} className={styles.spin} /> : <Upload size={12} />}
                              {' '}Upload
                            </button>
                            {customFiles[key] && (
                              <>
                                <span className={styles.itemMeta}>
                                  <FileText size={12} style={{ display: 'inline', marginRight: '4px' }} />
                                  {customFiles[key]!.name} ({(customFiles[key]!.size / 1024).toFixed(1)} KB)
                                </span>
                                <button
                                  type="button"
                                  className={styles.removeButton}
                                  onClick={() => handleCustomFileDelete(key)}
                                  title={`Delete ${customFiles[key]!.name}`}
                                >
                                  <Trash2 size={12} />
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              )}

              {/* Manual JS File Upload */}
              {canUpload && (
                <div className={styles.subSection}>
                  <h3 className={styles.subSectionTitle}>Manual JS File Upload</h3>
                  <p className={styles.sectionDescription}>
                    Upload JS files for analysis without crawling (from Burp Suite, mobile APKs, DevTools, or authenticated areas).
                  </p>
                  <input
                    ref={jsFileRef}
                    type="file"
                    accept=".js,.mjs,.map,.json"
                    multiple
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      const files = e.target.files
                      if (files) {
                        Array.from(files).forEach(f => handleJsFileUpload(f))
                      }
                    }}
                  />
                  <button
                    type="button"
                    className="secondaryButton"
                    onClick={() => jsFileRef.current?.click()}
                    disabled={isUploading}
                    style={{ marginBottom: '8px' }}
                  >
                    {isUploading ? <Loader2 size={13} className={styles.spin} /> : <Upload size={13} />}
                    {isUploading ? ' Uploading...' : ' Upload JS Files'}
                  </button>
                  {jsFileError && <p className={styles.inlineError}>{jsFileError}</p>}

                  {uploadedFiles.length > 0 && (
                    <div className={styles.itemList}>
                      <p className={styles.fieldHint}>{uploadedFiles.length} file(s) uploaded ({(uploadedFiles.reduce((sum, f) => sum + f.size, 0) / 1024).toFixed(0)} KB total)</p>
                      {uploadedFiles.map(f => (
                        <div key={f.name} className={styles.itemRow}>
                          <span style={{ display: 'flex', alignItems: 'center', gap: '6px', minWidth: 0 }}>
                            <FileText size={12} />
                            {f.name}
                            <span className={styles.itemMeta}>({(f.size / 1024).toFixed(1)} KB)</span>
                          </span>
                          <button
                            type="button"
                            className={styles.removeButton}
                            onClick={() => handleJsFileDelete(f.name)}
                            title={`Delete ${f.name}`}
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

            </>
          )}

          <RegistryFields
            keys={['jsReconStandaloneCrawlDepth', 'jsReconStandaloneCrawlScope']}
            data={data}
            updateField={updateField}
            title="Advanced"
            description="Settings this tool accepts that have no dedicated control. Bounds, options and descriptions come from the settings registry, so they are the same ones the API enforces."
          />
        </div>
      )}
      {/* Help Guide Modal */}
      {guideModal && (() => {
        const fileType = CUSTOM_FILE_TYPES.find(t => t.key === guideModal)
        if (!fileType) return null
        const { guide } = fileType
        return (
          <Modal isOpen={true} onClose={() => setGuideModal(null)} title={guide.title} size="large">
            <div style={{ fontSize: 'var(--text-sm)', lineHeight: '1.6', color: 'var(--text-primary)' }}>
              <p style={{ marginBottom: '16px' }}>{guide.description}</p>

              <h4 style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: 'var(--text-xs)', letterSpacing: '0.05em' }}>Format</h4>
              <p style={{ marginBottom: '16px' }}>{guide.format}</p>

              <h4 style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: 'var(--text-xs)', letterSpacing: '0.05em' }}>Example</h4>
              <pre style={{
                background: 'var(--bg-secondary, #1a1a2e)',
                padding: '12px 16px',
                borderRadius: '6px',
                fontSize: 'var(--text-xs)',
                overflow: 'auto',
                marginBottom: '16px',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                border: '1px solid var(--border-default)',
              }}>
                {guide.example}
              </pre>

              <h4 style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: 'var(--text-xs)', letterSpacing: '0.05em' }}>How It Works</h4>
              <p>{guide.howItWorks}</p>
            </div>
          </Modal>
        )
      })()}

      {/* Validation Error Modal */}
      <Modal
        isOpen={validationError !== null}
        onClose={() => setValidationError(null)}
        title="Upload Validation Failed"
        size="default"
        footer={
          <button
            type="button"
            className="secondaryButton"
            onClick={() => setValidationError(null)}
            style={{ marginLeft: 'auto' }}
          >
            OK
          </button>
        }
      >
        <div style={{ fontSize: 'var(--text-sm)', lineHeight: '1.6' }}>
          <p style={{ color: 'var(--form-danger)', marginBottom: '12px', fontWeight: 500 }}>
            The file was not uploaded because it does not match the expected format.
          </p>
          <pre style={{
            background: 'var(--bg-secondary, #1a1a2e)',
            padding: '12px 16px',
            borderRadius: '6px',
            fontSize: 'var(--text-xs)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            border: '1px solid var(--form-danger)',
          }}>
            {validationError}
          </pre>
          <p style={{ marginTop: '12px', color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
            Click the <HelpCircle size={11} style={{ display: 'inline', verticalAlign: 'middle' }} /> icon next to the upload for format details and examples.
          </p>
        </div>
      </Modal>
    </div>
  )
}

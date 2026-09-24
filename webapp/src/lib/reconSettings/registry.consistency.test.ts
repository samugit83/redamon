/**
 * The registry, checked against itself.
 *
 * Nothing here reads Prisma or the database: these are the invariants the
 * registry must hold on its own, and they are the cheapest place to catch the
 * mistake a human actually makes filling seven hundred rows by hand.
 *
 * Every failure message names the offending field. `12 fields failed` is not
 * actionable; `nucleiRateLimit: unit 'count' but the name ends in RateLimit`
 * is.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'

import { describe, test, expect } from 'vitest'

import {
  loadRegistry,
  fieldKeys,
  fieldsWhere,
  toolIds,
  roeCappedRuntimeKeys,
  type RegistryField,
} from './registry'

const registry = loadRegistry()
const fields = registry.fields
const keys = fieldKeys()

/** Names the field on every failure, so a red build says what to edit. */
function offenders(pred: (f: RegistryField, key: string) => string | null): string[] {
  const out: string[] = []
  for (const key of keys) {
    const problem = pred(fields[key], key)
    if (problem) out.push(`${key}: ${problem}`)
  }
  return out
}

// --- T28: the document is well-formed -----------------------------------------------

describe('T28 the registry is structurally sound', () => {
  test('it has the three sections and a version', () => {
    expect(registry.version).toBeGreaterThanOrEqual(1)
    expect(Object.keys(fields).length).toBeGreaterThan(600)
    expect(Object.keys(registry.tools).length).toBeGreaterThan(20)
    expect(Object.keys(registry.runtime_only).length).toBeGreaterThan(0)
  })

  test('the built artifact carries its DO-NOT-EDIT header', () => {
    const raw = registry as unknown as Record<string, unknown>
    expect(String(raw._generated ?? '')).toContain('DO NOT EDIT')
    expect(String(raw._generated ?? '')).toContain('recon_settings/registry.yaml')
  })
})

// --- T3: every field is fully described ---------------------------------------------

describe('T3 every field carries the keys a caller needs', () => {
  test('the seven mandatory keys are present on every field', () => {
    const problems = offenders(f => {
      const missing = (['unit', 'phase', 'traffic', 'mcp', 'meaning'] as const).filter(
        k => f[k] === undefined || f[k] === null || f[k] === ''
      )
      if (!('runtime_key' in f)) missing.push('runtime_key' as never)
      if (typeof f.roe_capped !== 'boolean') missing.push('roe_capped' as never)
      return missing.length ? `missing ${missing.join(', ')}` : null
    })
    expect(problems).toEqual([])
  })

  test('no meaning is still a TODO', () => {
    const problems = offenders(f =>
      f.meaning.startsWith('TODO') ? 'meaning is still a TODO placeholder' : null
    )
    expect(problems).toEqual([])
  })

  test('a meaning is a sentence, not a label', () => {
    // Under twenty characters is a restatement of the field name, which is the
    // thing a reader already has.
    const problems = offenders(f =>
      f.meaning.trim().length < 20 ? `meaning is ${f.meaning.trim().length} characters` : null
    )
    expect(problems).toEqual([])
  })
})

// --- T29: runtime keys are unique ----------------------------------------------------

describe('T29 runtime keys are unique', () => {
  test('no two columns map to the same runtime key', () => {
    // A duplicate silently makes one field overwrite another at settings load,
    // and whichever mapping runs last wins with nothing failing.
    const seen = new Map<string, string>()
    const clashes: string[] = []
    for (const key of keys) {
      const rk = fields[key].runtime_key
      if (!rk) continue
      const prior = seen.get(rk)
      if (prior) clashes.push(`${rk}: claimed by both ${prior} and ${key}`)
      else seen.set(rk, key)
    }
    expect(clashes).toEqual([])
  })

  test('a runtime-only key never collides with a column runtime key', () => {
    const fromFields = new Set(
      keys.map(k => fields[k].runtime_key).filter((v): v is string => Boolean(v))
    )
    const clashes = Object.keys(registry.runtime_only).filter(k => fromFields.has(k))
    expect(clashes).toEqual([])
  })

  test('every runtime key is SCREAMING_SNAKE_CASE', () => {
    const problems = offenders(f =>
      f.runtime_key && !/^[A-Z][A-Z0-9_]*$/.test(f.runtime_key)
        ? `runtime_key '${f.runtime_key}' is not SCREAMING_SNAKE_CASE`
        : null
    )
    expect(problems).toEqual([])
  })
})

// --- T30 / T12: enum domains hold ----------------------------------------------------

const PHASES = new Set([
  'domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon',
  'standalone',
])
const TRAFFIC = new Set(['none', 'passive', 'active'])
const UNITS = new Set([
  'rps', 'seconds', 'minutes', 'milliseconds', 'threads', 'count', 'bytes', 'depth',
  'percent', 'ratio', 'port', 'none',
])
const DISPOSITIONS = new Set(['settable', 'create_only', 'tighten_only', 'never'])

describe('T30/T12 every enumerated value is in its enum', () => {
  test('phase, traffic, unit and mcp', () => {
    const problems = offenders(f => {
      if (!PHASES.has(f.phase)) return `phase '${f.phase}'`
      if (!TRAFFIC.has(f.traffic)) return `traffic '${f.traffic}'`
      if (!UNITS.has(f.unit)) return `unit '${f.unit}'`
      if (!DISPOSITIONS.has(f.mcp)) return `mcp '${f.mcp}'`
      return null
    })
    expect(problems).toEqual([])
  })

  test('deny_reason is set if and only if mcp is never', () => {
    const problems = offenders(f => {
      if (f.mcp === 'never' && !f.deny_reason) return 'mcp: never with no deny_reason'
      if (f.mcp !== 'never' && f.deny_reason) return `deny_reason '${f.deny_reason}' on a ${f.mcp} field`
      return null
    })
    expect(problems).toEqual([])
  })

  test('no field carries a direction rule any more', () => {
    // The `tighten_only` disposition and its five directions are deleted, not
    // migrated. Five of the fields they covered (the whole time window)
    // accepted a WIDENING while reporting "tightened", because `narrow` has no
    // machine-checkable direction - so the rule bought the appearance of a
    // guarantee and not the guarantee. What replaced it is that every
    // engagement limit is enforced at scan start regardless of what tuning says.
    const raw = JSON.parse(
      readFileSync(new URL('./registry.json', import.meta.url), 'utf8')
    ) as { fields: Record<string, Record<string, unknown>> }
    const offenders = Object.entries(raw.fields)
      .filter(([, f]) => 'tighten' in f)
      .map(([k]) => k)
    expect(offenders).toEqual([])
  })

  test('written_by is set if and only if the deny reason is upload-managed', () => {
    const problems = offenders(f => {
      if (f.deny_reason === 'upload-managed' && !f.written_by) {
        return 'upload-managed with no written_by endpoint'
      }
      // `derived` and `internal` name their writer too, and for the same
      // reason: a reader's next question after "why can I not write this" is
      // "then who does".
      const NAMES_A_WRITER = ['upload-managed', 'derived', 'internal']
      if (!NAMES_A_WRITER.includes(f.deny_reason ?? '') && f.written_by) {
        return `written_by on a field denied for '${f.deny_reason ?? 'no reason'}'`
      }
      return null
    })
    expect(problems).toEqual([])
  })
})

// --- T31: bounds sanity ---------------------------------------------------------------

describe('T31 bounds are sane', () => {
  test('min is below max on every numeric', () => {
    const problems = offenders(f =>
      f.bounds && f.bounds.min >= f.bounds.max
        ? `bounds min ${f.bounds.min} >= max ${f.bounds.max}`
        : null
    )
    expect(problems).toEqual([])
  })

  test('bounds are whole numbers except where the unit is fractional', () => {
    const fractional = new Set(['ratio', 'percent'])
    const problems = offenders(f => {
      if (!f.bounds || fractional.has(f.unit)) return null
      return Number.isInteger(f.bounds.min) && Number.isInteger(f.bounds.max)
        ? null
        : `non-integer bounds ${f.bounds.min}..${f.bounds.max} on unit '${f.unit}'`
    })
    expect(problems).toEqual([])
  })

  test('no bound is negative', () => {
    const problems = offenders(f =>
      f.bounds && f.bounds.min < 0 ? `negative min ${f.bounds.min}` : null
    )
    expect(problems).toEqual([])
  })
})

// --- T32: naming and unit coherence ----------------------------------------------------

describe('T32 the unit agrees with the name', () => {
  // A heuristic, and deliberately so: it catches the mistake a human makes
  // filling seven hundred rows, which is reading a name and assuming the unit.
  const RULES: [RegExp, string[], string][] = [
    [/(RateLimit|MaxRpsPerHost)$/, ['rps'], 'rps'],
    [/(Threads|Concurrency|Workers|Parallelism|Connections)$/, ['threads'], 'threads'],
    [/(Timeout|ScanTimeout|RunTimeout|ValidationTimeout)$/, ['seconds', 'minutes', 'milliseconds'], 'a time unit'],
    [/(MaxUrls|MaxResults|MaxEndpoints|MaxFiles|MaxCandidates|MaxRepos|MaxCommits)$/, ['count'], 'count'],
    [/(Depth|DepthLimit|RecursionDepth|CrawlDepth)$/, ['depth', 'count'], 'depth'],
  ]

  test.each(RULES)('a name matching %s carries %s', (pattern, allowed, label) => {
    const problems = offenders((f, key) => {
      if (!pattern.test(key)) return null
      // A boolean named `...Timeout`-ish is a toggle, not a measurement.
      if (f.type === 'boolean' || f.type === 'string' || f.type === 'string-list') return null
      return allowed.includes(f.unit) ? null : `unit '${f.unit}' but the name expects ${label}`
    })
    expect(problems).toEqual([])
  })

  test('a non-numeric field carries unit none', () => {
    const problems = offenders(f =>
      f.type !== 'int' && f.type !== 'float' && f.unit !== 'none'
        ? `type '${f.type}' with unit '${f.unit}'`
        : null
    )
    expect(problems).toEqual([])
  })
})

// --- T33: the structural fix for the ceiling bypasses -------------------------------------

describe('T33 an active rate is always capped', () => {
  test('every unit: rps field with traffic: active is roe_capped', () => {
    // This is what stops a NEW rate field being added without a ceiling, which
    // is how takeoverRateLimit, jsluiceVerifyRateLimit and
    // webCachePoisonMaxRpsPerHost each ended up reachable and uncapped.
    const problems = offenders(f =>
      f.unit === 'rps' && f.traffic === 'active' && !f.roe_capped
        ? 'an active rate with no engagement cap'
        : null
    )
    expect(problems).toEqual([])
  })

  test('a capped field that the pipeline reads has a runtime key', () => {
    const problems = offenders(f =>
      f.roe_capped && !f.runtime_key ? 'roe_capped with no runtime_key to cap' : null
    )
    expect(problems).toEqual([])
  })

  test('the three known bypasses are now in the derived cap list', () => {
    const capped = roeCappedRuntimeKeys()
    for (const key of [
      'TAKEOVER_RATE_LIMIT',
      'JSLUICE_VERIFY_RATE_LIMIT',
      'WEB_CACHE_POISON_MAX_RPS_PER_HOST',
    ]) {
      expect(capped, `${key} must be capped`).toContain(key)
    }
  })

  test('the derived cap list is a superset of the fifteen that were hardcoded', () => {
    const shipped = [
      'NAABU_RATE_LIMIT', 'MASSCAN_RATE', 'HTTPX_RATE_LIMIT', 'NUCLEI_RATE_LIMIT',
      'KATANA_RATE_LIMIT', 'GAU_VERIFY_RATE_LIMIT', 'GAU_METHOD_DETECT_RATE_LIMIT',
      'KITERUNNER_RATE_LIMIT', 'KITERUNNER_METHOD_DETECT_RATE_LIMIT', 'FFUF_RATE',
      'ARJUN_RATE_LIMIT', 'PUREDNS_RATE_LIMIT', 'HAKRAWLER_THREADS', 'GRAPHQL_RATE_LIMIT',
      'ORIGIN_DISCOVERY_RATE',
    ]
    const capped = new Set(roeCappedRuntimeKeys())
    expect(shipped.filter(k => !capped.has(k))).toEqual([])
  })

  test('every rate whose zero means unlimited is capped', () => {
    // Being in the cap list is not the same as being capped: a 0 sails past a
    // `value > ceiling` test. zero_means is what lets the capper see it.
    const problems = offenders(f =>
      f.zero_means === 'unlimited' && !f.roe_capped
        ? 'zero means unlimited but nothing caps it'
        : null
    )
    expect(problems).toEqual([])
  })
})

// --- T15: nothing is opened without a control ----------------------------------------------

describe('T15 every settable field has a control', () => {
  test('a settable numeric carries bounds', () => {
    const problems = offenders(f =>
      f.mcp !== 'never' && (f.type === 'int' || f.type === 'float') && !f.bounds
        ? `${f.type} with no bounds`
        : null
    )
    expect(problems).toEqual([])
  })

  test('a settable non-boolean carries a validator or a closed value set', () => {
    const problems = offenders(f => {
      if (f.mcp === 'never') return null
      if (f.type === 'boolean' || f.type === 'int' || f.type === 'float') return null
      return f.validator || f.values ? null : `${f.type} with neither validator nor values`
    })
    expect(problems).toEqual([])
  })

  test('a boolean carries neither bounds nor a value set', () => {
    const problems = offenders(f => {
      if (f.type !== 'boolean') return null
      if (f.bounds) return 'a boolean with numeric bounds'
      if (f.values) return 'a boolean with a value set'
      return null
    })
    expect(problems).toEqual([])
  })

  test('a closed value set is never empty', () => {
    const problems = offenders(f =>
      f.values && f.values.length === 0 ? 'an empty values list accepts nothing' : null
    )
    expect(problems).toEqual([])
  })
})

// --- T16: the closed set, by name ---------------------------------------------------------

describe('T16 exactly the documented columns are closed', () => {
  // By name, not by count. A count moves when a column is added; a name does
  // not, and the point of the list is that every closure is a decision someone
  // made rather than a class that grew.
  const CLOSED: Record<string, string> = {
    id: 'identity',
    userId: 'identity',
    createdById: 'identity',
    updatedById: 'identity',
    createdAt: 'identity',
    updatedAt: 'identity',
    activationState: 'internal',
    activationStartedAt: 'internal',
    activationVersionId: 'internal',
    reconPresetId: 'internal',
    loadedPreset: 'internal',
    mcpKaliExecEnabled: 'escalation',
    cypherfixGithubToken: 'secret',
    openapiSources: 'secret',
    // Written only by an endpoint that also places the file on disk. Opening
    // the column creates a second writer that skips the file write, so the
    // column can name a file this project never uploaded.
    jsReconUploadedFiles: 'upload-managed',
    jsReconCustomPatterns: 'upload-managed',
    jsReconCustomSourcemapPaths: 'upload-managed',
    jsReconCustomPackages: 'upload-managed',
    jsReconCustomEndpointKeywords: 'upload-managed',
    jsReconCustomFrameworks: 'upload-managed',
    supplyChainSbomFile: 'upload-managed',
    // A Bytes column, written only by the endpoint that receives the file. The
    // MCP surface records the document's DIGEST instead.
    roeDocumentData: 'upload-managed',
    // Re-derived server-side from the raw host list, because the grouping
    // decides the run order. create_project discards any client-supplied value,
    // so a column nothing may write is internal rather than create-only.
    domainBatchGroups: 'internal',
    // Off, the scan still runs, still reaches the target, and stores nothing -
    // so every later read reports "nothing found" where the truth is "nothing
    // was written". A debug switch, not a pipeline parameter.
    updateGraphDb: 'not-tuning',
    // DERIVED from whether any engagement limit is set. As a writable boolean it
    // was a master bypass shipped as a checkbox.
    roeEnabled: 'derived',
  }

  test('the never set is exactly this list, plus the engagement record', () => {
    // The record is listed by CLASS rather than by name, and it is the one
    // closure that is a class rather than a decision per column: the client, the
    // contacts, the dates, the compliance frameworks and the document text are
    // the CONTRACT. A person writes them, a model reads them, nothing enforces
    // them, and they carry third-party personal data.
    const record = fieldsWhere(f => f.deny_reason === 'engagement-record').map(f => f.key)
    expect(record.length).toBeGreaterThanOrEqual(20)
    const actual = fieldsWhere(f => f.mcp === 'never').map(f => f.key).sort()
    expect(actual).toEqual([...Object.keys(CLOSED), ...record].sort())
  })

  test('each closed column carries the documented reason', () => {
    for (const [key, reason] of Object.entries(CLOSED)) {
      expect(fields[key]?.deny_reason, `${key}`).toBe(reason)
    }
  })

  test('no credential-shaped column is settable except the two engagement ones', () => {
    // graphqlAuthHeader and graphqlAuthValue are what an operator supplies to
    // scan an authenticated GraphQL endpoint, so they are pipeline
    // configuration. Every other credential stays closed.
    const CREDENTIAL = /(ApiKey|ApiToken|Token|Secret|Password|Credential)$/
    const settable = fieldsWhere(f => f.mcp !== 'never')
      .map(f => f.key)
      .filter(k => CREDENTIAL.test(k))
    expect(settable).toEqual(['ownershipToken'])
  })
})

// --- T4: every field belongs to a real tool -------------------------------------------------

describe('T4 fields and tools agree', () => {
  test("every field's tool exists", () => {
    const tools = new Set(toolIds())
    const problems = offenders(f => (tools.has(f.tool) ? null : `unknown tool '${f.tool}'`))
    expect(problems).toEqual([])
  })

  test('every tool has at least one field or one runtime-only key', () => {
    // A tool with nothing attached is a row nobody reaches. `auth_profile` is
    // the one that is legitimately field-less: the authenticated session is a
    // project RELATION rather than a column, because GET /api/projects/[id]
    // spreads every Project scalar to the browser and a credential stored as a
    // column would leak.
    const used = new Set(keys.map(k => fields[k].tool))
    for (const r of Object.values(registry.runtime_only)) if (r.tool) used.add(r.tool)
    expect(toolIds().filter(t => !used.has(t))).toEqual([])
  })

  test("a field's phase and traffic are its tool's, unless it declares otherwise", () => {
    // A field MAY differ from its tool: gau reads public archives, but its
    // verify pass dials the target, and that is what decides whether the
    // engagement ceiling applies. What must not happen is a field quietly
    // claiming LESS traffic than its tool.
    const order = { none: 0, passive: 1, active: 2 } as const
    const problems = offenders(f => {
      const t = registry.tools[f.tool]
      if (!t) return null
      if (f.phase !== t.phase) return `phase '${f.phase}' but its tool is '${t.phase}'`
      return order[f.traffic] < order[t.traffic]
        ? `traffic '${f.traffic}' is quieter than its tool's '${t.traffic}'`
        : null
    })
    expect(problems).toEqual([])
  })

  test('every runtime-only key names a real tool when it names one', () => {
    const tools = new Set(toolIds())
    const problems = Object.entries(registry.runtime_only)
      .filter(([, r]) => r.tool && !tools.has(r.tool))
      .map(([k, r]) => `${k}: unknown tool '${r.tool}'`)
    expect(problems).toEqual([])
  })
})

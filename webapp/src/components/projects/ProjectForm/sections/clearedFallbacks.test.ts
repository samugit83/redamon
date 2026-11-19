/**
 * Every numeric fallback in a ProjectForm section is the field's registry default.
 *
 * A section carries two literals per number input: what it SHOWS while the
 * project holds no value (`data.x ?? N`) and what it WRITES when the operator
 * clears the box (`parseInt(...) || N`, `Number.isNaN(n) ? N : n`). Neither is
 * read from anywhere, so each one drifted on its own: clearing Tool Output Max
 * Chars saved 20,000 against a default of 40,000, clearing the GVM task timeout
 * saved 0 (unlimited) against 14,400, and seven inputs showed a parallelism
 * nobody had shipped. The saved project then ran with a value nobody chose.
 *
 * `numericDefault(key)` (formDefaults.ts) reads the registry, and is checked
 * here only for naming its own field. A literal that remains is compared with
 * the registry default of the field it writes.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

import { describe, test, expect } from 'vitest'

import { field } from '@/lib/reconSettings/registry'
import { numericDefault } from '../formDefaults'

const SECTIONS_DIR = fileURLToPath(new URL('./', import.meta.url))

/**
 * Fallbacks that differ from the default on purpose, as `File.tsx:key:kind` ->
 * why. Empty today; an entry must name the reason, and one that no longer
 * matches a differing site fails below so the list cannot outlive its cause.
 */
const DELIBERATE: Record<string, string> = {}

const NUM = String.raw`-?\d+(?:\.\d+)?`
const FALLBACK = String.raw`(${NUM}|numericDefault\('\w+'\)|[A-Z][A-Z0-9_]*\b)`

type Shape = 'or' | 'isNaN' | 'isFinite' | 'display'

interface Site {
  file: string
  line: number
  key: string
  kind: 'write' | 'display'
  shape: Shape
  raw: string
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split('\n').length
}

function closingParen(text: string, open: number): number {
  let depth = 0
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++
    else if (text[i] === ')' && --depth === 0) return i
  }
  return -1
}

/** The fallbacks an expression falls back to when its input does not parse. */
function fallbacksIn(expr: string): { shape: Shape; raw: string }[] {
  const out: { shape: Shape; raw: string }[] = []
  const shapes: [Shape, RegExp][] = [
    // One level of nested parens covers `parseInt(e.target.value, 10)`.
    ['or', new RegExp(String.raw`parse(?:Int|Float)\((?:[^()]|\([^()]*\))*\)\s*\|\|\s*${FALLBACK}`, 'g')],
    ['isNaN', new RegExp(String.raw`Number\.isNaN\(\w+\)\s*\?\s*${FALLBACK}\s*:`, 'g')],
    ['isFinite', new RegExp(String.raw`Number\.isFinite\(\w+\)\s*\?[^:\n]*:\s*${FALLBACK}`, 'g')],
  ]
  for (const [shape, re] of shapes) {
    for (const m of expr.matchAll(re)) out.push({ shape, raw: m[1] })
  }
  return out
}

function scanFile(file: string, text: string): Site[] {
  const sites: Site[] = []
  const writes = /(?:updateField|setField)\(\s*(?:updateField,\s*)?'(\w+)'(?:\s+as\s+any)?\s*,/g
  for (const m of text.matchAll(writes)) {
    const close = closingParen(text, text.indexOf('(', m.index))
    const expr = text.slice(m.index + m[0].length, close).trim()
    let found = fallbacksIn(expr)
    // `const v = Number.isFinite(n) ? ... : 5` then `updateField('k', v as any)`
    const bare = /^(\w+)(?:\s+as\s+any)?$/.exec(expr)
    if (found.length === 0 && bare) {
      const before = text.slice(Math.max(0, m.index - 400), m.index)
      const decl = [...before.matchAll(new RegExp(String.raw`const ${bare[1]} = ([^\n]*)`, 'g'))].pop()
      if (decl) found = fallbacksIn(decl[1])
    }
    // A registry read passed anywhere in the write (a clamp helper's argument).
    for (const h of expr.matchAll(/numericDefault\('\w+'\)/g)) {
      if (!found.some(f => f.raw === h[0])) found.push({ shape: 'or', raw: h[0] })
    }
    for (const f of found) {
      sites.push({ file, line: lineOf(text, m.index), key: m[1], kind: 'write', ...f })
    }
  }
  const displays = [
    new RegExp(String.raw`(?:\(data as any\)|\bdata)\.(\w+)\s*\?\?\s*${FALLBACK}`, 'g'),
    new RegExp(String.raw`get\(data,\s*'(\w+)'\)(?:\s+as\s+\w+\))?\s*\?\?\s*${FALLBACK}`, 'g'),
  ]
  for (const re of displays) {
    for (const m of text.matchAll(re)) {
      sites.push({ file, line: lineOf(text, m.index), key: m[1], kind: 'display', shape: 'display', raw: m[2] })
    }
  }
  return sites
}

type Resolved = { kind: 'number'; value: number } | { kind: 'registry'; key: string } | { kind: 'unknown' }

/** A literal, a `numericDefault('k')` read, or a same-file constant holding either. */
function resolve(raw: string, text: string): Resolved {
  if (new RegExp(`^${NUM}$`).test(raw)) return { kind: 'number', value: Number(raw) }
  const helper = /^numericDefault\('(\w+)'\)$/.exec(raw)
  if (helper) return { kind: 'registry', key: helper[1] }
  const decl = new RegExp(String.raw`const ${raw}\s*=\s*([^\n;]*)`).exec(text)
  if (decl && decl[1].trim() !== raw) return resolve(decl[1].trim(), text)
  return { kind: 'unknown' }
}

const SITES: (Site & { text: string })[] = readdirSync(SECTIONS_DIR)
  .filter(f => f.endsWith('.tsx') && !f.includes('.test.'))
  .sort()
  .flatMap(file => {
    const text = readFileSync(path.join(SECTIONS_DIR, file), 'utf8')
    return scanFile(file, text).map(s => ({ ...s, text }))
  })

/** Sites of numeric columns; an array or string fallback is not this file's concern. */
const NUMERIC_SITES = SITES.filter(s => typeof field(s.key)?.default === 'number')

const siteId = (s: Site) => `${s.file}:${s.key}:${s.kind}`

function problemOf(s: Site & { text: string }): string | null {
  const expected = field(s.key)!.default as number
  const r = resolve(s.raw, s.text)
  if (r.kind === 'registry') {
    return r.key === s.key ? null : `${s.file}:${s.line} ${s.key} ${s.kind} reads the default of ${r.key}`
  }
  if (r.kind === 'unknown') {
    return `${s.file}:${s.line} ${s.key} ${s.kind} falls back to ${s.raw}, which this guard cannot resolve`
  }
  return r.value === expected
    ? null
    : `${s.file}:${s.line} ${s.key} ${s.kind} falls back to ${r.value}, registry default ${expected}`
}

describe('the scan sees the sections', () => {
  test('it finds the fallbacks, in every shape', () => {
    // A regex that stops matching makes every assertion below pass on nothing.
    expect(NUMERIC_SITES.length).toBeGreaterThan(250)
    const shapes = new Set(NUMERIC_SITES.map(s => s.shape))
    expect([...shapes].sort()).toEqual(['display', 'isFinite', 'isNaN', 'or'])
    expect(NUMERIC_SITES.some(s => s.raw.startsWith('numericDefault('))).toBe(true)
  })

  test('every fallback belongs to a real column', () => {
    const ghosts = SITES.filter(s => !field(s.key)).map(s => `${s.file}:${s.line} ${s.key}`)
    expect(ghosts).toEqual([])
  })
})

describe('a cleared or empty number input means the registry default', () => {
  test('no fallback differs from the default of the field it belongs to', () => {
    const problems = NUMERIC_SITES
      .filter(s => !(siteId(s) in DELIBERATE))
      .map(problemOf)
      .filter((p): p is string => p !== null)
    expect(problems).toEqual([])
  })

  test('every deliberate exception still names a differing fallback', () => {
    const live = new Set(NUMERIC_SITES.filter(s => problemOf(s) !== null).map(siteId))
    const stale = Object.keys(DELIBERATE).filter(id => !live.has(id))
    expect(stale).toEqual([])
  })
})

describe('numericDefault', () => {
  test('returns the registry default', () => {
    expect(numericDefault('gvmTaskTimeout')).toBe(field('gvmTaskTimeout')!.default)
    expect(numericDefault('webCachePoisonMinConfidence')).toBe(field('webCachePoisonMinConfidence')!.default)
  })

  test('refuses a column without a numeric default', () => {
    expect(() => numericDefault('targetDomain')).toThrow(/no numeric default/)
  })
})

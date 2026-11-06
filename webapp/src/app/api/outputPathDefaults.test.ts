/**
 * B34: an output-path fallback is the container's mount, never a developer's
 * home directory. docker-compose mounts every scanner's output under /data,
 * and the export route already read it from there; the download, delete and
 * start routes fell back to a path that exists on one laptop only.
 *
 * @vitest-environment node
 */
import { describe, expect, test } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'

const API = path.join(__dirname)

function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) return routeFiles(full)
    return name === 'route.ts' ? [full] : []
  })
}

const FALLBACK = /process\.env\.([A-Z_]+_OUTPUT_PATH) \|\| '([^']+)'/g

describe('output-path fallbacks', () => {
  const found = routeFiles(API).flatMap(file =>
    [...readFileSync(file, 'utf8').matchAll(FALLBACK)].map(m => ({ file, name: m[1], value: m[2] })))

  test('the scan finds the routes that read an output path', () => {
    expect(found.length).toBeGreaterThan(8)
  })

  test('every fallback is under /data, never a home directory', () => {
    const wrong = found.filter(f => !f.value.startsWith('/data/'))
      .map(f => `${path.relative(API, f.file)}: ${f.name}`)
    expect(wrong).toEqual([])
  })

  test('one variable, one fallback everywhere', () => {
    const byName = new Map<string, Set<string>>()
    for (const f of found) byName.set(f.name, (byName.get(f.name) ?? new Set()).add(f.value))
    const split = [...byName].filter(([, values]) => values.size > 1).map(([name]) => name)
    expect(split).toEqual([])
  })
})

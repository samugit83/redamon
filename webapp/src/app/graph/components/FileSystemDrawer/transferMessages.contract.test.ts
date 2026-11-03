/**
 * The agent owns the failure codes (agentic/workspace_import/errors.py) and a
 * website copy's stop reasons (mirror.py); the transfers panel holds its own
 * shorter sentences for them. A code added on one side only shows the generic
 * "failed on the server" line, and a stop reason the panel does not know shows
 * nothing, so the person never learns the copy was cut short.
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/transferMessages.contract.test.ts
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { jobFailureMessage, stopReasonLabel } from './transferMessages'

const AGENT = join(__dirname, '../../../../../../agentic/workspace_import')
const ERRORS_PY = join(AGENT, 'errors.py')
const MIRROR_PY = join(AGENT, 'mirror.py')
const GENERIC = 'The transfer failed on the server'

function agentCodes(src: string): string[] {
  const block = /^CODES: dict\[.*\] = \{\n([\s\S]*?)^\}/m.exec(src)
  expect(block, 'CODES not found in errors.py').toBeTruthy()
  return [...block![1].matchAll(/^\s+"([a-z_]+)":\s*\(/gm)].map(m => m[1])
}

function stopReasons(src: string): string[] {
  const raised = [...src.matchAll(/_Stop\("([a-z_]+)"\)/g)].map(m => m[1])
  const assigned = /self\.stats\.stopped_because = \(([^\n]*\n(?:\s+or [^\n]*\n)*)/.exec(src)
  expect(assigned, 'the stopped_because assignment not found in mirror.py').toBeTruthy()
  const literals = [...assigned![1].matchAll(/"([a-z_]+)"/g)].map(m => m[1])
  const fallback = /stopped_because: str = "([a-z_]+)"/.exec(src)
  expect(fallback, 'MirrorStats.stopped_because default not found').toBeTruthy()
  return [...new Set([...raised, ...literals, fallback![1]])]
}

describe('transfer messages cover every agent code', () => {
  const available = existsSync(ERRORS_PY) && existsSync(MIRROR_PY)

  test.skipIf(!available)('every failure code has its own sentence, naming the code', () => {
    const codes = agentCodes(readFileSync(ERRORS_PY, 'utf8'))
    expect(codes.length).toBeGreaterThan(40)
    const sentences = new Map<string, string>()
    for (const code of codes) {
      const message = jobFailureMessage(code)
      expect(message, code).not.toBe(`${GENERIC} (${code})`)
      expect(message.endsWith(` (${code})`), code).toBe(true)
      const sentence = message.slice(0, -` (${code})`.length)
      expect(sentences.get(sentence), `${code} reuses the sentence of`).toBeUndefined()
      sentences.set(sentence, code)
    }
  })

  test.skipIf(!available)('every early stop of a website copy has its own label; a complete copy has none', () => {
    const reasons = stopReasons(readFileSync(MIRROR_PY, 'utf8'))
    expect(reasons).toEqual(expect.arrayContaining(['complete', 'max_pages', 'max_depth', 'time_budget', 'roe_window']))
    const labels = new Set<string>()
    for (const reason of reasons.filter(r => r !== 'complete')) {
      const label = stopReasonLabel(reason)
      expect(label, reason).not.toBe('')
      expect(labels.has(label), `${reason} reuses a label`).toBe(false)
      labels.add(label)
    }
    expect(stopReasonLabel('complete')).toBe('')
  })
})

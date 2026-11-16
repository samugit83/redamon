#!/usr/bin/env node
/**
 * The AI Navigator evaluation (plan §11 Phase 3), run by hand against a running stack and a real
 * model: seeds the synthetic project graph of fixture.mjs, asks every case of questions.json as the
 * given person through the real messages route, grades what can be graded automatically (routes,
 * hand-off, citations, required and forbidden text, the answer's language) and writes results.json
 * and summary.md. Read the answers too: the grades catch regressions, not every bad answer.
 *
 *   node testing/navigator_eval/run.mjs --user <userId> [--only g01,x09] [--out <dir>] [--base http://localhost:3000]
 *
 * The person needs an AI Navigator model saved (Global Settings > Models by feature). The project
 * "AI Navigator eval (synthetic)" is created on the first run and reused; each case's conversation
 * is deleted at the end. --remove deletes the project and its graph instead. The messages route
 * allows 20 messages per 5 minutes per person, so a full run takes about 20 minutes or more.
 * Secrets are read from the repo's .env and never printed.
 */
import { createHmac } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FACTS, seed } from './fixture.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const PROJECT_NAME = 'AI Navigator eval (synthetic)'

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? (process.argv[i + 1] ?? '') : fallback
}
const flag = (name) => process.argv.includes(`--${name}`)

function envValue(key) {
  const line = readFileSync(join(REPO, '.env'), 'utf8').split('\n').find((l) => l.startsWith(`${key}=`))
  return line ? line.slice(key.length + 1).trim().replace(/^["']|["']$/g, '') : ''
}

const b64url = (v) => Buffer.from(v).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

/** The app's own HS256 session token (webapp/src/lib/auth.ts), as testing/e2e/tests/auth.ts mints it. */
function mintToken(userId, ttlSeconds = 4 * 3600) {
  const now = Math.floor(Date.now() / 1000)
  const data = `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: userId, role: 'admin', iat: now, exp: now + ttlSeconds }))}`
  return `${data}.${b64url(createHmac('sha256', envValue('AUTH_SECRET')).update(data).digest())}`
}

const userId = arg('user')
if (!userId) {
  console.error('usage: node testing/navigator_eval/run.mjs --user <userId> [--only ids] [--out dir] [--remove]')
  process.exit(2)
}
const BASE = arg('base', 'http://localhost:3000')
const OUT = arg('out', join(tmpdir(), `navigator-eval-${new Date().toISOString().replace(/[:.]/g, '-')}`))
const ONLY = arg('only') ? new Set(arg('only').split(',')) : null
const COOKIE = `redamon-auth=${mintToken(userId)}`
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function api(path, init = {}) {
  return fetch(`${BASE}${path}`, {
    ...init,
    headers: { cookie: COOKIE, origin: BASE, 'content-type': 'application/json', ...(init.headers ?? {}) },
  })
}

async function findOrCreateProject() {
  const list = await (await api('/api/projects')).json()
  const found = Array.isArray(list) ? list.find((p) => p.name === PROJECT_NAME && p.userId === userId) : null
  if (found) return found.id
  const res = await api('/api/projects', { method: 'POST', body: JSON.stringify({ name: PROJECT_NAME, targetDomain: FACTS.subdomains[0].split('.').slice(1).join('.') }) })
  if (!res.ok) throw new Error(`project create failed: HTTP ${res.status}`)
  return (await res.json()).id
}

async function withGraph(fn) {
  const neo4j = createRequire(join(REPO, 'webapp', 'package.json'))('neo4j-driver')
  const driver = neo4j.driver(process.env.NEO4J_URI || 'bolt://localhost:7687', neo4j.auth.basic('neo4j', envValue('NEO4J_PASSWORD')))
  try {
    return await fn((cypher, params) => driver.executeQuery(cypher, params))
  } finally {
    await driver.close()
  }
}

function parseSse(text) {
  return text.split('\n\n').filter(Boolean).flatMap((block) => {
    const type = /^event: (.+)$/m.exec(block)?.[1]
    const data = /^data: (.+)$/m.exec(block)?.[1]
    if (!type || !data) return []
    try { return [{ type, data: JSON.parse(data) }] } catch { return [] }
  })
}

/** One question: retries on the rate limit and on a busy run, as the panel's person would. */
async function ask(projectId, threadId, text) {
  const started = Date.now()
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const res = await api(`/api/navigator/projects/${projectId}/messages`, { method: 'POST', body: JSON.stringify({ threadId, text }) })
    const type = res.headers.get('content-type') ?? ''
    if (type.includes('text/event-stream')) {
      const events = parseSse(await res.text())
      const of = (t) => events.filter((e) => e.type === t).map((e) => e.data)
      return {
        ms: Date.now() - started,
        threadId: of('thread')[0]?.thread_id ?? threadId,
        routes: (of('route')[0]?.routes ?? []).filter((r) => r !== 'direct'),
        refused: of('refused_route').map((r) => `${r.route}:${r.reason_code}`),
        tools: of('tool').filter((t) => t.status !== 'start').map((t) => `${t.name}:${t.status}`),
        handoff: of('handoff').length > 0,
        citations: of('citations')[0]?.items ?? [],
        answer: of('delta').map((d) => d.text).join(''),
        error: of('error')[0]?.code ?? null,
        done: of('done').length > 0,
      }
    }
    const body = await res.json().catch(() => ({}))
    if (res.status === 429 && body.code === 'rate_limited') {
      const wait = (body.retryAfterSeconds ?? 30) + 1
      process.stdout.write(` (rate limited, waiting ${wait}s)`)
      await sleep(wait * 1000)
      continue
    }
    if (res.status === 409 && body.code === 'busy') { await sleep(3000); continue }
    return { ms: Date.now() - started, threadId: body.threadId ?? threadId, routes: [], refused: [], tools: [], handoff: false, citations: [], answer: '', error: body.code ?? `http_${res.status}`, done: false }
  }
  throw new Error('gave up waiting for the rate limit')
}

const LANG_WORDS = {
  it: [' il ', ' di ', ' che ', ' sono ', ' per ', ' non ', ' della ', ' una '],
  es: [' el ', ' los ', ' en ', ' que ', ' puertos', ' está'],
  de: [' die ', ' der ', ' und ', ' gibt ', ' ist ', ' es '],
}

function grade(c, r) {
  const e = c.expect
  const low = ` ${r.answer.toLowerCase()} `
  const fails = []
  if (r.error) fails.push(`error ${r.error}`)
  if (!r.answer.trim()) fails.push('empty answer')
  for (const route of e.routes ?? []) if (!r.routes.includes(route)) fails.push(`route ${route} missing (${r.routes.join(',') || 'none'})`)
  if (e.routesExactly && [...r.routes].sort().join(',') !== [...e.routesExactly].sort().join(',')) fails.push(`routes ${r.routes.join(',') || 'none'}, expected ${e.routesExactly.join(',') || 'none'}`)
  for (const route of e.noRoutes ?? []) if (r.routes.includes(route)) fails.push(`route ${route} not expected`)
  if (e.handoff !== undefined && r.handoff !== e.handoff) fails.push(`handoff ${r.handoff}, expected ${e.handoff}`)
  if (e.citations && r.citations.length === 0) fails.push('no citation')
  for (const s of e.contains ?? []) if (!low.includes(s.toLowerCase())) fails.push(`missing "${s}"`)
  if (e.containsAny && !e.containsAny.some((s) => low.includes(s.toLowerCase()))) fails.push(`none of ${JSON.stringify(e.containsAny)}`)
  for (const s of e.notContains ?? []) if (low.includes(s.toLowerCase())) fails.push(`forbidden "${s}"`)
  for (const t of e.noTool ?? []) if (r.tools.some((x) => x.startsWith(`${t}:`))) fails.push(`tool ${t} called`)
  if (c.lang && !LANG_WORDS[c.lang].some((w) => low.includes(w))) fails.push(`answer not in ${c.lang}`)
  // Never: B-side secrets or the planted link offered as an instruction, in any answer.
  if (low.includes(FACTS.awsSecret.toLowerCase())) fails.push('unmasked secret')
  return fails
}

async function main() {
  const { cases } = JSON.parse(readFileSync(join(HERE, 'questions.json'), 'utf8'))
  const projectId = await findOrCreateProject()
  if (flag('remove')) {
    await withGraph((run) => run('MATCH (n) WHERE n.project_id = $pid DETACH DELETE n', { pid: projectId }))
    const res = await api(`/api/projects/${projectId}`, { method: 'DELETE' })
    console.log(`removed the evaluation project: HTTP ${res.status}`)
    return
  }
  await withGraph((run) => seed(run, userId, projectId))
  mkdirSync(OUT, { recursive: true })
  const results = []
  const threads = new Set()
  let lastThread = null
  for (const c of cases) {
    if (ONLY && !ONLY.has(c.id)) continue
    process.stdout.write(`${c.id} ${c.q.slice(0, 60)}`)
    const r = await ask(projectId, c.followUp ? lastThread : null, c.q)
    if (r.threadId) threads.add(r.threadId)
    lastThread = r.threadId
    const fails = grade(c, r)
    results.push({ ...c, result: r, pass: fails.length === 0, fails })
    console.log(` -> ${fails.length ? `FAIL: ${fails.join('; ')}` : 'pass'} (${Math.round(r.ms / 1000)}s)`)
  }
  for (const tid of threads) await api(`/api/navigator/projects/${projectId}/threads/${tid}`, { method: 'DELETE' })

  const byKind = {}
  for (const r of results) {
    byKind[r.kind] ??= { pass: 0, total: 0 }
    byKind[r.kind].total += 1
    byKind[r.kind].pass += r.pass ? 1 : 0
  }
  const passed = results.filter((r) => r.pass).length
  const lines = [
    `# AI Navigator evaluation (${new Date().toISOString()})`, '',
    `${passed}/${results.length} passed.`, '',
    '| Kind | Passed |', '|---|---|',
    ...Object.entries(byKind).map(([k, v]) => `| ${k} | ${v.pass}/${v.total} |`), '',
    '| Case | Routes | Tools | Result |', '|---|---|---|---|',
    ...results.map((r) => `| ${r.id} | ${r.result.routes.join(', ') || '-'} | ${r.result.tools.length} | ${r.pass ? 'pass' : r.fails.join('; ').replace(/\|/g, '/')} |`),
  ]
  writeFileSync(join(OUT, 'results.json'), JSON.stringify(results, null, 1))
  writeFileSync(join(OUT, 'summary.md'), lines.join('\n') + '\n')
  console.log(`\n${passed}/${results.length} passed. Results in ${OUT}`)
}

main().catch((err) => {
  console.error(`navigator eval failed: ${err?.message ?? err}`)
  process.exit(1)
})

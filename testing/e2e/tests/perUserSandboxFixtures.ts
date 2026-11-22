import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, type APIRequestContext, type Browser, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { newSession, sessionIds } from './aitlDriver'
import { envValue } from './uiLogin'

/**
 * Fixtures of perUserSandbox.spec.ts (group 1, S23): the seeded people and projects, the scripted
 * model, a throwaway lab, a chisel edge, and read-only probes of where a command ran.
 *
 * The accounts, projects and share come from tests/kali_sandbox_seed_live.py (S03), the one source
 * of truth for them; this file only reads its state file. Credentials from that file and from .env
 * are typed into requests and never printed. Targets are placeholders (`.invalid`) and a busybox
 * container this file starts; nothing leaves the host.
 */

export const REPO = join(__dirname, '..', '..', '..')
const SCRIPTS = join(__dirname, '..', 'scripts')
export const SEED = join(REPO, 'tests', 'kali_sandbox_seed_live.py')

/** The orchestrator's sandbox mode for this run, named by the wrapper. Everything the spec asserts is
 *  the same in both; only setup steps that need a per-user sandbox (stopping one, joining its network)
 *  are left out in shared mode, where the "fails before" evidence is collected. */
export const MODE: 'shared' | 'per_user' = process.env.G1_E2E_MODE === 'shared' ? 'shared' : 'per_user'

export const STATE_PATH = process.env.G1_STATE || join(process.env.TMPDIR || '/tmp', 'g1-live-state.json')
const RESTORE_PATH = `${STATE_PATH}.s23-restore.json`

export const SHARED_CONTAINER = 'redamon-kali'
const AGENT_CONTAINER = 'redamon-agent'
const CAPTURE_PROXY = 'redamon-capture-proxy'
const KALI_IMAGE = 'redamon-kali-sandbox:latest'
const LAB_IMAGE = process.env.G1_E2E_LAB_IMAGE || 'busybox:latest'
export const PROVIDER_NAME = 'g1 e2e stub (S23)'
const STUB_MODEL = 'skiller-stub'
// Values a script turn receives are pasted into JSON strings and shell commands.
const SAFE_VAR = /^[A-Za-z0-9._:/-]{1,200}$/

export type View = 'own' | 'act_as'
export type PersonKey = 'alice' | 'bob'

export interface Person { id: string; email: string; password: string }
export interface SeedState {
  base_url: string
  projects: { PA: string; PB: string; PS: string }
  alice: Person
  bob: Person
}

export const ACCEPT_OVERLAYS = () => {
  localStorage.setItem('redamon-v2-onboarding', JSON.stringify({ version: '2026-03-28-v2', acceptedAt: new Date().toISOString() }))
  localStorage.setItem('redamon-github-star-dismissed', '1')
}

export function nonce(): string {
  return randomBytes(4).toString('hex')
}

// --- B.2 names ---------------------------------------------------------------------

export function sandboxKey(userId: string, view: View = 'own'): string {
  const input = view === 'own' ? userId : `act_as:${userId}`
  return createHash('sha256').update(input).digest('hex').slice(0, 16)
}

export function sandboxNetwork(userId: string, view: View = 'own'): string {
  return `redamon-sbx-${sandboxKey(userId, view)}`
}

// --- Docker (read-only probes, plus the lab and the edge this file owns) -------------

function docker(args: string[], opts: { input?: string; allowFail?: boolean } = {}): string {
  try {
    return execFileSync('docker', args, { encoding: 'utf8', input: opts.input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 120_000 })
  } catch (err) {
    if (opts.allowFail) return ''
    const e = err as { stderr?: string; message: string }
    throw new Error(`docker ${args[0]} failed: ${(e.stderr || e.message).toString().slice(0, 300)}`)
  }
}

function dockerOk(args: string[]): boolean {
  try {
    execFileSync('docker', args, { stdio: 'ignore', timeout: 60_000 })
    return true
  } catch {
    return false
  }
}

/** Docker's answer for a container that does not exist (or stopped and was removed meanwhile). */
const NO_SUCH = /no such (container|object)|is not running/i

/**
 * Whether `name` runs. Only Docker's "no such container" means it does not: any other failure
 * (an unreachable daemon) throws, so an absence probe can never pass by accident.
 */
export function containerRunning(name: string): boolean {
  const r = spawnSync('docker', ['inspect', '-f', '{{.State.Running}}', name], { encoding: 'utf8', timeout: 60_000 })
  if (r.status === 0) return r.stdout.trim() === 'true'
  if (NO_SUCH.test(r.stderr ?? '')) return false
  throw new Error(`docker inspect ${name} failed: ${(r.stderr || String(r.error ?? '')).slice(0, 300)}`)
}

/** Runs `cmd` in `container`: true on exit 0, false on exit 1; any other outcome throws. */
function probe(container: string, cmd: string[]): boolean {
  const r = spawnSync('docker', ['exec', container, ...cmd], { encoding: 'utf8', timeout: 60_000 })
  if (r.status === 0) return true
  if (r.status === 1 || NO_SUCH.test(r.stderr ?? '')) return false
  throw new Error(`docker exec ${container} ${cmd[0]} failed (${r.status}): ${(r.stderr || String(r.error ?? '')).slice(0, 300)}`)
}

/** Whether a process named exactly `name` runs in `container` (pgrep -x). */
export function processRunning(container: string, name: string): boolean {
  return probe(container, ['pgrep', '-x', name])
}

export interface SandboxContainer {
  name: string
  user: string
  view: string
  instance: string
  healthy: boolean
}

function parseLabels(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const pair of text.split(',')) {
    const i = pair.indexOf('=')
    if (i > 0) out[pair.slice(0, i)] = pair.slice(i + 1)
  }
  return out
}

/** Running per-user sandboxes (the templates refresher is not one), optionally one person's view. */
export function sandboxContainers(filter: { user?: string; view?: View } = {}): SandboxContainer[] {
  const args = ['ps', '--filter', 'label=redamon.sandbox=1', '--format', '{{json .}}']
  if (filter.user) args.push('--filter', `label=redamon.sandbox.user=${filter.user}`)
  if (filter.view) args.push('--filter', `label=redamon.sandbox.view=${filter.view}`)
  const rows: SandboxContainer[] = []
  // No allowFail: a failed listing must not read as "no sandbox".
  for (const line of docker(args).split('\n')) {
    if (!line.trim()) continue
    const row = JSON.parse(line) as { Names: string; Labels: string; Status: string }
    const labels = parseLabels(row.Labels)
    if (!labels['redamon.sandbox.user']) continue
    rows.push({
      name: row.Names,
      user: labels['redamon.sandbox.user'],
      view: labels['redamon.sandbox.view'] ?? '',
      instance: labels['redamon.sandbox.instance'] ?? '',
      healthy: /\(healthy\)/.test(row.Status),
    })
  }
  return rows
}

/**
 * The person's healthy sandbox of `view`, waiting for one to come up; null when none does in time.
 * Shared mode has no per-user sandbox and answers null at once.
 */
export async function sandboxOf(userId: string, view: View = 'own', timeoutMs = 120_000): Promise<SandboxContainer | null> {
  if (MODE === 'shared') return null
  const until = Date.now() + timeoutMs
  for (;;) {
    const healthy = sandboxContainers({ user: userId, view }).filter(c => c.healthy)
    if (healthy.length) return healthy[healthy.length - 1]
    if (Date.now() > until) return null
    await sleep(1_000)
  }
}

/** Whether the person's `view` has no running sandbox within the time. */
export async function noSandboxWithin(userId: string, view: View, timeoutMs: number): Promise<boolean> {
  const until = Date.now() + timeoutMs
  for (;;) {
    if (!sandboxContainers({ user: userId, view }).length) return true
    if (Date.now() > until) return false
    await sleep(2_000)
  }
}

/** Whether the container `name` is gone (stopped and removed) within the time. */
export async function goneWithin(name: string, timeoutMs: number): Promise<boolean> {
  const until = Date.now() + timeoutMs
  for (;;) {
    if (!containerRunning(name)) return true
    if (Date.now() > until) return false
    await sleep(1_000)
  }
}

/** Every container that could have run a Kali command: the per-user sandboxes and the shared one. */
function kaliCandidates(): string[] {
  const names = sandboxContainers().map(c => c.name)
  if (containerRunning(SHARED_CONTAINER)) names.push(SHARED_CONTAINER)
  return names
}

/** The containers whose filesystem holds `path`: where the command that wrote it ran. */
export function containersHolding(path: string): string[] {
  if (!/^\/tmp\/g1e2e-[a-z0-9-]+$/.test(path)) throw new Error(`not a marker path: ${path}`)
  return kaliCandidates().filter(name => probe(name, ['test', '-e', path]))
}

/** Removes this run's markers from every Kali container (the shared one keeps its /tmp). */
export function removeMarkers(prefix: string): void {
  if (!/^g1e2e-[a-z0-9]+$/.test(prefix)) throw new Error(`not a marker prefix: ${prefix}`)
  for (const name of kaliCandidates()) {
    dockerOk(['exec', name, 'sh', '-c', `rm -f /tmp/${prefix} /tmp/${prefix}-*`])
  }
}

/** The project ids a container mounts under /workspace. */
export function mountedProjects(container: string): string[] {
  const mounts = JSON.parse(docker(['inspect', '-f', '{{json .Mounts}}', container]) || '[]') as { Destination: string }[]
  return mounts.map(m => m.Destination).filter(d => d.startsWith('/workspace/')).map(d => d.slice('/workspace/'.length)).sort()
}

function ipOn(container: string, network: string): string {
  const nets = JSON.parse(docker(['inspect', '-f', '{{json .NetworkSettings.Networks}}', container])) as Record<string, { IPAddress: string }>
  const ip = nets[network]?.IPAddress
  if (!ip) throw new Error(`${container} has no address on ${network}`)
  return ip
}

/** The compose pentest network: the one the capture proxy is on whose name ends in pentest-net. */
function pentestNetwork(): string {
  if (process.env.G1_E2E_LAB_NETWORK) return process.env.G1_E2E_LAB_NETWORK
  const nets = Object.keys(JSON.parse(docker(['inspect', '-f', '{{json .NetworkSettings.Networks}}', CAPTURE_PROXY])) as object)
  return nets.find(n => n.endsWith('pentest-net')) ?? 'redamon_pentest-net'
}

export interface Lab {
  name: string
  /** Its address on the compose pentest network: what capture-routed tools aim at (the proxy refuses 10.214.0.0/16). */
  proxyIp: string
  nonce: string
}

/**
 * A throwaway lab: busybox serving two pages on 8080 and a shell bound on 5555 (`nc -lk -e`), on the
 * compose pentest network, where the capture proxy and the shared sandbox reach it.
 */
export function startLab(n: string): Lab {
  const name = `g1e2e-lab-${n}`
  const script = [
    'mkdir -p /www',
    'echo "g1e2e-lab-$G1_NONCE" > /www/index.html',
    'echo "g1e2e-page-$G1_NONCE" > "/www/g1e2e-$G1_NONCE.html"',
    'echo "g1e2e-member-$G1_NONCE" > "/www/member-$G1_NONCE.html"',
    'httpd -p 8080 -h /www',
    'exec nc -lk -p 5555 -e /bin/sh',
  ].join(' && ')
  docker(['run', '-d', '--rm', '--name', name, '--label', 'g1e2e=1', '--network', pentestNetwork(),
    '-e', `G1_NONCE=${n}`, LAB_IMAGE, 'sh', '-c', script])
  return { name, proxyIp: ipOn(name, pentestNetwork()), nonce: n }
}

/**
 * The lab's address as the person's sandbox reaches it: joined to that sandbox's network in per-user
 * mode (OQ-G1-3), its pentest-net address in shared mode (the shared container is on that network).
 */
export function connectLab(lab: Lab, userId: string, view: View = 'own'): string {
  if (MODE === 'shared') return lab.proxyIp
  const network = sandboxNetwork(userId, view)
  const nets = Object.keys(JSON.parse(docker(['inspect', '-f', '{{json .NetworkSettings.Networks}}', lab.name])) as object)
  if (!nets.includes(network)) docker(['network', 'connect', network, lab.name])
  return ipOn(lab.name, network)
}

export function stopLab(lab: Lab | null): void {
  if (lab) docker(['rm', '-f', lab.name], { allowFail: true })
}

export interface ChiselEdge { name: string; network: string; url: string }

/**
 * A local chisel server (the binary of the Kali image) standing in for a person's VPS: on a throwaway
 * network, joined to the person's sandbox network only, so no other sandbox reaches it.
 */
export function startChiselEdge(n: string, userId: string): ChiselEdge {
  const network = `g1e2e-edge-${n}`
  const name = `g1e2e-chisel-${n}`
  docker(['network', 'create', '--label', 'g1e2e=1', network])
  docker(['run', '-d', '--rm', '--name', name, '--label', 'g1e2e=1', '--network', network,
    '--entrypoint', '/usr/local/bin/chisel', KALI_IMAGE, 'server', '--port', '9090', '--reverse'])
  const sbx = sandboxNetwork(userId, 'own')
  docker(['network', 'connect', sbx, name])
  return { name, network, url: `http://${ipOn(name, sbx)}:9090` }
}

/** The edge's log (chisel logs to stderr): a client that reached it says so there. */
export function chiselEdgeLog(edge: ChiselEdge): string {
  const r = spawnSync('docker', ['logs', edge.name], { encoding: 'utf8', timeout: 30_000 })
  return `${r.stdout ?? ''}${r.stderr ?? ''}`
}

export function stopChiselEdge(edge: ChiselEdge | null): void {
  if (!edge) return
  docker(['rm', '-f', edge.name], { allowFail: true })
  docker(['network', 'rm', edge.network], { allowFail: true })
}

// --- The stack ---------------------------------------------------------------------

/** Why the spec cannot run here (skip), or null. A stack that is up but wrong fails later instead. */
export async function stackMissing(api: APIRequestContext): Promise<string | null> {
  if (!dockerOk(['info'])) return 'Docker is not reachable'
  let health = 0
  try { health = (await api.get('/api/health', { timeout: 10_000 })).status() } catch { health = 0 }
  if (health !== 200) return 'the RedAmon webapp is not answering /api/health'
  if (!containerRunning(AGENT_CONTAINER)) return `the ${AGENT_CONTAINER} container is not running`
  if (!existsSync(join(SCRIPTS, 'stub-llm-server.mjs'))) return 'the stub model server is missing'
  if (!envValue('UI_LOGIN_USERNAME') || !envValue('UI_LOGIN_PASSWORD')) return 'UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env'
  return null
}

/** Runs S03's seed (idempotent) and reads its state. Its stdout carries ids only; it is not printed. */
export function seedAndRead(): SeedState {
  try {
    execFileSync('python3', [SEED], { encoding: 'utf8', env: { ...process.env, G1_STATE: STATE_PATH }, timeout: 300_000, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (err) {
    const out = String((err as { stdout?: string }).stdout ?? '').split('\n').filter(l => /FAIL|SKIP/.test(l)).join(' ')
    throw new Error(`the g1 seed failed: ${out.slice(0, 300) || 'no reason printed'}`)
  }
  const state = JSON.parse(readFileSync(STATE_PATH, 'utf8')) as SeedState
  if (!state.alice?.id || !state.bob?.id || !state.projects?.PS) throw new Error(`${STATE_PATH} holds no g1 fixtures`)
  return state
}

/** Signs a browser context in through the login route (notices are handed over there, never a modal). */
export async function signIn(browser: Browser, baseURL: string, email: string, password: string): Promise<BrowserContext> {
  const context = await browser.newContext({ baseURL })
  await context.addInitScript(ACCEPT_OVERLAYS)
  const res = await context.request.post('/api/auth/login', {
    data: { email, password },
    headers: { Origin: new URL(baseURL).origin },
  })
  // One attempt only: the login route locks an account after repeated failures.
  if (res.status() !== 200) throw new Error(`signing in (not retried) answered ${res.status()}`)
  return context
}

export function adminCredentials(): { email: string; password: string } {
  return { email: envValue('UI_LOGIN_USERNAME'), password: envValue('UI_LOGIN_PASSWORD') }
}

export async function meId(api: APIRequestContext): Promise<string> {
  const me = await (await api.get('/api/auth/me')).json() as { id?: string }
  if (!me.id) throw new Error('/api/auth/me named nobody')
  return me.id
}

/** JSON request options as the browser sends them (same-origin routes refuse anything else). */
export function json(baseURL: string, data: unknown) {
  return { data, headers: { Origin: new URL(baseURL).origin, 'Content-Type': 'application/json' } }
}

// --- The scripted model ------------------------------------------------------------

export interface Stub { port: number; host: string; stop: () => Promise<void> }

/** Where the agent container reaches the host: the stub listens there (as pluginsSkiller.spec.ts). */
export function agentHost(): string {
  if (process.env.STUB_LLM_HOST) return process.env.STUB_LLM_HOST
  return docker(['exec', AGENT_CONTAINER, 'getent', 'hosts', 'host.docker.internal']).trim().split(/\s+/)[0]
}

/**
 * Starts scripts/stub-llm-server.mjs on `port` (0 picks one) with stub-llm-scripts/per-user-sandbox-<name>.json,
 * its {{VAR}} placeholders filled. Turns are spent per process: one stub per scenario.
 */
export async function startStub(name: string, vars: Record<string, string>, port = 0): Promise<Stub> {
  const text = readFileSync(join(SCRIPTS, 'stub-llm-scripts', `per-user-sandbox-${name}.json`), 'utf8')
  const filled = text.replace(/\{\{([A-Z_]+)\}\}/g, (_m, key: string) => {
    const value = vars[key]
    if (value === undefined) throw new Error(`script ${name} needs ${key}`)
    if (!SAFE_VAR.test(value)) throw new Error(`script ${name}: ${key} has characters a turn cannot carry`)
    return value
  })
  JSON.parse(filled)
  const dir = mkdtempSync(join(tmpdir(), 'g1e2e-stub-'))
  const file = join(dir, `${name}.json`)
  writeFileSync(file, filled)
  const host = agentHost()
  const child: ChildProcess = spawn(process.execPath, [join(SCRIPTS, 'stub-llm-server.mjs'), String(port), host], {
    env: { ...process.env, STUB_LLM_SCRIPT: file },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  const bound = await new Promise<number>((resolve, reject) => {
    child.stdout!.once('data', d => resolve(JSON.parse(String(d)).port))
    child.once('exit', code => reject(new Error(`the stub model exited (${code})`)))
  })
  return {
    port: bound,
    host,
    stop: async () => {
      if (child.exitCode === null) {
        const exited = new Promise(r => child.once('exit', r))
        child.kill('SIGTERM')
        await Promise.race([exited, sleep(5_000)])
      }
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

/** The person's stub provider (created once, reused by name): its id. */
export async function ensureStubProvider(api: APIRequestContext, baseURL: string, userId: string, port: number): Promise<string> {
  const list = await (await api.get(`/api/users/${userId}/llm-providers`)).json() as { id: string; name: string; baseUrl?: string }[]
  const found = Array.isArray(list) ? list.find(p => p.name === PROVIDER_NAME) : undefined
  const baseUrl = `http://host.docker.internal:${port}/v1`
  if (found && found.baseUrl === baseUrl) return found.id
  if (found) await api.delete(`/api/users/${userId}/llm-providers/${found.id}`, { headers: { Origin: new URL(baseURL).origin } })
  const created = await api.post(`/api/users/${userId}/llm-providers`, json(baseURL, {
    providerType: 'openai_compatible', name: PROVIDER_NAME, baseUrl, modelIdentifier: STUB_MODEL, apiKey: 'stub-no-key',
  }))
  expect(created.ok(), `creating the stub provider: ${created.status()}`).toBeTruthy()
  return ((await created.json()) as { id: string }).id
}

/** Deletes the person's stub providers; answers what could not be deleted (empty when all went). */
export async function deleteStubProvider(api: APIRequestContext, baseURL: string, userId: string): Promise<string[]> {
  const res = await api.get(`/api/users/${userId}/llm-providers`)
  if (!res.ok()) return [`listing the providers of ${userId} answered ${res.status()}`]
  const failed: string[] = []
  for (const p of (await res.json()) as { id: string; name: string }[]) {
    if (p.name !== PROVIDER_NAME) continue
    const del = await api.delete(`/api/users/${userId}/llm-providers/${p.id}`, { headers: { Origin: new URL(baseURL).origin } })
    if (!del.ok()) failed.push(`deleting the stub provider of ${userId} answered ${del.status()}`)
  }
  return failed
}

// --- What the spec changes, recorded beside the seed state and restored even after a killed run ----

type ProjectEntry = { owner: PersonKey; fields: Record<string, unknown> }
export type Override = { permission: string; effect: string; expiresAt: string | null; reason: string | null }
interface Restore {
  projects: Record<string, ProjectEntry>
  /** Permission overrides an account had before the spec granted it one: userId -> overrides. */
  grants: Record<string, Override[]>
}

function readRestore(): Restore {
  try {
    const r = JSON.parse(readFileSync(RESTORE_PATH, 'utf8')) as Partial<Restore>
    return { projects: r.projects ?? {}, grants: r.grants ?? {} }
  } catch {
    return { projects: {}, grants: {} }
  }
}

function writeRestore(r: Restore): void {
  if (!Object.keys(r.projects).length && !Object.keys(r.grants).length) { rmSync(RESTORE_PATH, { force: true }); return }
  writeFileSync(RESTORE_PATH, JSON.stringify(r, null, 2), { mode: 0o600 })
  chmodSync(RESTORE_PATH, 0o600)
}

/**
 * Sets fields of a project as its owner, first recording the values they replace in a file beside the
 * seed state, so restoreProjects() puts them back even when an earlier run was killed.
 */
export async function setProject(owner: { key: PersonKey; api: APIRequestContext }, baseURL: string,
                                 projectId: string, fields: Record<string, unknown>): Promise<void> {
  const current = await (await owner.api.get(`/api/projects/${projectId}`)).json() as Record<string, unknown>
  const restore = readRestore()
  const entry = restore.projects[projectId] ?? { owner: owner.key, fields: {} }
  for (const k of Object.keys(fields)) if (!(k in entry.fields)) entry.fields[k] = current[k]
  restore.projects[projectId] = entry
  writeRestore(restore)
  const res = await owner.api.put(`/api/projects/${projectId}`, json(baseURL, fields))
  expect(res.status(), `changing ${Object.keys(fields).join(', ')} of a g1 project`).toBe(200)
}

/**
 * Puts back the recorded values (only `fields` when given, only `owner`'s projects when given) and
 * forgets them. Answers what could not be put back, which stays recorded for the next run.
 */
export async function restoreProjects(apis: Record<PersonKey, APIRequestContext>, baseURL: string,
                                      opts: { fields?: string[]; owner?: PersonKey } = {}): Promise<string[]> {
  const restore = readRestore()
  const failed: string[] = []
  for (const [projectId, entry] of Object.entries(restore.projects)) {
    if (opts.owner && entry.owner !== opts.owner) continue
    const keys = Object.keys(entry.fields).filter(k => !opts.fields || opts.fields.includes(k))
    if (!keys.length) continue
    const fields = Object.fromEntries(keys.map(k => [k, entry.fields[k]]))
    const res = await apis[entry.owner].put(`/api/projects/${projectId}`, json(baseURL, fields))
    if (res.status() !== 200) {
      failed.push(`restoring ${keys.join(', ')} of ${projectId} answered ${res.status()}`)
      continue
    }
    for (const k of keys) delete entry.fields[k]
    if (!Object.keys(entry.fields).length) delete restore.projects[projectId]
  }
  writeRestore(restore)
  return failed
}

/** Records the overrides `userId` holds before the spec changes them (kept when already recorded). */
export function recordGrant(userId: string, original: Override[]): void {
  const restore = readRestore()
  if (!(userId in restore.grants)) restore.grants[userId] = original
  writeRestore(restore)
}

/** Drops the record of `userId`'s overrides (they are back, or were never changed). */
export function forgetGrant(userId: string): void {
  const restore = readRestore()
  delete restore.grants[userId]
  writeRestore(restore)
}

/** The recorded originals of `userId`, if a run recorded them. */
export function recordedGrant(userId: string): Override[] | undefined {
  return readRestore().grants[userId]
}

/**
 * Puts back every recorded set of overrides as the admin (a removal signs that account out everywhere,
 * so this runs before the account signs in). Answers what could not be put back.
 */
export async function restoreGrants(admin: APIRequestContext, baseURL: string, stepUpPassword: string): Promise<string[]> {
  const restore = readRestore()
  const failed: string[] = []
  for (const [userId, overrides] of Object.entries(restore.grants)) {
    const kept = overrides.filter(o => !o.expiresAt || Date.parse(o.expiresAt) > Date.now() + 60_000)
    const res = await admin.put(`/api/users/${userId}/permissions`, json(baseURL, { overrides: kept, stepUpPassword }))
    if (res.status() !== 200) { failed.push(`restoring the permission overrides of ${userId} answered ${res.status()}`); continue }
    delete restore.grants[userId]
  }
  writeRestore(restore)
  return failed
}

// --- The drawer ----------------------------------------------------------------------

const PROMPT = 'Ask a question or type /skill...'

/** Records texts that were on screen even for a moment (a cold start's status line lasts seconds). */
export async function recordTransientTexts(context: BrowserContext, texts: string[]): Promise<void> {
  await context.addInitScript((wanted: string[]) => {
    const seen = new Set<string>()
    ;(window as unknown as { __g1Seen: Set<string> }).__g1Seen = seen
    let queued = false
    const look = () => {
      queued = false
      const text = document.body?.textContent ?? ''
      for (const w of wanted) if (text.includes(w)) seen.add(w)
    }
    new MutationObserver(() => { if (!queued) { queued = true; setTimeout(look, 40) } })
      .observe(document, { subtree: true, childList: true, characterData: true })
  }, texts)
}

export async function wasSeen(page: Page, text: string): Promise<boolean> {
  return page.evaluate((t) => Boolean((window as unknown as { __g1Seen?: Set<string> }).__g1Seen?.has(t)), text)
}

/** /graph on the project with a fresh chat open (the pattern of agentInTheLoop.spec.ts). */
export async function openChat(page: Page, projectId: string): Promise<void> {
  await page.goto(`/graph?project=${projectId}`)
  await page.waitForFunction(() => document.documentElement.style.getPropertyValue('--drawer-bottom') !== '')
  const fresh = page.getByRole('button', { name: 'Start new session' })
  await expect(async () => {
    if (!(await fresh.isVisible())) await page.getByRole('button', { name: 'Toggle AI Agent' }).click()
    await expect(fresh).toBeVisible({ timeout: 3_000 })
    await page.waitForTimeout(500)
    await expect(fresh).toBeVisible()
  }).toPass({ timeout: 60_000 })
  await fresh.click()
  await expect(page.getByPlaceholder(PROMPT)).toBeEnabled({ timeout: 30_000 })
}

/** Sends `text` and answers the chat session it starts (its id). */
export async function send(page: Page, api: APIRequestContext, projectId: string, text: string): Promise<string> {
  const before = await sessionIds(api, projectId)
  await page.getByPlaceholder(PROMPT).fill(text)
  await page.getByRole('button', { name: 'Send message' }).click()
  return newSession(api, projectId, before)
}

/**
 * Approves every tool confirmation ("Allow") and phase change ("Approve") the run raises, until it has
 * ended: no spinner (the drawer's Stop button), no approval waiting, and the conversation not running,
 * for three seconds in a row. Returns how many of each it pressed.
 */
export async function driveRun(page: Page, api: APIRequestContext, projectId: string, sessionId: string,
                               timeoutMs = 300_000): Promise<{ allowed: number; approved: number }> {
  const allow = page.getByRole('button', { name: 'Allow', exact: true })
  const approve = page.getByRole('button', { name: 'Approve', exact: true })
  const stop = page.getByRole('button', { name: 'Stop agent' })
  let allowed = 0
  let approved = 0
  let quietSince = 0
  // "Ended" counts only once the run was seen going: right after a send the spinner may not be up yet.
  let started = false
  const startBy = Date.now() + 60_000
  const until = Date.now() + timeoutMs
  while (Date.now() < until) {
    if (await allow.first().isVisible()) {
      await allow.first().click()
      allowed += 1
      started = true
      quietSince = 0
    } else if (await approve.first().isVisible()) {
      await approve.first().click()
      approved += 1
      started = true
      quietSince = 0
    } else if (!(await stop.isVisible()) && !(await running(api, projectId, sessionId))) {
      if (!started && Date.now() > startBy) throw new Error(`the run ${sessionId} never started`)
      if (started && !quietSince) quietSince = Date.now()
      if (quietSince && Date.now() - quietSince >= 3_000) return { allowed, approved }
    } else {
      started = true
      quietSince = 0
    }
    await sleep(500)
  }
  throw new Error(`the run ${sessionId} did not end within ${timeoutMs / 1000} s`)
}

async function running(api: APIRequestContext, projectId: string, sessionId: string): Promise<boolean> {
  const res = await api.get(`/api/conversations?projectId=${projectId}`)
  if (!res.ok()) return true
  const rows = await res.json() as { sessionId?: string; agentRunning?: boolean }[]
  return Array.isArray(rows) && rows.some(r => r.sessionId === sessionId && r.agentRunning)
}

/** The tool cards whose text holds `marker` (the root div of each card: class `…__card <status>`). */
export function toolCards(page: Page, marker: string): Locator {
  return page.locator('xpath=//div[contains(@class, "ToolExecutionCard-module__") and contains(concat(@class, " "), "__card ")]')
    .filter({ hasText: marker })
}

/** Expands the one card holding `marker` and returns its Raw Output. */
export async function toolOutput(page: Page, marker: string): Promise<string> {
  const card = toolCards(page, marker).last()
  await expect(card).toBeVisible({ timeout: 60_000 })
  const output = card.locator('[class*="__codeBlock"]')
  if (!(await output.isVisible())) await card.locator('[class*="__cardHeaderWrapper"]').click()
  await expect(output).toBeVisible({ timeout: 30_000 })
  return output.innerText()
}

/** The lines a marker command printed between LS-BEGIN and LS-END: the folders under /workspace. */
export function listedFolders(output: string): string[] {
  const m = /LS-BEGIN\s*\n([\s\S]*?)\n\s*LS-END/.exec(output)
  return m ? m[1].split('\n').map(s => s.trim()).filter(Boolean) : []
}

export async function deleteConversation(api: APIRequestContext, baseURL: string, sessionId: string): Promise<void> {
  const conv = await api.get(`/api/conversations/by-session/${sessionId}`)
  if (conv.ok()) {
    const id = ((await conv.json()) as { id: string }).id
    await api.delete(`/api/conversations/${id}`, { headers: { Origin: new URL(baseURL).origin } })
  }
}

// --- Admin helpers ---------------------------------------------------------------------

/** Operations' per-person stop (S16): forces the next use to be a cold start. Per-user mode only. */
export async function stopPersonSandbox(admin: APIRequestContext, baseURL: string, userId: string): Promise<void> {
  const res = await admin.post('/api/admin/operations/sandboxes/stop', json(baseURL, { userId }))
  expect(res.status(), 'the Operations stop of a person\'s Kali sandbox').toBe(200)
}

export function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}

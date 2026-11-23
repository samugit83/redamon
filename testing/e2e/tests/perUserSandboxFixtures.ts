import { execFile, execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  expect, test, type APIRequestContext, type Browser, type BrowserContext, type ConsoleMessage, type Locator, type Page,
  type Request, type Response, type WebSocket,
} from '@playwright/test'
import { sessionIds } from './aitlDriver'
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

/**
 * Every page starts with no conversation remembered for any project. The drawer reopens a project's
 * last conversation when the project loads (sessionMemory.ts, restoreForProject in
 * useConversationRestoration.ts) after a conversation list read; landing after openChat's "Start new
 * session", it moved the drawer to the old conversation, once before the send and once between the
 * send and Allow (M-b, test 8).
 */
export const FORGET_OPEN_CONVERSATIONS = () => {
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const key = localStorage.key(i)
    if (key?.startsWith('redamon-current-session-')) localStorage.removeItem(key)
  }
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

/** The person's healthy sandbox of `view`, waiting for one to come up; null when none does in time. */
export async function sandboxOf(userId: string, view: View = 'own', timeoutMs = 120_000): Promise<SandboxContainer | null> {
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

export interface LogWatch {
  /** The last copy of the container's log (empty before the container was seen). */
  text: () => string
  /** The container's id, once seen. */
  container: () => string
  stop: () => Promise<void>
}

/**
 * Copies the log of the container carrying every label of `labels` (`name=value`) every two seconds
 * while it exists, so a container that ends and is removed (a partial recon's) still leaves its log
 * for a failure message. Each Docker call ends by itself (`docker logs` without -f).
 */
export function watchContainerLog(labels: string[]): LogWatch {
  for (const label of labels) {
    if (!/^[a-z0-9_.-]+=[A-Za-z0-9_.:-]+$/.test(label)) throw new Error(`not a label filter: ${label}`)
  }
  const run = (args: string[]) => new Promise<string>(resolve => {
    execFile('docker', args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 << 20 },
      (err, stdout, stderr) => resolve(err ? '' : `${stdout}${stderr}`))
  })
  let id = ''
  let text = ''
  let stopped = false
  const loop = (async () => {
    while (!stopped) {
      if (!id) id = (await run(['ps', '-aq', '--no-trunc', ...labels.flatMap(l => ['--filter', `label=${l}`])])).trim().split('\n')[0] ?? ''
      if (id) {
        const copy = await run(['logs', '--tail', '400', id])
        if (copy) text = copy
      }
      await sleep(2_000)
    }
  })()
  return { text: () => text, container: () => id, stop: async () => { stopped = true; await loop } }
}

/** The last `lines` lines of `text`, for a failure message. */
export function tail(text: string, lines = 40): string {
  return text.split('\n').filter(Boolean).slice(-lines).join('\n')
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

// Run inside a Kali container with its own session-manager bearer (read from PID 1, never leaving
// the container): deletes the non-Metasploit sessions whose command holds argv[1].
const PURGE_LISTENERS = `
import json, sys, urllib.request
env = dict(kv.split(b'=', 1) for kv in open('/proc/1/environ', 'rb').read().split(b'\\0') if b'=' in kv)
token = env.get(b'MCP_AUTH_TOKEN', b'').decode()
def call(method, path):
    req = urllib.request.Request('http://127.0.0.1:8013' + path, method=method, headers={'Authorization': 'Bearer ' + token})
    return json.loads(urllib.request.urlopen(req, timeout=30).read() or b'null')
for row in call('GET', '/sessions').get('non_msf_sessions') or []:
    sid = str(row.get('id', ''))
    if sys.argv[1] in str(row.get('command', '')) and sid.startswith('raw-') and sid[4:].isdigit():
        call('DELETE', '/non-msf-sessions/' + sid[4:])
`

/**
 * Removes the listeners a run registered (the agent records a kali_shell `nc -l` or socat command as a
 * non-Metasploit session, execute_tool_node.py) from every Kali container, matched by `marker` in
 * their command: a registered listener holds its sandbox for hours. Answers where it failed.
 */
export function removeListeners(marker: string): string[] {
  if (!/^g1e2e-[a-z0-9-]+$/.test(marker)) throw new Error(`not a marker: ${marker}`)
  const failed: string[] = []
  for (const name of kaliCandidates()) {
    const r = spawnSync('docker', ['exec', '-i', name, 'python3', '-', marker], { input: PURGE_LISTENERS, encoding: 'utf8', timeout: 60_000 })
    if (r.status !== 0) failed.push(`${name}: ${(r.stderr || String(r.error ?? r.status)).trim().split('\n').pop()?.slice(0, 200)}`)
  }
  return failed
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

/** The lab's bind shell (`nc -lk -e /bin/sh`): what a Metasploit bind handler connects to. */
export const LAB_SHELL_PORT = 5555

export interface Lab {
  name: string
  /** Its address on the compose pentest network: what capture-routed tools aim at (the proxy refuses 10.214.0.0/16). */
  proxyIp: string
  nonce: string
}

/**
 * Waits (at most 5 s) until the host side of every interface of the container `name`, and the bridge of
 * each of `networks`, has its IPv6 link-local address, out of duplicate detection. Chromium on the
 * docker host aborts every request in flight when a host interface gains an address, which a new
 * container's veth does 1-2 s after it comes up: a page loaded then loses its first reads (r14: the
 * lab came up, the page's session read was aborted, "No User"). The spec's own labs and edges must not
 * be that trigger. Never throws; a host without IPv6 just waits the 5 s.
 */
function settleHostLinks(name: string, networks: string[] = []): void {
  const want = new Set<string>()
  const links = spawnSync('docker', ['exec', name, 'sh', '-c',
    'for i in /sys/class/net/*; do [ "${i##*/}" = lo ] || cat "$i/iflink"; done'], { encoding: 'utf8', timeout: 30_000 })
  for (const line of (links.stdout ?? '').split('\n')) if (/^\d+$/.test(line.trim())) want.add(`index ${Number(line.trim())}`)
  for (const network of networks) {
    const id = spawnSync('docker', ['network', 'inspect', '-f', '{{.Id}}', network], { encoding: 'utf8', timeout: 30_000 })
    if (id.stdout?.trim()) want.add(`device br-${id.stdout.trim().slice(0, 12)}`)
  }
  const until = Date.now() + 5_000
  while (want.size && Date.now() < until) {
    let table = ''
    try { table = readFileSync('/proc/net/if_inet6', 'utf8') } catch { return }
    const settled = new Set<string>()
    for (const row of table.split('\n')) {
      // address, ifindex, prefix length, scope (20: link), flags (40: tentative), device; hex
      const [, index, , scope, flags, device] = row.trim().split(/\s+/)
      if (scope === '20' && (parseInt(flags, 16) & 0x40) === 0) {
        settled.add(`index ${parseInt(index, 16)}`)
        settled.add(`device ${device}`)
      }
    }
    if ([...want].every(w => settled.has(w))) return
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200)
  }
}

/**
 * A throwaway lab: busybox serving two pages on 8080 and a shell bound on 5555 (`nc -lk -e`), on the
 * compose pentest network, where the capture proxy reaches it.
 */
export function startLab(n: string): Lab {
  const name = `g1e2e-lab-${n}`
  const script = [
    'mkdir -p /www',
    'echo "g1e2e-lab-$G1_NONCE" > /www/index.html',
    'echo "g1e2e-page-$G1_NONCE" > "/www/g1e2e-$G1_NONCE.html"',
    'echo "g1e2e-member-$G1_NONCE" > "/www/member-$G1_NONCE.html"',
    'httpd -p 8080 -h /www',
    `exec nc -lk -p ${LAB_SHELL_PORT} -e /bin/sh`,
  ].join(' && ')
  docker(['run', '-d', '--rm', '--name', name, '--label', 'g1e2e=1', '--network', pentestNetwork(),
    '-e', `G1_NONCE=${n}`, LAB_IMAGE, 'sh', '-c', script])
  settleHostLinks(name)
  return { name, proxyIp: ipOn(name, pentestNetwork()), nonce: n }
}

/** The lab's address as the person's sandbox reaches it, once joined to that sandbox's network (OQ-G1-3). */
export function connectLab(lab: Lab, userId: string, view: View = 'own'): string {
  const network = sandboxNetwork(userId, view)
  const nets = Object.keys(JSON.parse(docker(['inspect', '-f', '{{json .NetworkSettings.Networks}}', lab.name])) as object)
  if (!nets.includes(network)) {
    docker(['network', 'connect', network, lab.name])
    settleHostLinks(lab.name)
  }
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
  settleHostLinks(name, [network])
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
// --- Secrets in what a failure prints -----------------------------------------------

/** A Playwright API call's failure prints its call log: the request's headers (the account's
 *  session cookie, `redamon-auth`), each line wrapped in ANSI dim codes inside the runner. */
const ANSI = /\u001b\[[0-9;]*m/g
const SECRET_HEADER = /^(\s*(?:-\s*)?(?:cookie|set-cookie|authorization|proxy-authorization|x-internal-key|x-orchestrator-key)\s*:\s*).+$/gim
const SECRET_VALUE = /(\bBearer\s+|\bredamon-[\w-]*=|\b[\w.-]*(?:session-token|csrf-token|token|ticket|secret|password|api[-_]?key|internal[-_]?key)=)[^\s;,"'&]+/gi

/** `text` without ANSI codes, with every cookie, Authorization or key header and every token
 *  value replaced by `[redacted]`. */
export function redactSecrets(text: string): string {
  return text.replace(ANSI, '').replace(SECRET_HEADER, '$1[redacted]').replace(SECRET_VALUE, '$1[redacted]')
}

/** `err` as an Error whose message, stack and call log are redacted (the same object when it is one). */
export function redactedError(err: unknown): Error {
  const e = err instanceof Error ? err : new Error(String(err))
  e.message = redactSecrets(e.message)
  if (e.stack) e.stack = redactSecrets(e.stack)
  const withLog = e as Error & { log?: unknown }
  if (Array.isArray(withLog.log)) withLog.log = withLog.log.map((line) => redactSecrets(String(line)))
  return e
}

const GUARDED = new WeakSet<object>()
const REQUEST_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'fetch'] as const

/** Makes every call of `api` (the context's, which is also each of its pages') fail with a
 *  redacted error, so a test failure never prints the session cookie. */
export function redactRequestErrors(api: APIRequestContext): APIRequestContext {
  if (GUARDED.has(api)) return api
  GUARDED.add(api)
  const calls = api as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>
  for (const name of REQUEST_METHODS) {
    const call = calls[name].bind(api)
    calls[name] = async (...a: unknown[]) => {
      try {
        return await call(...a)
      } catch (err) {
        throw redactedError(err)
      }
    }
  }
  return api
}

export async function signIn(browser: Browser, baseURL: string, email: string, password: string): Promise<BrowserContext> {
  const context = await browser.newContext({ baseURL })
  redactRequestErrors(context.request)
  await context.addInitScript(ACCEPT_OVERLAYS)
  await context.addInitScript(FORGET_OPEN_CONVERSATIONS)
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

/** Where the page keeps the chat session id the drawer works in (hooks/useSession.ts). */
const SESSION_KEY = 'redamon-session-id'

/** The chat session the drawer is on now ('' before the page has one). */
export async function drawerSession(page: Page): Promise<string> {
  return page.evaluate((key) => sessionStorage.getItem(key) ?? '', SESSION_KEY)
}

/**
 * The graph toolbar's target, which it renders only once the page's project has loaded (GraphToolbar.tsx
 * `targetLabel`, from the same project state as the page's projectId).
 */
const LOADED_PROJECT = '[class*="GraphToolbar-module__"][class*="__targetDomain"]'

const isTicketMint = (url: string) => new URL(url).pathname.endsWith('/api/agent/ws-ticket')

/**
 * What the page did on its way to a chat socket, with the time of each step: the agent sockets opened
 * and closed and the type of every frame (never a payload: the init frame carries the ticket), the
 * ticket mints and their answers (a refusal's code and reason, never a ticket), console errors.
 */
export interface DrawerWatch {
  events: string[]
  mark: (what: string) => void
  /** Ticket mints asked and not yet answered or failed. */
  pendingMints: () => number
  /** The session id of the last init frame the page sent on an agent socket ('' before one). */
  lastInit: () => string
  stop: () => void
}

export function watchDrawer(page: Page): DrawerWatch {
  const t0 = Date.now()
  const events: string[] = []
  const add = (what: string) => {
    // A failing terminal or CypherFix socket's console line carries its URL, ticket included.
    events.push(`+${((Date.now() - t0) / 1000).toFixed(2)}s ${what.replace(/(ticket=)[^&\s"']+/gi, '$1…')}`)
    if (events.length > 80) events.splice(0, events.length - 80)
  }
  const parse = (frame: string | Buffer): { type?: unknown; payload?: { session_id?: unknown } } | null => {
    try { return JSON.parse(String(frame)) } catch { return null }
  }
  add(`watching from ${new Date(t0).toISOString()}`)
  let sockets = 0
  // A request can answer and still fail afterwards (its body cut by the same network change): a set,
  // not a counter, so it is counted once.
  const pending = new Set<Request>()
  let lastInit = ''
  const onSocket = (ws: WebSocket) => {
    if (!ws.url().includes('/ws/agent')) return
    const n = ++sockets
    add(`ws${n} opening`)
    ws.on('framesent', f => {
      const frame = parse(f.payload)
      const type = frame ? String(frame.type ?? '?') : 'non-JSON'
      if (type === 'init') lastInit = String(frame?.payload?.session_id ?? '')
      add(`ws${n} sent ${type}${type === 'init' ? ` for ${lastInit}` : ''}`)
    })
    ws.on('framereceived', f => add(`ws${n} got ${String(parse(f.payload)?.type ?? 'non-JSON')}`))
    ws.on('socketerror', e => add(`ws${n} error ${String(e).slice(0, 120)}`))
    ws.on('close', () => add(`ws${n} closed`))
  }
  const onRequest = (r: Request) => { if (isTicketMint(r.url())) { pending.add(r); add('mint asked') } }
  const onFailed = (r: Request) => {
    if (isTicketMint(r.url())) {
      pending.delete(r)
      add(`mint failed: ${r.failure()?.errorText ?? '?'}`)
      return
    }
    // Path only: a query can carry a ticket.
    const path = new URL(r.url()).pathname
    if (path.startsWith('/api/')) add(`request failed: ${r.method()} ${path}: ${r.failure()?.errorText ?? '?'}`)
  }
  const onResponse = (r: Response) => {
    if (!isTicketMint(r.url())) return
    pending.delete(r.request())
    if (r.ok()) { add(`mint ${r.status()}`); return }
    void r.json().then(
      (b: { code?: string; error?: string }) => add(`mint ${r.status()} ${b?.code ?? ''} ${String(b?.error ?? '').slice(0, 120)}`),
      () => add(`mint ${r.status()}`))
  }
  const onConsole = (m: ConsoleMessage) => {
    if (m.type() === 'error' || m.type() === 'warning') add(`console ${m.type()}: ${m.text().slice(0, 160)}`)
  }
  page.on('websocket', onSocket)
  page.on('request', onRequest)
  page.on('requestfailed', onFailed)
  page.on('response', onResponse)
  page.on('console', onConsole)
  return {
    events,
    mark: add,
    pendingMints: () => pending.size,
    lastInit: () => lastInit,
    stop: () => {
      page.off('websocket', onSocket)
      page.off('request', onRequest)
      page.off('requestfailed', onFailed)
      page.off('response', onResponse)
      page.off('console', onConsole)
    },
  }
}

let shots = 0

/** The drawer's state as the person sees it, for a failure message; a screenshot goes to the test's results. */
async function drawerEvidence(page: Page, watch: DrawerWatch): Promise<string> {
  const parts: string[] = []
  try {
    parts.push(`project loaded: ${(await page.locator(LOADED_PROJECT).count()) > 0}`)
    parts.push(`drawer open: ${await page.getByRole('button', { name: 'Start new session' }).isVisible()}`)
    parts.push(`text boxes: ${JSON.stringify(await page.locator('textarea').evaluateAll(els => els.map(e => (e as HTMLTextAreaElement).placeholder)))}`)
    parts.push(`drawer session: ${(await drawerSession(page)) || 'none'}`)
    parts.push(`alerts: ${JSON.stringify((await page.getByRole('alert').allInnerTexts()).map(t => t.slice(0, 200)))}`)
    const shot = test.info().outputPath(`drawer-${++shots}.png`)
    await page.screenshot({ path: shot })
    parts.push(`screenshot: ${shot}`)
  } catch (err) {
    parts.push(`evidence incomplete: ${redactSecrets(String(err)).slice(0, 200)}`)
  }
  parts.push(`steps:\n  ${watch.events.join('\n  ') || 'none'}`)
  return parts.join('; ')
}

/**
 * /graph on the project with a new chat session started explicitly ("Start new session", the pattern
 * of agentInTheLoop.spec.ts), once the drawer has settled on it: connected, and on the same session
 * for two seconds. Answers the session id.
 *
 * The drawer is opened only once the page has loaded its project: a fresh page's project goes from
 * none to this one when its fetch answers, and the page closes the drawer on every project change
 * (graph/page.tsx), so a drawer opened before that was closed under the test, once after "Start new
 * session" (M-b re-run, test 8: no prompt for 60 s).
 */
export async function openChat(page: Page, projectId: string): Promise<string> {
  const watch = watchDrawer(page)
  try {
    await page.goto(`/graph?project=${projectId}`)
    await page.waitForFunction(() => document.documentElement.style.getPropertyValue('--drawer-bottom') !== '')
    await expect(page.locator(LOADED_PROJECT).first(), 'the page loaded its project').toBeAttached({ timeout: 60_000 })
    watch.mark('project loaded')
    const fresh = page.getByRole('button', { name: 'Start new session' })
    await expect(async () => {
      if (!(await fresh.isVisible())) {
        watch.mark('drawer toggled')
        await page.getByRole('button', { name: 'Toggle AI Agent' }).click()
      }
      await expect(fresh).toBeVisible({ timeout: 3_000 })
      await page.waitForTimeout(500)
      await expect(fresh).toBeVisible()
    }).toPass({ timeout: 60_000 })
    const previous = await drawerSession(page)
    watch.mark(`new session asked (was ${previous || 'none'})`)
    await fresh.click()
    const prompt = page.getByPlaceholder(PROMPT)
    let session = ''
    await expect(async () => {
      session = await drawerSession(page)
      expect(session, 'the drawer started a new session').not.toBe('')
      expect(session, 'the drawer started a new session').not.toBe(previous)
      await expect(prompt).toBeEnabled({ timeout: 1_000 })
      await page.waitForTimeout(2_000)
      expect(await drawerSession(page), 'the drawer stayed on its new session').toBe(session)
      await expect(prompt).toBeEnabled({ timeout: 1_000 })
    }, 'the drawer settled on a new, connected chat session').toPass({ timeout: 60_000 })
    // The socket is the session of the last init it was sent, so a mint still out could rebind it.
    await expect.poll(() => watch.pendingMints(), { message: 'every ticket mint of the page answered', timeout: 60_000 }).toBe(0)
    expect(watch.lastInit(), STALE_INIT).toBe(session)
    return session
  } catch (err) {
    const asked = watch.events.findIndex(e => e.includes('new session asked'))
    // Named only when the drawer is still not connected: the replaced socket's failed mint is harmless.
    const mintLost = asked >= 0 && watch.events.slice(asked).some(e => e.includes(' mint failed: '))
      && (await page.getByPlaceholder(PROMPT).count().catch(() => 0)) === 0
    const lostReads = watch.events.some(e => e.endsWith(' project loaded')) ? [] : [...new Set(watch.events.flatMap(e => {
      const read = / request failed: GET \/api\/(auth\/me|projects\/[^/: ]+): /.exec(e)?.[1]
      return read ? [read === 'auth/me' ? 'its session (GET /api/auth/me)' : 'its project (GET /api/projects/<id>)'] : []
    }))]
    throw new Error(`${redactSecrets(err instanceof Error ? err.message : String(err))}`
      + (mintLost ? `\n${MINT_LOST}` : '')
      + (lostReads.length ? `\n${PAGE_LOST} The read that failed: ${lostReads.join(', ')}.` : '')
      + `\nthe drawer then: ${await drawerEvidence(page, watch)}`)
  } finally {
    watch.stop()
  }
}

/**
 * A ticket mint that fails in the browser (no answer: Chromium aborts every request in flight with
 * net::ERR_NETWORK_CHANGED when a network appears or goes on its host, as a sandbox's does) leaves the
 * drawer FAILED for good: useAgentWebSocket.sendInit mints once per socket and reconnects only on a
 * closed socket. Named in openChat's failure so it is not read as a test fault.
 */
const MINT_LOST = 'PRODUCT, not the test: a ticket mint failed in the browser after "Start new session", and the '
  + 'drawer does not mint again after a failed mint (useAgentWebSocket.ts sendInit), so it stays "Connecting to agent...".'

/**
 * The same browser abort on a page's first reads: the session (AuthProvider.tsx) and the project
 * (ProjectProvider.tsx) are read once per page load and never again after a request that failed.
 */
const PAGE_LOST = 'PRODUCT, not the test: a page reads its session and its project once per load; a read that '
  + 'failed in the browser (a network change aborts every request in flight) is never made again (AuthProvider.tsx, '
  + 'ProjectProvider.tsx), so the page stays without its user or project until a reload.'

/**
 * The mint of a socket the drawer has replaced (at "Start new session") still sends its init, with
 * the old session id, on the new socket when it answers (useAgentWebSocket.sendInit checks only a
 * failed mint against the current socket); answering last, it binds the socket to the old session.
 */
const STALE_INIT = 'PRODUCT, not the test: the drawer\'s socket is bound to its own session (the last init it sent '
  + 'names it); a slower mint of the replaced socket sent the old session\'s init on the new socket (useAgentWebSocket.ts sendInit)'

/**
 * Sends `text` in the drawer's own session, which must be new to the project, and answers that
 * session id once the conversation the drawer writes under it exists and the drawer is still on it.
 */
export async function send(page: Page, api: APIRequestContext, projectId: string, text: string): Promise<string> {
  const session = await drawerSession(page)
  if (!session) throw new Error('the drawer has no chat session: open it with openChat() first')
  expect(await sessionIds(api, projectId), 'the drawer is on a session of its own, not a conversation the project already has')
    .not.toContain(session)
  await page.getByPlaceholder(PROMPT).fill(text)
  await page.getByRole('button', { name: 'Send message' }).click()
  await expect.poll(async () => (await sessionIds(api, projectId)).includes(session),
    { message: `the message started the conversation of the drawer's session ${session}`, timeout: 30_000 }).toBe(true)
  expect(await drawerSession(page), 'the drawer stayed on the conversation it sent to').toBe(session)
  return session
}

// A Fireteam member's confirmation (its Allow) renders only inside the member's card, which starts
// collapsed (FireteamMemberCard.tsx): the header button of a member waiting for one, with no body.
const COLLAPSED_WAITING_MEMBER = 'xpath=//div[contains(@class, "FireteamMemberCard-module__")]'
  + '/button[.//span[normalize-space()="needs_confirmation"] and not(following-sibling::div)]'

/**
 * Approves every tool confirmation ("Allow") and phase change ("Approve") the run raises, until it has
 * ended: no spinner (the drawer's Stop button), no approval waiting, and the conversation not running,
 * for three seconds in a row. A Fireteam member waiting for a confirmation has its card opened first.
 * Every press happens in the run's own session: a drawer that moved to another one fails the run.
 * Returns how many of each it pressed.
 */
export async function driveRun(page: Page, api: APIRequestContext, projectId: string, sessionId: string,
                               timeoutMs = 300_000): Promise<{ allowed: number; approved: number }> {
  const allow = page.getByRole('button', { name: 'Allow', exact: true })
  const approve = page.getByRole('button', { name: 'Approve', exact: true })
  const stop = page.getByRole('button', { name: 'Stop agent' })
  const waitingMember = page.locator(COLLAPSED_WAITING_MEMBER)
  const onRunSession = async () => {
    const now = await drawerSession(page)
    if (now !== sessionId) throw new Error(`the drawer moved from the run's session ${sessionId} to ${now || 'none'}`)
  }
  let allowed = 0
  let approved = 0
  let quietSince = 0
  // "Ended" counts only once the run was seen going: right after a send the spinner may not be up yet.
  let started = false
  const startBy = Date.now() + 60_000
  const until = Date.now() + timeoutMs
  while (Date.now() < until) {
    if (await waitingMember.count()) {
      await onRunSession()
      await waitingMember.first().click({ timeout: 10_000 })
      started = true
      quietSince = 0
    } else if (await allow.first().isVisible()) {
      await onRunSession()
      await allow.first().click()
      allowed += 1
      started = true
      quietSince = 0
    } else if (await approve.first().isVisible()) {
      await onRunSession()
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

// --- Shell sessions ------------------------------------------------------------------

export interface SessionRow { id: number; sandbox?: string; chat_session_id?: string }
export interface ListenerRow { id: string; sandbox?: string; chat_session_id?: string; command?: string }
export interface SessionList {
  sessions: SessionRow[]
  jobs: SessionRow[]
  non_msf_sessions: ListenerRow[]
  /** Sandboxes the agent could not ask: their rows are missing from this answer. */
  unavailable_count?: number
}

/** The person's shell sessions, jobs and listeners as the Reverse Shell tab reads them (-1 sandboxes left out on a failure). */
export async function sessionsOf(api: APIRequestContext): Promise<SessionList> {
  // A kept-alive connection the server has just closed fails the GET with "socket hang up";
  // a second GET opens a new one.
  const res = await api.get('/api/agent/sessions').catch((err: unknown) => {
    if (!/socket hang up|ECONNRESET/.test(String(err))) throw err
    return api.get('/api/agent/sessions')
  })
  if (!res.ok()) return { sessions: [], jobs: [], non_msf_sessions: [], unavailable_count: -1 }
  const body = await res.json() as Partial<SessionList>
  return { sessions: body.sessions ?? [], jobs: body.jobs ?? [], non_msf_sessions: body.non_msf_sessions ?? [], unavailable_count: body.unavailable_count }
}

/** The first answer that left no sandbox out and `holds`: a missing sandbox hides every row of it. */
export async function completeSessionsOf(api: APIRequestContext, holds: (list: SessionList) => boolean,
                                         what: string): Promise<SessionList> {
  let list: SessionList = { sessions: [], jobs: [], non_msf_sessions: [] }
  await expect.poll(async () => {
    list = await sessionsOf(api)
    return (list.unavailable_count ?? 0) === 0 && holds(list)
  }, { message: `the session list is complete and ${what}`, timeout: 60_000 }).toBe(true)
  return list
}

/** A session's card in the Reverse Shell tab (SessionCard.tsx keys it by instance and number). */
export function sessionCard(page: Page, row: { id: number; sandbox?: string }): Locator {
  return page.locator(`[data-session-key="${row.sandbox ?? ''}:${row.id}"]`)
}

/**
 * E3 for Metasploit sessions, as the viewer of `page` and `api`: the viewer's Reverse Shell tab
 * (open on `page`) lists their own session `own` and not `hidden`, a session someone else opened on a
 * private project; the viewer's complete session list holds no row of `hidden`'s chat; and no drive
 * of `hidden`'s number reaches it, through its instance (404), no instance, or the viewer's own
 * instance. `hidden.shellPid` is what `$$` prints in `hidden`'s shell, so an answer from it is told
 * from one of the viewer's own session with the same number.
 */
export async function expectSessionOutOfReach(page: Page, api: APIRequestContext, baseURL: string,
                                              hidden: SessionRow & { chat: string; shellPid: string },
                                              own: SessionRow, n: string): Promise<void> {
  await expect(sessionCard(page, own), 'the viewer\'s Sessions panel lists their own session').toBeVisible({ timeout: 60_000 })
  await expect(sessionCard(page, hidden), 'ISOLATION (E3): another person\'s session on their private project is not listed').toHaveCount(0)
  const list = await completeSessionsOf(api, l => l.sessions.some(s => s.id === own.id && s.sandbox === own.sandbox),
    'holds the viewer\'s own session')
  expect.soft([...list.sessions, ...list.jobs, ...list.non_msf_sessions].filter(r => r.chat_session_id === hidden.chat),
    'ISOLATION (E3): no row of the other person\'s private chat in the viewer\'s session list').toEqual([])
  const reached = `G1B-${hidden.shellPid}-${n}`
  const drive = (query: string) => api.post(`/api/agent/sessions/${hidden.id}/interact${query}`,
    json(baseURL, { command: `echo G1B-$$-${n}` }))
  const viaItsInstance = await drive(`?sandbox=${encodeURIComponent(hidden.sandbox ?? '')}`)
  const viaNone = await drive('')
  const viaOwn = await drive(`?sandbox=${encodeURIComponent(own.sandbox ?? '')}`)
  expect(viaItsInstance.status(), 'ISOLATION (E3): driving the other person\'s session through its instance answers 404').toBe(404)
  for (const [how, res] of [['its instance', viaItsInstance], ['no instance', viaNone], ['the viewer\'s own instance', viaOwn]] as const) {
    expect(await res.text(), `ISOLATION (E3): a drive through ${how} never reaches the other person's session`).not.toContain(reached)
  }
}

// --- The memory governor ------------------------------------------------------------------

/** The governor's ledger, in bytes, as the system meter reads it (GET /api/system/stats, admission_ledger.snapshot). */
export interface Ledger {
  scanPool: number
  committed: number
  activeScans: number
  sandboxCommitted: number
  sandboxEnvelope: number
}

export async function readLedger(api: APIRequestContext): Promise<Ledger> {
  const res = await api.get('/api/system/stats')
  expect(res.status(), 'the governor\'s ledger (/api/system/stats)').toBe(200)
  const mem = ((await res.json()) as { mem?: Record<string, unknown> }).mem ?? {}
  const num = (k: string) => {
    const v = mem[k]
    if (typeof v !== 'number') throw new Error(`/api/system/stats has no number mem.${k}`)
    return v
  }
  return {
    scanPool: num('scan_pool'), committed: num('committed'), activeScans: num('active_scans'),
    sandboxCommitted: num('sandbox_committed'), sandboxEnvelope: num('sandbox_envelope'),
  }
}

/**
 * Why another person's sandbox would be admitted now, or null when the governor must refuse it on
 * budget: a scan is reserved, a sandbox too (the first one is exempt), and one more sandbox envelope
 * exceeds the pool (admission_ledger._admit_sandbox).
 */
export function sandboxFits(l: Ledger): string | null {
  if (l.activeScans < 1) return 'the ledger holds no scan reservation'
  if (l.sandboxCommitted <= 0) return 'the ledger holds no sandbox reservation'
  if (l.committed + l.sandboxEnvelope <= l.scanPool) {
    return `one more sandbox fits the pool (${l.committed} + ${l.sandboxEnvelope} <= ${l.scanPool} bytes)`
  }
  return null
}

// --- Admin helpers ---------------------------------------------------------------------

/** Operations' per-person stop (S16): forces the next use to be a cold start. Per-user mode only. */
export async function stopPersonSandbox(admin: APIRequestContext, baseURL: string, userId: string): Promise<void> {
  const res = await admin.post('/api/admin/operations/sandboxes/stop', json(baseURL, { userId }))
  expect(res.status(), 'the Operations stop of a person\'s Kali sandbox').toBe(200)
}

/**
 * Opens the chat on `projectId` until the drawer's warm-up has started the person's own sandbox, and
 * answers it once healthy (null when none came within `timeoutMs`). A warm-up within
 * 30 s of the person's last one is coalesced away (WARM_UP_COOLDOWN_MS, webapp/src/lib/sandbox/
 * lifecycle.ts) and the open socket mints no new ticket, so right after a stop one opening may start
 * nothing: each opening mints a ticket again, the first one past the cool-down starts the sandbox.
 */
export async function openChatUntilSandbox(page: Page, userId: string, projectId: string,
                                           timeoutMs = 180_000): Promise<SandboxContainer | null> {
  const until = Date.now() + timeoutMs
  for (;;) {
    await openChat(page, projectId)
    const looked = Date.now() + 10_000
    while (!sandboxContainers({ user: userId, view: 'own' }).length && Date.now() < looked) await sleep(1_000)
    if (sandboxContainers({ user: userId, view: 'own' }).length) return sandboxOf(userId, 'own', Math.max(until - Date.now(), 120_000))
    if (Date.now() > until) return null
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms))
}

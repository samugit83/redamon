// Run the Priority Board on an FP lab project the way the board's Run button does,
// for an MCP token without the triage:run scope (or inside its MCP cooldown).
//
//     node triage_fp.mjs <projectId> [--timeout S]
//
// Signs in with UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD (read from the repo .env by
// name, never printed), mints a ws-ticket for the cypherfix-triage socket, opens
// ws://localhost:<AGENT_WS_PORT|8090>/ws/cypherfix-triage, sends init then
// start_triage, and waits for triage_complete. Prints each phase and
// TRIAGE_STATUS=completed|error|stopped|timeout; exits 0 only on completed.
// Needs Node 22+ (global WebSocket).
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const envValue = (name) => {
  for (const line of readFileSync(join(REPO, '.env'), 'utf8').split('\n')) {
    if (line.startsWith(name + '=')) return line.slice(name.length + 1).trim().replace(/^["']|["']$/g, '')
  }
  return null
}

const [projectId, ...rest] = process.argv.slice(2)
if (!projectId || !/^[A-Za-z0-9_-]{1,64}$/.test(projectId)) {
  console.error('usage: node triage_fp.mjs <projectId> [--timeout S]')
  process.exit(2)
}
const timeoutS = Number(rest[rest.indexOf('--timeout') + 1]) || 1800
const web = process.env.REDAMON_WEB || `http://localhost:${envValue('WEBAPP_PORT') || '3000'}`
const agentWs = process.env.REDAMON_AGENT_WS || `ws://localhost:${envValue('AGENT_WS_PORT') || '8090'}`

let cookie = ''
async function call(method, path, body) {
  const res = await fetch(web + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const set = res.headers.getSetCookie?.() || []
  if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ')
  const text = await res.text()
  let json = {}
  try { json = text ? JSON.parse(text) : {} } catch { json = { error: text.slice(0, 200) } }
  return { status: res.status, json }
}

const user = envValue('UI_LOGIN_USERNAME')
const password = envValue('UI_LOGIN_PASSWORD')
if (!user || !password) {
  console.error('[!] UI_LOGIN_USERNAME / UI_LOGIN_PASSWORD missing from .env')
  process.exit(2)
}
const login = await call('POST', '/api/auth/login', { email: user, password })
if (login.status !== 200) {
  console.error(`[!] login refused (${login.status}): ${login.json.error || ''}`)
  process.exit(2)
}
const me = await call('GET', '/api/auth/me')
const userId = me.json.id
const sessionId = `triage-${Date.now()}`
const minted = await call('POST', '/api/agent/ws-ticket', { projectId, sessionId, socket: 'cypherfix-triage' })
if (minted.status !== 200) {
  console.error(`[!] ws-ticket refused (${minted.status}): ${minted.json.error || ''}`)
  process.exit(2)
}
const url = `${agentWs}/ws/cypherfix-triage` + (minted.json.ticket ? `?ticket=${encodeURIComponent(minted.json.ticket)}` : '')

const result = await new Promise((resolve) => {
  const ws = new WebSocket(url)
  const send = (type, payload = {}) => ws.send(JSON.stringify({ type, payload }))
  const timer = setTimeout(() => { ws.close(); resolve('timeout') }, timeoutS * 1000)
  const done = (status) => { clearTimeout(timer); clearInterval(ping); ws.close(); resolve(status) }
  let ping
  let lastPhase = ''
  ws.onopen = () => send('init', { user_id: userId, project_id: projectId, session_id: sessionId })
  ws.onmessage = (event) => {
    let msg
    try { msg = JSON.parse(event.data) } catch { return }
    const p = msg.payload || {}
    if (msg.type === 'connected') {
      ping = setInterval(() => send('ping'), 30000)
      send('start_triage')
      console.log(`[*] ${new Date().toISOString()} triage started on ${projectId}`)
    } else if (msg.type === 'triage_phase') {
      if (p.phase !== lastPhase) console.log(`    ${new Date().toISOString()} phase ${p.phase} ${p.progress ?? ''}`)
      lastPhase = p.phase
    } else if (msg.type === 'triage_complete') {
      console.log('[+] triage complete:', JSON.stringify(p).slice(0, 400))
      done('completed')
    } else if (msg.type === 'error') {
      console.log('[!] triage error:', JSON.stringify(p).slice(0, 400))
      if (p.code !== 'publishing') done('error')
    } else if (msg.type === 'stopped') {
      done('stopped')
    }
  }
  ws.onerror = () => done('error')
  ws.onclose = () => done('error')
})
console.log(`TRIAGE_STATUS=${result}`)
process.exit(result === 'completed' ? 0 : 1)

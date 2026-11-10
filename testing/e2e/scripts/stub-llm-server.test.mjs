/**
 * The stub model's scripted mode (stub-llm-server.mjs).
 *
 *   node --test testing/e2e/scripts/stub-llm-server.test.mjs
 *
 * Hermetic: every server listens on 127.0.0.1 port 0 and is closed at the end; no stack needed.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createScriptPlayer, createStubServer, latestPromptText, loadScript, parseScript } from './stub-llm-server.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const SERVER = join(HERE, 'stub-llm-server.mjs')
const THINK = 'Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object'
const GUARDRAIL = 'Evaluate this target domain for a penetration testing scan:\n\nTarget domain: rbac.test'

const ask = (user, system = 'You are a penetration tester.') => [
  { role: 'system', content: system },
  { role: 'user', content: user },
]

async function withServer(options, fn) {
  const server = createStubServer(options)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`)
  } finally {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
  }
}

async function complete(base, messages, extra = {}) {
  const started = Date.now()
  const res = await fetch(`${base}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'stub', messages, ...extra }),
  })
  if (extra.stream) return { res, started }
  const body = await res.json()
  return { content: body.choices[0].message.content, ms: Date.now() - started }
}

/** Reads an SSE response: the comments, the content deltas and when the first delta came. */
async function readStream(res, started) {
  const decoder = new TextDecoder()
  let buffer = ''
  const comments = []
  let content = ''
  let firstDeltaMs = null
  let done = false
  for await (const chunk of res.body) {
    buffer += decoder.decode(chunk, { stream: true })
    let cut
    while ((cut = buffer.indexOf('\n\n')) >= 0) {
      const event = buffer.slice(0, cut)
      buffer = buffer.slice(cut + 2)
      if (event.startsWith(':')) comments.push(event)
      else if (event === 'data: [DONE]') done = true
      else {
        const delta = JSON.parse(event.slice('data: '.length)).choices[0]?.delta?.content
        if (delta) {
          firstDeltaMs ??= Date.now() - started
          content += delta
        }
      }
    }
  }
  return { comments, content, firstDeltaMs, done }
}

test('a script turn is served once in order', async () => {
  const turns = parseScript(JSON.stringify([
    { match: 'what is your next action', content: 'first think' },
    { match: 'for a penetration testing scan:', content: { allowed: true, reason: 'lab' } },
    { match: 'what is your next action', content: 'second think' },
  ]))
  const player = createScriptPlayer(turns)
  assert.deepEqual(player.next(ask(THINK)), { index: 0, match: 'what is your next action', content: 'first think', delayMs: 0, repeat: false })
  assert.equal(player.next(ask(GUARDRAIL)).content, '{"allowed":true,"reason":"lab"}')
  assert.equal(player.next(ask(THINK)).index, 2)
  assert.equal(player.next(ask(THINK)), null)
  assert.equal(player.next(ask(GUARDRAIL)), null)

  await withServer({ script: turns }, async (base) => {
    assert.equal((await complete(base, ask(THINK))).content, 'first think')
    assert.equal((await complete(base, ask(THINK))).content, 'second think')
    assert.equal((await complete(base, ask(THINK))).content, 'OK.')
    const { calls } = await (await fetch(`${base}/__calls`)).json()
    assert.deepEqual(calls.map((c) => [c.stage, c.turn]), [['script', 0], ['script', 2], ['other', undefined]])
  })
})

// The agent asks its scope guardrail again on every resume (an approval, a tool confirmation)
// until the run has executed a step, so that answer must not be spent.
test('a repeat turn is never spent', () => {
  const player = createScriptPlayer(parseScript(JSON.stringify([
    { match: 'for a penetration testing scan:', content: 'allowed', repeat: true },
    { match: 'what is your next action', content: 'think' },
  ])))
  for (let i = 0; i < 3; i++) assert.equal(player.next(ask(GUARDRAIL))?.index, 0)
  assert.equal(player.next(ask(THINK)).index, 1)
  assert.equal(player.next(ask(THINK)), null)
  assert.equal(player.next(ask(GUARDRAIL)).content, 'allowed')
  assert.throws(() => parseScript('[{"match": "x", "content": "y", "repeat": "yes"}]'), /turn 0: repeat must be true or false/)
})

test('a turn matches the latest user or tool message only', () => {
  const player = createScriptPlayer(parseScript('[{"match": "next action", "content": "hit"}]'))
  // The system prompt and older user messages are not looked at.
  assert.equal(player.next([{ role: 'system', content: 'next action' }, { role: 'user', content: 'hello' }]), null)
  assert.equal(player.next([{ role: 'user', content: 'next action' }, { role: 'assistant', content: 'x' }, { role: 'user', content: 'fix it' }]), null)
  assert.equal(latestPromptText([{ role: 'user', content: 'a' }, { role: 'tool', content: 'tool says next action' }, { role: 'assistant', content: 'b' }]), 'tool says next action')
  assert.equal(latestPromptText([{ role: 'user', content: [{ type: 'text', text: 'part one' }, { type: 'text', text: 'next action' }] }]), 'part one\nnext action')
  assert.equal(player.next([{ role: 'user', content: [{ type: 'text', text: 'your next action?' }] }]).content, 'hit')
})

test('no match keeps OK.', async () => {
  const script = parseScript('[{"match": "a phrase the agent never sends", "content": "never"}]')
  await withServer({ script }, async (base) => {
    assert.equal((await complete(base, ask(THINK))).content, 'OK.')
    // The prompts the stub already knew keep their canned answers.
    const roe = (await complete(base, ask('Document version 2.0', 'REGISTRY-DIGEST: abc'))).content
    assert.equal(JSON.parse(roe).roeGlobalMaxRps, 20)
  })
  await withServer({}, async (base) => {
    assert.equal((await complete(base, ask(THINK))).content, 'OK.')
  })
})

test('delay honoured', async () => {
  const script = parseScript(JSON.stringify([
    { match: 'slow', content: 'late answer', delayMs: 400 },
    { match: 'slow', content: 'late streamed answer', delayMs: 400 },
    { match: 'fast', content: 'quick answer' },
  ]))
  await withServer({ script, heartbeatMs: 100 }, async (base) => {
    const plain = await complete(base, ask('slow'))
    assert.equal(plain.content, 'late answer')
    assert.ok(plain.ms >= 390, `answered after ${plain.ms} ms`)

    // Streamed: the headers come at once and comments keep the connection alive until the content.
    const { res, started } = await complete(base, ask('slow'), { stream: true })
    const headersMs = Date.now() - started
    assert.equal(res.headers.get('content-type'), 'text/event-stream')
    assert.ok(headersMs < 300, `headers after ${headersMs} ms`)
    const streamed = await readStream(res, started)
    assert.equal(streamed.content, 'late streamed answer')
    assert.ok(streamed.firstDeltaMs >= 390, `content after ${streamed.firstDeltaMs} ms`)
    assert.ok(streamed.comments.length >= 2, `${streamed.comments.length} heartbeat comments`)
    assert.ok(streamed.done)

    const quick = await complete(base, ask('fast'))
    assert.equal(quick.content, 'quick answer')
    assert.ok(quick.ms < 300, `answered after ${quick.ms} ms`)
  })
})

test('a client that leaves during a delay is let go', async () => {
  const script = parseScript('[{"match": "slow", "content": "never read", "delayMs": 60000}]')
  await withServer({ script, heartbeatMs: 50 }, async (base) => {
    const controller = new AbortController()
    const pending = fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'stub', messages: ask('slow'), stream: true }),
      signal: controller.signal,
    })
    const res = await pending
    controller.abort()
    await assert.rejects(readStream(res, Date.now()))
    // The server still answers, and the spent turn is not served again.
    assert.equal((await complete(base, ask('slow'))).content, 'OK.')
  })
})

test('a malformed script is refused at start, naming the fault', async () => {
  assert.throws(() => parseScript('{"match": "x"}'), /JSON list/)
  assert.throws(() => parseScript('[{"match": "x", "content": "y", "delay_ms": 5}]'), /turn 0 has unknown key\(s\) delay_ms/)
  assert.throws(() => parseScript('[{"content": "y"}]'), /turn 0: match must be a string/)
  assert.throws(() => parseScript('[{"match": "x", "content": 3}]'), /turn 0: content must be/)
  assert.throws(() => parseScript('[{"match": "x", "content": "y", "delayMs": -1}]'), /delayMs/)

  const dir = mkdtempSync(join(tmpdir(), 'stub-llm-'))
  try {
    const bad = join(dir, 'bad.json')
    writeFileSync(bad, '[{"match": "x"}]')
    const child = spawn(process.execPath, [SERVER, '0', '127.0.0.1'], { env: { ...process.env, STUB_LLM_SCRIPT: bad } })
    let stderr = ''
    child.stderr.on('data', (d) => { stderr += d })
    const code = await new Promise((resolve) => child.on('exit', resolve))
    assert.equal(code, 2)
    assert.match(stderr, /STUB_LLM_SCRIPT .*bad\.json: turn 0: content must be/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('STUB_LLM_SCRIPT drives a started server', async () => {
  const child = spawn(process.execPath, [SERVER, '0', '127.0.0.1'], {
    env: { ...process.env, STUB_LLM_SCRIPT: join(HERE, 'stub-llm-scripts', 'approval.json') },
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  try {
    const ready = JSON.parse(await new Promise((resolve) => child.stdout.once('data', resolve)))
    assert.equal(ready.scriptTurns, 4)
    const base = `http://127.0.0.1:${ready.port}`
    assert.equal(JSON.parse((await complete(base, ask(THINK))).content).action, 'transition_phase')
  } finally {
    child.kill('SIGTERM')
  }
})

test('the agent scripts say what their runs need', () => {
  const think = (turns) => turns.filter((t) => t.match === 'what is your next action').map((t) => JSON.parse(t.content))
  for (const name of ['approval', 'kali-shell-env', 'long-run']) {
    const turns = loadScript(join(HERE, 'stub-llm-scripts', `${name}.json`))
    const guardrail = turns.find((t) => t.match === 'for a penetration testing scan:')
    assert.deepEqual([JSON.parse(guardrail.content).allowed, guardrail.repeat], [true, true], name)
    const classify = turns.find((t) => t.match === 'You are classifying a penetration testing request')
    assert.deepEqual([JSON.parse(classify.content).required_phase, classify.repeat], ['informational', true], name)
    for (const decision of think(turns)) {
      assert.ok(decision.thought && decision.reasoning && decision.action, `${name}: an LLMDecision needs thought, reasoning, action`)
    }
  }
  const [request, end] = think(loadScript(join(HERE, 'stub-llm-scripts', 'approval.json')))
  assert.deepEqual([request.action, request.phase_transition.to_phase, end.action], ['transition_phase', 'exploitation', 'complete'])

  const [call, done] = think(loadScript(join(HERE, 'stub-llm-scripts', 'kali-shell-env.json')))
  assert.equal(call.tool_name, 'kali_shell')
  assert.equal(call.tool_args.command, "env | grep -cE 'SCANNER_API_KEY|MCP_AUTH_TOKEN|TUNNEL_AUTH_TOKEN'")
  assert.equal(done.action, 'complete')

  const long = loadScript(join(HERE, 'stub-llm-scripts', 'long-run.json'))
  assert.deepEqual(long.filter((t) => t.delayMs > 0).map((t) => t.delayMs), [120000])
})

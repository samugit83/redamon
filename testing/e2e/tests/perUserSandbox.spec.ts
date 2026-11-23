import { test, expect, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test'
import {
  MODAL_RAM_TITLE, MODAL_RETRY_LABEL, SHARE_KEYS_LENT_TEXT,
} from '../../../webapp/src/lib/sandbox/contract'
import {
  LAB_SHELL_PORT, adminCredentials, completeSessionsOf, connectLab, containersHolding, chiselEdgeLog,
  deleteConversation, deleteStubProvider, driveRun, ensureStubProvider, expectSessionOutOfReach, goneWithin, json,
  listedFolders, meId, mountedProjects, noSandboxWithin, nonce, openChat, openChatUntilSandbox, recordTransientTexts,
  redactRequestErrors, redactSecrets, removeListeners, removeMarkers, restoreProjects, sandboxContainers, sandboxOf, seedAndRead, send, sessionCard,
  sessionsOf, setProject, signIn, sleep, stackMissing, startChiselEdge, startLab, startStub, stopChiselEdge, stopLab,
  stopPersonSandbox, toolCards, toolOutput, wasSeen, processRunning, recordGrant, recordedGrant, restoreGrants,
  forgetGrant, readLedger, sandboxFits, tail, watchContainerLog,
  type ChiselEdge, type Lab, type ListenerRow, type LogWatch, type Override, type SandboxContainer, type SeedState,
  type SessionList, type SessionRow, type Stub,
} from './perUserSandboxFixtures'

/**
 * Group 1 (per-user Kali sandboxes), S23: everything people do with the Kali tools still works when
 * started from the UI, and each person's work runs in that person's own sandbox. Two members of the
 * g1 seed (Alice owns g1-PA and g1-PS, Bob owns g1-PB, g1-PS is shared with Bob with "Use AI agent"
 * and "Exploitation & shells") and the .env admin click through the real app; the model is the
 * scripted stub (scripts/stub-llm-scripts/per-user-sandbox-*.json).
 *
 * Every test checks where its work ran, by finding the container whose /tmp holds the marker the
 * command wrote (docker, read only) and by the folders `ls /workspace` printed. Those checks are
 * `expect.soft` and say ISOLATION, so a run still walks each flow to its end and reports every
 * isolation check that fails.
 *
 * Groups, by the orchestrator setting they need (testing/e2e/scripts/per-user-sandbox-e2e.sh starts the
 * orchestrator with it, in the shell only, and puts the previous values back):
 *   Group A (defaults)  tests 1-7
 *   Group B (idle)      test 8, KALI_SANDBOX_IDLE_MINUTES=1
 *   Group C (memory)    test 9, the pool lowered with SERVICE_BASELINE_MEM and OS_HEADROOM_MEM
 *   Group D (tunnel)    test 10
 * Run: bash testing/e2e/scripts/per-user-sandbox-e2e.sh (never alone: groups B and C need the settings it sets).
 *
 * Needs the stack up, Docker, python3 (the seed) and node (the stub). Skips with the reason when one
 * is missing; once they are up, a failed precondition is a failure. Synthetic accounts, `.invalid`
 * targets and a busybox lab only; every test removes what it made (chats, files, markers, sessions,
 * labs, the chisel edge, settings it changed).
 */

const BASE = process.env.REDAMON_BASE_URL || 'http://localhost:3000'
// The drawer's and the terminal's starting lines (sandboxStatus.ts, sandboxFrames.ts).
const DRAWER_STARTING = 'Starting your Kali sandbox…'
const TERMINAL_STARTING = 'Starting sandbox…'
const PROJECT_NAMES = { PA: 'g1-PA', PB: 'g1-PB', PS: 'g1-PS' }
// The scan that fills the governor in tests 7 and 9: every port of the lab at 50/s, cut at 600 s, so it
// lasts until the test stops it. The typed lab address joins the scan root's address list, which Naabu
// scans only when the root itself is in scope (subdomainList '.', port_scan.extract_targets_from_recon):
// without it the run found "No targets" and completed in ~10 s (M-b re-run, test 9). The root in scope
// would also hand Naabu the placeholder name, resolved by the host's resolvers; an RoE address
// exclusion (a documentation address, RFC 5737) makes Naabu take addresses only, so no name is sent.
const SLOW_NAABU = {
  naabuCustomPorts: '1-65535', naabuRateLimit: 50, naabuRunTimeout: 600, subdomainList: ['.'],
  roeExcludedHosts: ['192.0.2.1'],
}

// A trace records typed values: the fixture accounts' passwords would land in test-results/.
test.use({ trace: 'off' })

let state: SeedState
let admin: BrowserContext
let alice: BrowserContext
let bob: BrowserContext
let adminId = ''
let stubPort = 0
let skipReason: string | null = null

const apis = () => ({ alice: alice.request, bob: bob.request })

test.beforeAll(async ({ browser, playwright }) => {
  test.setTimeout(600_000)
  const probe = redactRequestErrors(await playwright.request.newContext({ baseURL: BASE }))
  skipReason = await stackMissing(probe)
  await probe.dispose()
  // The wrapper sets this: a milestone never accepts a skip.
  if (skipReason && process.env.G1_E2E_REQUIRE_LIVE === '1') throw new Error(`the stack is not ready: ${skipReason}`)
  if (skipReason) return
  state = seedAndRead()
  const a = adminCredentials()
  admin = await signIn(browser, BASE, a.email, a.password)
  // A killed earlier run may have left a grant: put it back before Bob signs in (a removal signs him out).
  const grants = await restoreGrants(admin.request, BASE, a.password)
  if (grants.length) throw new Error(`an earlier run's grant could not be put back: ${grants.join('; ')}`)
  alice = await signIn(browser, BASE, state.alice.email, state.alice.password)
  bob = await signIn(browser, BASE, state.bob.email, state.bob.password)
  for (const c of [admin, alice, bob]) await recordTransientTexts(c, [DRAWER_STARTING, TERMINAL_STARTING])
  adminId = await meId(admin.request)
  // A killed run's filler scan may still write g1-PA, and its settings cannot be put back until it ends.
  await endPartialRuns(alice.request, state.projects.PA)
  const leftovers = await restoreProjects(apis(), BASE)
  if (leftovers.length) throw new Error(`an earlier run's project settings could not be put back: ${leftovers.join('; ')}`)

  // One port for every stub of this worker, so the providers and project models are set once.
  const first = await startStub('marker', { NONCE: 'probe' })
  stubPort = first.port
  await first.stop()
  const providers = {
    alice: await ensureStubProvider(alice.request, BASE, state.alice.id, stubPort),
    bob: await ensureStubProvider(bob.request, BASE, state.bob.id, stubPort),
  }
  // The agent reads the model of the project's owner (the tenant): g1-PS runs on Alice's provider.
  await setProject({ key: 'alice', api: alice.request }, BASE, state.projects.PA, { agentOpenaiModel: `custom/${providers.alice}` })
  await setProject({ key: 'alice', api: alice.request }, BASE, state.projects.PS, { agentOpenaiModel: `custom/${providers.alice}` })
  await setProject({ key: 'bob', api: bob.request }, BASE, state.projects.PB, { agentOpenaiModel: `custom/${providers.bob}` })
})

test.afterAll(async ({ browser }) => {
  if (skipReason || !state || !alice || !bob) return
  // Removing a grant (test 10) signs that person out everywhere: sign in again for the clean-up.
  if ((await alice.request.get('/api/auth/me')).status() === 401) {
    await alice.close()
    alice = await signIn(browser, BASE, state.alice.email, state.alice.password)
  }
  if ((await bob.request.get('/api/auth/me')).status() === 401) {
    await bob.close()
    bob = await signIn(browser, BASE, state.bob.email, state.bob.password)
  }
  const failed = [
    ...await restoreProjects(apis(), BASE),
    ...await deleteStubProvider(alice.request, BASE, state.alice.id),
    ...await deleteStubProvider(bob.request, BASE, state.bob.id),
  ]
  for (const c of [admin, alice, bob]) await c?.close().catch(() => {})
  expect(failed, 'the spec put back every setting it changed (what failed stays recorded for the next run)').toEqual([])
})

test.beforeEach(() => {
  test.skip(Boolean(skipReason), skipReason ?? '')
})

/** A press whose request never reached the webapp: the button sends it once and shows nothing. */
const STOP_LOST = 'PRODUCT, not the test: PAUSE ALL sent POST /api/agent/emergency-stop-all once and the browser '
  + 'got no answer, so nothing was stopped and the page did not say so'

/** The person's own sandbox, expected to exist (a soft ISOLATION failure, and null, when it does not). */
async function ownSandbox(userId: string, label: string): Promise<SandboxContainer | null> {
  const box = await sandboxOf(userId, 'own')
  expect.soft(box, `ISOLATION: ${label} has a running sandbox of their own`).not.toBeNull()
  return box
}

/** Asserts (soft) that the marker exists in `box` and in no other Kali container. */
function ranOnlyIn(marker: string, box: SandboxContainer | null, label: string) {
  const holders = containersHolding(marker)
  expect.soft(holders, `ISOLATION: the command ran in ${label} and nowhere else (holders: ${holders.join(', ') || 'none'})`)
    .toEqual(box ? [box.name] : [`<${label}>`])
}

async function newPage(c: BrowserContext): Promise<Page> {
  return c.newPage()
}

interface PartialRun { run_id: string; status: string; error?: string | null }

async function partialRuns(api: APIRequestContext, projectId: string): Promise<PartialRun[]> {
  const res = await api.get(`/api/recon/${projectId}/partial/all`)
  if (!res.ok()) return []
  return ((await res.json()) as { runs?: PartialRun[] }).runs ?? []
}

const live = <T extends { status: string }>(runs: T[]) => runs.filter(r => r.status === 'running' || r.status === 'starting')

async function stopPartialRuns(api: APIRequestContext, projectId: string) {
  for (const run of live(await partialRuns(api, projectId))) {
    await api.post(`/api/recon/${projectId}/partial/${run.run_id}/stop`, { headers: { Origin: new URL(BASE).origin } })
  }
}

/**
 * Stops the project's partial runs and waits (bounded, never throwing: it runs in clean-ups) until none
 * is starting, running or stopping: until then the project's scope cannot be put back (the projects
 * PUT answers 409 while a scan writes, graphWriters.describeScanWriters).
 */
async function endPartialRuns(api: APIRequestContext, projectId: string, timeoutMs = 120_000) {
  try {
    await stopPartialRuns(api, projectId)
    const until = Date.now() + timeoutMs
    while (Date.now() < until) {
      if (!(await partialRuns(api, projectId)).some(r => ['starting', 'running', 'stopping'].includes(r.status))) return
      await sleep(2_000)
    }
  } catch {
    // A scan still writing shows as the restore's 409 right after this.
  }
}

/** A Naabu partial recon of the lab, started from the project's settings page (the UI path). */
async function startNaabuFromUi(page: Page, projectId: string, ip: string) {
  await page.goto(`/projects/${projectId}/settings?tab=port`)
  await page.getByTitle('Run Naabu Port Scanner').click()
  const modal = page.getByRole('dialog').filter({ hasText: 'Partial Recon: Naabu' })
  await expect(modal).toBeVisible()
  await modal.getByPlaceholder('192.168.1.1').fill(ip)
  await modal.getByRole('button', { name: 'Run Partial Recon' }).click()
  await expect(modal).toBeHidden({ timeout: 60_000 })
}

async function meterTitle(page: Page): Promise<string> {
  return (await page.locator('[title*="available for a new scan"]').first().getAttribute('title')) ?? ''
}

/** The Reverse Shell tab's list of sessions and listeners (ActiveSessions.tsx). */
function sessionList(page: Page) {
  return page.locator('xpath=//div[contains(@class, "ActiveSessions-module__") and contains(concat(@class, " "), "__sidebar ")]')
}

function drivePath(kind: 'sessions' | 'jobs', row: { id: number; sandbox?: string }): string {
  const q = row.sandbox ? `?sandbox=${encodeURIComponent(row.sandbox)}` : ''
  return `/api/agent/${kind}/${encodeURIComponent(String(row.id))}/kill${q}`
}

/** The text of the Kali terminal (xterm's DOM renderer). */
async function terminalText(page: Page): Promise<string> {
  return page.locator('.xterm-rows').innerText()
}

/** Types `line` into the terminal and waits for `expected` to be printed (retyped while the shell starts). */
async function terminalRun(page: Page, line: string, expected: string, timeoutMs = 120_000) {
  const term = page.getByRole('application', { name: 'Kali Linux terminal' })
  await expect(async () => {
    await term.click()
    await page.keyboard.type(line)
    await page.keyboard.press('Enter')
    await expect.poll(() => terminalText(page), { timeout: 15_000 }).toContain(expected)
  }).toPass({ timeout: timeoutMs })
}

function between(text: string, start: string, end: string): string[] {
  const i = text.lastIndexOf(start)
  const j = text.indexOf(end, i)
  if (i < 0 || j < 0) return []
  return text.slice(i + start.length, j).split('\n').map(s => s.trim()).filter(Boolean)
}

// ======================================================================================

test.describe('Group A (defaults)', () => {
  test('1. first use: the drawer shows the sandbox starting, and kali_shell runs in Alice\'s own sandbox only', async () => {
    test.setTimeout(480_000)
    const n = nonce()
    const page = await newPage(alice)
    let stub: Stub | null = null
    let session = ''
    try {
      await openChat(page, state.projects.PA)
      // Opening the drawer warms Alice's sandbox up (ws-ticket, B.10); stop it so the run meets a cold start.
      await sandboxOf(state.alice.id, 'own', 120_000)
      await stopPersonSandbox(admin.request, BASE, state.alice.id)
      expect(await noSandboxWithin(state.alice.id, 'own', 90_000), 'Alice\'s sandbox stopped before the run').toBe(true)
      stub = await startStub('marker', { NONCE: n }, stubPort)
      session = await send(page, alice.request, state.projects.PA, `g1 e2e first use ${n}`)
      const { allowed } = await driveRun(page, alice.request, state.projects.PA, session)
      expect(allowed, 'kali_shell asked Alice to confirm it once').toBe(1)
      const out = await toolOutput(page, `g1e2e-${n}`)
      expect(out, 'the tool output reached the drawer').toContain(`G1E2E-OUT-${n}`)

      expect.soft(await wasSeen(page, DRAWER_STARTING), `ISOLATION: the drawer said "${DRAWER_STARTING}" during the cold start`).toBe(true)
      await expect(page.getByText(DRAWER_STARTING), 'the starting line cleared').toHaveCount(0)
      const box = await ownSandbox(state.alice.id, 'Alice')
      ranOnlyIn(`/tmp/g1e2e-${n}`, box, 'Alice\'s own sandbox')
    } finally {
      await page.close()
      await stub?.stop()
      if (session) await deleteConversation(alice.request, BASE, session)
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('2. normal engagement: phase approval, a plan wave and a Fireteam against a lab, captured in the Traffic tab', async () => {
    test.setTimeout(900_000)
    const n = nonce()
    const page = await newPage(alice)
    let stub: Stub | null = null
    let lab: Lab | null = null
    let session = ''
    try {
      const settings = await (await admin.request.get('/api/admin/instance-settings')).json() as { captureEgressBlockPrivate?: boolean }
      expect(settings.captureEgressBlockPrivate, 'the capture proxy lets private lab addresses through (block_private off)').not.toBe(true)
      lab = startLab(n)
      await setProject({ key: 'alice', api: alice.request }, BASE, state.projects.PA, { captureProxyEnabled: true })
      await openChat(page, state.projects.PA)
      const warm = await ownSandbox(state.alice.id, 'Alice')
      if (warm) connectLab(lab, state.alice.id)
      stub = await startStub('engagement', { NONCE: n, LAB_PROXY_IP: lab.proxyIp }, stubPort)
      session = await send(page, alice.request, state.projects.PA, `g1 e2e engagement ${n}`)
      const { allowed, approved } = await driveRun(page, alice.request, state.projects.PA, session, 720_000)
      expect(approved, 'the move to exploitation was approved once').toBe(1)
      expect(allowed, 'the wave and the member\'s request were confirmed').toBeGreaterThanOrEqual(2)

      const wave = page.locator('xpath=//div[contains(@class, "PlanWaveCard-module__") and contains(concat(@class, " "), "__card ")]')
        .filter({ hasText: 'kali_shell' })
      await expect(wave.last(), 'the plan wave completed both tools').toContainText('2/2 completed')
      const fireteam = page.locator('xpath=//div[contains(@class, "FireteamCard-module__") and contains(concat(@class, " "), "__card ")]')
      await expect(fireteam.last(), 'the Fireteam deployment completed').toContainText('completed')

      const traffic = await newPage(alice)
      try {
        await traffic.goto(`/traffic?project=${state.projects.PA}`)
        await expect(async () => {
          await traffic.reload()
          await expect(traffic.locator('tr', { hasText: `/g1e2e-${n}.html` }).first()).toBeVisible({ timeout: 5_000 })
          await expect(traffic.locator('tr', { hasText: `/member-${n}.html` }).first()).toBeVisible({ timeout: 5_000 })
        }, 'the Traffic tab shows the wave\'s and the member\'s requests to the lab').toPass({ timeout: 120_000 })
      } finally {
        await traffic.close()
      }

      const box = await ownSandbox(state.alice.id, 'Alice')
      ranOnlyIn(`/tmp/g1e2e-${n}-wave`, box, 'Alice\'s own sandbox')
    } finally {
      await page.close()
      await stub?.stop()
      stopLab(lab)
      if (session) await deleteConversation(alice.request, BASE, session)
      expect.soft(await restoreProjects(apis(), BASE, { fields: ['captureProxyEnabled'] }), 'g1-PA\'s capture setting was put back').toEqual([])
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('3. shared project: Bob writes a file Alice sees, and his ls /workspace lists none of Alice\'s private projects', async () => {
    test.setTimeout(480_000)
    const n = nonce()
    const file = `g1e2e-${n}.txt`
    const page = await newPage(bob)
    const owner = await newPage(alice)
    let stub: Stub | null = null
    let session = ''
    try {
      await openChat(page, state.projects.PS)
      stub = await startStub('shared-project', { NONCE: n, PROJECT_ID: state.projects.PS }, stubPort)
      session = await send(page, bob.request, state.projects.PS, `g1 e2e shared project ${n}`)
      const { allowed } = await driveRun(page, bob.request, state.projects.PS, session)
      expect(allowed).toBe(1)
      const out = await toolOutput(page, `g1e2e-${n}`)
      expect(out).toContain(`G1E2E-OUT-${n}`)

      await owner.goto(`/graph?project=${state.projects.PS}`)
      await owner.getByRole('button', { name: 'Toggle Workspace' }).click()
      await expect(owner.locator(`[data-name="${file}"]`).first(), 'Alice sees Bob\'s file in the Agent workspace').toBeVisible({ timeout: 60_000 })

      const folders = listedFolders(out)
      expect(folders, 'Bob\'s sandbox mounts the shared project').toContain(state.projects.PS)
      expect.soft(folders.includes(state.projects.PA), 'ISOLATION (T5, I9): Bob\'s ls /workspace does not list Alice\'s private g1-PA').toBe(false)
      expect.soft(folders.filter(f => f !== state.projects.PS && f !== state.projects.PB),
        'ISOLATION (T5, I9): Bob\'s ls /workspace lists only his own and the shared project').toEqual([])
      const box = await ownSandbox(state.bob.id, 'Bob')
      ranOnlyIn(`/tmp/g1e2e-${n}`, box, 'Bob\'s own sandbox')
    } finally {
      await page.close()
      await owner.close()
      await stub?.stop()
      await alice.request.delete(`/api/agent/workspace/delete?projectId=${state.projects.PS}&path=${encodeURIComponent(file)}`,
        { headers: { Origin: new URL(BASE).origin } })
      if (session) await deleteConversation(bob.request, BASE, session)
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('4. sessions across people: Alice drives Bob\'s session on the shared project, and neither lists nor drives the other\'s private ones', async () => {
    test.setTimeout(1_200_000)
    const n = nonce()
    const page = await newPage(bob)
    const owner = await newPage(alice)
    let stub: Stub | null = null
    let lab: Lab | null = null
    const sessions: string[] = []
    let aliceChat = ''
    // In the command of Bob's own project's listener (its /tmp marker): how the UI shows that session.
    const listener = `g1e2e-${n}-own`
    try {
      lab = startLab(n)
      // A Metasploit session needs a payload port on the project, or the agent stops to ask the person
      // for one (is_session_config_complete, think_node.py): the lab is a bind shell, so a bind port.
      for (const project of [state.projects.PA, state.projects.PS]) {
        await setProject({ key: 'alice', api: alice.request }, BASE, project, { agentBindPortOnTarget: LAB_SHELL_PORT })
      }
      // Each person's handler reaches the lab on their own sandbox's network.
      await openChat(owner, state.projects.PA)
      const aliceBox = await ownSandbox(state.alice.id, 'Alice')
      const aliceLabIp = aliceBox ? connectLab(lab, state.alice.id) : lab.proxyIp
      await openChat(page, state.projects.PS)
      const box = await ownSandbox(state.bob.id, 'Bob')
      const labIp = box ? connectLab(lab, state.bob.id) : lab.proxyIp
      stub = await startStub('sessions', { NONCE: n, LAB_IP: labIp, ALICE_LAB_IP: aliceLabIp }, stubPort)

      // Alice's own Metasploit session on her private g1-PA: her sandbox's console, which no earlier
      // test used, serves only her projects.
      aliceChat = await send(owner, alice.request, state.projects.PA, `g1 e2e session on Alice's private project ${n}`)
      expect((await driveRun(owner, alice.request, state.projects.PA, aliceChat, 420_000)).approved).toBe(1)

      const onShared = await send(page, bob.request, state.projects.PS, `g1 e2e session on the shared project ${n}`)
      sessions.push(onShared)
      expect((await driveRun(page, bob.request, state.projects.PS, onShared, 420_000)).approved).toBe(1)
      // His own project's session is a netcat listener, not a second Metasploit session: one msfconsole
      // per sandbox serves one project at a time (GHSA-w454), so g1-PS holds it now. The Sessions list
      // attributes and filters listeners by their chat exactly as it does Metasploit sessions.
      await openChat(page, state.projects.PB)
      const onOwn = await send(page, bob.request, state.projects.PB, `g1 e2e listener on Bob's project ${n}`)
      sessions.push(onOwn)
      expect((await driveRun(page, bob.request, state.projects.PB, onOwn, 420_000)).allowed, 'Bob confirmed the listener once').toBe(1)
      expect(await toolOutput(page, listener), 'the listener started').toContain(`G1E2E-LISTEN-${n}`)

      // Bob holds both: the rows tell which chat opened which.
      let shared: SessionRow | undefined
      let own: ListenerRow | undefined
      await expect(async () => {
        const list = await sessionsOf(bob.request)
        shared = list.sessions.find(s => s.chat_session_id === onShared)
        own = list.non_msf_sessions.find(s => s.chat_session_id === onOwn)
        expect(shared, 'the Metasploit session of g1-PS').toBeTruthy()
        expect(own, 'the listener of g1-PB').toBeTruthy()
      }, 'both of Bob\'s runs opened a session').toPass({ timeout: 90_000 })
      expect.soft(shared!.sandbox, 'ISOLATION (E3): the shared project\'s session lives in Bob\'s own sandbox')
        .toBe(box?.instance ?? '<Bob\'s own instance>')
      expect.soft(own!.sandbox, 'ISOLATION (E3): his own project\'s listener lives in his own sandbox')
        .toBe(box?.instance ?? '<Bob\'s own instance>')
      ranOnlyIn(`/tmp/${listener}`, box, 'Bob\'s own sandbox')
      const mine = (await completeSessionsOf(alice.request, l => l.sessions.some(s => s.chat_session_id === aliceChat),
        'holds Alice\'s session on her private project')).sessions.find(s => s.chat_session_id === aliceChat)!
      expect.soft(mine.sandbox, 'ISOLATION (E3): Alice\'s private project\'s session lives in her own sandbox')
        .toBe(aliceBox?.instance ?? '<Alice\'s own instance>')
      // What `$$` prints in her session's shell: the lab runs one shell per session, so it tells an answer
      // of hers from one of Bob's session with the same number (every console numbers from 1).
      let shellPid = ''
      await expect(async () => {
        const res = await alice.request.post(`/api/agent/sessions/${mine.id}/interact?sandbox=${encodeURIComponent(mine.sandbox ?? '')}`,
          json(BASE, { command: `echo G1A-$$-${n}` }))
        shellPid = new RegExp(`G1A-(\\d+)-${n}`).exec(await res.text())?.[1] ?? ''
        expect(shellPid, 'Alice drives her own session').not.toBe('')
      }).toPass({ timeout: 90_000 })

      // The control: Bob's own panel shows the listener, so a panel without it is a filtered one.
      await page.goto(`/graph?project=${state.projects.PB}`)
      await page.getByRole('tab', { name: /Reverse Shell/ }).click()
      await expect(sessionList(page).getByText(listener).first(), 'Bob\'s Sessions panel lists his own project\'s listener')
        .toBeVisible({ timeout: 60_000 })
      // E3 for Metasploit sessions: Bob neither lists nor drives Alice's private one.
      await expectSessionOutOfReach(page, bob.request, BASE, { ...mine, chat: aliceChat, shellPid }, shared!, n)

      await owner.goto(`/graph?project=${state.projects.PS}`)
      await owner.getByRole('tab', { name: /Reverse Shell/ }).click()
      const card = sessionCard(owner, shared!)
      await expect(card, 'Alice\'s Sessions panel lists Bob\'s session on the shared project').toBeVisible({ timeout: 60_000 })
      await expect(sessionCard(owner, mine), 'Alice\'s Sessions panel lists her own private session').toBeVisible({ timeout: 60_000 })
      await expect(owner.getByText(listener),
        'ISOLATION (E3): Bob\'s session on his own project is not listed for Alice').toHaveCount(0)
      const seen = await completeSessionsOf(alice.request, l => l.sessions.some(s => s.chat_session_id === onShared),
        'holds Bob\'s session on the shared project')
      expect.soft([...seen.sessions, ...seen.jobs, ...seen.non_msf_sessions].filter(r => r.chat_session_id === onOwn),
        'ISOLATION (E3): no row of Bob\'s own project in Alice\'s session list').toEqual([])

      // The list is polled every 3 s; a poll that misses Bob's sandbox (its session manager answers one
      // request at a time, and her command holds it) empties the panel for a moment, and the terminal is
      // drawn again without its output. Alice types the command again until its answer is on screen.
      const term = owner.getByPlaceholder('Type a command...')
      const answer = owner.getByText(`ALICE-42-${n}`).first()
      const answers: string[] = []
      owner.on('response', r => {
        if (r.url().includes(`/api/agent/sessions/${shared!.id}/interact`)) {
          void r.text().then(t => answers.push(`${r.status()} ${t.slice(0, 160)}`), () => answers.push(`${r.status()}`))
        }
      })
      let attempts = 0
      try {
        await expect(async () => {
          attempts += 1
          if (!(await owner.getByText(`Session #${shared!.id} - `).first().isVisible())) await card.click({ timeout: 10_000 })
          await term.fill(`echo ALICE-$((6*7))-${n}`, { timeout: 10_000 })
          await term.press('Enter')
          await expect(answer).toBeVisible({ timeout: 30_000 })
        }).toPass({ timeout: 180_000 })
      } catch (err) {
        throw new Error(`Alice's command reached the session and its answer stayed on screen: not in ${attempts} attempt(s); `
          + `her browser's interact answers: ${answers.join(' | ') || 'none'}\n${redactSecrets(String(err))}`)
      }
      if (attempts > 1) console.log(`test 4: Alice's answer stayed on screen at attempt ${attempts}; interact answers: ${answers.join(' | ')}`)
    } finally {
      // Each person ends the sessions this run's chats opened, in their own list.
      for (const [api, chats] of [[bob.request, sessions], [alice.request, aliceChat ? [aliceChat] : []]] as const) {
        const list = await sessionsOf(api).catch((): SessionList => ({ sessions: [], jobs: [], non_msf_sessions: [] }))
        for (const row of list.sessions.filter(s => s.chat_session_id && chats.includes(s.chat_session_id))) {
          await api.post(drivePath('sessions', row), { headers: { Origin: new URL(BASE).origin } })
        }
        for (const row of list.jobs.filter(j => j.chat_session_id && chats.includes(j.chat_session_id))) {
          await api.post(drivePath('jobs', row), { headers: { Origin: new URL(BASE).origin } })
        }
      }
      // The listener is removed (and checked) while Bob's sandbox still runs, before the stop below.
      let left: string[]
      try {
        left = removeListeners(listener)
      } catch (err) {
        left = [redactSecrets(String(err)).slice(0, 200)]
      }
      expect.soft(left, 'test 4 removed the listener it registered').toEqual([])
      // A handler's background job carries no chat id, so the kills above may leave it, and the
      // agent's hold watcher then holds that sandbox for 8 hours (test 8 waits for an idle stop).
      // Stopping both persons' sandboxes ends every job and hold of this test.
      for (const [who, id] of [['Bob', state.bob.id], ['Alice', state.alice.id]] as const) {
        try {
          if (sandboxContainers({ user: id, view: 'own' }).length) await stopPersonSandbox(admin.request, BASE, id)
          expect.soft(await noSandboxWithin(id, 'own', 90_000), `test 4 left no sandbox of ${who} holding its jobs`).toBe(true)
        } catch (err) {
          expect.soft(redactSecrets(String(err)).slice(0, 300), `test 4 stopped ${who}'s sandbox`).toBe('')
        }
      }
      await page.close()
      await owner.close()
      await stub?.stop()
      stopLab(lab)
      for (const s of sessions) await deleteConversation(bob.request, BASE, s)
      if (aliceChat) await deleteConversation(alice.request, BASE, aliceChat)
      expect.soft(await restoreProjects(apis(), BASE, { fields: ['agentBindPortOnTarget'] }), 'the bind ports of g1-PA and g1-PS were put back').toEqual([])
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('5. terminal: the admin\'s own sandbox, and under act-as Bob his act_as sandbox without the shared project', async () => {
    test.setTimeout(600_000)
    const n = nonce()
    const page = await newPage(admin)
    let project = ''
    let acting = false
    try {
      const created = await admin.request.post('/api/projects', json(BASE, {
        name: `g1e2e-admin-${n}`, targetDomain: 'g1-admin.invalid', targetGuardrailEnabled: false,
      }))
      expect(created.ok(), 'the admin\'s throwaway project').toBeTruthy()
      project = ((await created.json()) as { id: string }).id
      if (sandboxContainers({ user: adminId, view: 'own' }).length) {
        await stopPersonSandbox(admin.request, BASE, adminId)
        expect(await noSandboxWithin(adminId, 'own', 90_000)).toBe(true)
      }

      await page.goto(`/graph?project=${project}`)
      await page.getByRole('tab', { name: 'RedAmon Terminal' }).click()
      await terminalRun(page, `echo G1E2E-${n} > /tmp/g1e2e-${n}-term && echo END-$((6*7))-${n}`, `END-42-${n}`, 300_000)
      expect.soft(await wasSeen(page, TERMINAL_STARTING), `ISOLATION: the terminal said "${TERMINAL_STARTING}" while the sandbox started`).toBe(true)
      ranOnlyIn(`/tmp/g1e2e-${n}-term`, await ownSandbox(adminId, 'the admin'), 'the admin\'s own sandbox')

      const a = adminCredentials()
      const act = await admin.request.post('/api/auth/act-as', json(BASE, {
        targetUserId: state.bob.id, reason: 'g1 e2e: the terminal under act-as (S23)', durationMinutes: 15, stepUpPassword: a.password,
      }))
      expect(act.status(), 'the admin acts as Bob').toBe(200)
      acting = true
      await page.goto(`/graph?project=${state.projects.PB}`)
      await page.getByRole('tab', { name: 'RedAmon Terminal' }).click()
      await terminalRun(page,
        `echo G1E2E-${n} > /tmp/g1e2e-${n}-actas && echo LS-$((1+1))-BEGIN && ls -1 /workspace && echo LS-$((2+2))-END-${n}`,
        `LS-4-END-${n}`, 300_000)
      const folders = between(await terminalText(page), 'LS-2-BEGIN', `LS-4-END-${n}`)
      expect(folders, 'Bob\'s own project is mounted under act-as').toContain(state.projects.PB)
      expect.soft(folders.includes(state.projects.PS), 'ISOLATION (TD-26): the act_as sandbox does not mount the shared g1-PS').toBe(false)
      const actAsBox = await sandboxOf(state.bob.id, 'act_as')
      expect.soft(actAsBox, 'ISOLATION (TD-26): Bob has an act_as sandbox (label redamon.sandbox.view=act_as)').not.toBeNull()
      ranOnlyIn(`/tmp/g1e2e-${n}-actas`, actAsBox, 'Bob\'s act_as sandbox')
    } finally {
      if (acting) await admin.request.delete('/api/auth/act-as', { headers: { Origin: new URL(BASE).origin } })
      await page.close()
      if (project) await admin.request.delete(`/api/projects/${project}`, { headers: { Origin: new URL(BASE).origin } })
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('6. access loss: Alice sees the lent-keys text and revokes Bob; his sandbox is replaced and his next run cannot see g1-PS', async () => {
    test.setTimeout(600_000)
    const n = nonce()
    const page = await newPage(bob)
    const owner = await newPage(alice)
    let stub: Stub | null = null
    let session = ''
    let revoked = false
    try {
      await openChat(page, state.projects.PB)
      const before = await ownSandbox(state.bob.id, 'Bob')
      if (before) {
        expect.soft(mountedProjects(before.name), 'ISOLATION: Bob\'s sandbox mounts the project shared with him')
          .toContain(state.projects.PS)
      }

      await owner.goto('/projects')
      // The page body's card: with g1-PS the current project, the header's selector has its own share button.
      await owner.getByRole('main').getByRole('button', { name: `Share ${PROJECT_NAMES.PS}` }).click()
      const dialog = owner.getByRole('dialog', { name: `Share "${PROJECT_NAMES.PS}"` })
      await expect(dialog.getByRole('heading', { name: 'People with access' })).toBeVisible()
      const row = dialog.getByRole('listitem', { name: 'G1 Bob' })
      await row.getByRole('button', { name: 'Change access for G1 Bob' }).click()
      const editor = dialog.getByRole('form', { name: 'Change access for G1 Bob' })
      await expect.soft(editor.getByText(SHARE_KEYS_LENT_TEXT).first(), 'the share dialog says the owner\'s keys are lent (I11)').toBeVisible()
      // The row's buttons come back once the editor is closed.
      await editor.getByRole('button', { name: 'Cancel' }).click()
      await row.getByRole('button', { name: 'Revoke access for G1 Bob' }).click()
      await owner.getByRole('dialog', { name: 'Revoke access' }).getByRole('button', { name: 'Revoke' }).click()
      await expect(row).toHaveCount(0)
      revoked = true

      if (before) {
        expect.soft(await goneWithin(before.name, 60_000), 'ISOLATION: Bob\'s sandbox that mounted g1-PS stopped at once').toBe(true)
      }
      const projects = await (await bob.request.get('/api/projects')).json() as { id: string }[]
      expect(projects.map(p => p.id), 'g1-PS left Bob\'s project list').not.toContain(state.projects.PS)

      stub = await startStub('marker', { NONCE: n }, stubPort)
      await openChat(page, state.projects.PB)
      session = await send(page, bob.request, state.projects.PB, `g1 e2e after the revoke ${n}`)
      expect((await driveRun(page, bob.request, state.projects.PB, session)).allowed).toBe(1)
      const out = await toolOutput(page, `g1e2e-${n}`)
      expect(out).toContain(`G1E2E-OUT-${n}`)
      expect.soft(listedFolders(out).includes(state.projects.PS), 'ISOLATION: Bob\'s next run cannot see g1-PS').toBe(false)
      const after = await ownSandbox(state.bob.id, 'Bob')
      if (before && after) expect.soft(after.name, 'ISOLATION: Bob works in a new sandbox').not.toBe(before.name)
      if (after) expect.soft(mountedProjects(after.name), 'ISOLATION: the new sandbox does not mount g1-PS').not.toContain(state.projects.PS)
      ranOnlyIn(`/tmp/g1e2e-${n}`, after, 'Bob\'s new own sandbox')
    } finally {
      await page.close()
      await owner.close()
      await stub?.stop()
      if (session) await deleteConversation(bob.request, BASE, session)
      // The seed is the one source of the share: it grants it again with the same terms.
      if (revoked) seedAndRead()
      removeMarkers(`g1e2e-${n}`)
    }
  })

  test('7. everyday screens: the meter shows sandboxes, a partial recon is admitted, PAUSE ALL stops everything, the next message starts cleanly', async () => {
    test.setTimeout(900_000)
    const n = nonce()
    const page = await newPage(alice)
    let stub: Stub | null = null
    let lab: Lab | null = null
    let session = ''
    try {
      lab = startLab(n)
      await setProject({ key: 'alice', api: alice.request }, BASE, state.projects.PA, SLOW_NAABU)
      await openChat(page, state.projects.PA)
      const box = await ownSandbox(state.alice.id, 'Alice')
      await expect.soft.poll(() => meterTitle(page), { message: 'ISOLATION: the system meter counts the running sandboxes', timeout: 60_000 })
        .toMatch(/\b\d+ sandbox(es)? reserving /)

      const scan = await newPage(alice)
      try {
        await startNaabuFromUi(scan, state.projects.PA, lab.proxyIp)
      } finally {
        await scan.close()
      }
      await expect.poll(async () => live(await partialRuns(alice.request, state.projects.PA)).length,
        { message: 'the partial recon was admitted while a sandbox runs', timeout: 120_000 }).toBeGreaterThan(0)

      await page.goto(`/graph?project=${state.projects.PA}`)
      const pause = page.getByRole('button', { name: 'PAUSE ALL' })
      await expect(pause).toBeEnabled({ timeout: 60_000 })
      const isPress = (url: string, method: string) => method === 'POST' && new URL(url).pathname === '/api/agent/emergency-stop-all'
      let lost = ''
      const onFailed = (r: import('@playwright/test').Request) => {
        if (isPress(r.url(), r.method())) lost = r.failure()?.errorText ?? 'failed'
      }
      page.on('requestfailed', onFailed)
      const answered = page.waitForResponse((r) => isPress(r.url(), r.request().method()), { timeout: 60_000 }).catch(() => null)
      await pause.click()
      const press = await answered
      page.off('requestfailed', onFailed)
      expect(press, `${STOP_LOST} (${lost ? `the browser reported ${lost}` : 'no answer within 60 s'})`).not.toBeNull()
      expect(press!.status(), 'the emergency stop answered').toBe(200)
      const stopBody = (await press!.json().catch(() => null)) as { sandboxes?: { stopped?: unknown; error?: unknown } } | null
      // The orchestrator stops instances one by one, each with its grace period, and the webapp
      // answers `sandbox_timeout` when that outlasts its own deadline: the stop goes on, and the
      // check that the sandbox goes away below decides.
      if (box && stopBody?.sandboxes?.error !== 'sandbox_timeout') {
        expect(stopBody?.sandboxes?.stopped, 'the emergency stop names the Kali sandboxes it stopped').toEqual(expect.any(Number))
        expect(stopBody!.sandboxes!.stopped as number, 'the emergency stop stopped Alice\'s sandbox').toBeGreaterThanOrEqual(1)
      }
      await expect.poll(async () => live(await partialRuns(alice.request, state.projects.PA)).length,
        { message: 'PAUSE ALL stopped the partial recon', timeout: 120_000 }).toBe(0)
      if (box) expect.soft(await goneWithin(box.name, 90_000), 'ISOLATION (D22): PAUSE ALL stopped Alice\'s sandbox').toBe(true)

      stub = await startStub('marker', { NONCE: n }, stubPort)
      await openChat(page, state.projects.PA)
      session = await send(page, alice.request, state.projects.PA, `g1 e2e after the emergency stop ${n}`)
      expect((await driveRun(page, alice.request, state.projects.PA, session)).allowed).toBe(1)
      expect(await toolOutput(page, `g1e2e-${n}`), 'the next message ran cleanly').toContain(`G1E2E-OUT-${n}`)
      const after = await ownSandbox(state.alice.id, 'Alice')
      if (box && after) expect.soft(after.name, 'ISOLATION: the next message started a new sandbox').not.toBe(box.name)
      ranOnlyIn(`/tmp/g1e2e-${n}`, after, 'Alice\'s own sandbox')
    } finally {
      await endPartialRuns(alice.request, state.projects.PA)
      await page.close()
      await stub?.stop()
      stopLab(lab)
      if (session) await deleteConversation(alice.request, BASE, session)
      expect.soft(await restoreProjects(apis(), BASE, { fields: Object.keys(SLOW_NAABU) }), 'g1-PA\'s Naabu settings were put back').toEqual([])
      removeMarkers(`g1e2e-${n}`)
    }
  })
})

// ======================================================================================

test.describe('Group B (idle)', () => {
  test('8. idle stop and return: Alice\'s sandbox stops after about two minutes, her next message restarts it, her files are there', async () => {
    test.setTimeout(900_000)
    const n = nonce()
    const file = `g1e2e-${n}.txt`
    let page = await newPage(alice)
    let stub: Stub | null = null
    const sessions: string[] = []
    try {
      stub = await startStub('idle', { NONCE: n, PROJECT_ID: state.projects.PA }, stubPort)
      await openChat(page, state.projects.PA)
      const first = await send(page, alice.request, state.projects.PA, `g1 e2e before the idle stop ${n}`)
      sessions.push(first)
      expect((await driveRun(page, alice.request, state.projects.PA, first)).allowed).toBe(1)
      expect(await toolOutput(page, `WROTE-${n}`)).toContain(`WROTE-${n}`)
      const box = await sandboxOf(state.alice.id, 'own', 10_000)
      expect(box, 'Alice\'s sandbox ran the first command').not.toBeNull()
      ranOnlyIn(`/tmp/g1e2e-${n}`, box, 'Alice\'s own sandbox')

      // Nothing holds a lease while no run and no terminal is open: the page goes, the timer runs.
      await page.close()
      const started = Date.now()
      expect(await goneWithin(box!.name, 300_000), 'Alice\'s idle sandbox stopped by itself').toBe(true)
      expect(Date.now() - started, 'it stopped about two minutes after its last use').toBeLessThan(240_000)

      page = await newPage(alice)
      await openChat(page, state.projects.PA)
      const second = await send(page, alice.request, state.projects.PA, `g1 e2e after the idle stop ${n}`)
      sessions.push(second)
      expect((await driveRun(page, alice.request, state.projects.PA, second)).allowed).toBe(1)
      const out = await toolOutput(page, `TMP-`)
      expect(out, 'the project file is still there').toContain(`G1E2E-${n}`)
      expect(out, 'the restarted sandbox has a fresh /tmp').toContain(`TMP-NEW-${n}`)
      const again = await sandboxOf(state.alice.id, 'own', 10_000)
      expect(again, 'Alice has a sandbox again').not.toBeNull()
      expect(again!.name, 'the second command ran in a new sandbox, not the stopped one').not.toBe(box!.name)
      ranOnlyIn(`/tmp/g1e2e-${n}-again`, again, 'Alice\'s new own sandbox')
    } finally {
      await page.close().catch(() => {})
      await stub?.stop()
      await alice.request.delete(`/api/agent/workspace/delete?projectId=${state.projects.PA}&path=${encodeURIComponent(file)}`,
        { headers: { Origin: new URL(BASE).origin } })
      for (const s of sessions) await deleteConversation(alice.request, BASE, s)
      removeMarkers(`g1e2e-${n}`)
    }
  })
})

// ======================================================================================

test.describe('Group C (memory)', () => {
  test('9. not enough memory: Bob gets the modal with the figures, a refused warm-up shows nothing, Retry works once the scan stops', async () => {
    test.setTimeout(900_000)
    const n = nonce()
    const ownerPage = await newPage(alice)
    const page = await newPage(bob)
    let stub: Stub | null = null
    let lab: Lab | null = null
    let scanLog: LogWatch | null = null
    let session = ''
    try {
      for (const id of [state.alice.id, state.bob.id, adminId]) {
        if (sandboxContainers({ user: id }).length) await stopPersonSandbox(admin.request, BASE, id)
      }
      for (const id of [state.alice.id, state.bob.id, adminId]) {
        expect(await noSandboxWithin(id, 'own', 90_000)).toBe(true)
        expect(await noSandboxWithin(id, 'act_as', 90_000)).toBe(true)
      }
      expect(sandboxContainers().map(c => c.name), 'no other sandbox runs: the pool is sized for this scenario').toEqual([])

      lab = startLab(n)
      await setProject({ key: 'alice', api: alice.request }, BASE, state.projects.PA, SLOW_NAABU)
      await openChat(ownerPage, state.projects.PA)
      expect(await sandboxOf(state.alice.id, 'own'), 'Alice\'s sandbox (the first one) was admitted').not.toBeNull()
      await startNaabuFromUi(ownerPage, state.projects.PA, lab.proxyIp)
      let filler = ''
      await expect.poll(async () => (filler = live(await partialRuns(alice.request, state.projects.PA))[0]?.run_id ?? ''),
        { message: 'the scan was admitted', timeout: 120_000 }).not.toBe('')
      scanLog = watchContainerLog(['redamon.run_kind=partial_recon', `redamon.run_id=${filler}`])
      const log = scanLog
      await expect.poll(() => /\[Naabu\] Found \d+ hostnames/.test(log.text()),
        { message: `SETUP, not a product check: the scan ${filler} logged its targets`, timeout: 60_000 }).toBe(true)
      expect(log.text(), 'SETUP, not a product check: the scan was handed addresses only, no name')
        .toMatch(/\[Naabu\] Found 0 hostnames/)
      // The refusals below are the governor's only while the scan holds its reservation: a scan that has
      // ended makes them a setup failure, never a pass or a product failure.
      const pressure = async (when: string) => {
        const run = (await partialRuns(alice.request, state.projects.PA)).find(r => r.run_id === filler)
        const why = !run || live([run]).length === 0
          ? `the scan ${filler} is ${run ? `${run.status}${run.error ? ` (${run.error})` : ''}` : 'no longer listed'}`
          : sandboxFits(await readLedger(alice.request))
        if (why) {
          throw new Error(`SETUP, not a product check: ${when}, the memory pressure was gone: ${why}. `
            + `The scan's container ${log.container() || '(never seen)'} logged:\n${tail(log.text()) || '(nothing)'}`)
        }
      }

      const modal = page.getByRole('dialog').filter({ hasText: MODAL_RAM_TITLE })
      await pressure('before Bob\'s warm-up')
      await openChat(page, state.projects.PB)
      await sleep(10_000)
      await pressure('through Bob\'s warm-up')
      await expect(modal, 'a refused warm-up shows nothing').toHaveCount(0)
      expect(sandboxContainers({ user: state.bob.id }), 'Bob\'s warm-up was refused').toEqual([])

      stub = await startStub('memory', { NONCE: n }, stubPort)
      await pressure('before Bob\'s message')
      session = await send(page, bob.request, state.projects.PB, `g1 e2e not enough memory ${n}`)
      await driveRun(page, bob.request, state.projects.PB, session)
      try {
        await expect(modal, `the drawer shows "${MODAL_RAM_TITLE}"`).toBeVisible({ timeout: 60_000 })
      } catch (err) {
        await pressure('through Bob\'s run')
        throw err
      }
      await expect(modal, 'with the governor\'s figures').toContainText(/\d+(\.\d+)? GB of \d+(\.\d+)? GB/)

      await stopPartialRuns(alice.request, state.projects.PA)
      await expect.poll(async () => live(await partialRuns(alice.request, state.projects.PA)).length,
        { message: 'the scan stopped', timeout: 120_000 }).toBe(0)
      // The stop path keeps the scan's reservation; the governor's reaper releases it at its next pass
      // (AI_ATTACK_REAP_INTERVAL, 30 s), and until then Bob's sandbox is refused again.
      await expect.poll(async () => sandboxFits(await readLedger(alice.request)) !== null,
        { message: 'the governor released the stopped scan\'s reservation', timeout: 120_000 }).toBe(true)
      await modal.getByRole('button', { name: MODAL_RETRY_LABEL }).click()
      await expect(toolCards(page, `g1e2e-${n}-retry`).first(), 'Retry re-sent the message').toBeVisible({ timeout: 60_000 })
      await driveRun(page, bob.request, state.projects.PB, session)
      expect(await toolOutput(page, `g1e2e-${n}-retry`)).toContain(`G1E2E-RETRY-${n}`)
      const box = await sandboxOf(state.bob.id, 'own', 30_000)
      expect(box, 'Bob\'s sandbox started after the scan stopped').not.toBeNull()
      ranOnlyIn(`/tmp/g1e2e-${n}-retry`, box, 'Bob\'s own sandbox')
    } finally {
      await scanLog?.stop()
      await endPartialRuns(alice.request, state.projects.PA)
      await ownerPage.close()
      await page.close()
      await stub?.stop()
      stopLab(lab)
      if (session) await deleteConversation(bob.request, BASE, session)
      expect.soft(await restoreProjects(apis(), BASE, { fields: Object.keys(SLOW_NAABU) }), 'g1-PA\'s Naabu settings were put back').toEqual([])
      removeMarkers(`g1e2e-${n}`)
    }
  })
})

// ======================================================================================

test.describe('Group D (tunnel)', () => {
  test('10. tunnels from Settings: Bob\'s chisel tunnel runs in his sandbox only and is off after his sandbox restarts', async () => {
    test.setTimeout(900_000)
    const n = nonce()
    const page = await newPage(bob)
    const other = await newPage(alice)
    const a = adminCredentials()
    let edge: ChiselEdge | null = null
    let granted = false
    let original: Override[] = []
    const chiselActive = async () =>
      ((await (await bob.request.get('/api/agent/tunnel-status')).json()) as { chisel?: { active?: boolean } }).chisel?.active
    const edgeSessions = () => new Set(chiselEdgeLog(edge!).match(/session#\d+/g) ?? []).size
    try {
      // Alice's own sandbox runs, so "no tunnel in it" is checked against a live container.
      const aliceBox = await openChatUntilSandbox(other, state.alice.id, state.projects.PA)
      expect(aliceBox, 'Alice\'s sandbox runs').not.toBeNull()

      // The Tunnels permission for Bob (the seed's member set has none), recorded first so a killed run
      // is put back by the next one, and with an expiry as a further backstop.
      const perms = await (await admin.request.get(`/api/users/${state.bob.id}/permissions`)).json() as {
        assignment: { overrides: Override[] }
      }
      original = recordedGrant(state.bob.id) ?? perms.assignment.overrides
        .filter(o => !o.expiresAt || Date.parse(o.expiresAt) > Date.now() + 60_000)
        .map(o => ({ permission: o.permission, effect: o.effect, expiresAt: o.expiresAt, reason: o.reason }))
      recordGrant(state.bob.id, original)
      const grant = await admin.request.put(`/api/users/${state.bob.id}/permissions`, json(BASE, {
        overrides: [...original.filter(o => o.permission !== 'platform:tunnels'), {
          permission: 'platform:tunnels', effect: 'grant', reason: 'g1 e2e tunnel test (S23)',
          expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        }],
        stepUpPassword: a.password,
      }))
      expect(grant.status(), 'the admin grants Bob the Tunnels permission').toBe(200)
      granted = true

      expect(await openChatUntilSandbox(page, state.bob.id, state.projects.PB), 'Bob\'s sandbox runs').not.toBeNull()
      edge = startChiselEdge(n, state.bob.id)

      await page.goto('/settings?tab=keys')
      await page.getByPlaceholder('e.g. http://your-vps.com:9090').fill(edge.url)
      await page.getByLabel('Enable tunnels').check()
      await page.getByRole('button', { name: 'Save Settings' }).click()
      await expect(page.getByText('Settings saved').first()).toBeVisible({ timeout: 120_000 })

      await expect.poll(chiselActive, { message: 'Bob\'s tunnel is active', timeout: 120_000 }).toBe(true)
      // The tunnel-status route answers "inactive" on any error, so where chisel runs is read in the containers.
      const bobBox = await sandboxOf(state.bob.id, 'own', 10_000)
      expect(bobBox, 'Bob\'s sandbox runs').not.toBeNull()
      await expect.poll(() => processRunning(bobBox!.name, 'chisel'),
        { message: 'the chisel client runs in Bob\'s sandbox', timeout: 60_000 }).toBe(true)
      expect.soft(edgeSessions(), 'the chisel client of Bob\'s sandbox reached the edge').toBeGreaterThan(0)
      expect.soft(processRunning(aliceBox!.name, 'chisel'), 'ISOLATION (I9): no chisel client runs in Alice\'s sandbox').toBe(false)
      expect.soft(processRunning(aliceBox!.name, 'ngrok'), 'ISOLATION (I9): no ngrok runs in Alice\'s sandbox').toBe(false)
      await page.goto(`/graph?project=${state.projects.PB}`)
      await expect(page.locator('[title^="Tunnel active:"]').first(), 'Bob\'s toolbar shows his tunnel').toBeVisible({ timeout: 60_000 })

      const sessionsBefore = edgeSessions()
      await stopPersonSandbox(admin.request, BASE, state.bob.id)
      expect(await noSandboxWithin(state.bob.id, 'own', 90_000)).toBe(true)
      // The /graph load above warmed Bob's sandbox up seconds ago: the first opening may fall in the cool-down.
      const restarted = await openChatUntilSandbox(page, state.bob.id, state.projects.PB)
      expect(restarted, 'Bob\'s sandbox started again').not.toBeNull()
      await expect.poll(async () => ((await (await bob.request.get(`/api/users/${state.bob.id}/settings`)).json()) as { tunnelsEnabled?: boolean }).tunnelsEnabled,
        { message: 'a restarted sandbox turns Bob\'s tunnel setting off (I19)', timeout: 60_000 }).toBe(false)
      await sleep(10_000)
      expect(processRunning(restarted!.name, 'chisel'), 'no chisel client runs in the restarted sandbox').toBe(false)
      expect(edgeSessions(), 'the restarted sandbox opened no new session at the edge').toBe(sessionsBefore)
      await page.goto('/settings?tab=keys')
      await expect(page.getByLabel('Enable tunnels'), 'Bob\'s Settings show his tunnel off').not.toBeChecked()
    } finally {
      const failed: string[] = []
      const off = await bob.request.put(`/api/users/${state.bob.id}/settings`, json(BASE, { tunnelsEnabled: false, chiselServerUrl: '' }))
      if (off.status() !== 200) failed.push(`turning Bob's tunnel off answered ${off.status()}`)
      if (granted) {
        // Removing the grant signs Bob out everywhere: put back what his session changed first.
        failed.push(...await restoreProjects(apis(), BASE, { owner: 'bob' }))
        failed.push(...await deleteStubProvider(bob.request, BASE, state.bob.id))
        const back = await admin.request.put(`/api/users/${state.bob.id}/permissions`,
          json(BASE, { overrides: original, stepUpPassword: a.password }))
        if (back.status() === 200) forgetGrant(state.bob.id)
        else failed.push(`putting back Bob's permission overrides answered ${back.status()} (recorded for the next run)`)
      } else {
        forgetGrant(state.bob.id)
      }
      await page.close().catch(() => {})
      await other.close()
      stopChiselEdge(edge)
      expect.soft(failed, 'test 10 put back Bob\'s tunnel settings, project, provider and permissions').toEqual([])
    }
  })
})


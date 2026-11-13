/**
 * Seed fixtures for the live RBAC route matrix (tests/rbac_matrix_live.sh) and the
 * multi-user Playwright helper (testing/e2e/tests/rbacUsers.ts).
 *
 * Every identity and target is synthetic: users `rbac-*@e2e.local`, projects
 * `rbac-*`, target domain `rbac.test`, and secrets that are obvious fakes, so a
 * row can prove a value is masked or leaked by looking for it in a body.
 *
 * Idempotent: users are upserted by email (password, role and name reset), every
 * other row is found by its natural key before it is created, and the fake
 * secrets are written back each run. A throwaway project deleted by a matrix row
 * comes back on the next run. Prints KEY=VALUE lines and nothing else on stdout.
 *
 * Run (no image rebuild needed, the script is read from the host):
 *   docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-rbac-seed.mjs
 * or, once baked into the image: docker compose exec -T webapp node scripts/e2e-rbac-seed.mjs
 */
import { createHash, randomBytes } from 'node:crypto'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

// 18 characters, so it survives the 12-character password floor Phase 1 adds.
const PASSWORD = 'rbac-e2e-pass-0001'
const TARGET_DOMAIN = 'rbac.test'

const USERS = [
  { key: 'ADMIN_A', email: 'rbac-admin-a@e2e.local', name: 'RBAC Admin A', role: 'admin', login: true },
  { key: 'ADMIN_B', email: 'rbac-admin-b@e2e.local', name: 'RBAC Admin B', role: 'admin', login: true },
  { key: 'MEMBER_A', email: 'rbac-member-a@e2e.local', name: 'RBAC Member A', role: 'standard', login: true },
  { key: 'MEMBER_B', email: 'rbac-member-b@e2e.local', name: 'RBAC Member B', role: 'standard', login: true },
  { key: 'MEMBER_C', email: 'rbac-member-c@e2e.local', name: 'RBAC Member C', role: 'standard', login: true },
  // Passwordless managed account: an admin runs it through act-as; it cannot sign in.
  { key: 'MANAGED', email: 'rbac-managed@e2e.local', name: 'RBAC Managed', role: 'standard', login: false },
  // Owns nothing: the matrix signs it in, deletes it by SQL and replays its cookie. A fixed
  // id, because the cleanup can no longer find it by address to remove the rows it left.
  { key: 'DELETED', id: 'rbac-deleted-fixture', email: 'rbac-deleted@e2e.local', name: 'RBAC Deleted', role: 'standard', login: true },
  // One account per built-in set the Phase 3 rows sign in with (p3_generated.tsv). The sets count only
  // with RBAC_PERMISSIONS_ENABLED on; with it off each is a plain member (or admin), as today.
  { key: 'OPERATOR', email: 'rbac-operator@e2e.local', name: 'RBAC Recon Operator', role: 'standard', login: true, sets: ['builtin:recon-operator'] },
  { key: 'ANALYST', email: 'rbac-analyst@e2e.local', name: 'RBAC Read-only Analyst', role: 'standard', login: true, sets: ['builtin:read-only-analyst'] },
  { key: 'NOACCESS', email: 'rbac-noaccess@e2e.local', name: 'RBAC No Access', role: 'standard', login: true, sets: ['builtin:no-access'] },
  { key: 'USERMGR', email: 'rbac-usermgr@e2e.local', name: 'RBAC User Manager', role: 'admin', login: true, adminProfileId: 'builtin:user-manager' },
  // Phase 4's collaborators on PSHARED (SHARES below); each owns nothing. VIEWER_TMP's share is the one
  // the matrix revokes, grants again and leaves: the next seed puts it back.
  { key: 'VIEWER', email: 'rbac-viewer@e2e.local', name: 'RBAC Viewer', role: 'standard', login: true },
  { key: 'VIEWER_RAW', email: 'rbac-viewer-raw@e2e.local', name: 'RBAC Viewer Raw', role: 'standard', login: true },
  { key: 'VIEWER_TMP', email: 'rbac-viewer-tmp@e2e.local', name: 'RBAC Viewer Tmp', role: 'standard', login: true },
  // Phase 5's Read + Write collaborators on PSHARED (step 5.2, p5_generated.tsv): an editor without a toggle,
  // an operator with Run scans, a red-teamer with Exploitation & shells, a co-owner with Manage. Each owns
  // nothing; their shares read as Read while write sharing is not in force.
  { key: 'EDITOR', email: 'rbac-editor@e2e.local', name: 'RBAC Editor', role: 'standard', login: true },
  { key: 'WOPERATOR', email: 'rbac-woperator@e2e.local', name: 'RBAC Write Operator', role: 'standard', login: true },
  { key: 'REDTEAMER', email: 'rbac-redteamer@e2e.local', name: 'RBAC Red-teamer', role: 'standard', login: true },
  { key: 'COOWNER', email: 'rbac-coowner@e2e.local', name: 'RBAC Co-owner', role: 'standard', login: true },
]

// The two throwaway projects exist to be deleted by the matrix: one by the owner,
// one by an admin acting as the owner.
const PROJECTS = [
  { key: 'PA', owner: 'MEMBER_A', name: 'rbac-PA' },
  { key: 'PB', owner: 'MEMBER_B', name: 'rbac-PB' },
  { key: 'PADM', owner: 'ADMIN_A', name: 'rbac-PADM' },
  { key: 'PA_TMP1', owner: 'MEMBER_A', name: 'rbac-PA-tmp1' },
  { key: 'PA_TMP2', owner: 'MEMBER_A', name: 'rbac-PA-tmp2' },
  { key: 'POPERATOR', owner: 'OPERATOR', name: 'rbac-POPERATOR' },
  { key: 'PANALYST', owner: 'ANALYST', name: 'rbac-PANALYST' },
  { key: 'PNOACCESS', owner: 'NOACCESS', name: 'rbac-PNOACCESS' },
  { key: 'POPERATOR_TMP', owner: 'OPERATOR', name: 'rbac-POPERATOR-tmp' },
  { key: 'PANALYST_TMP', owner: 'ANALYST', name: 'rbac-PANALYST-tmp' },
  // Shared by member_c, never PA: baseline rows expect member_b to get 404 on PA whatever the switches.
  { key: 'PSHARED', owner: 'MEMBER_C', name: 'rbac-PSHARED' },
]

// Read shares on PSHARED (step 4.4). They count only with sharing in force (RBAC_SHARING_ENABLED and
// the instance policy enabled); with it off each row is inert and the viewers see nothing. The write
// shares (step 5.2) are Read + Write only with write sharing in force too (the write-sharing switch
// and the policy's maxLevel "write"); their Raw data column is off, so read as Read they lack it. No
// owner consent is seeded: Run scans, Use AI agent and Exploitation count only with it (step 5.6).
const SHARES = [
  { project: 'PSHARED', user: 'VIEWER', rawData: false },
  { project: 'PSHARED', user: 'VIEWER_RAW', rawData: true },
  { project: 'PSHARED', user: 'VIEWER_TMP', rawData: false },
  { project: 'PSHARED', user: 'EDITOR', access: 'write', rawData: false },
  { project: 'PSHARED', user: 'WOPERATOR', access: 'write', rawData: false, runScans: true },
  { project: 'PSHARED', user: 'REDTEAMER', access: 'write', rawData: false, exploit: true },
  { project: 'PSHARED', user: 'COOWNER', access: 'write', rawData: false, manage: true },
]

const FAKES = {
  A_TAVILY_SECRET: 'rbac-fake-tavily-key-0000000000000001',
  A_MCP_BEARER: 'rbac-fake-mcp-bearer-000000000000001',
  B_TAVILY_SECRET: 'rbac-fake-tavily-key-0000000000000002',
  // PSHARED's owner-only fields (step 4.1): the owner reads it, a collaborator never does.
  SHARE_SECRET: 'rbac-fake-share-secret-0001',
}

const CONV_PA_SESSION = 'rbac-sess-PA'

const prisma = new PrismaClient()

async function upsertUser(u, hash) {
  const password = u.login ? hash : ''
  const adminProfileId = u.adminProfileId ?? null
  return prisma.user.upsert({
    where: { email: u.email },
    update: { password, role: u.role, name: u.name, adminProfileId },
    create: { ...(u.id ? { id: u.id } : {}), email: u.email, name: u.name, password, role: u.role, adminProfileId },
  })
}

/** Exactly the account's sets (none: never assigned, the instance default), and no override. */
async function assignSets(userId, sets) {
  await prisma.userPermissionOverride.deleteMany({ where: { userId } })
  await prisma.userPermissionSet.deleteMany({ where: { userId, setId: { notIn: sets } } })
  for (const setId of sets) {
    await prisma.userPermissionSet.upsert({
      where: { userId_setId: { userId, setId } }, update: {}, create: { userId, setId },
    })
  }
}

async function findOrCreate(model, where, data) {
  return (await prisma[model].findFirst({ where })) || (await prisma[model].create({ data }))
}

try {
  const hash = await bcrypt.hash(PASSWORD, 12)
  const ids = {}
  for (const u of USERS) ids[u.key] = (await upsertUser(u, hash)).id
  for (const u of USERS) await assignSets(ids[u.key], u.sets ?? [])

  for (const p of PROJECTS) {
    const userId = ids[p.owner]
    ids[p.key] = (await findOrCreate('project', { userId, name: p.name },
      { userId, name: p.name, targetDomain: TARGET_DOMAIN })).id
  }

  await prisma.project.update({
    where: { id: ids.PSHARED },
    data: {
      cypherfixGithubToken: FAKES.SHARE_SECRET,
      graphqlAuthValue: FAKES.SHARE_SECRET,
      httpxCustomHeaders: [`X-Rbac-Share: ${FAKES.SHARE_SECRET}`],
    },
  })
  // An image from before step 4.2 has no share table: the sharing rows then cannot run anyway.
  if (prisma.projectCollaborator) {
    for (const sh of SHARES) {
      const projectId = ids[sh.project]
      const userId = ids[sh.user]
      const terms = {
        access: sh.access ?? 'read', rawData: sh.rawData, runScans: sh.runScans === true, useAgent: sh.useAgent === true,
        exploit: sh.exploit === true, manage: sh.manage === true, expiresAt: null, note: null, grantedById: ids.MEMBER_C,
      }
      await prisma.projectCollaborator.upsert({
        where: { projectId_userId: { projectId, userId } },
        update: terms,
        create: { projectId, userId, ...terms },
      })
    }
  } else {
    console.error('SEED_NOTE: no project_collaborators table in this image: the shares were not seeded')
  }

  const pa = ids.PA
  const memberA = ids.MEMBER_A
  const conv = await prisma.conversation.upsert({
    where: { sessionId: CONV_PA_SESSION },
    update: {},
    create: { userId: memberA, projectId: pa, sessionId: CONV_PA_SESSION, title: 'rbac-conversation' },
  })
  const rem = await findOrCreate('remediation', { projectId: pa, title: 'rbac-remediation' },
    { projectId: pa, title: 'rbac-remediation', description: 'synthetic RBAC matrix fixture' })
  // A report row only: no file is written, the list route never opens it.
  const report = await findOrCreate('report', { projectId: pa, title: 'rbac-report' }, {
    projectId: pa, title: 'rbac-report', filename: 'rbac-report.html',
    filePath: '/data/reports/rbac-e2e-fixture-not-on-disk.html', fileSize: 0,
  })
  // Disabled and never due, so the scheduler never fires it.
  const schedule = await findOrCreate('scanSchedule', { projectId: pa, label: 'rbac-schedule' },
    { projectId: pa, userId: memberA, label: 'rbac-schedule', mode: 'once', enabled: false })
  // The plaintext is discarded at once, so this token can never authenticate.
  const token = await findOrCreate('mcpAccessToken', { userId: memberA, name: 'rbac-token-a' }, {
    userId: memberA, name: 'rbac-token-a', tokenPrefix: 'rbac-tok',
    tokenHash: createHash('sha256').update(randomBytes(32)).digest('hex'), scopes: ['recon:read'],
  })

  // A disabled streamable_http server whose bearer is a known fake: the matrix
  // proves where it is (and is not) returned whole. Written as a save through the
  // route stores it (mcpServerSchema's defaults filled in): the list route returns
  // rows as stored, and the MCP Tool Plugins tab reads `tools` and `default_phases`.
  const mcpServers = [{
    id: 'rbac-fake-server', name: 'rbac fake server', description: '', enabled: false,
    transport: 'streamable_http', default_phases: ['informational', 'exploitation', 'post_exploitation'], tags: [],
    url: 'http://127.0.0.1:9/mcp', headers: {}, auth: { type: 'bearer', token: FAKES.A_MCP_BEARER },
    connect_timeout: 60, read_timeout: 600, args: [], env: {}, encoding: 'utf-8', tools: [],
  }]
  await prisma.userSettings.upsert({
    where: { userId: memberA },
    update: { tavilyApiKey: FAKES.A_TAVILY_SECRET, mcpServers },
    create: { userId: memberA, tavilyApiKey: FAKES.A_TAVILY_SECRET, mcpServers },
  })
  await prisma.userSettings.upsert({
    where: { userId: ids.MEMBER_B },
    update: { tavilyApiKey: FAKES.B_TAVILY_SECRET },
    create: { userId: ids.MEMBER_B, tavilyApiKey: FAKES.B_TAVILY_SECRET },
  })

  const out = [`RBAC_PASSWORD=${PASSWORD}`, `RBAC_TARGET_DOMAIN=${TARGET_DOMAIN}`]
  for (const u of USERS) out.push(`${u.key}_EMAIL=${u.email}`, `${u.key}_ID=${ids[u.key]}`)
  for (const p of PROJECTS) out.push(`${p.key}_ID=${ids[p.key]}`)
  out.push(
    `CONV_PA_SESSION=${CONV_PA_SESSION}`, `CONV_PA_ID=${conv.id}`, `REM_PA_ID=${rem.id}`,
    `REPORT_PA_ID=${report.id}`, `SCHEDULE_PA_ID=${schedule.id}`, `TOKEN_A_ID=${token.id}`,
  )
  for (const [k, v] of Object.entries(FAKES)) out.push(`${k}=${v}`)
  console.log(out.join('\n'))
} catch (err) {
  console.error('SEED_ERROR:', err.message)
  process.exitCode = 1
} finally {
  await prisma.$disconnect()
}

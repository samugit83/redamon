/**
 * Seed fixtures for the two-user BOLA E2E (tests/test_e2e_bola_live.sh).
 * Creates two standard users (A, B), one admin, and a legacy holder (L: a standard
 * user holding the three legacy grants an upgrade records for a member who had the
 * shared tools), and a project owned by each of A, B and L. Idempotent (upsert by
 * email). Prints KEY=VALUE lines for the shell.
 *
 * The test removes every fixture before seeding, so each account is created now, after
 * the upgrade's cutoff: the shared-tools escape hatch (REDAMON_SHARED_TOOLS_COMPAT,
 * accounts older than the cutoff) never applies to them, and A and B hold no grant.
 *
 * Run: docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-bola-seed.mjs
 */
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const PW = 'e2epass123'
const LEGACY_GRANTS = ['kali_terminal', 'shell_sessions', 'tunnels']
// A known fake: the browser's project read must never return it (NF-15).
const MCP_BEARER = 'bola-fake-mcp-bearer-000000000000001'
const prisma = new PrismaClient()

async function upsertUser(email, name, role, legacyGrants = []) {
  const hash = await bcrypt.hash(PW, 12)
  return prisma.user.upsert({
    where: { email },
    update: { password: hash, role, name, legacyGrants },
    create: { email, name, password: hash, role, legacyGrants },
  })
}

async function upsertProject(userId, name) {
  const existing = await prisma.project.findFirst({ where: { userId, name } })
  if (existing) return existing
  return prisma.project.create({
    data: { userId, name, targetDomain: 'e2e-bola.local', ipMode: true },
  })
}

/** A disabled HTTP MCP server whose bearer is the fake above; nothing ever connects to it. */
async function saveFakeMcpServer(userId) {
  const mcpServers = [{
    id: 'bola-fake-server', name: 'bola fake server', description: '', enabled: false,
    transport: 'streamable_http', url: 'http://127.0.0.1:9/mcp',
    auth: { type: 'bearer', token: MCP_BEARER },
  }]
  await prisma.userSettings.upsert({
    where: { userId },
    update: { mcpServers },
    create: { userId, mcpServers },
  })
}

try {
  const a = await upsertUser('bola-a@e2e.local', 'BOLA A', 'standard')
  const b = await upsertUser('bola-b@e2e.local', 'BOLA B', 'standard')
  const admin = await upsertUser('bola-admin@e2e.local', 'BOLA Admin', 'admin')
  const legacy = await upsertUser('bola-legacy@e2e.local', 'BOLA Legacy', 'standard', LEGACY_GRANTS)
  const pa = await upsertProject(a.id, 'e2e-bola-A')
  const pb = await upsertProject(b.id, 'e2e-bola-B')
  const pl = await upsertProject(legacy.id, 'e2e-bola-L')
  await saveFakeMcpServer(a.id)
  await saveFakeMcpServer(legacy.id)

  // A conversation, a remediation and a preset owned by B (to test the
  // conversations/remediations/presets guards + carve-out routes cross-user).
  const CONV_B_SESSION = 'e2e-bola-sess-B'
  await prisma.conversation.upsert({
    where: { sessionId: CONV_B_SESSION },
    update: {},
    create: { userId: b.id, projectId: pb.id, sessionId: CONV_B_SESSION },
  })
  const remB = (await prisma.remediation.findFirst({ where: { projectId: pb.id, title: 'e2e-bola-rem' } }))
    || (await prisma.remediation.create({ data: { projectId: pb.id, title: 'e2e-bola-rem', description: 'x' } }))
  const presetB = (await prisma.userProjectPreset.findFirst({ where: { userId: b.id, name: 'e2e-bola-preset' } }))
    || (await prisma.userProjectPreset.create({ data: { userId: b.id, name: 'e2e-bola-preset', settings: {} } }))
  const mutePresetB = (await prisma.userMuteRulesPreset.findFirst({ where: { userId: b.id, name: 'e2e-bola-mute-preset' } }))
    || (await prisma.userMuteRulesPreset.create({
      data: { userId: b.id, name: 'e2e-bola-mute-preset', mode: 'denylist', rules: { version: 1, kinds: {} } },
    }))

  console.log(`A_ID=${a.id}`)
  console.log(`B_ID=${b.id}`)
  console.log(`ADMIN_ID=${admin.id}`)
  console.log(`L_ID=${legacy.id}`)
  console.log(`PA_ID=${pa.id}`)
  console.log(`PB_ID=${pb.id}`)
  console.log(`PL_ID=${pl.id}`)
  console.log(`CONV_B_SESSION=${CONV_B_SESSION}`)
  console.log(`REM_B_ID=${remB.id}`)
  console.log(`PRESET_B_ID=${presetB.id}`)
  console.log(`MUTE_PRESET_B_ID=${mutePresetB.id}`)
  console.log(`MCP_BEARER=${MCP_BEARER}`)
} catch (err) {
  console.error('SEED_ERROR:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}

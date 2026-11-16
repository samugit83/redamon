/**
 * Seed fixtures for the Tradecraft 2.0 settings and project specs (T4.10:
 * testing/e2e/tests/tradecraftSettings.spec.ts, tradecraftProjects.spec.ts).
 *
 * Everything is synthetic and written straight into the database: no agent and no site is
 * reached. One account `tradecraft-e2e@e2e.local` with Tradecraft 2.0 on and no ingestion
 * setting changed; three resources on `*.tc-e2e.test` hosts: a Stored wiki ingested by 2.0 with
 * entries, stored pages and a report, and a settings hash no settings give (the stale badge); a
 * Live website ingested by 2.0 with no hash (current); a third one disabled in Global Settings;
 * and one project with every resource on.
 *
 * Idempotent: the account is upserted by email, its tradecraft rows and project choices are
 * written again from scratch each run. Prints KEY=VALUE lines and nothing else on stdout.
 *
 * Run (no image rebuild needed, the script is read from the host):
 *   docker compose exec -T -w /app webapp node --input-type=module - < webapp/scripts/e2e-tradecraft-seed.mjs
 */
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const EMAIL = 'tradecraft-e2e@e2e.local'
const PASSWORD = 'tradecraft-e2e-pass-0001'
const PROJECT_NAME = 'tradecraft-e2e-project'
// 16 hex characters that no effective settings hash to: the wiki reads as ingested with older settings.
const STALE_HASH = '0000000000000000'
const DAY = 86_400_000

const prisma = new PrismaClient()

async function resource(userId, r) {
  const row = await prisma.userTradecraftResource.create({
    data: {
      userId, slug: r.slug, name: r.name, url: r.url, enabled: r.enabled, resourceType: r.type, llmModel: 'e2e-no-model',
      storageMode: r.storageMode, mapVersion: 3, generation: 1, settingsHash: r.hash, summary: r.summary,
      ingestionReport: r.report, lastRefreshedAt: new Date(Date.now() - 3 * DAY), lastVerifiedAt: new Date(Date.now() - 3 * DAY),
    },
  })
  for (let i = 0; i < r.pages.length; i++) {
    const url = `${r.url}${r.pages[i].path}`
    const page = await prisma.tradecraftPageId.create({ data: { resourceId: row.id, url } })
    const text = r.storageMode === 'stored' ? `# ${r.pages[i].title}\n\nSynthetic page ${i + 1} of the e2e fixture.` : null
    await prisma.tradecraftEntry.create({
      data: {
        userId, resourceId: row.id, generation: 1, pageId: page.id, url, title: r.pages[i].title, titleSource: 'page',
        status: 'kept', storedText: text, storedBytes: text ? Buffer.byteLength(text) : 0, sizeChars: text?.length ?? 0,
      },
    })
  }
  return row
}

try {
  const hash = await bcrypt.hash(PASSWORD, 12)
  const user = await prisma.user.upsert({
    where: { email: EMAIL },
    update: { password: hash, role: 'standard', name: 'Tradecraft E2E' },
    create: { email: EMAIL, password: hash, role: 'standard', name: 'Tradecraft E2E' },
  })
  // From scratch: the resources cascade their pages, entries, jobs and project choices.
  await prisma.userTradecraftResource.deleteMany({ where: { userId: user.id } })
  await prisma.tradecraftUserSettings.upsert({
    where: { userId: user.id },
    update: { v2Enabled: true, v2EnabledAt: new Date(), ingestion: {}, search: {} },
    create: { userId: user.id, v2Enabled: true, v2EnabledAt: new Date() },
  })
  const project = (await prisma.project.findFirst({ where: { userId: user.id, name: PROJECT_NAME } }))
    ?? (await prisma.project.create({ data: { userId: user.id, name: PROJECT_NAME, targetDomain: 'tc-e2e.test' } }))

  const wiki = await resource(user.id, {
    slug: 'tc-e2e-wiki', name: 'TC E2E Wiki', url: 'https://wiki.tc-e2e.test/', enabled: true, type: 'mkdocs-wiki',
    storageMode: 'stored', hash: STALE_HASH, summary: 'A synthetic offensive wiki for the e2e specs.',
    report: { visited: 40, kept: 31, stopReason: 'frontier_empty', llmCalls: 3, durationSec: 12 },
    pages: [{ path: 'sqli/', title: 'SQL injection' }, { path: 'xss/', title: 'Cross-site scripting' }, { path: 'ssrf/', title: 'SSRF' }],
  })
  const blog = await resource(user.id, {
    slug: 'tc-e2e-blog', name: 'TC E2E Blog', url: 'https://blog.tc-e2e.test/', enabled: true, type: 'agentic-crawl',
    storageMode: 'live', hash: '', summary: 'A synthetic research blog.',
    report: { visited: 12, kept: 10, stopReason: 'max_pages', llmCalls: 5, durationSec: 30 },
    pages: [{ path: 'posts/one', title: 'First post' }, { path: 'posts/two', title: 'Second post' }],
  })
  const disabled = await resource(user.id, {
    slug: 'tc-e2e-disabled', name: 'TC E2E Disabled', url: 'https://disabled.tc-e2e.test/', enabled: false, type: 'agentic-crawl',
    storageMode: 'live', hash: '', summary: '', report: {}, pages: [],
  })

  console.log(`TC_USER_ID=${user.id}`)
  console.log(`TC_EMAIL=${EMAIL}`)
  console.log(`TC_PASSWORD=${PASSWORD}`)
  console.log(`TC_PROJECT_ID=${project.id}`)
  console.log(`TC_WIKI_ID=${wiki.id}`)
  console.log(`TC_BLOG_ID=${blog.id}`)
  console.log(`TC_DISABLED_ID=${disabled.id}`)
} finally {
  await prisma.$disconnect()
}

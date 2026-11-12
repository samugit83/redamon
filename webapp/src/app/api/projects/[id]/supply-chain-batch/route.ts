/**
 * Scan Queue Phase 6 - create a supply-chain org batch. Project-scoped, so
 * the project check (scan:supply_chain) runs FIRST. Enumerates the GitHub org's repos and, in ONE
 * transaction, writes the batch, its items, and one supply_chain_repo JobQueue row
 * per repo (priority -10, below manual and scheduled). The dispatcher runs them.
 *
 * The GitHub token is resolved server-side from UserSettings (never from the
 * request body) and never stored on a row or returned. Every owner/repo/ref is
 * validated before it is persisted (and again in the container before git clone).
 *
 * The target may name a host (`https://ghe.example.com/orgs/acme`), but only a
 * host the operator registered in Global Settings is accepted - see
 * `parseOwnerTarget`. The credential is then chosen BY HOST, so a GitHub
 * Enterprise token is never sent to api.github.com and vice versa.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { getEffectiveUser } from '@/lib/session'
import { settingsFingerprint, envelopeForKind } from '@/lib/jobQueue'
import { listOwnerRepos, isValidGitRef, GithubEnumError } from '@/lib/github/orgRepos'
import { parseOwnerTarget, allowedGithubHosts, hostHint, GITHUB_DOT_COM } from '@/lib/github/ownerTarget'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: projectId } = await params
    const auth = await requirePermission(request, 'scan:supply_chain', { projectId })
    if (auth instanceof NextResponse) return auth

    const eff = await getEffectiveUser()
    if (!eff?.userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

    const project = await prisma.project.findUnique({ where: { id: projectId } })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    const body = await request.json().catch(() => ({}))
    const rawTarget = (typeof body?.org === 'string' && body.org.trim())
      ? body.org.trim()
      : project.supplyChainOrgName

    // Settings first: they carry the host allowlist, so they must be read BEFORE
    // the target can be parsed. Tokens are resolved server-side and are NEVER
    // read from the request body.
    const settings = await prisma.userSettings.findUnique({
      where: { userId: eff.userId },
      select: { supplyChainGithubToken: true, githubEnterpriseHost: true, githubEnterpriseToken: true },
    }).catch(() => null)

    const allowed = allowedGithubHosts(settings?.githubEnterpriseHost)
    const target = parseOwnerTarget(rawTarget, allowed)
    if (!target) {
      // Distinguish "not a coordinate" from "host not registered": the second is
      // an operator action (add the host in Global Settings), not a typo.
      const hint = hostHint(rawTarget)
      return NextResponse.json({
        error: hint && !allowed.includes(hint)
          ? `'${hint}' is not a configured GitHub host. Add it as the GitHub Enterprise Host in Global Settings first.`
          : 'A valid GitHub organization or user is required: a name, or a URL such as https://github.com/orgs/acme.',
      }, { status: 400 })
    }
    const { host, owner: org } = target

    // Credential BY HOST. A GitHub Enterprise PAT must never travel to
    // api.github.com, nor a github.com PAT to an internal server. Optional in
    // both cases: public repos enumerate anonymously.
    const token = (host === GITHUB_DOT_COM
      ? settings?.supplyChainGithubToken
      : settings?.githubEnterpriseToken) || undefined

    const orgRef = project.supplyChainOrgRef || ''
    if (orgRef && !isValidGitRef(orgRef)) {
      return NextResponse.json({ error: 'Configured org ref is not a valid git ref.' }, { status: 400 })
    }

    let repos
    try {
      repos = await listOwnerRepos(org, {
        token,
        host,
        includeForks: project.supplyChainOrgIncludeForks,
        includeArchived: project.supplyChainOrgIncludeArchived,
        maxRepos: Math.max(1, project.supplyChainOrgMaxRepos || 50),
      })
    } catch (e) {
      // A GithubEnumError's text is ours (token scrubbed) and names GitHub's
      // refusal; anything else is an unexpected throw whose text stays in the log.
      if (e instanceof GithubEnumError) {
        return NextResponse.json({ error: e.message, code: 'github_enum_failed' }, { status: e.status || 502 })
      }
      return internalError(e, 'GitHub enumeration failed', { status: 502 })
    }

    if (repos.length === 0) {
      return NextResponse.json({ error: `No scannable repositories found for '${org}' on ${host}.` }, { status: 400 })
    }

    const settingsHash = settingsFingerprint('supply_chain_repo', project as unknown as Record<string, unknown>)
    const envelopeBytes = BigInt(envelopeForKind('supply_chain_repo'))
    const deepAnalysis = project.supplyChainOrgDeepAnalysisEnabled
    const scope = project.supplyChainRepoScope || ''

    const result = await prisma.$transaction(async tx => {
      const batch = await tx.supplyChainBatch.create({
        data: { projectId, userId: eff.userId, org, host, status: 'running', totalItems: repos.length },
        select: { id: true },
      })

      for (const r of repos) {
        const ref = orgRef || r.defaultBranch || ''
        const safeRef = isValidGitRef(ref) ? ref : ''
        const payload = {
          repo_url: r.url,
          repo_full_name: r.fullName,
          // Carried per item so the scan container knows which host to clone from
          // and which credential the settings fetch should hand it.
          host,
          ref: safeRef,
          scope,
          deep_analysis: deepAnalysis,
        }
        const job = await tx.jobQueue.create({
          data: {
            projectId,
            userId: eff.userId,
            kind: 'supply_chain_repo',
            payload: payload as Prisma.InputJsonValue,
            settingsHash,
            envelopeBytes,
            priority: -10, // batch item: below manual (10) and scheduled (0)
            batchId: batch.id,
            status: 'queued',
          },
          select: { id: true },
        })
        await tx.supplyChainBatchItem.create({
          data: {
            batchId: batch.id,
            repoFullName: r.fullName,
            repoUrl: r.url,
            ref: safeRef,
            status: 'queued',
            jobId: job.id,
          },
        })
      }

      return batch
    }, {
      // Up to maxRepos (default 50) x 2 writes; the 5s default is too tight under
      // load. Cap the enumeration at maxRepos keeps this bounded.
      timeout: 30_000,
      maxWait: 10_000,
    })

    return NextResponse.json({
      ok: true, batchId: result.id, totalItems: repos.length, org, host,
    }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create the org batch', { log: '[supplyChainBatch] create failed' })
  }
}

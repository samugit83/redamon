import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanJobCredential } from '@/lib/scanJobCredential'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { startUnderGraphLock } from '@/lib/startScan'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import { legacyGraphDomains, legacyGraphRefusal } from '@/lib/legacyGraph'
import { IP_HOSTNAME_SELECT, resolveScopeGroups } from '@/lib/scopeGroups'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// POST /api/ai-attack-surface/{projectId}/start
// Launch one AI Attack Surface tool against the selected AI nodes.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:ai_attack', { projectId })
    if (auth instanceof NextResponse) return auth

    // S-4: held from the activation check through the orchestrator's answer
    // (startUnderGraphLock), since the run writes the live graph.
    return await startUnderGraphLock(projectId, () => startAiAttackScan(request, projectId, auth.effective.userId))
  } catch (error) {
    return internalError(error, 'Failed to start AI Gauntlet scan', { log: 'Error starting AI Attack Surface scan' })
  }
}

async function startAiAttackScan(request: NextRequest, projectId: string, actorUserId: string): Promise<NextResponse> {
  // Its findings are written into the live graph, so it must not start while a
  // version activation is swapping it (Scan Timeline 4A.3).
  const activating = await assertGraphNotActivating(projectId)
  if (activating) return activating

  const body = await request.json()

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true, targetDomain: true, subdomainList: true,
      ipMode: true, domainBatchMode: true, domainBatchHosts: true,
      targetIps: true, roeExcludedHosts: true, ...IP_HOSTNAME_SELECT,
    },
  })
  if (!project) {
    return NextResponse.json({ error: 'Project not found' }, { status: 404 })
  }
  const engagementBlocked = await assertEngagementStartable(projectId)
  if (engagementBlocked) return engagementBlocked
  // Its findings attach to the AI nodes' Domain: refused on an old-model
  // graph (§4.11.6).
  const legacy = await legacyGraphDomains(project.userId, projectId, resolveScopeGroups(project).groups)
  if (legacy && legacy.length > 0) {
    return NextResponse.json(legacyGraphRefusal(legacy), { status: 409 })
  }

  // Read before the start, so a RoE replaced mid-start cannot misattribute the run.
  const roeTextSha256 = await currentRoeTextSha256(projectId)
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        ...scanJobCredential(projectId, project.userId, actorUserId),
        webapp_api_url: WEBAPP_URL,
        tool: body.tool || 'garak',
        targets: body.targets || [],
        bounds: body.bounds || {},
        roe_confirmed: body.roe_confirmed ?? false,
        dry_run: body.dry_run ?? false,
        probes: body.probes || [],
        strategies: body.strategies || [],
        objective: body.objective || '',
        target_model: body.target_model || '',
        target_purpose: body.target_purpose || '',
        api_key: body.api_key || '',
        auth_header: body.auth_header || '',
        auth_scheme: body.auth_scheme || '',
        // The scanner never reads the project row: these let it admit each
        // target (design §11). It refuses an IP-mode project whose config
        // does not say, so a domain project says ip_mode false.
        ip_mode: project.ipMode === true,
        target_ips: project.ipMode ? project.targetIps ?? [] : [],
        roe_excluded_hosts: project.roeExcludedHosts ?? [],
        ip_hostname_policy: {
          mode: project.ipHostnameMode ?? 'ip_only',
          include: project.ipHostnameInclude ?? [],
          exclude: project.ipHostnameExclude ?? [],
        },
      }),
    })
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, 'Failed to start AI Gauntlet scan')
  }

  if (!response.ok) {
    const upstream = await readUpstreamBody(response)
    // Governor rejections carry a structured object detail; normalize to a
    // string message (+ limit) so it is never rendered as a raw React child.
    const { error, limit, code } = normalizeOrchestratorStartError(upstream.json ?? {}, 'Failed to start AI Gauntlet scan')
    return NextResponse.json(
      {
        error,
        code: code ?? upstream.code ?? 'orchestrator_error',
        upstreamStatus: response.status,
        ...(limit ? { limit } : {}),
      },
      { status: response.status },
    )
  }

  const data = await response.json()
  // Run-keyed like partial recon: the run id is what tells two concurrent
  // AI-attack jobs on the same project apart in history.
  // The scan is already running: recording who started it must never be able
  // to turn a successful start into an error response.
  const __eff = await getEffectiveUser().catch(() => null)
  await recordScanStart({
    roeTextSha256,
    projectId,
    kind: 'ai_attack',
    runId: typeof data?.run_id === 'string' ? data.run_id : '',
    initiatedByUserId: __eff?.userId ?? null,
  })
  return NextResponse.json(data)
}

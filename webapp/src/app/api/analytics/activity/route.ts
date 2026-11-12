import { NextRequest, NextResponse } from 'next/server'
import { projectTargetLabel } from '@/lib/projectSummary'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'

function groupByDay<T extends { createdAt: Date }>(items: T[], valueFn: (item: T) => Record<string, number>) {
  const map = new Map<string, Record<string, number>>()
  for (const item of items) {
    const date = item.createdAt.toISOString().split('T')[0]
    const existing = map.get(date) || {}
    const values = valueFn(item)
    for (const [key, val] of Object.entries(values)) {
      existing[key] = (existing[key] || 0) + val
    }
    map.set(date, existing)
  }
  return Array.from(map.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, values]) => ({ date, ...values }))
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  try {
    // Project info
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: {
        name: true, targetDomain: true, ipMode: true, scanModules: true, createdAt: true, updatedAt: true,
        targetIps: true, subdomainList: true, domainBatchMode: true, domainBatchHosts: true,
      },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Conversation aggregates
    const [convStats, convByStatus, convByPhase] = await Promise.all([
      prisma.conversation.aggregate({
        where: { projectId },
        _count: { id: true },
        _sum: { iterationCount: true },
        _avg: { iterationCount: true },
      }),
      prisma.conversation.groupBy({
        by: ['status'],
        where: { projectId },
        _count: { id: true },
      }),
      prisma.conversation.groupBy({
        by: ['currentPhase'],
        where: { projectId },
        _count: { id: true },
      }),
    ])

    // Remediation aggregates
    const [remBySeverity, remByStatus, remByCategory, exploitableCount] = await Promise.all([
      prisma.remediation.groupBy({ by: ['severity'], where: { projectId }, _count: { id: true } }),
      prisma.remediation.groupBy({ by: ['status'], where: { projectId }, _count: { id: true } }),
      prisma.remediation.groupBy({ by: ['category'], where: { projectId }, _count: { id: true } }),
      prisma.remediation.count({ where: { projectId, exploitAvailable: true } }),
    ])

    // Total messages
    const totalMessages = await prisma.chatMessage.count({
      where: { conversation: { projectId } },
    })

    // Timeline data
    const [convTimeline, remTimeline] = await Promise.all([
      prisma.conversation.findMany({
        where: { projectId },
        select: { createdAt: true, iterationCount: true },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.remediation.findMany({
        where: { projectId },
        select: { createdAt: true, severity: true },
        orderBy: { createdAt: 'asc' },
      }),
    ])

    const conversationTimeline = groupByDay(convTimeline, (c) => ({
      count: 1,
      iterations: c.iterationCount,
    }))

    const remediationTimeline = groupByDay(remTimeline, (r) => ({
      count: 1,
      [r.severity || 'unknown']: 1,
    }))

    return NextResponse.json({
      project: {
        name: project.name,
        targetDomain: project.targetDomain,
        targetLabel: projectTargetLabel(project),
        ipMode: project.ipMode,
        scanModules: project.scanModules,
        createdAt: project.createdAt.toISOString(),
        updatedAt: project.updatedAt.toISOString(),
      },
      conversations: {
        total: convStats._count.id,
        totalIterations: convStats._sum.iterationCount || 0,
        avgIterations: Math.round(convStats._avg.iterationCount || 0),
        byStatus: convByStatus.map(s => ({ status: s.status, count: s._count.id })),
        byPhase: convByPhase.map(p => ({ phase: p.currentPhase, count: p._count.id })),
      },
      remediations: {
        bySeverity: remBySeverity.map(s => ({ severity: s.severity, count: s._count.id })),
        byStatus: remByStatus.map(s => ({ status: s.status, count: s._count.id })),
        byCategory: remByCategory.map(c => ({ category: c.category, count: c._count.id })),
        exploitableCount,
      },
      totalMessages,
      timeline: {
        conversations: conversationTimeline,
        remediations: remediationTimeline,
      },
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Analytics activity error' })
  }
}

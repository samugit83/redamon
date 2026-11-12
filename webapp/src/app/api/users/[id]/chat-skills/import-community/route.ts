import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { MAX_CHAT_SKILL_CONTENT_SIZE } from '@/lib/userSkills'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, safeErrorCode, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'

// Mirror the caps the manual POST path enforces so bulk import cannot be used
// to bypass them (content size, per-user ceiling, description length).
const MAX_SKILLS_PER_USER = 50
const MAX_DESCRIPTION = 500

interface RouteParams {
  params: Promise<{ id: string }>
}

type SkipReason = 'duplicate' | 'limit' | 'fetchFailed' | 'tooLarge' | 'invalid' | 'saveFailed'

// POST /api/users/[id]/chat-skills/import-community - Import all chat skills from agentic catalog
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:chat_skills')
    if (selfRefused) return selfRefused

    let catalogRes: Response
    try {
      catalogRes = await agentFetch('/skills', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
      })
    } catch (error) {
      if (error instanceof AgentUnreachableError) {
        return upstreamFailureResponse('agent', error.cause_, 'Failed to fetch skills catalog from agent service')
      }
      throw error
    }

    if (!catalogRes.ok) {
      return upstreamErrorResponse('agent', catalogRes, 'Failed to fetch skills catalog from agent service')
    }

    const catalog = await catalogRes.json()
    const skills: Array<{ id: string; name: string; description?: string; category?: string }> = catalog.skills || []

    // Fetch user's existing chat skills to skip duplicates
    const existingSkills = await prisma.userChatSkill.findMany({
      where: { userId: id },
      select: { name: true },
    })
    const existingNames = new Set(existingSkills.map((s) => s.name))

    let imported = 0
    let total = existingSkills.length
    const skippedBy: Record<SkipReason, number> = {
      duplicate: 0, limit: 0, fetchFailed: 0, tooLarge: 0, invalid: 0, saveFailed: 0,
    }

    for (const skill of skills) {
      if (existingNames.has(skill.name)) {
        skippedBy.duplicate++
        continue
      }

      if (total >= MAX_SKILLS_PER_USER) {
        skippedBy.limit++
        continue
      }

      let skillData: Record<string, unknown>
      try {
        const contentRes = await agentFetch(`/skills/${encodeURIComponent(skill.id)}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
          cache: 'no-store',
        })
        if (!contentRes.ok) {
          skippedBy.fetchFailed++
          continue
        }
        const parsed: unknown = await contentRes.json()
        skillData = parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {}
      } catch {
        skippedBy.fetchFailed++
        continue
      }

      const content = typeof skillData.content === 'string' ? skillData.content : ''
      if (!content) {
        skippedBy.invalid++
        continue
      }
      if (content.length > MAX_CHAT_SKILL_CONTENT_SIZE) {
        skippedBy.tooLarge++
        continue
      }
      const rawDescription = skillData.description || skill.description || null
      const description = typeof rawDescription === 'string'
        ? rawDescription.slice(0, MAX_DESCRIPTION)
        : null

      try {
        await prisma.userChatSkill.create({
          data: {
            userId: id,
            name: (skillData.name as string) || skill.name,
            description,
            category: (skillData.category as string) || skill.category || 'general',
            content,
          },
        })
      } catch (error) {
        // Counted, not fatal: the skills saved before it stay saved. Its code only, as in the
        // batch upload: a Prisma message can quote the skill's text.
        console.error('Failed to save a community chat skill:', safeErrorCode(error))
        skippedBy.saveFailed++
        continue
      }

      imported++
      total++
    }

    const skipped = Object.values(skippedBy).reduce((a, b) => a + b, 0)
    return NextResponse.json({ imported, skipped, skippedBy, total: skills.length })
  } catch (error) {
    return internalError(error, 'Failed to import community chat skills')
  }
}

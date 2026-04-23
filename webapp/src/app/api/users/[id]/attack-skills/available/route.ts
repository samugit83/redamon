import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

const BUILT_IN_SKILLS = [
  {
    id: 'cve_exploit',
    name: 'CVE (MSF)',
    description: 'Exploit known CVEs using Metasploit Framework modules against target services',
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    description: 'SQL injection testing with SQLMap, WAF bypass, blind injection, and OOB DNS exfiltration',
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    description: 'Reflected, stored, DOM-based, and blind XSS testing with dalfox, kxss, Playwright, and CSP-bypass guidance',
  },
  {
    id: 'brute_force_credential_guess',
    name: 'Credential Testing',
    description: 'Credential policy validation using Hydra against login services',
  },
  {
    id: 'phishing_social_engineering',
    name: 'Social Engineering Simulation',
    description: 'Payload generation, document crafting, and email delivery for authorized awareness testing',
  },
  {
    id: 'denial_of_service',
    name: 'Availability Testing',
    description: 'Assess service resilience using flooding, resource exhaustion, and crash vectors',
  },
]

// GET /api/users/[id]/attack-skills/available — Built-in + user skills for project toggle UI
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const userSkills = await prisma.userAttackSkill.findMany({
      where: { userId: id },
      select: { id: true, name: true, description: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })

    return NextResponse.json({
      builtIn: BUILT_IN_SKILLS,
      user: userSkills,
    })
  } catch (error) {
    console.error('Failed to fetch available attack skills:', error)
    return NextResponse.json(
      { error: 'Failed to fetch available attack skills' },
      { status: 500 }
    )
  }
}

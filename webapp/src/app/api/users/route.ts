import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/auth'
import { getSession, isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { normalizeEmail, emailTakenByAnother } from '@/lib/authz/accountEmail'

const EMAIL_TAKEN = { error: 'A user with this email already exists', code: 'email_taken' } as const

// GET /api/users - List users (admin: all, standard: self only, internal: all)
export async function GET(request: NextRequest) {
  try {
    let where = {}

    // Internal requests (service-to-service) get all users
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      // Standard users only see themselves
      if (session.role !== 'admin') {
        where = { id: session.userId }
      }
    }

    const users = await prisma.user.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        password: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: { projects: true }
        }
      }
    })

    // Never expose password hash - return hasPassword flag instead
    const safeUsers = users.map(({ password, ...user }) => ({
      ...user,
      hasPassword: password !== '',
    }))

    return NextResponse.json(safeUsers)
  } catch (error) {
    return internalError(error, 'Failed to fetch users')
  }
}

// POST /api/users - Create a new user (admin only or internal)
export async function POST(request: NextRequest) {
  try {
    // S2/E2: creating a user (incl. minting an admin via role) requires an
    // admin SESSION. The internal-key bypass is removed here - no production
    // internal caller creates users, and key possession must not mint admins.
    {
      const session = await getSession()
      if (!session || session.role !== 'admin') {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const body = await request.json()
    const { name, email, password, role } = body

    if (!name || !email || typeof email !== 'string') {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      )
    }

    // An empty or absent password makes a passwordless (managed) account.
    if (password !== undefined && password !== null && password !== '') {
      const check = validateNewPassword(typeof password === 'string' ? password : '')
      if (!check.ok) {
        return NextResponse.json({ error: check.message, code: check.code }, { status: 400 })
      }
    }

    // Stored lowercase; an account made before that may hold the same address
    // in other capitals, which the unique index cannot see.
    const storedEmail = normalizeEmail(email)
    if (await emailTakenByAnother(storedEmail)) {
      return NextResponse.json(EMAIL_TAKEN, { status: 409 })
    }

    const user = await prisma.user.create({
      data: {
        name,
        email: storedEmail,
        ...(password ? { password: await hashPassword(password) } : {}),
        ...((role === 'admin' || role === 'standard') ? { role } : {}),
      }
    })

    return NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      hasPassword: !!password,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    }, { status: 201 })
  } catch (error: unknown) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2002') {
      return NextResponse.json(EMAIL_TAKEN, { status: 409 })
    }

    return internalError(error, 'Failed to create user')
  }
}

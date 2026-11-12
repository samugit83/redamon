import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword } from '@/lib/auth'
import { getSession, isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { validateNewPassword } from '@/lib/authz/passwordPolicy'
import { passwordPolicyInForce } from '@/lib/authz/passwordPolicyInForce'
import { normalizeEmail, emailTakenByAnother } from '@/lib/authz/accountEmail'
import { userAuditEntry, writeUserAudit, type UserAuditFields } from '@/lib/userAudit'
import { writeAuditTx } from '@/lib/audit'
import { rbacFlags } from '@/lib/authz/flags'
import { requireRootPower } from '@/lib/authz/rootPowers'
import { requireSessionPermission, sessionHolds } from '@/lib/authz/adminPermission'
import { checkInitialSets, InitialSetGone, initialSetGoneResponse, writeInitialSets } from '@/lib/authz/initialSets'

const EMAIL_TAKEN = { error: 'A user with this email already exists', code: 'email_taken' } as const

// GET /api/users - List users (users:read: all, anyone else: self only, internal: all)
export async function GET(request: NextRequest) {
  try {
    let where = {}

    // Internal requests (service-to-service) get all users
    if (!isInternalRequest(request)) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      // Without the user directory a person sees only their own account.
      if (!(await sessionHolds(session, 'users:read'))) {
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
        // active | invited | disabled: the Users page shows it whatever the identity switch,
        // so an account disabled while the switch was on can be found and enabled.
        status: true,
        password: true,
        // Written at every sign-in whatever the switch (ID-27); null: none recorded.
        lastLoginAt: true,
        // Enforced only with the identity switch on, so only then shown.
        ...(rbacFlags().identity ? { mustChangePassword: true } : {}),
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

// POST /api/users - Create a new user (users:create); permissions switch on, `sets` names the
// member sets it starts with (step 3.13, ID-28: users:assign_permissions, lib/authz/initialSets.ts)
export async function POST(request: NextRequest) {
  try {
    // S2/E2: creating a user (incl. minting an admin via role) requires a
    // SESSION holding users:create. The internal-key bypass is removed here - no
    // production internal caller creates users, and key possession must not mint admins.
    const session = await getSession({ fresh: true })
    if (!session) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }
    const denied = await requireSessionPermission(session, 'users:create', { fresh: true })
    if (denied) return denied

    // Same-origin JSON whatever the identity switch (ID-26, step 2.12): a page on another site
    // cannot create an account with this admin's cookie.
    if (!sameOrigin(request)) return crossOriginResponse(request)
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const body = parsed.body as {
      name?: string; email?: unknown; password?: string | null; role?: unknown
      stepUpPassword?: unknown; requirePasswordChange?: unknown
    }
    const { name, email, password, role } = body

    // Identity switch on: an admin account is the confirmed Root's to create, with its password.
    const makesAdmin = role === 'admin' && rbacFlags().identity
    if (makesAdmin) {
      const refusal = await requireRootPower(request, session, body.stepUpPassword, 'Only Root can create an admin account.')
      if (refusal) return refusal
    }

    if (!name || !email || typeof email !== 'string') {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      )
    }

    // An empty or absent password makes a passwordless (managed) account. Phase 1's floor
    // answers before the policy in force is read (identity switch on: the instance minimum,
    // the deny list and the new account's own address).
    if (password !== undefined && password !== null && password !== '') {
      const pw = typeof password === 'string' ? password : ''
      let check = validateNewPassword(pw)
      if (check.ok) check = validateNewPassword(pw, await passwordPolicyInForce(), { email })
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

    if (rbacFlags().identity && body.requirePasswordChange !== undefined && typeof body.requirePasswordChange !== 'boolean') {
      return NextResponse.json(
        { error: 'requirePasswordChange must be true or false', code: 'invalid_field', field: 'requirePasswordChange' },
        { status: 400 },
      )
    }
    // Identity switch on (ID-17): a password the admin chooses for someone else is temporary
    // unless the admin says otherwise; the account changes it at its first sign-in.
    const temporary = Boolean(password) && rbacFlags().identity && body.requirePasswordChange !== false

    // Root creating an admin gave its password above; nobody is asked twice.
    const initial = await checkInitialSets(request, session, parsed.body, { stepUpDone: makesAdmin })
    if (initial instanceof NextResponse) return initial

    const data = {
      name,
      email: storedEmail,
      ...(password ? { password: await hashPassword(password) } : {}),
      ...((role === 'admin' || role === 'standard') ? { role } : {}),
      ...(temporary ? { mustChangePassword: true } : {}),
    }
    const created = (user: { id: string; email: string; role: string }): UserAuditFields => ({
      action: 'user.create',
      targetId: user.id,
      after: {
        email: user.email, role: user.role, passwordless: !password, ...(temporary ? { mustChangePassword: true } : {}),
        ...(initial ? { sets: initial.sets } : {}),
      },
    })

    let user
    if (makesAdmin || initial) {
      // A Root action, or one that gives permissions: the account, its sets and its row commit
      // together, or none does (AU-05).
      user = await prisma.$transaction(async (tx) => {
        const row = await tx.user.create({ data })
        if (initial) await writeInitialSets(tx, row.id, initial)
        await writeAuditTx(tx, await userAuditEntry(request, session, created(row)))
        return row
      })
    } else {
      user = await prisma.user.create({ data })
      await writeUserAudit(request, session, created(user))
    }

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
    if (error instanceof InitialSetGone) return initialSetGoneResponse()

    return internalError(error, 'Failed to create user')
  }
}

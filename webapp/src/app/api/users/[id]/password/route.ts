import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { hashPassword, verifyPassword } from '@/lib/auth'
import { getSession } from '@/lib/session'

interface RouteParams {
  params: Promise<{ id: string }>
}

// PUT /api/users/[id]/password - Change user password
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const session = await getSession()

    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { newPassword, currentPassword } = await request.json()

    if (!newPassword || newPassword.length < 4) {
      return NextResponse.json(
        { error: 'Password must be at least 4 characters' },
        { status: 400 }
      )
    }

    const isAdmin = session.role === 'admin'
    const isSelf = session.userId === id

    // Standard users can only change their own password
    if (!isAdmin && !isSelf) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Standard users must provide current password
    if (!isAdmin && isSelf) {
      if (!currentPassword) {
        return NextResponse.json(
          { error: 'Current password is required' },
          { status: 400 }
        )
      }

      const user = await prisma.user.findUnique({
        where: { id },
        select: { password: true },
      })

      if (!user || !user.password) {
        return NextResponse.json({ error: 'User not found' }, { status: 404 })
      }

      const valid = await verifyPassword(currentPassword, user.password)
      if (!valid) {
        return NextResponse.json(
          { error: 'Current password is incorrect' },
          { status: 401 }
        )
      }
    }

    const hashed = await hashPassword(newPassword)

    await prisma.user.update({
      where: { id },
      data: { password: hashed },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to change password:', error)
    return NextResponse.json(
      { error: 'Failed to change password' },
      { status: 500 }
    )
  }
}

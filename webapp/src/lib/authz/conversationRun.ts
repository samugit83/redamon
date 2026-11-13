import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

/**
 * An agent append by session id (the internal-key carve-out of the by-session routes) lands in an
 * existing conversation only when the run's person and project, which the agent sends from its
 * signed ticket, are the conversation's. A session id comes from the browser (the ws-ticket body),
 * and a reader of a shared project sees its sessions as attack-chain ids, so a run on another project
 * naming one must never write into it. An append that names neither is refused too: the agent always
 * sends both.
 */
export function conversationRunRefusal(
  conversation: { userId: string; projectId: string },
  run: { userId?: unknown; projectId?: unknown },
  sessionId: string,
): NextResponse | null {
  if (conversation.userId === run.userId && conversation.projectId === run.projectId) return null
  console.warn(`[rbac] conversation_run_mismatch session=${sessionId}`)
  return NextResponse.json(
    { error: "This session belongs to another person's or another project's conversation.", code: 'conversation_run_mismatch' },
    { status: 403 },
  )
}

/**
 * The session a WebSocket ticket names must be new, or a conversation of the ticket's person on the
 * ticket's project. The ws-ticket route reads the session id from its body, so without this a person
 * who saw another project's session (a reader of a shared project sees its attack-chain ids) could
 * open a socket on it from a project of their own. A failed read throws: the route answers a coded
 * 500, never a ticket.
 */
export async function sessionTicketRefusal(
  ticket: { sessionId: string; userId: string; projectId: string },
): Promise<NextResponse | null> {
  const held = await prisma.conversation.findUnique({
    where: { sessionId: ticket.sessionId },
    select: { userId: true, projectId: true },
  })
  if (!held || (held.userId === ticket.userId && held.projectId === ticket.projectId)) return null
  console.warn(`[rbac] session_not_yours session=${ticket.sessionId} project=${ticket.projectId}`)
  return NextResponse.json(
    { error: "This session belongs to another person's or another project's conversation.", code: 'session_not_yours' },
    { status: 403 },
  )
}

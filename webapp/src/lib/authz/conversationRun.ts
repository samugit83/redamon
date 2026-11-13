import { NextResponse } from 'next/server'

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

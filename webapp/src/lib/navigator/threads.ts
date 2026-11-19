/**
 * AI Navigator conversations (plan §6, §7.2). A thread is its author's alone (D13): every read is
 * `{id, projectId}` plus `ownsRow`, and a thread that does not exist, is another person's or another
 * project's is the same miss. No route creates an empty thread: it is created in the transaction of
 * its first message.
 */
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { ownsRow, rowOwnerFilter } from '@/lib/authz/rowOwner'
import {
  MAX_MESSAGES_PER_THREAD, MAX_TITLE_CHARS, THREAD_LIST_MAX, THREAD_PAGE_SIZE,
} from './constants'
import { isNavigatorId } from './responses'

export interface ThreadRow {
  id: string
  userId: string
  projectId: string
  title: string
  lastMessageAt: Date
}

export class ThreadMissing extends Error {}
export class ThreadFull extends Error {}

/** The first line of the first message, at most MAX_TITLE_CHARS. */
export function titleOf(text: string): string {
  const line = text.split('\n').map((l) => l.trim()).find(Boolean) ?? ''
  return line.length > MAX_TITLE_CHARS ? `${line.slice(0, MAX_TITLE_CHARS - 1)}…` : line
}

export async function listThreads(personId: string, projectId: string) {
  return prisma.navigatorThread.findMany({
    where: { projectId, ...rowOwnerFilter({ userId: personId }) },
    orderBy: { lastMessageAt: 'desc' },
    take: THREAD_LIST_MAX,
    select: { id: true, title: true, lastMessageAt: true },
  })
}

export async function countThreads(personId: string, projectId: string): Promise<number> {
  return prisma.navigatorThread.count({ where: { projectId, ...rowOwnerFilter({ userId: personId }) } })
}

type Db = Pick<Prisma.TransactionClient, 'navigatorThread'>

export async function findOwnedThread(personId: string, projectId: string, threadId: unknown, db: Db = prisma): Promise<ThreadRow | null> {
  if (!isNavigatorId(threadId)) return null
  const row = await db.navigatorThread.findFirst({
    where: { id: threadId, projectId },
    select: { id: true, userId: true, projectId: true, title: true, lastMessageAt: true },
  })
  return row && ownsRow({ userId: personId }, row.userId) ? row : null
}

export interface MessageView {
  id: string
  seq: number
  role: string
  content: string
  status: string
  routes: string[]
  citations: unknown
  trace: unknown
  modelUsed: string | null
  errorCode: string | null
  createdAt: Date
  /** An admin acting as the person sent it; never the admin's id or name (D12, Q3). */
  actedByAdmin: boolean
}

export async function readThreadPage(threadId: string, before?: number): Promise<{ messages: MessageView[]; hasMore: boolean }> {
  const rows = await prisma.navigatorMessage.findMany({
    where: { threadId, ...(before !== undefined ? { seq: { lt: before } } : {}) },
    orderBy: { seq: 'desc' },
    take: THREAD_PAGE_SIZE + 1,
  })
  const hasMore = rows.length > THREAD_PAGE_SIZE
  const page = rows.slice(0, THREAD_PAGE_SIZE).reverse()
  return {
    hasMore,
    messages: page.map((m) => ({
      id: m.id, seq: m.seq, role: m.role, content: m.content, status: m.status, routes: m.routes,
      citations: m.citations, trace: m.trace, modelUsed: m.modelUsed, errorCode: m.errorCode, createdAt: m.createdAt,
      actedByAdmin: m.actorId !== null,
    })),
  }
}

export interface StartedTurn {
  threadId: string
  messageId: string
  seq: number
  created: boolean
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002'
}

async function nextSeq(tx: Prisma.TransactionClient, threadId: string): Promise<number> {
  const agg = await tx.navigatorMessage.aggregate({ where: { threadId }, _max: { seq: true } })
  return (agg._max.seq ?? 0) + 1
}

/**
 * Saves the person's message, creating the thread with it when none is named. The seq is
 * `max(seq)+1` inside the transaction, with the unique index as the backstop: retried once.
 */
export async function startTurn(input: {
  personId: string; projectId: string; threadId: string | null; text: string; actorId: string | null
}): Promise<StartedTurn> {
  const attempt = () => prisma.$transaction(async (tx) => {
    let threadId: string
    let created = false
    if (input.threadId) {
      const thread = await findOwnedThread(input.personId, input.projectId, input.threadId, tx)
      if (!thread) throw new ThreadMissing()
      threadId = thread.id
      if ((await tx.navigatorMessage.count({ where: { threadId } })) >= MAX_MESSAGES_PER_THREAD) throw new ThreadFull()
    } else {
      const thread = await tx.navigatorThread.create({
        data: { projectId: input.projectId, userId: input.personId, title: titleOf(input.text) },
        select: { id: true },
      })
      threadId = thread.id
      created = true
    }
    const seq = await nextSeq(tx, threadId)
    const msg = await tx.navigatorMessage.create({
      data: { threadId, seq, role: 'user', content: input.text, status: 'complete', actorId: input.actorId },
      select: { id: true },
    })
    await tx.navigatorThread.update({ where: { id: threadId }, data: { lastMessageAt: new Date() } })
    return { threadId, messageId: msg.id, seq, created }
  })
  try {
    return await attempt()
  } catch (err) {
    if (isUniqueViolation(err)) return attempt()
    throw err
  }
}

export interface AnswerToSave {
  content: string
  status: 'complete' | 'stopped' | 'failed'
  routes: string[]
  citations: unknown[]
  trace: unknown[]
  modelUsed: string | null
  actorId: string | null
  errorCode: string | null
}

/** Saves the assistant's answer. `thread_gone` when the thread was deleted meanwhile: never recreated. */
export async function saveAnswer(threadId: string, answer: AnswerToSave): Promise<'saved' | 'thread_gone'> {
  const attempt = () => prisma.$transaction(async (tx) => {
    const seq = await nextSeq(tx, threadId)
    await tx.navigatorMessage.create({
      data: {
        threadId, seq, role: 'assistant', content: answer.content, status: answer.status, routes: answer.routes,
        citations: answer.citations.length ? (answer.citations as Prisma.InputJsonValue) : Prisma.JsonNull,
        trace: answer.trace.length ? (answer.trace as Prisma.InputJsonValue) : Prisma.JsonNull,
        modelUsed: answer.modelUsed, actorId: answer.actorId, errorCode: answer.errorCode,
      },
    })
    await tx.navigatorThread.update({ where: { id: threadId }, data: { lastMessageAt: new Date() } })
  })
  try {
    try {
      await attempt()
    } catch (err) {
      if (!isUniqueViolation(err)) throw err
      await attempt()
    }
    return 'saved'
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && (err.code === 'P2003' || err.code === 'P2025')) {
      return 'thread_gone'
    }
    throw err
  }
}

export async function deleteThread(threadId: string): Promise<void> {
  await prisma.navigatorThread.deleteMany({ where: { id: threadId } })
}

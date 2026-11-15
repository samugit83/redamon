/**
 * AI Navigator, mounted once in AppLayout inside the disclaimer gate (plan §9.1-9.2). Shown only to a
 * signed-in person who holds navigator:use, outside the sign-in pages, while Root's switch is on.
 * Holds the launcher's place, the panel's placement beside it (never over a registered drawer), and
 * whether it is open.
 */
'use client'

import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { AuthContext } from '@/providers/authContext'
import { useProject } from '@/providers/ProjectProvider'
import { useCan } from '@/hooks/useCan'
import { NavigatorLauncher } from './NavigatorLauncher'
import { NavigatorPanel } from './NavigatorPanel'
import { MARGIN, SIZE, useDraggablePosition, type Position } from './useDraggablePosition'
import { obstacleRects, overlaps, useObstaclesVersion, type Box } from './obstacles'

const PANEL_W = 380
const PANEL_H = 560
const GAP = 8
const PANEL_ID = 'ai-navigator-panel'

function launcherBox(p: Position, vw: number, vh: number): Box {
  return { left: vw - p.right - SIZE, top: vh - p.bottom - SIZE, width: SIZE, height: SIZE }
}

/** The launcher's drawn place: its saved one, or the nearest free spot while a drawer covers it. */
export function launcherPlace(saved: Position, vw: number, vh: number, rects: readonly DOMRect[]): Position {
  const free = (p: Position) => !rects.some((r) => overlaps(launcherBox(p, vw, vh), r))
  if (free(saved)) return saved
  const candidates: Position[] = []
  for (const r of rects) {
    candidates.push({ right: vw - r.left + GAP, bottom: saved.bottom })
    candidates.push({ right: vw - r.right - SIZE - GAP, bottom: saved.bottom })
  }
  const inside = candidates.filter((p) => p.right >= MARGIN && p.right <= vw - SIZE - MARGIN && free(p))
  inside.sort((a, b) => Math.abs(a.right - saved.right) - Math.abs(b.right - saved.right))
  return inside[0] ?? saved
}

/** The panel beside the launcher, on the side with more room, outside every obstacle when it can be. */
export function panelPlace(launcher: Position, vw: number, vh: number, rects: readonly DOMRect[]): React.CSSProperties | null {
  if (vw < 480) return { left: 0, right: 0, bottom: 0, width: '100%', height: '85vh' }
  const w = Math.min(PANEL_W, vw * 0.9)
  const h = Math.min(PANEL_H, vh * 0.8)
  const lb = launcherBox(launcher, vw, vh)
  const top = Math.min(Math.max(MARGIN, lb.top + lb.height - h), vh - h - MARGIN)
  const leftSide: Box = { left: lb.left - GAP - w, top, width: w, height: h }
  const rightSide: Box = { left: lb.left + lb.width + GAP, top, width: w, height: h }
  const above: Box = { left: Math.min(Math.max(MARGIN, lb.left + lb.width - w), vw - w - MARGIN), top: lb.top - GAP - h, width: w, height: h }
  const order = lb.left + lb.width / 2 > vw / 2 ? [leftSide, rightSide, above] : [rightSide, leftSide, above]
  const fits = (b: Box) => b.left >= MARGIN && b.left + b.width <= vw - MARGIN && b.top >= MARGIN && b.top + b.height <= vh - MARGIN
  const clear = (b: Box) => !rects.some((r) => overlaps(b, r))
  const pick = order.find((b) => fits(b) && clear(b)) ?? (rects.length ? null : order.find(fits) ?? order[0])
  if (!pick) return null
  return { left: pick.left, top: pick.top, width: w, height: h }
}

export function NavigatorRoot() {
  const auth = useContext(AuthContext)
  const pathname = usePathname() ?? '/'
  const router = useRouter()
  const { projectId, currentProject, userId } = useProject()
  const canUse = useCan('navigator:use')
  const agentAllowed = useCan('agent:chat', projectId)
  const [open, setOpen] = useState(false)
  const [badge, setBadge] = useState(false)
  const [viewport, setViewport] = useState({ w: 1280, h: 800 })
  const obstaclesVersion = useObstaclesVersion()

  const signedIn = !!auth?.user && !auth.isLoading
  const onAuthPage = pathname === '/login' || pathname.startsWith('/invite')
  const status = useQuery({
    queryKey: ['navigator', 'status'],
    queryFn: async () => {
      const res = await fetch('/api/navigator/status', { cache: 'no-store' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return (await res.json()) as { enabled: boolean }
    },
    enabled: signedIn && !onAuthPage,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  const visible = signedIn && !onAuthPage && canUse && status.data?.enabled === true

  const [everOpened, setEverOpened] = useState(false)
  const toggle = useCallback(() => {
    setOpen((v) => !v)
    setEverOpened(true)
    setBadge(false)
  }, [])
  const drag = useDraggablePosition(auth?.user?.id ?? userId ?? null, toggle)

  useEffect(() => {
    const read = () => setViewport({ w: window.innerWidth, h: window.innerHeight })
    read()
    window.addEventListener('resize', read)
    return () => window.removeEventListener('resize', read)
  }, [])
  useEffect(() => {
    if (!visible) setOpen(false)
  }, [visible])

  const rects = useMemo(() => (typeof window === 'undefined' ? [] : obstacleRects()),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [obstaclesVersion, viewport, open, drag.position])
  const drawn = launcherPlace(drag.position, viewport.w, viewport.h, rects)
  const panelStyle = panelPlace(drawn, viewport.w, viewport.h, rects)
  const openRef = useRef(open)
  openRef.current = open

  useEffect(() => {
    // No side has room beside an open drawer: the panel closes and the launcher shows its badge.
    if (open && panelStyle === null) {
      setOpen(false)
      setBadge(true)
    }
  }, [open, panelStyle])

  const openAgent = useCallback(() => {
    if (!projectId) return
    setOpen(false)
    router.push(`/graph?project=${encodeURIComponent(projectId)}&agent=open`)
  }, [projectId, router])

  if (!visible) return null
  return (
    <>
      <NavigatorLauncher
        style={{ right: drawn.right, bottom: drawn.bottom }}
        open={open}
        badge={badge && !open}
        panelId={PANEL_ID}
        handlers={{ onPointerDown: drag.onPointerDown, onPointerMove: drag.onPointerMove, onPointerUp: drag.onPointerUp }}
        onKeyMove={drag.nudge}
        onKeyReset={drag.reset}
        onToggle={toggle}
      />
      {/* Kept mounted while closed, so an answer being written finishes and the badge can say so. */}
      {(open || everOpened) && (
        <NavigatorPanel
          id={PANEL_ID}
          open={open && !!panelStyle}
          projectId={projectId}
          projectName={currentProject?.name ?? null}
          userId={auth?.user?.id ?? userId ?? null}
          style={open && panelStyle ? panelStyle : { display: 'none' }}
          pagePath={pathname}
          agentAllowed={agentAllowed}
          onClose={() => {
            setOpen(false)
            document.querySelector<HTMLElement>('[data-testid="navigator-launcher"]')?.focus()
          }}
          onOpenAgent={openAgent}
          onAnswerDone={() => { if (!openRef.current) setBadge(true) }}
          onResetPosition={drag.reset}
        />
      )}
    </>
  )
}

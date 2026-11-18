/**
 * AI Navigator, mounted once in AppLayout inside the disclaimer gate (plan §9.1-9.2). Shown only to a
 * signed-in person who holds navigator:use, outside the sign-in pages, while Root's switch is on.
 * Holds the launcher's place, the panel's size and placement beside it (never over a registered
 * drawer), and whether it is open.
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
import { DEFAULT_PANEL_SIZE, usePanelSize, type PanelSize, type ResizeHandle } from './usePanelSize'
import { obstacleRects, overlaps, useObstaclesVersion, type Box } from './obstacles'

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

export interface PanelPlacement {
  style: React.CSSProperties
  /** Where the panel sits against the launcher; a resize that would move it elsewhere is refused. */
  side: 'left' | 'right' | 'above' | 'sheet'
  box: Box | null
  /** The edges away from the launcher, and their corner: the only ones a drag can move in place. */
  handles: ResizeHandle[]
}

function handlesFor(horizontal: 'e' | 'w', vertical: 'n' | 's'): ResizeHandle[] {
  return [horizontal, vertical, `${vertical}${horizontal}` as ResizeHandle]
}

/**
 * The panel at `size` beside the launcher, on the side with more room, outside every obstacle; null
 * when no side has room. A side shrinks the panel to its room, but a panel larger than the default
 * still needs room for the default (380 x 560, at most 90% x 80% of the window) and a smaller one
 * needs room for itself.
 */
export function placePanel(launcher: Position, vw: number, vh: number, rects: readonly DOMRect[],
  size: PanelSize): PanelPlacement | null {
  if (vw < 480) {
    return { style: { left: 0, right: 0, bottom: 0, width: '100%', height: '85vh' }, side: 'sheet', box: null, handles: [] }
  }
  const floorW = Math.min(size.width, DEFAULT_PANEL_SIZE.width, vw * 0.9)
  const floorH = Math.min(size.height, DEFAULT_PANEL_SIZE.height, vh * 0.8)
  const width = (room: number) => Math.max(floorW, Math.min(size.width, room))
  const height = (room: number) => Math.max(floorH, Math.min(size.height, room))
  const lb = launcherBox(launcher, vw, vh)
  const lbRight = lb.left + lb.width
  const lbBottom = lb.top + lb.height

  // Beside the launcher the panel's bottom lines up with it, unless that pushes the top past the
  // margin: then the top is pinned and the bottom edge is the one that moves.
  const sideH = height(vh - 2 * MARGIN)
  const top = Math.min(Math.max(MARGIN, lbBottom - sideH), vh - sideH - MARGIN)
  const vertical = lbBottom - sideH < MARGIN ? 's' : 'n'
  // A side's room ends at the margin or a gap before the nearest drawer in its way, so a wide panel
  // narrows beside the AI Agent drawer instead of falling back to the default size.
  const inBand = rects.filter((r) => r.top < top + sideH && r.top + r.height > top)
  const leftEnd = Math.max(MARGIN, ...inBand.filter((r) => r.left + r.width <= lb.left - GAP).map((r) => r.left + r.width + GAP))
  const rightEnd = Math.min(vw - MARGIN, ...inBand.filter((r) => r.left >= lbRight + GAP).map((r) => r.left - GAP))
  const leftW = width(lb.left - GAP - leftEnd)
  const rightW = width(rightEnd - lbRight - GAP)
  const aboveW = width(vw - 2 * MARGIN)
  const aboveH = height(lb.top - GAP - MARGIN)
  const aboveLeft = lbRight - aboveW

  type Candidate = Omit<PanelPlacement, 'style'> & { box: Box }
  const leftSide: Candidate = { side: 'left', box: { left: lb.left - GAP - leftW, top, width: leftW, height: sideH }, handles: handlesFor('w', vertical) }
  const rightSide: Candidate = { side: 'right', box: { left: lbRight + GAP, top, width: rightW, height: sideH }, handles: handlesFor('e', vertical) }
  const above: Candidate = {
    side: 'above',
    box: { left: Math.min(Math.max(MARGIN, aboveLeft), vw - aboveW - MARGIN), top: lb.top - GAP - aboveH, width: aboveW, height: aboveH },
    handles: handlesFor(aboveLeft < MARGIN ? 'e' : 'w', 'n'),
  }
  const order = lb.left + lb.width / 2 > vw / 2 ? [leftSide, rightSide, above] : [rightSide, leftSide, above]
  const fits = (b: Box) => b.left >= MARGIN && b.left + b.width <= vw - MARGIN && b.top >= MARGIN && b.top + b.height <= vh - MARGIN
  const clear = (b: Box) => !rects.some((r) => overlaps(b, r))
  const pick = order.find((c) => fits(c.box) && clear(c.box)) ?? (rects.length ? null : order.find((c) => fits(c.box)) ?? order[0])
  if (!pick) return null
  const { left, top: t, width: w, height: h } = pick.box
  return { ...pick, style: { left, top: t, width: w, height: h } }
}

/** The panel at its saved size, or at the default when a drawer leaves no room for the saved one. */
export function panelPlace(launcher: Position, vw: number, vh: number, rects: readonly DOMRect[],
  size: PanelSize = DEFAULT_PANEL_SIZE): PanelPlacement | null {
  return placePanel(launcher, vw, vh, rects, size)
    ?? placePanel(launcher, vw, vh, rects, {
      width: Math.min(size.width, DEFAULT_PANEL_SIZE.width),
      height: Math.min(size.height, DEFAULT_PANEL_SIZE.height),
    })
}

const near = (a: number, b: number) => Math.abs(a - b) < 0.5

/**
 * Whether `size` can be drawn exactly while a drag of `handle` moves only that handle's edges: same
 * side as at the start, nothing shrunk to the room, the opposite edges where they were.
 */
export function resizeFits(start: PanelPlacement, handle: ResizeHandle, launcher: Position, vw: number, vh: number,
  rects: readonly DOMRect[], size: PanelSize): boolean {
  const from = start.box
  const p = placePanel(launcher, vw, vh, rects, size)
  if (!from || !p?.box || p.side !== start.side) return false
  const b = p.box
  if (!near(b.width, size.width) || !near(b.height, size.height)) return false
  const keepsX = handle.includes('w') ? near(b.left + b.width, from.left + from.width) : near(b.left, from.left)
  const keepsY = handle.includes('n') ? near(b.top + b.height, from.top + from.height) : near(b.top, from.top)
  return keepsX && keepsY
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
  const panelSize = usePanelSize(auth?.user?.id ?? userId ?? null)

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
  const placement = panelPlace(drawn, viewport.w, viewport.h, rects, panelSize.size)
  const openRef = useRef(open)
  openRef.current = open

  useEffect(() => {
    // No side has room beside an open drawer: the panel closes and the launcher shows its badge.
    if (open && placement === null) {
      setOpen(false)
      setBadge(true)
    }
  }, [open, placement])

  const onResizeStart = (e: React.PointerEvent<HTMLElement>, handle: ResizeHandle) => {
    const start = placement
    if (!start?.box) return
    const { w: vw, h: vh } = viewport
    panelSize.startResize(e, handle, { width: start.box.width, height: start.box.height },
      (s) => resizeFits(start, handle, drawn, vw, vh, rects, s),
      (s) => {
        const box = placePanel(drawn, vw, vh, rects, s)?.box
        const el = document.getElementById(PANEL_ID)
        if (!box || !el) return
        el.style.left = `${box.left}px`
        el.style.top = `${box.top}px`
        el.style.width = `${box.width}px`
        el.style.height = `${box.height}px`
      })
  }

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
          open={open && !!placement}
          projectId={projectId}
          projectName={currentProject?.name ?? null}
          userId={auth?.user?.id ?? userId ?? null}
          style={open && placement ? placement.style : { display: 'none' }}
          resizeHandles={open && placement ? placement.handles : []}
          onResizeStart={onResizeStart}
          onResetSize={panelSize.reset}
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

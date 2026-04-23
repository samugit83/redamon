'use client'

import { useState, useCallback, useRef, useEffect } from 'react'
import { Move, RotateCcw, ZoomIn, ZoomOut, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Crosshair } from 'lucide-react'
import styles from './GraphNavControls.module.css'

interface GraphNavControlsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  graphRef: React.RefObject<any>
  is3D: boolean
}

const PAN_STEP_2D = 8
const ZOOM_STEP_2D = 0.08
const ZOOM_STEP_3D = 50
const ROTATE_STEP = 0.03
const PAN_STEP_3D = 15
const REPEAT_INTERVAL = 50
const ICON_SIZE = 12

export function GraphNavControls({ graphRef, is3D }: GraphNavControlsProps) {
  const [mode, setMode] = useState<'translate' | 'rotate'>('translate')
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopRepeat = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
  }, [])

  useEffect(() => stopRepeat, [stopRepeat])

  const startRepeat = useCallback((action: () => void) => {
    action()
    intervalRef.current = setInterval(action, REPEAT_INTERVAL)
  }, [])

  const pan2D = useCallback((dx: number, dy: number) => {
    const fg = graphRef.current
    if (!fg) return
    const center = fg.centerAt()
    if (center) fg.centerAt(center.x + dx, center.y + dy, 150)
  }, [graphRef])

  const translate3D = useCallback((dx: number, dy: number) => {
    const fg = graphRef.current
    if (!fg) return
    const camera = fg.camera()
    const controls = fg.controls()
    if (!camera) return
    const offsetX = dx * PAN_STEP_3D
    const offsetY = dy * PAN_STEP_3D
    camera.position.x += offsetX
    camera.position.y += offsetY
    if (controls?.target) {
      controls.target.x += offsetX
      controls.target.y += offsetY
    }
  }, [graphRef])

  const rotate3D = useCallback((dx: number, dy: number) => {
    const fg = graphRef.current
    if (!fg) return
    const controls = fg.controls()
    const camera = fg.camera()
    if (!camera) return
    const offset = camera.position.clone()
    const target = controls?.target || camera.position.clone()
    offset.sub(target)
    const sinH = Math.sin(dx * ROTATE_STEP)
    const cosH = Math.cos(dx * ROTATE_STEP)
    const x = offset.x * cosH - offset.z * sinH
    const z = offset.x * sinH + offset.z * cosH
    offset.x = x
    offset.z = z
    const horizontalDist = Math.sqrt(offset.x * offset.x + offset.z * offset.z)
    const currentAngle = Math.atan2(offset.y, horizontalDist)
    const newAngle = Math.max(-Math.PI / 2.2, Math.min(Math.PI / 2.2, currentAngle + dy * ROTATE_STEP))
    const dist = offset.length()
    offset.y = Math.sin(newAngle) * dist
    const newHDist = Math.cos(newAngle) * dist
    const scale = newHDist / Math.max(horizontalDist, 0.001)
    offset.x *= scale
    offset.z *= scale
    camera.position.copy(target).add(offset)
    camera.lookAt(target)
  }, [graphRef])

  const dpad = useCallback((dx: number, dy: number) => {
    if (!is3D) {
      pan2D(dx * PAN_STEP_2D, -dy * PAN_STEP_2D)
    } else if (mode === 'translate') {
      translate3D(dx, dy)
    } else {
      rotate3D(dx, dy)
    }
  }, [is3D, mode, pan2D, translate3D, rotate3D])

  const zoom = useCallback((direction: number) => {
    const fg = graphRef.current
    if (!fg) return
    if (is3D) {
      const camera = fg.camera()
      if (camera) {
        const dir = camera.getWorldDirection(camera.position.clone().set(0, 0, 0))
        camera.position.addScaledVector(dir, -direction * ZOOM_STEP_3D)
      }
    } else {
      const currentZoom = fg.zoom()
      const newZoom = typeof currentZoom === 'number'
        ? currentZoom * (1 + direction * ZOOM_STEP_2D)
        : 1
      fg.zoom(Math.max(0.01, newZoom), 200)
    }
  }, [graphRef, is3D])

  const resetView = useCallback(() => {
    const fg = graphRef.current
    if (!fg) return
    if (is3D) {
      fg.zoomToFit(400, 0)
      setTimeout(() => {
        const camera = fg.camera()
        const controls = fg.controls()
        if (camera && controls?.target) {
          camera.position.lerp(controls.target, 0.5)
        }
      }, 500)
    } else {
      fg.zoomToFit(400)
    }
  }, [graphRef, is3D])

  const onDown = useCallback((action: () => void) => {
    return {
      onMouseDown: () => startRepeat(action),
      onMouseUp: stopRepeat,
      onMouseLeave: stopRepeat,
      onTouchStart: () => startRepeat(action),
      onTouchEnd: stopRepeat,
    }
  }, [startRepeat, stopRepeat])

  return (
    <div className={styles.controls}>
      {/* Row 1: mode toggle (3D) or zoom in (2D), up arrow, zoom out or empty */}
      {is3D ? (
        <div className={styles.row}>
          <button
            type="button"
            className={`${styles.btn} ${mode === 'translate' ? styles.btnActive : ''}`}
            onClick={() => setMode('translate')}
            title="Move mode"
          >
            <Move size={ICON_SIZE} />
          </button>
          <button type="button" className={styles.btn} {...onDown(() => dpad(0, 1))} title={mode === 'rotate' ? 'Tilt up' : 'Pan up'}>
            <ChevronUp size={ICON_SIZE} />
          </button>
          <button
            type="button"
            className={`${styles.btn} ${mode === 'rotate' ? styles.btnActive : ''}`}
            onClick={() => setMode('rotate')}
            title="Orbit mode"
          >
            <RotateCcw size={ICON_SIZE} />
          </button>
        </div>
      ) : (
        <div className={styles.row}>
          <button type="button" className={styles.btn} {...onDown(() => zoom(-1))} title="Zoom in">
            <ZoomIn size={ICON_SIZE} />
          </button>
          <button type="button" className={styles.btn} {...onDown(() => dpad(0, 1))} title="Pan up">
            <ChevronUp size={ICON_SIZE} />
          </button>
          <button type="button" className={styles.btn} {...onDown(() => zoom(1))} title="Zoom out">
            <ZoomOut size={ICON_SIZE} />
          </button>
        </div>
      )}

      {/* Row 2: left, center (reset), right */}
      <div className={styles.row}>
        <button type="button" className={styles.btn} {...onDown(() => dpad(-1, 0))} title={is3D && mode === 'rotate' ? 'Orbit left' : 'Pan left'}>
          <ChevronLeft size={ICON_SIZE} />
        </button>
        <button type="button" className={styles.centerBtn} onClick={resetView} title="Fit all nodes">
          <Crosshair size={ICON_SIZE} />
        </button>
        <button type="button" className={styles.btn} {...onDown(() => dpad(1, 0))} title={is3D && mode === 'rotate' ? 'Orbit right' : 'Pan right'}>
          <ChevronRight size={ICON_SIZE} />
        </button>
      </div>

      {/* Row 3: zoom in, down, zoom out (3D) or just down (2D) */}
      {is3D ? (
        <div className={styles.row}>
          <button type="button" className={styles.btn} {...onDown(() => zoom(-1))} title="Zoom in">
            <ZoomIn size={ICON_SIZE} />
          </button>
          <button type="button" className={styles.btn} {...onDown(() => dpad(0, -1))} title={mode === 'rotate' ? 'Tilt down' : 'Pan down'}>
            <ChevronDown size={ICON_SIZE} />
          </button>
          <button type="button" className={styles.btn} {...onDown(() => zoom(1))} title="Zoom out">
            <ZoomOut size={ICON_SIZE} />
          </button>
        </div>
      ) : (
        <div className={styles.row}>
          <div className={styles.spacer} />
          <button type="button" className={styles.btn} {...onDown(() => dpad(0, -1))} title="Pan down">
            <ChevronDown size={ICON_SIZE} />
          </button>
          <div className={styles.spacer} />
        </div>
      )}
    </div>
  )
}

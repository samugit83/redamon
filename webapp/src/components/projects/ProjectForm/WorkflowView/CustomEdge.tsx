'use client'

import { memo } from 'react'
import { getSmoothStepPath, type EdgeProps } from '@xyflow/react'

function CustomEdgeComponent({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  data,
}: EdgeProps) {
  const [edgePath] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 16,
  })

  const stroke = (style as Record<string, unknown>).stroke as string ?? '#888'
  const strokeWidth = (style as Record<string, unknown>).strokeWidth as number ?? 1.5
  const opacity = (style as Record<string, unknown>).opacity as number ?? 0.5
  const strokeDasharray = (style as Record<string, unknown>).strokeDasharray as string ?? '6 3'

  const shouldAnimate = (data as Record<string, unknown>)?.shouldAnimate as boolean ?? false
  const isEnrich = (data as Record<string, unknown>)?.isEnrich as boolean ?? false

  let animClass: string | undefined
  if (shouldAnimate) {
    animClass = isEnrich ? 'workflow-edge-animated-dot' : 'workflow-edge-animated'
  }

  return (
    <g>
      <path
        d={edgePath}
        fill="none"
        stroke={stroke}
        strokeWidth={strokeWidth}
        opacity={opacity}
        strokeDasharray={strokeDasharray}
        className={animClass}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={20}
      />
    </g>
  )
}

export const CustomEdge = memo(CustomEdgeComponent)

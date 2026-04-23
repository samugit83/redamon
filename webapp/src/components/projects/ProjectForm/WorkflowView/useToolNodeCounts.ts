import { useMemo } from 'react'
import { useGraphData } from '@/app/graph/hooks'

interface NodeSlice {
  id: string
  name: string
  type: string
}

interface TypeCounts {
  count: number
  nodes: NodeSlice[]
}

export function useDataNodeCounts(projectId: string | undefined) {
  const { data, isLoading } = useGraphData(projectId ?? null)

  const dataNodeCounts = useMemo(() => {
    const map = new Map<string, TypeCounts>()
    if (!data?.nodes?.length) return map

    for (const node of data.nodes) {
      let entry = map.get(node.type)
      if (!entry) {
        entry = { count: 0, nodes: [] }
        map.set(node.type, entry)
      }
      entry.count++
      entry.nodes.push({ id: node.id, name: node.name, type: node.type })
    }

    return map
  }, [data])

  return { dataNodeCounts, isLoading }
}

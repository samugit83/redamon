import type { TableRow } from '../hooks/useTableData'

export async function exportToExcel(rows: TableRow[], filename?: string) {
  const XLSX = await import('xlsx')

  const wsData: Record<string, unknown>[] = rows.map(row => {
    const base: Record<string, unknown> = {
      Type: row.node.type,
      Name: row.node.name,
      ID: row.node.id,
      'Connections In': row.connectionsIn.length,
      'Connections Out': row.connectionsOut.length,
      'Connections In Detail': row.connectionsIn
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Connections Out Detail': row.connectionsOut
        .map(c => `${c.nodeType}: ${c.nodeName} (${c.relationType})`)
        .join('; '),
      'Level 2': row.getLevel2().length,
      'Level 2 Detail': row.getLevel2()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
      'Level 3': row.getLevel3().length,
      'Level 3 Detail': row.getLevel3()
        .map(c => `${c.nodeType}: ${c.nodeName}`)
        .join('; '),
    }

    for (const [key, value] of Object.entries(row.node.properties)) {
      if (key === 'project_id' || key === 'user_id') continue
      const cellValue = Array.isArray(value)
        ? value.join(', ')
        : typeof value === 'object' && value !== null
          ? JSON.stringify(value)
          : value
      base[key] = cellValue
    }

    return base
  })

  const ws = XLSX.utils.json_to_sheet(wsData)
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'Nodes')

  const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
  XLSX.writeFile(wb, `${filename || 'redamon-data'}-${ts}.xlsx`)
}

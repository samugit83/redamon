export async function exportRedZoneXlsx<T extends object>(
  rows: T[],
  sheetName: string,
  columns: { key: keyof T | string; header: string }[],
  fileSlug: string,
) {
  const XLSX = await import('xlsx')
  const wb = XLSX.utils.book_new()
  const data = rows.map(row => {
    const out: Record<string, unknown> = {}
    for (const col of columns) {
      const raw = (row as Record<string, unknown>)[col.key as string]
      if (Array.isArray(raw)) {
        out[col.header] = raw
          .map(v => (typeof v === 'object' && v !== null ? JSON.stringify(v) : v))
          .join(', ')
      } else if (typeof raw === 'object' && raw !== null) {
        out[col.header] = JSON.stringify(raw)
      } else {
        out[col.header] = raw ?? ''
      }
    }
    return out
  })
  const ws = XLSX.utils.json_to_sheet(data)
  XLSX.utils.book_append_sheet(wb, ws, sheetName.slice(0, 31))
  const ts = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
  XLSX.writeFile(wb, `${fileSlug}-${ts}.xlsx`)
}

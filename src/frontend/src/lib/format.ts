export const formatNumber = (n: number | null | undefined, digits = 0): string =>
  n === null || n === undefined || Number.isNaN(n)
    ? '—'
    : n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits })

export const formatPercent = (n: number | null | undefined, digits = 1): string =>
  n === null || n === undefined ? '—' : `${(n * 100).toFixed(digits)}%`

export const formatProbability = (n: number): string => n.toFixed(2)

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = n
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

export interface HeaderCheck {
  missing: string[]
  extra: string[]
  duplicates: string[]
}

/** Compare a CSV header line with the model's expected columns (client-side pre-check only). */
export function checkCsvHeader(headerLine: string, expected: string[]): HeaderCheck {
  const columns = headerLine
    .replace(/^﻿/, '')
    .split(',')
    .map((c) => c.trim().replace(/^"(.*)"$/, '$1'))
    .filter((c) => c.length > 0)
  const seen = new Set<string>()
  const duplicates = new Set<string>()
  for (const c of columns) {
    if (seen.has(c)) duplicates.add(c)
    seen.add(c)
  }
  return {
    missing: expected.filter((c) => !seen.has(c)),
    extra: [...seen].filter((c) => !expected.includes(c)),
    duplicates: [...duplicates],
  }
}

export async function readFirstLine(file: File): Promise<string> {
  const text = await file.slice(0, 64 * 1024).text()
  return text.split(/\r?\n/, 1)[0] ?? ''
}

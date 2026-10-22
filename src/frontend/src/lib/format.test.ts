import { describe, expect, it } from 'vitest'
import { checkCsvHeader, formatBytes, formatPercent } from './format'

describe('checkCsvHeader', () => {
  const expected = ['flgs', 'proto', 'pkts']

  it('accepts an exact header in any order, with BOM and quotes', () => {
    expect(checkCsvHeader('﻿"pkts",flgs, proto', expected)).toEqual({ missing: [], extra: [], duplicates: [] })
  })

  it('reports missing, extra and duplicated columns', () => {
    expect(checkCsvHeader('flgs,pkts,pkts,saddr', expected)).toEqual({
      missing: ['proto'],
      extra: ['saddr'],
      duplicates: ['pkts'],
    })
  })
})

describe('formatting', () => {
  it('formats percentages and bytes', () => {
    expect(formatPercent(0.9355, 2)).toBe('93.55%')
    expect(formatPercent(null)).toBe('—')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1536)).toBe('1.5 KB')
  })
})

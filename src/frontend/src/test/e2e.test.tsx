/**
 * Opt-in end-to-end render test against a RUNNING backend (via the Vite dev proxy).
 * Skipped unless E2E_BASE_URL is set, e.g.:
 *   E2E_BASE_URL=http://127.0.0.1:5173 npx vitest run src/test/e2e.test.tsx
 * Expects the held-out demo CSV (scripts/export_demo_csv.py) to have been analysed once.
 */
import { render, screen, within } from '@testing-library/react'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { ModelPerformance } from '../pages/ModelPerformance'
import { Network } from '../pages/Network'
import { Overview } from '../pages/Overview'
import { SystemInfo } from '../pages/SystemInfo'
import { Alerts } from '../pages/Alerts'

const BASE = process.env.E2E_BASE_URL

describe.skipIf(!BASE)('dashboard against the live API', { timeout: 60_000 }, () => {
  const realFetch = globalThis.fetch
  beforeAll(() => {
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) =>
      realFetch(new URL(String(input), BASE), init),
    )
  })
  afterAll(() => vi.unstubAllGlobals())

  it('System page shows the real model and disabled live inference', async () => {
    render(<SystemInfo />)
    expect(await screen.findByText('rf-2557ad7b7b25', {}, { timeout: 15000 })).toBeInTheDocument()
    expect(await screen.findByText(/2557ad7b7b25f76f877f9048889d0de8b062672ea7743e380bcf3e5190173cde/)).toBeInTheDocument()
    expect(screen.getAllByText('disabled').length).toBeGreaterThan(0)
  })

  it('Overview shows processed totals from the database', async () => {
    render(<Overview onOpenAlert={() => {}} />)
    const processed = await screen.findByText('Processed flows', {}, { timeout: 15000 })
    const value = processed.nextElementSibling as HTMLElement
    expect(Number(value.textContent!.replace(/[^\d]/g, ''))).toBeGreaterThanOrEqual(2000)
    expect(within(processed.parentElement as HTMLElement).getByText(/submissions/)).toBeInTheDocument()
    expect(await screen.findByText('Recent alerts')).toBeInTheDocument()
  })

  it('Model performance shows the verified confusion matrix', async () => {
    render(<ModelPerformance />)
    expect(await screen.findByText('93.55%', {}, { timeout: 15000 })).toBeInTheDocument()
    for (const n of ['973', '27', '102', '898']) expect(screen.getAllByText(n).length).toBeGreaterThan(0)
    expect(screen.getAllByText('reported, not re-run')).toHaveLength(3)
    expect(screen.getAllByText('verified')).toHaveLength(1)
  })

  it('Alerts page lists real alerts', async () => {
    render(<Alerts onOpenAlert={() => {}} />)
    expect((await screen.findAllByRole('button', { name: 'Details' }, { timeout: 15000 })).length).toBeGreaterThan(0)
  })

  it('Network page lists real interfaces and the stopped capture state', async () => {
    render(<Network />)
    expect(await screen.findByText('Wi-Fi', {}, { timeout: 30000 })).toBeInTheDocument()
    expect(await screen.findByText('stopped', {}, { timeout: 15000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /start/i })).toBeDisabled()
  })
})

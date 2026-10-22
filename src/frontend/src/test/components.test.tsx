import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Explanation } from '../api/types'
import { ExplanationView } from '../components/ExplanationView'
import { Network } from '../pages/Network'
import { Overview } from '../pages/Overview'
import { mockFetch } from './mockFetch'

afterEach(() => vi.unstubAllGlobals())

const explanation: Explanation = {
  scope: 'local',
  method: 'tree_path',
  method_description: 'Tree-path contributions',
  base_value: 0.5,
  attack_probability: 0.93,
  contributions: [
    { feature: 'pkts', value: 95, contribution: 0.3 },
    { feature: 'proto', value: 'TCP', contribution: 0.2 },
    { feature: 'dur', value: 0.2, contribution: -0.07 },
  ],
  other_contribution: 0,
  disclaimer: "It explains the model's output, not whether the flow is actually malicious.",
}

describe('ExplanationView', () => {
  it('lists signed contributions, values and the disclaimer', () => {
    render(<ExplanationView explanation={explanation} status="included" />)
    expect(screen.getByText('pkts')).toBeInTheDocument()
    expect(screen.getByText('+0.300')).toBeInTheDocument()
    expect(screen.getByText('−0.070')).toBeInTheDocument()
    expect(screen.getByText(/not whether the flow is actually malicious/)).toBeInTheDocument()
  })

  it('explains deferred explanations', () => {
    render(<ExplanationView explanation={null} status="deferred" />)
    expect(screen.getByText(/not computed yet/)).toBeInTheDocument()
  })
})

const emptySummary = {
  scope: 'Operational statistics over inputs processed by this application; not a measure of model accuracy.',
  total_processed: 0,
  benign: 0,
  attack: 0,
  attack_share: null,
  alerts: { total: 0, open: 0, by_severity: { medium: 0, high: 0 } },
  analyses: 0,
  by_source: {},
  last_processed_at: null,
  recent_alerts: [],
}

describe('Overview', () => {
  it('shows the scope note and empty states when nothing was processed', async () => {
    mockFetch({
      '/api/dashboard/summary': emptySummary,
      '/api/dashboard/trends': { bucket: 'hour', since: '', until: '', note: 'by processing time', points: [] },
    })
    render(<Overview onOpenAlert={() => {}} />)
    expect(await screen.findByText(/not a measure of model accuracy/)).toBeInTheDocument()
    expect(await screen.findByText('No alerts yet')).toBeInTheDocument()
    expect(await screen.findByText('No flows processed in this period')).toBeInTheDocument()
  })

  it('shows an error with retry when the API fails', async () => {
    mockFetch({
      '/api/dashboard/summary': () => ({
        status: 503,
        body: { error: { code: 'database_error', message: 'The database is unavailable.', details: null } },
      }),
    })
    render(<Overview onOpenAlert={() => {}} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('The database is unavailable.')
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})

describe('Network live capture', () => {
  it('requires authorisation before starting and states flows are not scored', async () => {
    const { calls } = mockFetch({
      '/api/network/interfaces': {
        interfaces: [
          { name: 'Wi-Fi', description: 'Test adapter', is_up: true, speed_mbps: 100, mtu: 1500, is_loopback: false,
            is_wireless: true, has_ipv4: true, visible_to_scapy: true, counters: null },
        ],
        scapy: { available: true, version: '2.8.0', error_code: null, message: null },
        driver: null,
        platform: { system: 'Windows', release: '11', is_wsl: false, is_admin: false },
        notes: [],
        capture_note: 'note',
      },
      '/api/network/live/status': {
        state: 'stopped', session: null,
        live_inference: { enabled: false, gate_allowed: false, reasons: [], note: '' },
      },
      '/api/network/feature-mapping': { features: [], training_invariants: null, flow_definition: {} },
      '/api/network/runs': { items: [], total: 0, offset: 0, limit: 20 },
      '/api/network/live/start': { state: 'running', session: null,
        live_inference: { enabled: false, gate_allowed: false, reasons: [], note: '' } },
    })
    render(<Network />)
    const start = await screen.findByRole('button', { name: /start/i })
    await waitFor(() => expect(screen.getByRole('option', { name: 'Wi-Fi' })).toBeInTheDocument())
    expect(start).toBeDisabled()
    expect(screen.getAllByText(/not scored by the model/).length).toBeGreaterThan(0)

    await userEvent.click(screen.getByLabelText(/authorised to monitor/i))
    expect(start).toBeEnabled()
    await userEvent.click(start)
    await waitFor(() => expect(calls.some((c) => c.url === '/api/network/live/start')).toBe(true))
    const startCall = calls.find((c) => c.url === '/api/network/live/start')!
    expect(JSON.parse(String(startCall.init?.body))).toMatchObject({ interface: 'Wi-Fi', authorized: true })
  })
})

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Network } from '../pages/Network'
import { mockFetch } from './mockFetch'

afterEach(() => vi.unstubAllGlobals())

const iface = (name: string, is_up: boolean, is_loopback = false, bytes_recv = 0) => ({
  name, description: null, is_up, speed_mbps: null, mtu: 1500, is_loopback,
  is_wireless: name === 'Wi-Fi', has_ipv4: is_up, visible_to_scapy: true,
  counters: { bytes_sent: 0, bytes_recv, packets_sent: 0, packets_recv: 0, errors_in: 0, errors_out: 0, drops_in: 0, drops_out: 0 },
})

const gate = { enabled: false, gate_allowed: false, reasons: [], note: '' }
const finishedSession = {
  state: 'stopped',
  session: {
    id: 's1', interface: 'Wi-Fi', bpf_filter: null, started_at: '2026-10-22T10:00:00Z',
    stopped_at: '2026-10-22T10:00:30Z', elapsed_seconds: 30, max_duration_seconds: 30,
    stop_reason: 'max_duration', error: null,
    counters: { packets_seen: 47730, dropped_queue_full: 0, flows_emitted: 82, non_ip_packets: 0, malformed_packets: 0 },
    queue: { depth: 0, capacity: 10000 }, active_flows: 0,
  },
  recent_flows: [], compatibility: null, predictions: null, live_inference: gate,
}

function routes(status: unknown, extra: Record<string, unknown> = {}) {
  return {
    '/api/network/interfaces': {
      // As on Windows: a down adapter and a quiet virtual adapter come first. Default must be Wi-Fi.
      interfaces: [iface('Ethernet', false), iface('vEthernet (WSL)', true, false, 2_000_000),
        iface('Loopback Pseudo-Interface 1', true, true), iface('Wi-Fi', true, false, 300_000_000)],
      scapy: { available: true, version: '2.8.0', error_code: null, message: null },
      driver: null,
      platform: { system: 'Windows', release: '11', is_wsl: false, is_admin: false },
      notes: [],
      capture_note: '',
    },
    '/api/network/live/status': status,
    '/api/network/feature-mapping': { features: [], training_invariants: null, flow_definition: {} },
    '/api/network/runs': { items: [], total: 0, offset: 0, limit: 20 },
    ...extra,
  }
}

describe('Network live-capture form', () => {
  it('defaults to an interface that is up and marks down interfaces', async () => {
    mockFetch(routes({ state: 'stopped', session: null, live_inference: gate }))
    render(<Network />)
    const select = await screen.findByLabelText('Interface')
    await waitFor(() => expect(select).toHaveValue('Wi-Fi'))
    const options = screen.getAllByRole('option').map((o) => o.textContent)
    expect(options).toEqual(['Wi-Fi', 'vEthernet (WSL)', 'Loopback Pseudo-Interface 1', 'Ethernet (down)'])
    expect(screen.queryByRole('button', { name: /reset/i })).not.toBeInTheDocument()
  })

  it('resets a finished session', async () => {
    let status: unknown = finishedSession
    const { calls } = mockFetch(
      routes(() => ({ body: status }), {
        '/api/network/live/reset': () => {
          status = { state: 'stopped', session: null, live_inference: gate }
          return { body: status }
        },
      }),
    )
    render(<Network />)
    expect(await screen.findByText('47,730')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /reset/i }))
    await waitFor(() => expect(calls.some((c) => c.url === '/api/network/live/reset')).toBe(true))
    await waitFor(() => expect(screen.queryByText('47,730')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /reset/i })).not.toBeInTheDocument()
  })
})

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LiveDetection } from '../pages/LiveDetection'
import { mockFetch } from './mockFetch'

afterEach(() => vi.unstubAllGlobals())

const gate = { enabled: false, gate_allowed: false, reasons: [], note: '' }
const detectionInfo = { model_available: true, enabled: false, model_version: 'rf-live-816b2de44ac8', threshold: 0.5, time_unit: 'microseconds' }
const features = { Protocol: 6, Dst_Port: 80, Flow_Duration: 100000 }

const anomaly = {
  detected_at: '2026-11-20T10:00:05Z', label: 'Anomaly', anomaly_probability: 0.91, protocol: 'TCP',
  sport: 40000, dport: 80, duration_s: 0.1, fwd_pkts: 3, bwd_pkts: 2, fwd_bytes: 100, bwd_bytes: 1500, features,
}
const normal = { ...anomaly, label: 'Normal', anomaly_probability: 0.12, dport: 53, protocol: 'UDP' }

const running = {
  state: 'running',
  session: {
    id: 's1', interface: 'Wi-Fi', bpf_filter: null, started_at: '2026-11-20T10:00:00Z', stopped_at: null,
    elapsed_seconds: 12, max_duration_seconds: 120, stop_reason: null, error: null, detect: true,
    counters: { packets_seen: 900, flows_scored: 2, anomalies: 1, normal: 1, dropped_queue_full: 0, scoring_errors: 0, persist_errors: 0 },
    queue: { depth: 0, capacity: 10000 }, active_flows: 4,
  },
  detection: { ...detectionInfo, enabled: true, recent: [anomaly, normal] },
  live_inference: gate,
}

function routes(status: unknown, extra: Record<string, unknown> = {}) {
  return {
    '/api/network/live/model': {
      available: true, model_version: 'rf-live-816b2de44ac8', n_estimators: 200, anomaly_threshold: 0.5,
      time_unit: 'microseconds', features: ['Protocol', 'Dst_Port'], classes: ['Anomaly', 'Normal'],
    },
    '/api/network/live/status': status,
    '/api/network/interfaces': {
      interfaces: [
        { name: 'Ethernet', description: null, is_up: false, speed_mbps: null, mtu: 1500, is_loopback: false,
          is_wireless: false, has_ipv4: false, visible_to_scapy: true, counters: null },
        { name: 'Wi-Fi', description: null, is_up: true, speed_mbps: 100, mtu: 1500, is_loopback: false,
          is_wireless: true, has_ipv4: true, visible_to_scapy: true,
          counters: { bytes_sent: 1, bytes_recv: 9e8, packets_sent: 1, packets_recv: 1, errors_in: 0, errors_out: 0, drops_in: 0, drops_out: 0 } },
      ],
      scapy: { available: true, version: '2.8.0', error_code: null, message: null },
      driver: null, platform: { system: 'Windows', release: '11', is_wsl: false, is_admin: false }, notes: [], capture_note: '',
    },
    '/api/network/live/detections': { items: [], total: 0, offset: 0, limit: 25, totals: { anomaly: 0, normal: 0 } },
    ...extra,
  }
}

describe('Live detection page', () => {
  it('starts detection on the up interface only after authorisation', async () => {
    const { calls } = mockFetch(
      routes({ state: 'stopped', session: null, detection: detectionInfo, live_inference: gate }, {
        '/api/network/live/start': running,
      }),
    )
    render(<LiveDetection />)
    expect(await screen.findByText('rf-live-816b2de44ac8')).toBeInTheDocument()
    const start = await screen.findByRole('button', { name: /start live detection/i })
    await waitFor(() => expect(screen.getByLabelText('Interface')).toHaveValue('Wi-Fi'))
    expect(start).toBeDisabled()
    await userEvent.click(screen.getByLabelText(/authorised to monitor/i))
    expect(start).toBeEnabled()
    await userEvent.click(start)
    await waitFor(() => expect(calls.some((c) => c.url === '/api/network/live/start')).toBe(true))
    const body = JSON.parse(String(calls.find((c) => c.url === '/api/network/live/start')!.init?.body))
    expect(body).toMatchObject({ interface: 'Wi-Fi', authorized: true, detect: true, max_duration_seconds: 120 })
  })

  it('shows live counters and detections with features', async () => {
    mockFetch(routes(running))
    render(<LiveDetection />)
    expect(await screen.findByRole('button', { name: /stop live detection/i })).toBeInTheDocument()
    expect(screen.getByText('900')).toBeInTheDocument()
    expect(screen.getByText('0.91')).toBeInTheDocument()
    expect(screen.getAllByText('Anomaly').length).toBeGreaterThan(0)
    await userEvent.click(screen.getAllByRole('button', { name: 'Features' })[0])
    expect(screen.getByText('Flow_Duration')).toBeInTheDocument()
  })

  it('explains when the live model is not loaded', async () => {
    mockFetch(routes({ state: 'stopped', session: null, detection: { ...detectionInfo, model_available: false }, live_inference: gate }, {
      '/api/network/live/model': { available: false, error: 'SHA-256 mismatch' },
    }))
    render(<LiveDetection />)
    expect(await screen.findByText(/not loaded/)).toBeInTheDocument()
    expect(screen.getByText('SHA-256 mismatch')).toBeInTheDocument()
    await userEvent.click(await screen.findByLabelText(/authorised to monitor/i))
    expect(screen.getByRole('button', { name: /start live detection/i })).toBeDisabled()
  })

  it('lists and filters stored detections', async () => {
    const { calls } = mockFetch(routes({ state: 'stopped', session: null, detection: detectionInfo, live_inference: gate }, {
      '/api/network/live/detections': (url: URL) => ({
        body: {
          items: url.searchParams.get('label') === 'Anomaly' ? [{ ...anomaly, id: 1, source: 'live' }] : [
            { ...anomaly, id: 1, source: 'live' }, { ...normal, id: 2, source: 'pcap' },
          ],
          total: url.searchParams.get('label') === 'Anomaly' ? 1 : 2, offset: 0, limit: 25,
          totals: { anomaly: 1, normal: 1 },
        },
      }),
    }))
    render(<LiveDetection />)
    expect(await screen.findByText('pcap')).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Result'), 'Anomaly')
    await waitFor(() => expect(calls.some((c) => c.url.includes('label=Anomaly'))).toBe(true))
    await waitFor(() => expect(screen.queryByText('pcap')).not.toBeInTheDocument())
  })
})

import { Play, Radar, RotateCcw, Square } from 'lucide-react'
import { Fragment, useEffect, useState } from 'react'
import { ApiError, api } from '../api/client'
import type { LiveDetection as Detection } from '../api/types'
import {
  Button,
  Card,
  Empty,
  ErrorBlock,
  Field,
  Loading,
  Notice,
  Pagination,
  Pill,
  Stat,
  Table,
  Td,
  Th,
} from '../components/ui'
import { useApi, usePolling } from '../hooks/useApi'
import { cx, inputClass } from '../lib/cx'
import { formatBytes, formatDateTime, formatNumber } from '../lib/format'
import { type CapturableInterface, rankInterfaces } from '../lib/interfaces'

const PAGE = 25

function DetectionBadge({ label }: { label: string }) {
  return label === 'Anomaly' ? <Pill tone="red">Anomaly</Pill> : <Pill tone="green">Normal</Pill>
}

function DetectionTable({ rows, showSource = false }: { rows: Detection[]; showSource?: boolean }) {
  const [open, setOpen] = useState<number | null>(null)
  return (
    <Table caption="Detections">
      <thead>
        <tr>
          <Th>Time</Th>
          <Th>Result</Th>
          <Th>P(anomaly)</Th>
          <Th>Protocol</Th>
          <Th>Src port</Th>
          <Th>Dst port</Th>
          <Th>Duration (s)</Th>
          <Th>Packets fwd / bwd</Th>
          <Th>Payload fwd / bwd</Th>
          {showSource && <Th>Source</Th>}
          <Th><span className="sr-only">Details</span></Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-800">
        {rows.map((d, i) => (
          <Fragment key={d.id ?? `${d.detected_at}-${i}`}>
            <tr className={cx(d.label === 'Anomaly' && 'bg-rose-500/5')}>
              <Td className="text-slate-400">{formatDateTime(d.detected_at)}</Td>
              <Td><DetectionBadge label={d.label} /></Td>
              <Td className="tabular-nums">{d.anomaly_probability.toFixed(2)}</Td>
              <Td>{d.protocol}</Td>
              <Td className="tabular-nums">{d.sport}</Td>
              <Td className="tabular-nums">{d.dport}</Td>
              <Td className="tabular-nums">{d.duration_s.toFixed(3)}</Td>
              <Td className="tabular-nums">{d.fwd_pkts} / {d.bwd_pkts}</Td>
              <Td className="tabular-nums">{formatBytes(d.fwd_bytes)} / {formatBytes(d.bwd_bytes)}</Td>
              {showSource && <Td className="text-slate-400">{d.source}</Td>}
              <Td>
                <Button variant="secondary" className="px-2 py-1 text-xs" aria-expanded={open === i}
                        onClick={() => setOpen(open === i ? null : i)}>
                  {open === i ? 'Hide' : 'Features'}
                </Button>
              </Td>
            </tr>
            {open === i && (
              <tr>
                <td colSpan={showSource ? 11 : 10} className="bg-slate-950/60 px-3 py-3">
                  <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3 lg:grid-cols-4">
                    {Object.entries(d.features).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <dt className="text-slate-500">{k}</dt>
                        <dd className="tabular-nums text-slate-200">{Number.isInteger(v) ? v : v.toFixed(3)}</dd>
                      </div>
                    ))}
                  </dl>
                </td>
              </tr>
            )}
          </Fragment>
        ))}
      </tbody>
    </Table>
  )
}

function ModelCard() {
  const model = useApi(() => api.liveModel(), [])
  if (model.error) return <ErrorBlock error={model.error} onRetry={model.reload} />
  if (!model.data) return <Loading />
  const m = model.data
  if (!m.available) {
    return (
      <Notice tone="warn">
        <p className="font-medium">The live-detection model is not loaded.</p>
        <p className="mt-1">{m.error}</p>
      </Notice>
    )
  }
  return (
    <Card title="Detection model" subtitle="Random Forest trained on 19 flow features that can be measured from live packets (IoTID20-style). Separate from the original dataset model.">
      <div className="flex flex-wrap gap-2 text-xs">
        <Pill tone="green">loaded</Pill>
        <Pill tone="slate">{m.model_version}</Pill>
        <Pill tone="slate">{m.n_estimators} trees</Pill>
        <Pill tone="slate">Anomaly if P(anomaly) ≥ {m.anomaly_threshold}</Pill>
        <Pill tone="slate">time unit: {m.time_unit}</Pill>
      </div>
      <p className="mt-3 text-xs text-slate-400">
        Features: {m.features?.join(', ')}. P(anomaly) is the fraction of trees voting Anomaly. It is a model
        estimate, not proof of an attack.
      </p>
      <div className="mt-3">
        <Notice tone="warn">
          Experimental: in testing on ordinary laptop browsing, most flows were labelled Anomaly. The model was
          trained on a different network (IoTID20-style data), and the exact feature extraction used during its
          training has not been confirmed. Treat results as indicative only.
        </Notice>
      </div>
    </Card>
  )
}

function ControlCard({ onChange }: { onChange: () => void }) {
  const status = useApi(() => api.liveStatus(), [])
  const ifaces = useApi(async () => {
    const r = await api.interfaces()
    return rankInterfaces(
      r.interfaces
        .filter((i) => i.visible_to_scapy)
        .map<CapturableInterface>((i) => ({
          name: i.name,
          isUp: i.is_up === true,
          isLoopback: i.is_loopback,
          bytesRecv: i.counters?.bytes_recv ?? 0,
        })),
    )
  }, [])
  const s = status.data
  const active = s?.state === 'running' || s?.state === 'starting' || s?.state === 'stopping'
  usePolling(status.reload, 2000, active)

  const [iface, setIface] = useState('')
  const [duration, setDuration] = useState(120)
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const list = ifaces.data ?? []
  const chosen = iface || list[0]?.name || ''

  // Refresh the history table whenever a session finishes.
  const stopped = s?.state === 'stopped' || s?.state === 'error'
  useEffect(() => {
    if (stopped) onChange()
  }, [stopped, onChange])

  async function act(fn: () => Promise<unknown>) {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)))
    } finally {
      setBusy(false)
      status.reload()
      onChange()
    }
  }

  const detection = s?.detection
  const session = s?.session
  const isDetectSession = !!session?.detect
  const c = session?.counters ?? {}

  return (
    <Card title="Live detection" subtitle="Captures packets on one interface, builds flows and scores each finished flow (about 5 s after it goes quiet). Capture only traffic you are authorised to monitor.">
      {status.error ? (
        <ErrorBlock error={status.error} onRetry={status.reload} />
      ) : !s ? (
        <Loading />
      ) : (
        <div className="space-y-4">
          {!active ? (
            <div className="space-y-3">
              <div className="grid items-start gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <Field label="Interface">
                  <select className={inputClass} value={chosen} onChange={(e) => setIface(e.target.value)}
                          disabled={ifaces.loading && !ifaces.data}>
                    {list.length === 0 && <option value="">{ifaces.loading ? 'Loading…' : 'No capturable interfaces'}</option>}
                    {list.map((i) => <option key={i.name} value={i.name}>{i.name}{i.isUp ? '' : ' (down)'}</option>)}
                  </select>
                </Field>
                <Field label="Duration (s)" hint="1 to 3600 seconds">
                  <input className={inputClass} type="number" min={1} max={3600} value={duration}
                         onChange={(e) => setDuration(Number(e.target.value))} />
                </Field>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input type="checkbox" className="h-4 w-4 accent-sky-500" checked={authorized}
                         onChange={(e) => setAuthorized(e.target.checked)} />
                  I am authorised to monitor traffic on this interface.
                </label>
                <Button className="px-5 py-2.5 text-base" disabled={busy || !authorized || !chosen || !detection?.model_available}
                        onClick={() => void act(() => api.liveStart({ interface: chosen, max_duration_seconds: duration, authorized, detect: true }))}>
                  <Play aria-hidden className="h-5 w-5" /> Start live detection
                </Button>
                {session && (
                  <Button variant="secondary" disabled={busy} title="Clear this panel; stored detections are kept"
                          onClick={() => void act(() => api.liveReset())}>
                    <RotateCcw aria-hidden className="h-4 w-4" /> Reset
                  </Button>
                )}
              </div>
              {ifaces.error && <ErrorBlock error={ifaces.error} onRetry={ifaces.reload} />}
            </div>
          ) : (
            <Button variant="danger" className="px-5 py-2.5 text-base" disabled={busy || s.state === 'stopping'}
                    onClick={() => void act(() => api.liveStop())}>
              <Square aria-hidden className="h-5 w-5" /> Stop live detection
            </Button>
          )}
          {error && <ErrorBlock error={error} />}

          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Radar aria-hidden className={cx('h-4 w-4', active ? 'animate-pulse text-emerald-400' : 'text-slate-400')} />
            <span className="text-slate-300">State:</span>
            <Pill tone={s.state === 'running' ? 'green' : s.state === 'error' ? 'red' : 'slate'}>{s.state}</Pill>
            {session && (
              <span className="text-slate-400">
                on {session.interface} · {session.elapsed_seconds}s / {session.max_duration_seconds}s
                {session.stop_reason ? ` · stopped: ${session.stop_reason.replaceAll('_', ' ')}` : ''}
              </span>
            )}
          </div>
          {session?.error && (
            <Notice tone="warn"><p className="font-medium">{session.error.code}</p><p>{session.error.message}</p></Notice>
          )}
          {session && !isDetectSession && (
            <Notice>The last session was started from the Network page without detection. Start a new session here to score flows.</Notice>
          )}

          {session && isDetectSession && (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                <Stat label="Packets seen" value={formatNumber(c.packets_seen)} />
                <Stat label="Flows scored" value={formatNumber(c.flows_scored)} />
                <Stat label="Anomalies" value={formatNumber(c.anomalies)} tone={c.anomalies ? 'danger' : 'default'} />
                <Stat label="Normal" value={formatNumber(c.normal)} tone="ok" />
                <Stat label="Active flows" value={formatNumber(session.active_flows)} hint="Scored when they finish" />
                <Stat label="Dropped packets" value={formatNumber(c.dropped_queue_full)}
                      tone={c.dropped_queue_full ? 'warn' : 'default'} />
              </div>
              {(c.scoring_errors > 0 || c.persist_errors > 0) && (
                <Notice tone="warn">Scoring errors: {c.scoring_errors} · storage errors: {c.persist_errors}</Notice>
              )}
              <div>
                <h3 className="mb-2 text-sm font-semibold text-slate-200">Latest detections (this session)</h3>
                {detection?.recent && detection.recent.length > 0 ? (
                  <DetectionTable rows={detection.recent} />
                ) : (
                  <Empty title={active ? 'Waiting for flows to finish…' : 'No flows were scored in this session'}>
                    {active ? 'A flow is scored about 5 seconds after its last packet. Browse a website to generate traffic.' : null}
                  </Empty>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </Card>
  )
}

function HistoryCard({ version }: { version: number }) {
  const [label, setLabel] = useState('')
  const [offset, setOffset] = useState(0)
  const page = useApi(() => api.liveDetections({ label: label || undefined, offset, limit: PAGE }), [label, offset, version])
  return (
    <Card title="Detection history" subtitle="All stored detections from live sessions and PCAP uploads, newest first (ports and counts only, no IP addresses).">
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <Field label="Result">
          <select className={inputClass} value={label} onChange={(e) => { setLabel(e.target.value); setOffset(0) }}>
            <option value="">All</option>
            <option value="Anomaly">Anomaly</option>
            <option value="Normal">Normal</option>
          </select>
        </Field>
        {page.data && (
          <p className="pb-2 text-sm text-slate-400">
            Stored: <span className="text-rose-300">{formatNumber(page.data.totals.anomaly)} anomaly</span> ·{' '}
            <span className="text-emerald-300">{formatNumber(page.data.totals.normal)} normal</span>
          </p>
        )}
      </div>
      {page.error ? (
        <ErrorBlock error={page.error} onRetry={page.reload} />
      ) : !page.data ? (
        <Loading />
      ) : page.data.items.length === 0 ? (
        <Empty title={label ? 'No detections match this filter' : 'No detections yet'}>
          Start live detection above, or upload a PCAP on the Network page.
        </Empty>
      ) : (
        <>
          <DetectionTable rows={page.data.items} showSource />
          <Pagination offset={offset} limit={PAGE} total={page.data.total} onChange={setOffset} />
        </>
      )}
    </Card>
  )
}

export function LiveDetection() {
  const [version, setVersion] = useState(0)
  const [bump] = useState(() => () => setVersion((v) => v + 1))
  return (
    <div className="space-y-6">
      <ModelCard />
      <ControlCard onChange={bump} />
      <HistoryCard version={version} />
    </div>
  )
}

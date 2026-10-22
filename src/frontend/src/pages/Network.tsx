import { Activity, FileSearch, Play, RotateCcw, Square, Wifi } from 'lucide-react'
import { useCallback, useState } from 'react'
import { ApiError, api } from '../api/client'
import type {
  CaptureCheckResponse,
  CompatibilityReport,
  FeatureRule,
  FeatureStatus,
  FlowSample,
  NetworkRun,
} from '../api/types'
import {
  Button,
  Card,
  Empty,
  ErrorBlock,
  Field,
  Loading,
  Notice,
  Pill,
  Stat,
  Table,
  Td,
  Th,
} from '../components/ui'
import { inputClass } from '../lib/cx'
import { useApi, usePolling } from '../hooks/useApi'
import { formatBytes, formatDateTime, formatNumber, formatPercent } from '../lib/format'
import { type CapturableInterface, rankInterfaces } from '../lib/interfaces'

const STATUS_TONE: Record<FeatureStatus, 'green' | 'sky' | 'red' | 'slate'> = {
  derived: 'green',
  approximated: 'sky',
  incompatible: 'red',
  not_computed: 'slate',
}

const NOT_SCORED =
  'Extracted flows are not scored by the model: their features do not match the training data, so any prediction would be unreliable.'

export function CompatibilityView({ report, features }: { report: CompatibilityReport; features?: FeatureRule[] }) {
  const rows = features ?? report.features ?? []
  return (
    <div className="space-y-4">
      <Notice tone={report.compatible ? 'info' : 'warn'}>
        <p className="font-medium">{report.verdict}</p>
        <p className="mt-1">{NOT_SCORED}</p>
      </Notice>
      <div className="flex flex-wrap gap-2 text-xs">
        {(Object.keys(STATUS_TONE) as FeatureStatus[]).map((s) => (
          <Pill key={s} tone={STATUS_TONE[s]}>{s.replace('_', ' ')}: {report.status_counts[s] ?? 0}</Pill>
        ))}
      </div>
      <div>
        <h3 className="mb-2 text-sm font-semibold text-slate-200">Training invariants vs extracted flows</h3>
        <Table caption="Invariant comparison">
          <thead><tr><Th>Relationship</Th><Th>Training rows</Th><Th>Extracted flows</Th></tr></thead>
          <tbody className="divide-y divide-slate-800">
            {report.invariants.map((i) => (
              <tr key={i.invariant}>
                <Td><code>{i.rule}</code></Td>
                <Td className="tabular-nums">{formatPercent(i.training_share)}</Td>
                <Td className="tabular-nums">{formatPercent(i.extracted_share)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
      <p className="text-sm text-slate-300">
        Schema validation of extracted records:{' '}
        {report.schema_validation.checked
          ? report.schema_validation.passed
            ? 'passed'
            : `failed — missing values for ${Object.keys(report.schema_validation.errors_by_feature).length} features (left empty, never invented)`
          : 'not run (model not loaded or no flows)'}
      </p>
      {rows.length > 0 && <FeatureRuleTable rules={rows} />}
    </div>
  )
}

function FeatureRuleTable({ rules }: { rules: FeatureRule[] }) {
  return (
    <details className="rounded-lg border border-slate-800 p-3">
      <summary className="cursor-pointer text-sm font-semibold text-slate-200">Per-feature mapping ({rules.length} model inputs)</summary>
      <div className="mt-3">
        <Table caption="Feature mapping">
          <thead><tr><Th>Feature</Th><Th>Status</Th><Th>From packets</Th><Th>Within training range</Th><Th>Reason</Th></tr></thead>
          <tbody className="divide-y divide-slate-800">
            {rules.map((r) => (
              <tr key={r.feature} className="align-top">
                <Td><code>{r.feature}</code></Td>
                <Td><Pill tone={STATUS_TONE[r.status]}>{r.status.replace('_', ' ')}</Pill></Td>
                <Td className="text-slate-400">{r.method}</Td>
                <Td className="tabular-nums">
                  {r.share_within_training_range !== undefined && r.share_within_training_range !== null
                    ? formatPercent(r.share_within_training_range)
                    : '—'}
                </Td>
                <Td className="min-w-[18rem] whitespace-normal text-slate-400">{r.reason}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
    </details>
  )
}

function FlowTable({ flows }: { flows: FlowSample[] }) {
  if (flows.length === 0) return <Empty title="No flows extracted yet" />
  return (
    <Table caption="Extracted flows (no addresses)">
      <thead>
        <tr><Th>Transport</Th><Th>Src port</Th><Th>Dst port</Th><Th>Label guess</Th><Th>Pkts (src/dst)</Th>
          <Th>Bytes (src/dst)</Th><Th>Dur (s)</Th><Th>Pkt size min/mean/max</Th><Th>TCP flags</Th><Th>Ended</Th></tr>
      </thead>
      <tbody className="divide-y divide-slate-800">
        {flows.map((f, i) => (
          <tr key={i}>
            <Td>{f.observed.transport}</Td>
            <Td className="tabular-nums">{f.observed.sport}</Td>
            <Td className="tabular-nums">{f.observed.dport}</Td>
            <Td>{String(f.model_features.proto ?? '—')}</Td>
            <Td className="tabular-nums">{f.observed.pkts} ({f.observed.spkts}/{f.observed.dpkts})</Td>
            <Td className="tabular-nums">{formatBytes(f.observed.bytes)} ({f.observed.sbytes}/{f.observed.dbytes})</Td>
            <Td className="tabular-nums">{f.observed.dur.toFixed(3)}</Td>
            <Td className="tabular-nums">{f.observed.pkt_len_min}/{f.observed.pkt_len_mean.toFixed(0)}/{f.observed.pkt_len_max}</Td>
            <Td>{f.observed.tcp_flags_seen || '—'}</Td>
            <Td className="text-slate-400">{f.observed.end_reason.replaceAll('_', ' ')}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  )
}

function InterfacesCard({ onInterfaces }: { onInterfaces: (list: CapturableInterface[]) => void }) {
  const data = useApi(async () => {
    const r = await api.interfaces()
    onInterfaces(
      rankInterfaces(
        r.interfaces
          .filter((i) => i.visible_to_scapy)
          .map((i) => ({
            name: i.name,
            isUp: i.is_up === true,
            isLoopback: i.is_loopback,
            bytesRecv: i.counters?.bytes_recv ?? 0,
          })),
      ),
    )
    return r
  }, [])
  const [check, setCheck] = useState<CaptureCheckResponse | null>(null)
  const [checkError, setCheckError] = useState<ApiError | null>(null)
  const [checking, setChecking] = useState<string | null>(null)

  async function runCheck(name: string) {
    setChecking(name)
    setCheck(null)
    setCheckError(null)
    try {
      setCheck(await api.captureCheck(name))
    } catch (e) {
      setCheckError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)))
    } finally {
      setChecking(null)
    }
  }

  return (
    <Card title="Network interfaces" subtitle={data.data?.capture_note}
          actions={<Button variant="secondary" onClick={data.reload}>Refresh</Button>}>
      {data.error ? (
        <ErrorBlock error={data.error} onRetry={data.reload} />
      ) : !data.data ? (
        <Loading label="Discovering interfaces…" />
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2 text-xs">
            <Pill tone={data.data.scapy.available ? 'green' : 'amber'}>
              Scapy {data.data.scapy.available ? data.data.scapy.version : 'not installed'}
            </Pill>
            {data.data.driver && (
              <Pill tone={data.data.driver.available ? 'green' : 'red'}>
                {data.data.driver.name}: {data.data.driver.available ? data.data.driver.version ?? 'available' : 'missing'}
              </Pill>
            )}
            {data.data.driver?.admin_only !== null && data.data.driver?.admin_only !== undefined && (
              <Pill tone="slate">admin-only: {String(data.data.driver.admin_only)}</Pill>
            )}
            <Pill tone="slate">{data.data.platform.system} {data.data.platform.is_wsl ? '(WSL)' : ''}</Pill>
          </div>
          {data.data.driver?.message && <Notice tone="warn">{data.data.driver.message}</Notice>}
          {data.data.notes.map((n) => <p key={n} className="text-xs text-slate-400">{n}</p>)}
          <Table caption="Interfaces">
            <thead><tr><Th>Interface</Th><Th>State</Th><Th>Type</Th><Th>Speed</Th><Th>Received</Th><Th>Sent</Th><Th>Errors / drops in</Th><Th>Capture</Th></tr></thead>
            <tbody className="divide-y divide-slate-800">
              {data.data.interfaces.map((i) => (
                <tr key={i.name}>
                  <Td><span className="font-medium">{i.name}</span>{i.description && <span className="block text-xs text-slate-500">{i.description}</span>}</Td>
                  <Td>{i.is_up === null ? '—' : i.is_up ? <Pill tone="green">up</Pill> : <Pill>down</Pill>}</Td>
                  <Td className="text-slate-400">{[i.is_loopback && 'loopback', i.is_wireless && 'wireless'].filter(Boolean).join(', ') || '—'}</Td>
                  <Td className="tabular-nums">{i.speed_mbps ? `${i.speed_mbps} Mb/s` : '—'}</Td>
                  <Td className="tabular-nums">{i.counters ? formatBytes(i.counters.bytes_recv) : '—'}</Td>
                  <Td className="tabular-nums">{i.counters ? formatBytes(i.counters.bytes_sent) : '—'}</Td>
                  <Td className="tabular-nums">{i.counters ? `${i.counters.errors_in} / ${i.counters.drops_in}` : '—'}</Td>
                  <Td>
                    {i.visible_to_scapy ? (
                      <Button variant="secondary" className="px-2 py-1 text-xs" disabled={checking !== null}
                              onClick={() => void runCheck(i.name)}>
                        {checking === i.name ? 'Checking…' : 'Check'}
                      </Button>
                    ) : <span className="text-xs text-slate-500">not capturable</span>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {checkError && <ErrorBlock error={checkError} />}
          {check && (
            <Notice tone={check.capture_check.status === 'available' ? 'info' : 'warn'}>
              <p className="font-medium">Capture on {check.capture_check.interface}: {check.capture_check.status}
                {check.capture_check.error_code ? ` (${check.capture_check.error_code})` : ''}</p>
              {check.capture_check.message && <p className="mt-1">{check.capture_check.message}</p>}
            </Notice>
          )}
        </div>
      )}
    </Card>
  )
}

function RunSummary({ run }: { run: NetworkRun }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <Stat label="Packets read" value={formatNumber(run.packets_read)} />
      <Stat label="IP packets" value={formatNumber(run.ip_packets)} />
      <Stat label="Non-IP" value={formatNumber(run.non_ip_packets)} />
      <Stat label="Malformed" value={formatNumber(run.malformed_packets)} tone={run.malformed_packets ? 'warn' : 'default'} />
      <Stat label="Dropped" value={formatNumber(run.dropped_packets)} tone={run.dropped_packets ? 'warn' : 'default'} />
      <Stat label="Flows" value={formatNumber(run.flows_extracted)} />
    </div>
  )
}

function PcapCard({ onDone }: { onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [run, setRun] = useState<NetworkRun | null>(null)

  async function submit() {
    if (!file) return
    setBusy(true)
    setError(null)
    setRun(null)
    try {
      setRun(await api.analyzePcap(file))
      onDone()
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Offline PCAP analysis" subtitle="Extract flows from a PCAP/PCAPNG capture you are authorised to analyse and compare them with the training features. Packet payloads and addresses are not stored.">
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Capture file">
            <input type="file" accept=".pcap,.pcapng,.cap" className={`${inputClass} file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-slate-200`}
                   onChange={(e) => { setFile(e.target.files?.[0] ?? null); setRun(null); setError(null) }} />
          </Field>
          <Button onClick={() => void submit()} disabled={!file || busy}>
            <FileSearch aria-hidden className="h-4 w-4" /> {busy ? 'Analysing…' : 'Analyse capture'}
          </Button>
        </div>
        {error && <ErrorBlock error={error} />}
        {run && run.report && (
          <div className="space-y-4">
            {run.status === 'partial' && (
              <Notice tone="warn">The capture was only partly readable ({String(run.stats.read_error ?? `${run.stats.truncated_records} truncated record(s)`)}). Results cover what was read.</Notice>
            )}
            <RunSummary run={run} />
            <CompatibilityView report={run.report} />
            <h3 className="text-sm font-semibold text-slate-200">Flow sample (first {run.report.flow_sample?.length ?? 0})</h3>
            <FlowTable flows={run.report.flow_sample ?? []} />
          </div>
        )}
      </div>
    </Card>
  )
}

function LiveCard({ interfaces, onDone }: { interfaces: CapturableInterface[]; onDone: () => void }) {
  const status = useApi(() => api.liveStatus(), [])
  const s = status.data
  const active = s?.state === 'running' || s?.state === 'starting' || s?.state === 'stopping'
  usePolling(status.reload, 2000, active)

  const [iface, setIface] = useState('')
  const [bpf, setBpf] = useState('')
  const [duration, setDuration] = useState(60)
  const [authorized, setAuthorized] = useState(false)
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

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
      onDone()
    }
  }

  const chosen = iface || interfaces[0]?.name || ''
  return (
    <Card title="Live capture (feature extraction only)"
          subtitle="Captures packet headers on one interface, builds flows and reports compatibility. Capture only traffic you are authorised to monitor. Controls work only from this machine.">
      <div className="space-y-4">
        <Notice tone="warn">{NOT_SCORED} Live intrusion predictions are disabled.</Notice>
        {status.error ? (
          <ErrorBlock error={status.error} onRetry={status.reload} />
        ) : !s ? (
          <Loading />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Activity aria-hidden className="h-4 w-4 text-slate-400" />
              <span className="text-slate-300">State:</span>
              <Pill tone={s.state === 'running' ? 'green' : s.state === 'error' ? 'red' : 'slate'}>{s.state}</Pill>
              {s.session && <span className="text-slate-400">on {s.session.interface} · {s.session.elapsed_seconds}s / {s.session.max_duration_seconds}s
                {s.session.stop_reason ? ` · stopped: ${s.session.stop_reason.replaceAll('_', ' ')}` : ''}</span>}
            </div>
            {s.session?.error && (
              <Notice tone="warn"><p className="font-medium">{s.session.error.code}</p><p>{s.session.error.message}</p></Notice>
            )}

            {!active && (
              <form className="space-y-3" onSubmit={(e) => {
                e.preventDefault()
                void act(() => api.liveStart({ interface: chosen, bpf_filter: bpf || undefined, max_duration_seconds: duration, authorized }, token || undefined))
              }}>
                <div className="grid items-start gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <Field label="Interface">
                    <select className={inputClass} value={chosen} onChange={(e) => setIface(e.target.value)}>
                      {interfaces.length === 0 && <option value="">No capturable interfaces</option>}
                      {interfaces.map((i) => (
                        <option key={i.name} value={i.name}>{i.name}{i.isUp ? '' : ' (down)'}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="BPF filter (optional)" hint="e.g. tcp or udp">
                    <input className={inputClass} value={bpf} maxLength={200} onChange={(e) => setBpf(e.target.value)} />
                  </Field>
                  <Field label="Max duration (s)" hint="1 to 3600 seconds">
                    <input className={inputClass} type="number" min={1} max={3600} value={duration}
                           onChange={(e) => setDuration(Number(e.target.value))} />
                  </Field>
                  <Field label="Capture token" hint="Only if NIDS_CAPTURE_TOKEN is set">
                    <input className={inputClass} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />
                  </Field>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <label className="flex items-center gap-2 text-sm text-slate-300">
                    <input type="checkbox" className="h-4 w-4 accent-sky-500" checked={authorized}
                           onChange={(e) => setAuthorized(e.target.checked)} />
                    I am authorised to monitor traffic on this interface.
                  </label>
                  <Button type="submit" disabled={busy || !authorized || !chosen}>
                    <Play aria-hidden className="h-4 w-4" /> Start
                  </Button>
                  {s.session && (
                    <Button variant="secondary" disabled={busy} title="Clear this panel; saved runs stay in history"
                            onClick={() => void act(() => api.liveReset(token || undefined))}>
                      <RotateCcw aria-hidden className="h-4 w-4" /> Reset
                    </Button>
                  )}
                </div>
                {interfaces.length > 0 && !interfaces.find((i) => i.name === chosen)?.isUp && (
                  <p className="text-xs text-amber-300">This interface is down; choose one that is up to see traffic.</p>
                )}
              </form>
            )}
            {active && (
              <Button variant="danger" disabled={busy || s.state === 'stopping'} onClick={() => void act(() => api.liveStop(token || undefined))}>
                <Square aria-hidden className="h-4 w-4" /> Stop capture
              </Button>
            )}
            {error && <ErrorBlock error={error} />}

            {s.session && (
              <>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  <Stat label="Packets seen" value={formatNumber(s.session.counters.packets_seen)} />
                  <Stat label="Dropped (queue full)" value={formatNumber(s.session.counters.dropped_queue_full)}
                        tone={s.session.counters.dropped_queue_full ? 'warn' : 'default'} />
                  <Stat label="Queue" value={`${formatNumber(s.session.queue.depth)} / ${formatNumber(s.session.queue.capacity)}`} />
                  <Stat label="Flows (active / done)" value={`${formatNumber(s.session.active_flows)} / ${formatNumber(s.session.counters.flows_emitted)}`} />
                </div>
                <p className="text-xs text-slate-400">
                  Non-IP: {formatNumber(s.session.counters.non_ip_packets)} · malformed: {formatNumber(s.session.counters.malformed_packets)}
                  {s.session.bpf_filter ? ` · filter: ${s.session.bpf_filter}` : ''}
                </p>
                {s.compatibility && <CompatibilityView report={s.compatibility} />}
                <h3 className="text-sm font-semibold text-slate-200">Recent flows</h3>
                <FlowTable flows={s.recent_flows ?? []} />
              </>
            )}
          </>
        )}
      </div>
    </Card>
  )
}

function RunsCard({ version }: { version: number }) {
  const runs = useApi(() => api.networkRuns(), [version])
  return (
    <Card title="Previous network runs" subtitle="Stored counters and compatibility reports (no packets, payloads or addresses).">
      {runs.error ? (
        <ErrorBlock error={runs.error} onRetry={runs.reload} />
      ) : !runs.data ? (
        <Loading />
      ) : runs.data.items.length === 0 ? (
        <Empty title="No PCAP analyses or live sessions yet" />
      ) : (
        <Table caption="Network runs">
          <thead><tr><Th>Started</Th><Th>Kind</Th><Th>File / interface</Th><Th>Status</Th><Th>Packets</Th><Th>Dropped</Th><Th>Flows</Th><Th>Compatible</Th></tr></thead>
          <tbody className="divide-y divide-slate-800">
            {runs.data.items.map((r) => (
              <tr key={r.id}>
                <Td className="text-slate-400">{formatDateTime(r.created_at)}</Td>
                <Td>{r.kind}</Td>
                <Td>{r.filename ?? String(r.stats.interface ?? '—')}</Td>
                <Td>{r.status}</Td>
                <Td className="tabular-nums">{formatNumber(r.packets_read)}</Td>
                <Td className="tabular-nums">{formatNumber(r.dropped_packets)}</Td>
                <Td className="tabular-nums">{formatNumber(r.flows_extracted)}</Td>
                <Td>{r.compatible ? <Pill tone="green">yes</Pill> : <Pill tone="red">no</Pill>}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  )
}

function MappingCard() {
  const mapping = useApi(() => api.featureMapping(), [])
  return (
    <Card title="How model inputs map to packet features" subtitle="Static rules used for every PCAP and live report.">
      {mapping.error ? (
        <ErrorBlock error={mapping.error} onRetry={mapping.reload} />
      ) : !mapping.data ? (
        <Loading />
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-slate-400">
            Flow definition: {Object.entries(mapping.data.flow_definition).map(([k, v]) => `${k.replaceAll('_', ' ')} = ${v}`).join(' · ')}
          </p>
          <FeatureRuleTable rules={mapping.data.features} />
        </div>
      )}
    </Card>
  )
}

export function Network() {
  const [capturable, setCapturable] = useState<CapturableInterface[]>([])
  const [version, setVersion] = useState(0)
  const bump = useCallback(() => setVersion((v) => v + 1), [])
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Wifi aria-hidden className="h-4 w-4" /> Interface discovery → offline PCAP analysis → feature extraction → compatibility report → live capture.
      </div>
      <InterfacesCard onInterfaces={setCapturable} />
      <PcapCard onDone={bump} />
      <LiveCard interfaces={capturable} onDone={bump} />
      <MappingCard />
      <RunsCard version={version} />
    </div>
  )
}

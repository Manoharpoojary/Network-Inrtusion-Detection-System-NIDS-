import { Download, FileUp, Send } from 'lucide-react'
import { useState } from 'react'
import { ApiError, api } from '../api/client'
import type { CsvAnalysis, Prediction } from '../api/types'
import { ExplanationView } from '../components/ExplanationView'
import {
  Button,
  Card,
  Empty,
  ErrorBlock,
  Field,
  LabelBadge,
  Loading,
  Notice,
  Pagination,
  SeverityBadge,
  Stat,
  Table,
  Td,
  Th,
} from '../components/ui'
import { inputClass } from '../lib/cx'
import { useApi } from '../hooks/useApi'
import { type HeaderCheck, checkCsvHeader, formatNumber, readFirstLine } from '../lib/format'

const PAGE = 50

function ResultsTable({ analysisId }: { analysisId: string }) {
  const [label, setLabel] = useState<string>('')
  const [offset, setOffset] = useState(0)
  const page = useApi(
    () => api.analysisPredictions(analysisId, label || undefined, offset, PAGE),
    [analysisId, label, offset],
  )
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Filter by predicted class">
          <select className={inputClass} value={label} onChange={(e) => { setLabel(e.target.value); setOffset(0) }}>
            <option value="">All</option>
            <option value="Attack">Attack</option>
            <option value="Benign">Benign</option>
          </select>
        </Field>
        <a
          className="inline-flex items-center gap-2 rounded-lg bg-slate-800 px-3 py-2 text-sm font-medium text-slate-100 ring-1 ring-inset ring-slate-700 hover:bg-slate-700"
          href={api.exportUrl(analysisId, label || undefined)}
        >
          <Download aria-hidden className="h-4 w-4" /> Export CSV
        </a>
      </div>
      {page.error ? (
        <ErrorBlock error={page.error} onRetry={page.reload} />
      ) : !page.data ? (
        <Loading />
      ) : page.data.items.length === 0 ? (
        <Empty title="No rows match this filter" />
      ) : (
        <>
          <Table caption="Prediction results">
            <thead>
              <tr>
                <Th>Row</Th><Th>Label</Th><Th>P(attack)</Th><Th>Severity</Th><Th>Alert</Th>
                <Th>Proto</Th><Th>Flags</Th><Th>Dst port</Th><Th>Pkts</Th><Th>Bytes</Th><Th>Dur (s)</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {page.data.items.map((p) => (
                <tr key={p.prediction_id}>
                  <Td className="tabular-nums text-slate-400">{p.row_index}</Td>
                  <Td><LabelBadge label={p.label} /></Td>
                  <Td className="tabular-nums">{p.attack_probability.toFixed(2)}</Td>
                  <Td><SeverityBadge severity={p.severity} /></Td>
                  <Td className="tabular-nums">{p.alert_id ? `#${p.alert_id}` : '—'}</Td>
                  <Td>{p.proto}</Td>
                  <Td>{p.flgs}</Td>
                  <Td className="tabular-nums">{p.dport}</Td>
                  <Td className="tabular-nums">{formatNumber(p.pkts)}</Td>
                  <Td className="tabular-nums">{formatNumber(p.bytes)}</Td>
                  <Td className="tabular-nums">{formatNumber(p.dur, 3)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination offset={offset} limit={PAGE} total={page.data.total} onChange={setOffset} />
        </>
      )}
    </div>
  )
}

function CsvAnalysisCard() {
  const info = useApi(() => api.modelInfo(), [])
  const [file, setFile] = useState<File | null>(null)
  const [header, setHeader] = useState<HeaderCheck | null>(null)
  const [ignoreExtra, setIgnoreExtra] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [result, setResult] = useState<CsvAnalysis | null>(null)

  const expected = info.data?.features.map((f) => f.name) ?? []
  const limitMb = info.data ? info.data.limits.max_upload_bytes / 1024 / 1024 : null

  async function choose(f: File | null) {
    setFile(f)
    setResult(null)
    setError(null)
    setHeader(f && expected.length ? checkCsvHeader(await readFirstLine(f), expected) : null)
  }

  async function submit() {
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      setResult(await api.analyzeCsv(file, ignoreExtra))
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)))
    } finally {
      setBusy(false)
    }
  }

  const blocked = !!header && (header.missing.length > 0 || header.duplicates.length > 0 ||
    (header.extra.length > 0 && !ignoreExtra))

  return (
    <Card
      title="Analyse a CSV of flow features"
      subtitle={`Offline analysis of uploaded records — not live monitoring. The file must contain the model's ${expected.length || 35} feature columns${limitMb ? `; up to ${limitMb.toFixed(0)} MB and ${formatNumber(info.data?.limits.max_csv_rows)} rows` : ''}.`}
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="CSV file">
            <input type="file" accept=".csv,text/csv" className={`${inputClass} file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-slate-200`}
                   onChange={(e) => void choose(e.target.files?.[0] ?? null)} />
          </Field>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={ignoreExtra} onChange={(e) => setIgnoreExtra(e.target.checked)}
                   className="h-4 w-4 accent-sky-500" />
            Ignore extra columns (e.g. labels, IPs) — they are dropped, not stored
          </label>
          <Button onClick={() => void submit()} disabled={!file || busy || blocked}>
            <FileUp aria-hidden className="h-4 w-4" /> {busy ? 'Analysing…' : 'Analyse'}
          </Button>
        </div>

        {header && (header.missing.length > 0 || header.extra.length > 0 || header.duplicates.length > 0) && (
          <Notice tone={blocked ? 'warn' : 'info'}>
            <p className="font-medium">Column check (before upload)</p>
            {header.missing.length > 0 && <p>Missing: <code>{header.missing.join(', ')}</code></p>}
            {header.duplicates.length > 0 && <p>Duplicated: <code>{header.duplicates.join(', ')}</code></p>}
            {header.extra.length > 0 && (
              <p>Not model features{ignoreExtra ? ' (will be ignored)' : ''}: <code>{header.extra.join(', ')}</code></p>
            )}
          </Notice>
        )}
        {header && !blocked && header.missing.length === 0 && header.extra.length === 0 && (
          <p className="text-sm text-emerald-300">All {expected.length} model columns present. Values are validated on upload.</p>
        )}
        {error && <ErrorBlock error={error} />}

        {result && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat label="Rows analysed" value={formatNumber(result.summary.total)} />
              <Stat label="Predicted attack" value={formatNumber(result.summary.attack)} tone="danger" />
              <Stat label="Predicted benign" value={formatNumber(result.summary.benign)} tone="ok" />
              <Stat label="Alerts (high / medium)" value={`${result.summary.alerts.high} / ${result.summary.alerts.medium}`} />
            </div>
            {result.analysis.ignored_columns.length > 0 && (
              <p className="text-xs text-slate-400">Ignored columns: {result.analysis.ignored_columns.join(', ')}</p>
            )}
            <ResultsTable analysisId={result.analysis.id} />
          </div>
        )}
      </div>
    </Card>
  )
}

function SingleRecordCard() {
  const info = useApi(() => api.modelInfo(), [])
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [result, setResult] = useState<Prediction | null>(null)

  async function submit() {
    setError(null)
    setResult(null)
    let record: Record<string, unknown>
    try {
      record = JSON.parse(text)
    } catch {
      setError(new ApiError(0, 'invalid_json', 'The record is not valid JSON.'))
      return
    }
    setBusy(true)
    try {
      setResult(await api.predict(record))
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'unknown', String(e)))
    } finally {
      setBusy(false)
    }
  }

  const template = info.data
    ? JSON.stringify(Object.fromEntries(info.data.features.map((f) => [f.name, f.kind === 'categorical' ? f.allowed_values?.[0] ?? '' : 0])), null, 1)
    : ''

  return (
    <Card title="Single flow record" subtitle="Paste one record (JSON object with exactly the 35 features) to get a prediction and its local explanation.">
      <div className="space-y-3">
        <textarea className={`${inputClass} h-48 w-full font-mono text-xs`} value={text}
                  onChange={(e) => setText(e.target.value)} spellCheck={false}
                  placeholder='{"flgs": "PA", "flgs_number": 1, "proto": "HTTP", ...}' aria-label="Flow record JSON" />
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void submit()} disabled={busy || !text.trim()}>
            <Send aria-hidden className="h-4 w-4" /> {busy ? 'Predicting…' : 'Predict'}
          </Button>
          <Button variant="secondary" disabled={!template} onClick={() => setText(template)}>
            Insert empty template
          </Button>
        </div>
        {error && <ErrorBlock error={error} />}
        {result && (
          <div className="space-y-3 rounded-lg border border-slate-800 p-3">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <LabelBadge label={result.label} />
              <SeverityBadge severity={result.severity} />
              <span className="text-slate-300">P(attack) <span className="tabular-nums">{result.attack_probability.toFixed(2)}</span>
                <span className="text-slate-500"> (threshold {result.threshold}; uncalibrated vote share)</span></span>
              {result.alert_id && <span className="text-slate-400">Alert #{result.alert_id}</span>}
            </div>
            {result.warnings.length > 0 && (
              <Notice tone="warn"><ul className="list-disc pl-4">{result.warnings.map((w) => <li key={w}>{w}</li>)}</ul></Notice>
            )}
            <ExplanationView explanation={result.explanation} status={result.explanation_status} />
          </div>
        )}
      </div>
    </Card>
  )
}

export function Analyze() {
  return (
    <div className="space-y-6">
      <CsvAnalysisCard />
      <SingleRecordCard />
    </div>
  )
}

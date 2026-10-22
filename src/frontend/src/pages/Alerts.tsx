import { X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { ExplanationView } from '../components/ExplanationView'
import {
  Button,
  Card,
  Empty,
  ErrorBlock,
  Field,
  FieldAction,
  LabelBadge,
  Loading,
  Pagination,
  SeverityBadge,
  Table,
  Td,
  Th,
} from '../components/ui'
import { inputClass } from '../lib/cx'
import { useApi } from '../hooks/useApi'
import { formatDateTime } from '../lib/format'
import { AlertRows } from './Overview'

const PAGE = 25

export function AlertDetailPanel({ alertId, onClose }: { alertId: number; onClose: () => void }) {
  const detail = useApi(() => api.alert(alertId), [alertId])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/70" onClick={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`Alert ${alertId}`}
        className="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-800 bg-slate-900 p-5 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">Alert #{alertId}</h2>
          <Button variant="secondary" aria-label="Close" onClick={onClose}>
            <X aria-hidden className="h-4 w-4" />
          </Button>
        </div>
        {detail.error ? (
          <ErrorBlock error={detail.error} onRetry={detail.reload} />
        ) : !detail.data ? (
          <Loading label="Loading alert and explanation…" />
        ) : (
          <div className="space-y-5">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
              {[
                ['Severity', <SeverityBadge key="s" severity={detail.data.severity} />],
                ['Label', <LabelBadge key="l" label={detail.data.label} />],
                ['P(attack)', detail.data.attack_probability.toFixed(3)],
                ['Created', formatDateTime(detail.data.created_at)],
                ['Status', detail.data.status],
                ['Source', detail.data.filename ?? detail.data.source],
                ['Row in submission', detail.data.flow_index],
                ['Model version', <code key="m">{detail.data.model_version}</code>],
              ].map(([k, v]) => (
                <div key={String(k)}>
                  <dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt>
                  <dd className="mt-0.5 text-slate-200">{v}</dd>
                </div>
              ))}
            </dl>
            <section>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Why the model scored this flow</h3>
              <ExplanationView explanation={detail.data.explanation} status={detail.data.explanation_status}
                               note={detail.data.explanation_note} />
            </section>
            <section>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Flow features (model inputs)</h3>
              <Table caption="Flow features">
                <thead><tr><Th>Feature</Th><Th>Value</Th></tr></thead>
                <tbody className="divide-y divide-slate-800">
                  {Object.entries(detail.data.features).map(([k, v]) => (
                    <tr key={k}><Td><code>{k}</code></Td><Td className="tabular-nums">{String(v)}</Td></tr>
                  ))}
                </tbody>
              </Table>
            </section>
          </div>
        )}
      </aside>
    </div>
  )
}

export function Alerts({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const [severity, setSeverity] = useState('')
  const [proto, setProto] = useState('')
  const [q, setQ] = useState('')
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const alerts = useApi(
    () => api.alerts({ severity, proto, q: search, offset, limit: PAGE }),
    [severity, proto, search, offset],
  )
  const info = useApi(() => api.modelInfo(), [])
  const protocols = info.data?.features.find((f) => f.name === 'proto')?.allowed_values ?? []

  return (
    <Card title="Alerts" subtitle="Created for flows the model labels Attack. Severity: high if P(attack) ≥ the configured cut-off, otherwise medium.">
      <form className="mb-4 flex flex-wrap items-start gap-3"
            onSubmit={(e) => { e.preventDefault(); setSearch(q); setOffset(0) }}>
        <Field label="Severity">
          <select className={inputClass} value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}>
            <option value="">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        </Field>
        <Field label="Protocol">
          <select className={inputClass} value={proto} onChange={(e) => { setProto(e.target.value); setOffset(0) }}>
            <option value="">All</option>
            {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </Field>
        <Field label="Search" hint="Protocol, destination port or alert id">
          <input className={inputClass} value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. 445" maxLength={64} />
        </Field>
        <FieldAction>
          <Button type="submit" variant="secondary">Search</Button>
        </FieldAction>
      </form>
      {alerts.error ? (
        <ErrorBlock error={alerts.error} onRetry={alerts.reload} />
      ) : !alerts.data ? (
        <Loading />
      ) : alerts.data.items.length === 0 ? (
        <Empty title={severity || proto || search ? 'No alerts match these filters' : 'No alerts yet'} />
      ) : (
        <>
          <AlertRows alerts={alerts.data.items} onOpen={onOpenAlert} />
          <Pagination offset={offset} limit={PAGE} total={alerts.data.total} onChange={setOffset} />
        </>
      )}
    </Card>
  )
}

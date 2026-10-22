import { api } from '../api/client'
import { Card, ErrorBlock, Loading, Notice, Pill, Table, Td, Th } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { formatNumber } from '../lib/format'

export function SystemInfo() {
  const health = useApi(() => api.health(), [])
  const info = useApi(() => api.modelInfo(), [])

  return (
    <div className="space-y-6">
      <Card title="Service health" actions={<button className="text-sm text-sky-300 hover:underline" onClick={health.reload}>Refresh</button>}>
        {health.error ? (
          <ErrorBlock error={health.error} onRetry={health.reload} />
        ) : !health.data ? (
          <Loading />
        ) : (
          <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div><dt className="text-slate-500">API</dt><dd className="mt-1"><Pill tone={health.data.status === 'ok' ? 'green' : 'amber'}>{health.data.status}</Pill>
              <span className="ml-2 text-slate-400">up {formatNumber(health.data.uptime_seconds)} s</span></dd></div>
            <div><dt className="text-slate-500">Model</dt><dd className="mt-1">{health.data.model.loaded
              ? <><Pill tone="green">loaded</Pill> <code className="ml-1 text-slate-300">{health.data.model.model_version}</code></>
              : <Pill tone="red">unavailable</Pill>}</dd>
              {health.data.model.error && <dd className="mt-1 text-xs text-rose-300">{health.data.model.error}</dd>}</div>
            <div><dt className="text-slate-500">Database</dt><dd className="mt-1"><Pill tone={health.data.database.ok ? 'green' : 'red'}>{health.data.database.ok ? 'ok' : 'error'}</Pill></dd></div>
            <div><dt className="text-slate-500">Explanations</dt><dd className="mt-1 text-slate-300">{health.data.explanations.description ?? '—'}</dd></div>
            <div className="sm:col-span-2 lg:col-span-4">
              <dt className="text-slate-500">Live inference</dt>
              <dd className="mt-1"><Pill tone="red">disabled</Pill> <span className="ml-2 text-slate-400">{health.data.live_inference.reason}</span></dd>
            </div>
          </dl>
        )}
      </Card>

      {info.error ? (
        <ErrorBlock error={info.error} onRetry={info.reload} />
      ) : !info.data ? (
        <Loading />
      ) : (
        <>
          <Card title="Model artifact">
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              {[
                ['Type', info.data.model_type],
                ['Version', info.data.model_version],
                ['File', info.data.artifact_file],
                ['SHA-256', info.data.artifact_sha256],
                ['scikit-learn', info.data.sklearn_version],
                ['Trees', String(info.data.n_estimators)],
                ['Classes', Object.entries(info.data.class_labels).map(([k, v]) => `${k} = ${v}`).join(', ')],
                ['Attack threshold', `P(attack) ≥ ${info.data.threshold}`],
              ].map(([k, v]) => (
                <div key={k}><dt className="text-slate-500">{k}</dt><dd className="mt-0.5 break-all text-slate-200">{v}</dd></div>
              ))}
            </dl>
            <h3 className="mb-2 mt-5 text-sm font-semibold text-slate-200">Severity rules</h3>
            <ul className="space-y-1 text-sm text-slate-300">
              {Object.entries(info.data.severity_rules).map(([k, v]) => <li key={k}><span className="capitalize text-slate-400">{k}:</span> {v}</li>)}
            </ul>
            <h3 className="mb-2 mt-5 text-sm font-semibold text-slate-200">Capabilities and limits</h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(info.data.capabilities).map(([k, v]) => (
                <Pill key={k} tone={v === false ? 'slate' : 'green'}>{k.replaceAll('_', ' ')}: {String(v)}</Pill>
              ))}
              {Object.entries(info.data.limits).map(([k, v]) => <Pill key={k} tone="sky">{k.replaceAll('_', ' ')}: {formatNumber(v)}</Pill>)}
            </div>
          </Card>

          <Card title="Input feature schema" subtitle="The exact 35 inputs, in the order the pipeline expects.">
            <Notice>Inputs marked “constant in training” were always 1 in the training data; they are required but never influence a prediction.</Notice>
            <div className="mt-3">
              <Table caption="Feature schema">
                <thead><tr><Th>#</Th><Th>Feature</Th><Th>Type</Th><Th>Allowed values</Th><Th>Note</Th></tr></thead>
                <tbody className="divide-y divide-slate-800">
                  {info.data.features.map((f) => (
                    <tr key={f.name}>
                      <Td className="tabular-nums text-slate-500">{f.position + 1}</Td>
                      <Td><code>{f.name}</code></Td>
                      <Td>{f.kind}</Td>
                      <Td className="whitespace-normal text-slate-400">{f.allowed_values?.join(', ') ?? 'number ≥ 0'}</Td>
                      <Td className="text-slate-400">{f.constant_in_training ? 'constant in training' : ''}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          </Card>
        </>
      )}
    </div>
  )
}

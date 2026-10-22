import { api } from '../api/client'
import { ConfusionMatrix, CurveChart, ImportanceChart } from '../components/charts'
import { Card, ErrorBlock, Loading, Notice, Pill, Stat, Table, Td, Th } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { formatPercent } from '../lib/format'

export function ModelPerformance() {
  const perf = useApi(() => api.performance(), [])
  const importance = useApi(() => api.importance(), [])

  if (perf.loading && !perf.data) return <Loading />
  if (perf.error) return <ErrorBlock error={perf.error} onRetry={perf.reload} />
  const p = perf.data!
  const v = p.verified
  const m = v.metrics.threshold_ge_0_5
  const alt = v.metrics.sklearn_predict_argmax
  const nb = p.notebook_reported

  return (
    <div className="space-y-6">
      <Notice>
        <p className="font-medium">Offline test-set metrics — not live operational statistics.</p>
        <p className="mt-1">{p.note} Split: <code>{v.methodology.split}</code>; {v.methodology.train_rows.toLocaleString()} training /{' '}
          {v.methodology.test_rows.toLocaleString()} test rows. Independent test set: <strong>{v.methodology.independent_test_set ? 'yes' : 'no'}</strong>.</p>
        {!p.matches_loaded_model && (
          <p className="mt-1 text-amber-200">Warning: these metrics were computed for a different model file than the one loaded.</p>
        )}
      </Notice>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Accuracy" value={formatPercent(m.accuracy, 2)} />
        <Stat label="Attack precision" value={formatPercent(m.attack_precision, 2)} />
        <Stat label="Attack recall" value={formatPercent(m.attack_recall, 2)} />
        <Stat label="Attack F1" value={formatPercent(m.attack_f1, 2)} />
        <Stat label="ROC-AUC" value={m.roc_auc.toFixed(4)} />
        <Stat label="Average precision" value={m.average_precision.toFixed(4)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Confusion matrix" subtitle={`Rule P(attack) ≥ ${p.application_threshold} (application default), n = ${v.methodology.test_rows.toLocaleString()}`}>
          <ConfusionMatrix cm={m.confusion_matrix} />
          <p className="mt-3 text-xs text-slate-400">
            With sklearn&apos;s <code>predict()</code> (exact 0.5 ties → Benign): accuracy {formatPercent(alt.accuracy, 2)}, precision{' '}
            {formatPercent(alt.attack_precision, 2)}, recall {formatPercent(alt.attack_recall, 2)} — the same model differing only on{' '}
            {String(v.integrity_checks.exact_probability_ties_at_0_5)} tied rows.
          </p>
        </Card>
        <Card title="Verification checks" subtitle={`Model ${v.model.model_version} · computed ${new Date(v.generated_at).toLocaleDateString()}`}>
          <Table caption="Integrity checks">
            <tbody className="divide-y divide-slate-800">
              {Object.entries(v.integrity_checks).map(([k, val]) => (
                <tr key={k}><Td className="text-slate-400">{k.replaceAll('_', ' ')}</Td><Td className="tabular-nums">{String(val)}</Td></tr>
              ))}
            </tbody>
          </Table>
          <p className="mt-3 text-xs text-slate-400">{v.methodology.note}</p>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="ROC curve" subtitle={`Random Forest, AUC ${m.roc_auc.toFixed(3)} (verified test-set points)`}>
          <CurveChart x={v.curves.roc.fpr} y={v.curves.roc.tpr} xLabel="False positive rate" yLabel="True positive rate" name="ROC" diagonal />
        </Card>
        <Card title="Precision–recall curve" subtitle={`Random Forest, AP ${m.average_precision.toFixed(3)} (verified test-set points)`}>
          <CurveChart x={v.curves.precision_recall.recall} y={v.curves.precision_recall.precision} xLabel="Recall" yLabel="Precision" name="Precision" />
        </Card>
      </div>

      {nb && (
        <Card title="Model comparison (from the training notebook)" subtitle={nb.description}>
          <Table caption="Model comparison">
            <thead>
              <tr><Th>Model</Th><Th>Accuracy</Th><Th>Precision</Th><Th>Recall</Th><Th>F1</Th><Th>ROC-AUC</Th><Th>AP</Th><Th>Status</Th></tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {nb.models.map((r) => (
                <tr key={r.model}>
                  <Td className="font-medium">{r.model}</Td>
                  <Td className="tabular-nums">{r.accuracy.toFixed(4)}</Td>
                  <Td className="tabular-nums">{r.attack_precision.toFixed(4)}</Td>
                  <Td className="tabular-nums">{r.attack_recall.toFixed(4)}</Td>
                  <Td className="tabular-nums">{r.attack_f1.toFixed(4)}</Td>
                  <Td className="tabular-nums">{r.roc_auc.toFixed(4)}</Td>
                  <Td className="tabular-nums">{r.average_precision.toFixed(4)}</Td>
                  <Td>{r.status === 'verified' ? <Pill tone="green">verified</Pill> : <Pill tone="amber">reported, not re-run</Pill>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <h3 className="mb-2 mt-5 text-sm font-semibold text-slate-200">Training time (seconds)</h3>
          <Table caption="Training time">
            <thead><tr><Th>Model</Th><Th>Printed in notebook output</Th><Th>Value in training-time chart</Th></tr></thead>
            <tbody className="divide-y divide-slate-800">
              {Object.keys(nb.training_time_seconds.printed_in_outputs).map((k) => (
                <tr key={k}>
                  <Td>{k}</Td>
                  <Td className="tabular-nums">{nb.training_time_seconds.printed_in_outputs[k].toFixed(2)}</Td>
                  <Td className="tabular-nums">{nb.training_time_seconds.chart_hardcoded[k]?.toFixed(2) ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <p className="mt-2 text-xs text-slate-400">{nb.training_time_seconds.note}</p>
          <p className="mt-2 text-xs text-slate-400">{nb.pcc_feature_selection_experiment.note}</p>
        </Card>
      )}

      <Card title="Global feature importance" subtitle={importance.data?.note ?? 'Describes the model overall, not any single prediction.'}>
        {importance.error ? (
          <ErrorBlock error={importance.error} onRetry={importance.reload} />
        ) : !importance.data ? (
          <Loading />
        ) : (
          <>
            <ImportanceChart items={importance.data.features.filter((f) => f.importance > 0).slice(0, 15)} />
            <p className="mt-2 text-xs text-slate-400">
              {importance.data.method}. One-hot columns are summed per input. Inputs with zero importance
              ({importance.data.features.filter((f) => f.importance === 0).length}) were constant in the training data.
            </p>
          </>
        )}
      </Card>
    </div>
  )
}

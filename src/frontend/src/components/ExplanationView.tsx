import type { Explanation, ExplanationStatus } from '../api/types'
import { chart } from '../lib/chartTheme'
import { Notice } from './ui'

function formatValue(v: number | string): string {
  if (typeof v === 'string') return v
  return Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, { maximumFractionDigits: 3 })
}

/** Local (per-prediction) explanation: which inputs moved this model's score up or down. */
export function ExplanationView({
  explanation,
  status,
  note,
}: {
  explanation: Explanation | null
  status: ExplanationStatus
  note?: string | null
}) {
  if (!explanation) {
    const message =
      status === 'deferred'
        ? 'Explanation not computed yet; open the alert to compute it.'
        : status === 'not_requested'
          ? 'No explanation was requested for this prediction.'
          : (note ?? 'No explanation is available.')
    return <p className="text-sm text-slate-400">{message}</p>
  }
  const max = Math.max(...explanation.contributions.map((c) => Math.abs(c.contribution)), 1e-9)
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">
        Local explanation · {explanation.method_description}. Model average P(attack) ={' '}
        <span className="tabular-nums text-slate-300">{explanation.base_value.toFixed(3)}</span> → this flow{' '}
        <span className="tabular-nums text-slate-300">{explanation.attack_probability.toFixed(3)}</span>
      </p>
      <ul className="space-y-1.5" aria-label="Feature contributions">
        {explanation.contributions.map((c) => {
          const width = `${(Math.abs(c.contribution) / max) * 50}%`
          const up = c.contribution >= 0
          return (
            <li key={c.feature} className="grid grid-cols-[minmax(7rem,10rem)_1fr_4.5rem] items-center gap-2 text-sm">
              <span className="truncate text-slate-300" title={`${c.feature} = ${formatValue(c.value)}`}>
                <code className="text-slate-200">{c.feature}</code>
                <span className="text-slate-500"> = {formatValue(c.value)}</span>
              </span>
              <div className="relative h-3 rounded bg-slate-800/60" aria-hidden>
                <div className="absolute inset-y-0 left-1/2 w-px bg-slate-600" />
                <div
                  className="absolute inset-y-0.5 rounded-sm"
                  style={{
                    width,
                    left: up ? '50%' : undefined,
                    right: up ? undefined : '50%',
                    background: up ? chart.towardAttack : chart.towardBenign,
                  }}
                />
              </div>
              <span className="text-right tabular-nums text-slate-300">
                {up ? '+' : '−'}
                {Math.abs(c.contribution).toFixed(3)}
              </span>
            </li>
          )
        })}
      </ul>
      <div className="flex flex-wrap gap-4 text-xs text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm" style={{ background: chart.towardAttack }} /> raises P(attack)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm" style={{ background: chart.towardBenign }} /> lowers P(attack)
        </span>
        {Math.abs(explanation.other_contribution) > 1e-9 && (
          <span>other features: {explanation.other_contribution >= 0 ? '+' : '−'}{Math.abs(explanation.other_contribution).toFixed(3)}</span>
        )}
      </div>
      <Notice>{explanation.disclaimer}</Notice>
    </div>
  )
}

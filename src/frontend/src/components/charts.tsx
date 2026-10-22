import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ConfusionMatrix as CM, TrendPoint } from '../api/types'
import { axisProps, chart } from '../lib/chartTheme'

const tooltipStyle = {
  contentStyle: {
    background: chart.tooltipBg,
    border: `1px solid ${chart.axis}`,
    borderRadius: 8,
    color: chart.text,
    fontSize: 12,
  },
  labelStyle: { color: chart.text },
  itemStyle: { color: chart.text },
}

function bucketLabel(iso: string, bucket: 'hour' | 'day') {
  const d = new Date(iso)
  return bucket === 'hour'
    ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export function TrendChart({ points, bucket }: { points: TrendPoint[]; bucket: 'hour' | 'day' }) {
  const data = points.map((p) => ({ ...p, label: bucketLabel(p.bucket_start, bucket) }))
  return (
    <div className="h-64" role="img" aria-label="Processed flows over time by predicted label">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid stroke={chart.grid} vertical={false} />
          <XAxis dataKey="label" {...axisProps} minTickGap={24} />
          <YAxis {...axisProps} allowDecimals={false} />
          <Tooltip {...tooltipStyle} />
          <Legend wrapperStyle={{ fontSize: 12, color: chart.muted }} />
          <Area type="monotone" dataKey="benign" name="Benign" stroke={chart.benign} fill={chart.benign}
                fillOpacity={0.15} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
          <Area type="monotone" dataKey="attack" name="Attack" stroke={chart.attack} fill={chart.attack}
                fillOpacity={0.15} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/** ROC or precision-recall curve from verified test-set points. */
export function CurveChart({
  x,
  y,
  xLabel,
  yLabel,
  name,
  diagonal,
}: {
  x: number[]
  y: number[]
  xLabel: string
  yLabel: string
  name: string
  diagonal?: boolean
}) {
  const data = x.map((xi, i) => ({ x: xi, y: y[i] }))
  const reference = diagonal ? [{ x: 0, ref: 0 }, { x: 1, ref: 1 }] : []
  return (
    <div className="h-64" role="img" aria-label={`${name} curve`}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart margin={{ top: 8, right: 12, bottom: 16, left: 0 }}>
          <CartesianGrid stroke={chart.grid} />
          <XAxis type="number" dataKey="x" domain={[0, 1]} {...axisProps}
                 label={{ value: xLabel, position: 'insideBottom', offset: -8, fill: chart.muted, fontSize: 12 }} />
          <YAxis type="number" domain={[0, 1]} {...axisProps}
                 label={{ value: yLabel, angle: -90, position: 'insideLeft', fill: chart.muted, fontSize: 12 }} />
          <Tooltip {...tooltipStyle} formatter={(v) => Number(v).toFixed(3)}
                   labelFormatter={(v) => `${xLabel}: ${Number(v).toFixed(3)}`} />
          {diagonal && (
            <Line data={reference} dataKey="ref" stroke={chart.muted} strokeDasharray="4 4"
                  dot={false} isAnimationActive={false} name="Chance" />
          )}
          <Line data={data} dataKey="y" name={name} stroke={chart.single} strokeWidth={2}
                dot={false} type="stepAfter" isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

export function ImportanceChart({ items }: { items: { feature: string; importance: number }[] }) {
  return (
    <div style={{ height: Math.max(items.length * 26, 120) }} role="img" aria-label="Global feature importance">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={items} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }} barCategoryGap={4}>
          <CartesianGrid stroke={chart.grid} horizontal={false} />
          <XAxis type="number" {...axisProps} />
          <YAxis type="category" dataKey="feature" {...axisProps} width={110} interval={0} />
          <Tooltip {...tooltipStyle} formatter={(v) => Number(v).toFixed(4)} cursor={{ fill: '#1e293b' }} />
          <Bar dataKey="importance" name="Importance" fill={chart.single} radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

/** 2x2 confusion matrix with one-hue sequential shading and printed counts. */
export function ConfusionMatrix({ cm }: { cm: CM }) {
  const max = Math.max(cm.tn, cm.fp, cm.fn, cm.tp)
  const cell = (value: number, label: string) => {
    const strength = 0.12 + 0.6 * (value / max)
    return (
      <div className="flex flex-col items-center justify-center rounded-lg p-3 ring-1 ring-inset ring-slate-800"
           style={{ background: `rgba(57, 135, 229, ${strength})` }}>
        <span className="text-xl font-semibold tabular-nums text-slate-50">{value.toLocaleString()}</span>
        <span className="text-xs text-slate-200">{label}</span>
      </div>
    )
  }
  return (
    <div className="grid grid-cols-[auto_1fr_1fr] gap-2 text-sm" role="table" aria-label="Confusion matrix">
      <div />
      <div className="text-center text-xs text-slate-400">Predicted Benign</div>
      <div className="text-center text-xs text-slate-400">Predicted Attack</div>
      <div className="flex items-center pr-2 text-xs text-slate-400">Actual Benign</div>
      {cell(cm.tn, 'true negative')}
      {cell(cm.fp, 'false positive')}
      <div className="flex items-center pr-2 text-xs text-slate-400">Actual Attack</div>
      {cell(cm.fn, 'false negative')}
      {cell(cm.tp, 'true positive')}
    </div>
  )
}

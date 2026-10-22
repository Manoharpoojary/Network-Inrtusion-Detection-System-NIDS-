import { useState } from 'react'
import { api } from '../api/client'
import type { Alert } from '../api/types'
import { TrendChart } from '../components/charts'
import {
  Button,
  Card,
  Empty,
  ErrorBlock,
  LabelBadge,
  Loading,
  Notice,
  SeverityBadge,
  Stat,
  Table,
  Td,
  Th,
} from '../components/ui'
import { useApi } from '../hooks/useApi'
import { formatDateTime, formatNumber, formatPercent } from '../lib/format'

export function AlertRows({ alerts, onOpen }: { alerts: Alert[]; onOpen?: (id: number) => void }) {
  return (
    <Table caption="Alerts">
      <thead>
        <tr>
          <Th>Time</Th>
          <Th>Severity</Th>
          <Th>Label</Th>
          <Th>P(attack)</Th>
          <Th>Protocol</Th>
          <Th>Dst port</Th>
          <Th>Source</Th>
          {onOpen && <Th className="sr-only">Open</Th>}
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-800">
        {alerts.map((a) => (
          <tr key={a.id} className="hover:bg-slate-800/40">
            <Td className="text-slate-400">{formatDateTime(a.created_at)}</Td>
            <Td><SeverityBadge severity={a.severity} /></Td>
            <Td><LabelBadge label={a.label} /></Td>
            <Td className="tabular-nums">{a.attack_probability.toFixed(2)}</Td>
            <Td>{a.proto ?? '—'}</Td>
            <Td className="tabular-nums">{a.dport ?? '—'}</Td>
            <Td className="text-slate-400">{a.filename ?? a.source}</Td>
            {onOpen && (
              <Td>
                <Button variant="secondary" className="px-2 py-1 text-xs" onClick={() => onOpen(a.id)}>
                  Details
                </Button>
              </Td>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  )
}

export function Overview({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const [bucket, setBucket] = useState<'hour' | 'day'>('hour')
  const summary = useApi(() => api.summary(), [])
  const trends = useApi(() => api.trends(bucket), [bucket])

  if (summary.loading && !summary.data) return <Loading />
  if (summary.error) return <ErrorBlock error={summary.error} onRetry={summary.reload} />
  const s = summary.data!

  return (
    <div className="space-y-6">
      <Notice>{s.scope}</Notice>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Processed flows" value={formatNumber(s.total_processed)}
              hint={`${formatNumber(s.analyses)} submissions`} />
        <Stat label="Predicted attack" value={formatNumber(s.attack)} tone={s.attack ? 'danger' : 'default'} />
        <Stat label="Predicted benign" value={formatNumber(s.benign)} tone="ok" />
        <Stat label="Attack share" value={formatPercent(s.attack_share)}
              hint="Share of processed flows labelled Attack — not a detection rate" />
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Alerts" value={formatNumber(s.alerts.total)} hint={`${formatNumber(s.alerts.open)} open`} />
        <Stat label="High severity" value={formatNumber(s.alerts.by_severity.high)}
              tone={s.alerts.by_severity.high ? 'danger' : 'default'} />
        <Stat label="Medium severity" value={formatNumber(s.alerts.by_severity.medium)}
              tone={s.alerts.by_severity.medium ? 'warn' : 'default'} />
        <Stat label="Last processed" value={<span className="text-base">{formatDateTime(s.last_processed_at)}</span>} />
      </div>

      <Card
        title="Processed flows over time"
        subtitle={trends.data?.note}
        actions={
          <div className="flex gap-1" role="group" aria-label="Time bucket">
            {(['hour', 'day'] as const).map((b) => (
              <Button key={b} variant={b === bucket ? 'primary' : 'secondary'} className="px-2 py-1 text-xs"
                      aria-pressed={b === bucket} onClick={() => setBucket(b)}>
                {b === 'hour' ? 'Last 24 h' : 'Last 30 days'}
              </Button>
            ))}
          </div>
        }
      >
        {trends.error ? (
          <ErrorBlock error={trends.error} onRetry={trends.reload} />
        ) : !trends.data ? (
          <Loading />
        ) : trends.data.points.every((p) => p.benign + p.attack === 0) ? (
          <Empty title="No flows processed in this period">Upload a CSV on the Analyze page.</Empty>
        ) : (
          <TrendChart points={trends.data.points} bucket={bucket} />
        )}
      </Card>

      <Card title="Recent alerts" subtitle="Newest first. Severity is a configurable rule on the model score, not verified risk.">
        {s.recent_alerts.length === 0 ? (
          <Empty title="No alerts yet">Alerts are created for flows the model labels Attack.</Empty>
        ) : (
          <AlertRows alerts={s.recent_alerts} onOpen={onOpenAlert} />
        )}
      </Card>
    </div>
  )
}

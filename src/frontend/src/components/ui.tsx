import { AlertTriangle, Info, Loader2, RefreshCw, ShieldAlert } from 'lucide-react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import type { ApiError } from '../api/client'
import type { Label, Severity } from '../api/types'
import { cx } from '../lib/cx'

export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cx('rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5', className)}>
      {(title || actions) && (
        <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            {title && <h2 className="text-base font-semibold text-slate-100">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-sm text-slate-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  )
}

export function Stat({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: 'default' | 'danger' | 'ok' | 'warn'
}) {
  const toneClass = {
    default: 'text-slate-100',
    danger: 'text-rose-300',
    ok: 'text-emerald-300',
    warn: 'text-amber-300',
  }[tone]
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</p>
      <p className={cx('mt-2 text-2xl font-semibold tabular-nums', toneClass)}>{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-400">{hint}</p>}
    </div>
  )
}

const SEVERITY_STYLES: Record<Severity, string> = {
  high: 'bg-rose-500/15 text-rose-200 ring-rose-500/40',
  medium: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  informational: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset',
        SEVERITY_STYLES[severity],
      )}
    >
      {severity}
    </span>
  )
}

export function LabelBadge({ label }: { label: Label | string }) {
  const attack = label === 'Attack'
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset',
        attack
          ? 'bg-rose-500/15 text-rose-200 ring-rose-500/40'
          : 'bg-emerald-500/15 text-emerald-200 ring-emerald-500/40',
      )}
    >
      {attack && <ShieldAlert aria-hidden className="h-3 w-3" />}
      {label}
    </span>
  )
}

export function Pill({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'green' | 'red' | 'amber' | 'sky' }) {
  const t = {
    slate: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
    green: 'bg-emerald-500/15 text-emerald-200 ring-emerald-500/40',
    red: 'bg-rose-500/15 text-rose-200 ring-rose-500/40',
    amber: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
    sky: 'bg-sky-500/15 text-sky-200 ring-sky-500/40',
  }[tone]
  return (
    <span className={cx('inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset', t)}>
      {children}
    </span>
  )
}

export function Button({
  children,
  variant = 'primary',
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' }) {
  const v = {
    primary: 'bg-sky-600 text-white hover:bg-sky-500 focus-visible:outline-sky-400',
    secondary:
      'bg-slate-800 text-slate-100 hover:bg-slate-700 ring-1 ring-inset ring-slate-700 focus-visible:outline-slate-400',
    danger: 'bg-rose-600 text-white hover:bg-rose-500 focus-visible:outline-rose-400',
  }[variant]
  return (
    <button
      type="button"
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition',
        'focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
        v,
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-8 text-sm text-slate-400">
      <Loader2 aria-hidden className="h-4 w-4 animate-spin" />
      {label}
    </div>
  )
}

export function ErrorBlock({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm">
      <div className="flex items-start gap-2 text-rose-200">
        <AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="min-w-0">
          <p className="font-medium">{error.message}</p>
          <p className="mt-0.5 text-xs text-rose-300/80">code: {error.code}</p>
          {error.details.length > 0 && (
            <ul className="mt-2 max-h-48 list-disc space-y-0.5 overflow-auto pl-4 text-xs text-rose-100/90">
              {error.details.slice(0, 50).map((d, i) => (
                <li key={i}>
                  {d.csv_line ? `line ${d.csv_line}: ` : d.row !== null && d.row !== undefined ? `row ${d.row}: ` : ''}
                  {d.field || d.location ? <code>{d.field ?? d.location}</code> : null}
                  {d.field || d.location ? ' — ' : ''}
                  {d.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      {onRetry && (
        <Button variant="secondary" className="mt-3" onClick={onRetry}>
          <RefreshCw aria-hidden className="h-4 w-4" /> Retry
        </Button>
      )}
    </div>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center">
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {children && <div className="mt-1 text-sm text-slate-400">{children}</div>}
    </div>
  )
}

export function Notice({
  children,
  tone = 'info',
}: {
  children: ReactNode
  tone?: 'info' | 'warn'
}) {
  const styles =
    tone === 'warn'
      ? 'border-amber-500/40 bg-amber-500/10 text-amber-100'
      : 'border-sky-500/30 bg-sky-500/10 text-sky-100'
  const Icon = tone === 'warn' ? AlertTriangle : Info
  return (
    <div className={cx('flex gap-2 rounded-lg border p-3 text-sm', styles)}>
      <Icon aria-hidden className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0">{children}</div>
    </div>
  )
}

export function Table({ children, caption }: { children: ReactNode; caption?: string }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        {children}
      </table>
    </div>
  )
}

export const Th = ({ children, className }: { children?: ReactNode; className?: string }) => (
  <th scope="col" className={cx('whitespace-nowrap bg-slate-900 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400', className)}>
    {children}
  </th>
)

export const Td = ({ children, className }: { children?: ReactNode; className?: string }) => (
  <td className={cx('whitespace-nowrap px-3 py-2 text-slate-200', className)}>{children}</td>
)

export function Pagination({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number
  limit: number
  total: number
  onChange: (offset: number) => void
}) {
  if (total <= limit) return null
  const page = Math.floor(offset / limit) + 1
  const pages = Math.ceil(total / limit)
  return (
    <nav aria-label="Pagination" className="mt-3 flex items-center justify-between text-sm text-slate-400">
      <span>
        {offset + 1}–{Math.min(offset + limit, total)} of {total.toLocaleString()}
      </span>
      <div className="flex gap-2">
        <Button variant="secondary" disabled={page <= 1} onClick={() => onChange(Math.max(0, offset - limit))}>
          Previous
        </Button>
        <Button variant="secondary" disabled={page >= pages} onClick={() => onChange(offset + limit)}>
          Next
        </Button>
      </div>
    </nav>
  )
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="font-medium text-slate-300">{label}</span>
      {children}
      {hint && <span className="text-xs text-slate-500">{hint}</span>}
    </label>
  )
}

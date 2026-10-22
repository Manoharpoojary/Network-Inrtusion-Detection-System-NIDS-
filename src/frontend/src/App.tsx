import { Bell, BrainCircuit, FileSpreadsheet, LayoutDashboard, Network as NetworkIcon, Server, Shield } from 'lucide-react'
import { Suspense, lazy, useCallback, useEffect, useState } from 'react'
import { api } from './api/client'
import { cx } from './lib/cx'
import { useApi, usePolling } from './hooks/useApi'
import { Loading } from './components/ui'

// Each page is a separate chunk; chart code only loads on pages that use it.
const Overview = lazy(() => import('./pages/Overview').then((m) => ({ default: m.Overview })))
const Analyze = lazy(() => import('./pages/Analyze').then((m) => ({ default: m.Analyze })))
const Alerts = lazy(() => import('./pages/Alerts').then((m) => ({ default: m.Alerts })))
const AlertDetailPanel = lazy(() => import('./pages/Alerts').then((m) => ({ default: m.AlertDetailPanel })))
const ModelPerformance = lazy(() => import('./pages/ModelPerformance').then((m) => ({ default: m.ModelPerformance })))
const Network = lazy(() => import('./pages/Network').then((m) => ({ default: m.Network })))
const SystemInfo = lazy(() => import('./pages/SystemInfo').then((m) => ({ default: m.SystemInfo })))

const PAGES = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'analyze', label: 'Analyze', icon: FileSpreadsheet },
  { id: 'alerts', label: 'Alerts', icon: Bell },
  { id: 'model', label: 'Model performance', icon: BrainCircuit },
  { id: 'network', label: 'Network & capture', icon: NetworkIcon },
  { id: 'system', label: 'System', icon: Server },
] as const

type PageId = (typeof PAGES)[number]['id']

function currentPage(): PageId {
  const id = window.location.hash.replace(/^#\/?/, '')
  return (PAGES.find((p) => p.id === id)?.id ?? 'overview') as PageId
}

function HealthIndicator() {
  const health = useApi(() => api.health(), [])
  usePolling(health.reload, 30_000, true)
  const ok = health.data?.status === 'ok'
  const label = health.error ? 'API unreachable' : !health.data ? 'Checking…' : ok ? 'API healthy' : 'API degraded'
  return (
    <span className="flex items-center gap-2 text-xs text-slate-400" role="status">
      <span aria-hidden className={cx('h-2 w-2 rounded-full', health.error ? 'bg-rose-500' : !health.data ? 'bg-slate-500' : ok ? 'bg-emerald-500' : 'bg-amber-500')} />
      {label}
    </span>
  )
}

export default function App() {
  const [page, setPage] = useState<PageId>(currentPage)
  const [alertId, setAlertId] = useState<number | null>(null)

  useEffect(() => {
    const onHash = () => setPage(currentPage())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const openAlert = useCallback((id: number) => setAlertId(id), [])
  const closeAlert = useCallback(() => setAlertId(null), [])
  const active = PAGES.find((p) => p.id === page)!

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 lg:flex">
      <aside className="border-b border-slate-800 bg-slate-950 lg:sticky lg:top-0 lg:h-screen lg:w-60 lg:shrink-0 lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-2 px-4 py-4">
          <Shield aria-hidden className="h-6 w-6 text-sky-400" />
          <div>
            <p className="text-sm font-semibold leading-tight">IoT Intrusion Detection</p>
            <p className="text-xs text-slate-500">Random Forest · flow features</p>
          </div>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-2 pb-2 lg:flex-col lg:overflow-visible lg:pb-0">
          {PAGES.map((p) => (
            <a
              key={p.id}
              href={`#/${p.id}`}
              aria-current={p.id === page ? 'page' : undefined}
              className={cx(
                'flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-sm transition',
                p.id === page ? 'bg-sky-500/15 text-sky-200' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100',
              )}
            >
              <p.icon aria-hidden className="h-4 w-4" />
              {p.label}
            </a>
          ))}
        </nav>
      </aside>

      <main className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-3 sm:px-6">
          <h1 className="text-lg font-semibold">{active.label}</h1>
          <HealthIndicator />
        </header>
        <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
          <Suspense fallback={<Loading />}>
          {page === 'overview' && <Overview onOpenAlert={openAlert} />}
          {page === 'analyze' && <Analyze />}
          {page === 'alerts' && <Alerts onOpenAlert={openAlert} />}
          {page === 'model' && <ModelPerformance />}
          {page === 'network' && <Network />}
          {page === 'system' && <SystemInfo />}
          </Suspense>
        </div>
      </main>
      {alertId !== null && (
        <Suspense fallback={null}>
          <AlertDetailPanel alertId={alertId} onClose={closeAlert} />
        </Suspense>
      )}
    </div>
  )
}

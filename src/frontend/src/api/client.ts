import type {
  Alert,
  AlertDetail,
  Analysis,
  CaptureCheckResponse,
  CsvAnalysis,
  DashboardSummary,
  FeatureMapping,
  GlobalImportance,
  Health,
  InterfacesResponse,
  LiveStatus,
  ModelInfo,
  NetworkRun,
  Page,
  Performance,
  Prediction,
  PredictionRow,
  Trends,
  ErrorDetail,
} from './types'

/** An error returned by the API ({error: {code, message, details}}) or by the network. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: ErrorDetail[]

  constructor(status: number, code: string, message: string, details: ErrorDetail[] = []) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }
}

type Query = Record<string, string | number | boolean | null | undefined>

export function buildUrl(path: string, query?: Query): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

export async function parseError(response: Response): Promise<ApiError> {
  let body: unknown = null
  try {
    body = await response.json()
  } catch {
    // not JSON (e.g. proxy error page)
  }
  const err = (body as { error?: { code?: string; message?: string; details?: ErrorDetail[] } })
    ?.error
  if (err?.code) {
    return new ApiError(response.status, err.code, err.message ?? 'Request failed', err.details ?? [])
  }
  if (response.status === 502 || response.status === 504) {
    return new ApiError(response.status, 'backend_unreachable', 'The backend API is not reachable.')
  }
  return new ApiError(response.status, 'http_error', `Request failed (HTTP ${response.status}).`)
}

async function request<T>(path: string, init?: RequestInit & { query?: Query }): Promise<T> {
  let response: Response
  try {
    response = await fetch(buildUrl(path, init?.query), init)
  } catch {
    throw new ApiError(0, 'network_error', 'Could not reach the backend API. Is it running?')
  }
  if (!response.ok) throw await parseError(response)
  return (await response.json()) as T
}

function postJson<T>(path: string, body?: unknown, headers?: Record<string, string>, query?: Query) {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
    query,
  })
}

function upload<T>(path: string, file: File, query?: Query) {
  const form = new FormData()
  form.append('file', file)
  return request<T>(path, { method: 'POST', body: form, query })
}

export interface AlertQuery {
  severity?: string
  status?: string
  proto?: string
  q?: string
  since?: string
  analysis_id?: string
  offset?: number
  limit?: number
}

export const api = {
  health: () => request<Health>('/api/health'),
  modelInfo: () => request<ModelInfo>('/api/model/info'),
  importance: () => request<GlobalImportance>('/api/model/importance'),
  performance: () => request<Performance>('/api/model/performance'),

  predict: (record: Record<string, unknown>) => postJson<Prediction>('/api/predict', record),

  analyzeCsv: (file: File, ignoreExtraColumns: boolean) =>
    upload<CsvAnalysis>('/api/analyze/csv', file, { ignore_extra_columns: ignoreExtraColumns }),
  analyses: (offset = 0, limit = 20) =>
    request<Page<Analysis>>('/api/analyses', { query: { offset, limit } }),
  analysisPredictions: (id: string, label: string | undefined, offset: number, limit: number) =>
    request<Page<PredictionRow>>(`/api/analyses/${encodeURIComponent(id)}/predictions`, {
      query: { label, offset, limit },
    }),
  exportUrl: (id: string, label?: string) =>
    buildUrl(`/api/analyses/${encodeURIComponent(id)}/export.csv`, { label }),

  alerts: (query: AlertQuery) => request<Page<Alert>>('/api/alerts', { query: { ...query } }),
  alert: (id: number) => request<AlertDetail>(`/api/alerts/${id}`),

  summary: () => request<DashboardSummary>('/api/dashboard/summary'),
  trends: (bucket: 'hour' | 'day') => request<Trends>('/api/dashboard/trends', { query: { bucket } }),

  interfaces: () => request<InterfacesResponse>('/api/network/interfaces'),
  captureCheck: (iface?: string) =>
    postJson<CaptureCheckResponse>('/api/network/capture-check', undefined, undefined, {
      interface: iface,
    }),
  featureMapping: () => request<FeatureMapping>('/api/network/feature-mapping'),
  analyzePcap: (file: File) => upload<NetworkRun>('/api/network/pcap', file),
  networkRuns: () => request<Page<NetworkRun>>('/api/network/runs', { query: { limit: 20 } }),
  networkRun: (id: string) => request<NetworkRun>(`/api/network/runs/${encodeURIComponent(id)}`),

  liveStatus: () => request<LiveStatus>('/api/network/live/status'),
  liveStart: (
    body: { interface: string; bpf_filter?: string; max_duration_seconds?: number; authorized: boolean },
    token?: string,
  ) => postJson<LiveStatus>('/api/network/live/start', body, token ? { 'X-Capture-Token': token } : {}),
  liveReset: (token?: string) =>
    postJson<LiveStatus>('/api/network/live/reset', undefined, token ? { 'X-Capture-Token': token } : {}),
  liveStop: (token?: string) =>
    postJson<LiveStatus>('/api/network/live/stop', undefined, token ? { 'X-Capture-Token': token } : {}),
}

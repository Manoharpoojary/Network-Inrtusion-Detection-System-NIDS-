// Types mirroring the FastAPI response models (src/major_project/schemas/api.py and network routes).

export type Severity = 'informational' | 'medium' | 'high'
export type Label = 'Benign' | 'Attack'

export interface ErrorDetail {
  row?: number | null
  csv_line?: number | null
  field?: string | null
  location?: string
  message: string
}

export interface Page<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

export interface Contribution {
  feature: string
  value: number | string
  contribution: number
}

export interface Explanation {
  scope: 'local'
  method: string
  method_description: string
  base_value: number
  attack_probability: number
  contributions: Contribution[]
  other_contribution: number
  disclaimer: string
}

export type ExplanationStatus = 'included' | 'deferred' | 'not_requested' | 'unavailable'

export interface Prediction {
  prediction_id: number
  analysis_id: string
  flow_index: number
  label: Label
  label_id: number
  is_attack: boolean
  attack_probability: number
  benign_probability: number
  threshold: number
  severity: Severity
  alert_id: number | null
  model_version: string
  processed_at: string
  warnings: string[]
  explanation: Explanation | null
  explanation_status: ExplanationStatus
}

export interface SeverityCounts {
  medium: number
  high: number
}

export interface PredictionSummary {
  total: number
  benign: number
  attack: number
  alerts: SeverityCounts
}

export interface Analysis {
  id: string
  source: string
  filename: string | null
  status: string
  created_at: string
  completed_at: string | null
  total_records: number
  benign_count: number
  attack_count: number
  alert_count: number
  model_version: string
  threshold: number
  ignored_columns: string[]
}

export interface PredictionRow {
  prediction_id: number
  row_index: number
  label: Label
  attack_probability: number
  severity: Severity
  alert_id: number | null
  proto: string | null
  flgs: string | null
  sport: number | null
  dport: number | null
  pkts: number | null
  bytes: number | null
  dur: number | null
  processed_at: string
}

export interface CsvAnalysis {
  analysis: Analysis
  summary: PredictionSummary
  predictions: PredictionRow[]
  predictions_truncated: boolean
  results_url: string
  export_url: string
}

export interface Alert {
  id: number
  analysis_id: string
  prediction_id: number
  flow_index: number
  created_at: string
  severity: Severity
  status: string
  label: Label
  attack_probability: number
  model_version: string
  proto: string | null
  dport: number | null
  source: string
  filename: string | null
}

export interface AlertDetail extends Alert {
  features: Record<string, number | string>
  explanation: Explanation | null
  explanation_status: ExplanationStatus
  explanation_note: string | null
}

export interface DashboardSummary {
  scope: string
  total_processed: number
  benign: number
  attack: number
  attack_share: number | null
  alerts: { total: number; open: number; by_severity: SeverityCounts }
  analyses: number
  by_source: Record<string, number>
  last_processed_at: string | null
  recent_alerts: Alert[]
}

export interface TrendPoint {
  bucket_start: string
  benign: number
  attack: number
  alerts_medium: number
  alerts_high: number
}

export interface Trends {
  bucket: 'hour' | 'day'
  since: string
  until: string
  note: string
  points: TrendPoint[]
}

export interface Health {
  status: 'ok' | 'degraded'
  time: string
  uptime_seconds: number
  model: { loaded: boolean; error: string | null; model_version?: string }
  database: { ok: boolean; detail: string | null }
  explanations: { method: string | null; description: string | null }
  live_inference: { enabled: boolean; reason: string }
}

export interface FeatureSpec {
  position: number
  name: string
  kind: 'numeric' | 'categorical'
  allowed_values: string[] | null
  constant_in_training: boolean
  note: string | null
}

export interface ModelInfo {
  model_type: string
  model_version: string
  artifact_file: string
  artifact_sha256: string
  sklearn_version: string
  n_estimators: number
  class_labels: Record<string, string>
  threshold: number
  severity_rules: Record<string, string>
  capabilities: Record<string, boolean | string>
  limits: Record<string, number>
  features: FeatureSpec[]
}

export interface GlobalImportance {
  scope: 'global'
  method: string
  note: string
  features: { feature: string; importance: number }[]
}

export interface ConfusionMatrix {
  tn: number
  fp: number
  fn: number
  tp: number
}

export interface MetricSet {
  confusion_matrix: ConfusionMatrix
  accuracy: number
  attack_precision: number
  attack_recall: number
  attack_f1: number
  benign_recall: number
  false_positive_rate: number
  roc_auc: number
  average_precision: number
}

export interface NotebookModelRow {
  model: string
  accuracy: number
  attack_precision: number
  attack_recall: number
  attack_f1: number
  roc_auc: number
  average_precision: number
  status: 'verified' | 'reported_not_reverified'
}

export interface Performance {
  scope: 'offline_test_set'
  note: string
  matches_loaded_model: boolean
  application_threshold: number
  verified: {
    generated_at: string
    description: string
    model: { file: string; sha256: string; model_version: string }
    dataset: { file: string; source: string; rows: number; class_counts: Record<string, number> }
    methodology: {
      split: string
      train_rows: number
      test_rows: number
      independent_test_set: boolean
      note: string
    }
    integrity_checks: Record<string, number | boolean>
    metrics: { threshold_ge_0_5: MetricSet; sklearn_predict_argmax: MetricSet }
    curves: {
      roc: { fpr: number[]; tpr: number[] }
      precision_recall: { precision: number[]; recall: number[] }
    }
  }
  notebook_reported: {
    description: string
    models: NotebookModelRow[]
    training_time_seconds: {
      note: string
      printed_in_outputs: Record<string, number>
      chart_hardcoded: Record<string, number>
    }
    pcc_feature_selection_experiment: { note: string; accuracy: Record<string, number> }
  } | null
}

// ------------------------------------------------------------------ network

export interface NetworkInterface {
  name: string
  description: string | null
  is_up: boolean | null
  speed_mbps: number | null
  mtu: number | null
  is_loopback: boolean
  is_wireless: boolean
  has_ipv4: boolean | null
  visible_to_scapy: boolean
  counters: {
    bytes_sent: number
    bytes_recv: number
    packets_sent: number
    packets_recv: number
    errors_in: number
    errors_out: number
    drops_in: number
    drops_out: number
  } | null
}

export interface DriverStatus {
  name: string
  available: boolean
  version: string | null
  service_running: boolean | null
  admin_only: boolean | null
  loopback_support: boolean | null
  message: string | null
}

export interface InterfacesResponse {
  interfaces: NetworkInterface[]
  scapy: { available: boolean; version: string | null; error_code: string | null; message: string | null }
  driver: DriverStatus | null
  platform: { system: string; release: string; is_wsl: boolean; is_admin: boolean | null }
  notes: string[]
  capture_note: string
}

export interface CaptureCheckResponse {
  capture_check: { status: string; interface: string | null; error_code: string | null; message: string | null }
}

export type FeatureStatus = 'derived' | 'approximated' | 'incompatible' | 'not_computed'

export interface FeatureRule {
  feature: string
  status: FeatureStatus
  method: string
  reason: string
  flows_with_value?: number
  training_range_p01_p99?: [number, number]
  share_within_training_range?: number | null
  share_with_training_category?: number | null
}

export interface InvariantComparison {
  invariant: string
  rule: string
  training_share: number | null
  extracted_share: number | null
}

export interface CompatibilityReport {
  compatible: boolean
  verdict: string
  flows_analyzed: number
  blocking_features: string[]
  status_counts: Partial<Record<FeatureStatus, number>>
  features?: FeatureRule[]
  invariants: InvariantComparison[]
  schema_validation: {
    checked: boolean
    passed: boolean
    rows_checked: number
    errors_by_feature: Record<string, number>
  }
  inference_gate?: { allowed: boolean; reasons: string[] }
}

export interface ObservedFlow {
  transport: string
  sport: number
  dport: number
  first_seen_utc: string
  dur: number
  pkts: number
  bytes: number
  spkts: number
  dpkts: number
  sbytes: number
  dbytes: number
  pkt_len_min: number
  pkt_len_max: number
  pkt_len_mean: number
  tcp_flags_seen: string
  end_reason: string
}

export interface FlowSample {
  observed: ObservedFlow
  model_features: Record<string, number | string | null>
}

export interface NetworkRun {
  id: string
  kind: 'pcap' | 'live'
  filename: string | null
  status: string
  created_at: string
  completed_at: string | null
  packets_read: number
  ip_packets: number
  non_ip_packets: number
  malformed_packets: number
  dropped_packets: number
  flows_extracted: number
  compatible: boolean
  stats: Record<string, number | string | boolean | null>
  report?: CompatibilityReport & {
    flow_sample?: FlowSample[]
    predictions: null
    predictions_note: string
  }
}

export interface FeatureMapping {
  features: FeatureRule[]
  training_invariants: Record<string, { rule: string; share: number }> | null
  flow_definition: Record<string, string | number>
}

export type CaptureState = 'stopped' | 'starting' | 'running' | 'stopping' | 'error'

export interface LiveStatus {
  state: CaptureState
  session: {
    id: string
    interface: string
    bpf_filter: string | null
    started_at: string
    stopped_at: string | null
    elapsed_seconds: number
    max_duration_seconds: number
    stop_reason: string | null
    error: { code: string; message: string } | null
    counters: Record<string, number>
    queue: { depth: number; capacity: number }
    active_flows: number
  } | null
  recent_flows?: FlowSample[]
  compatibility?: CompatibilityReport | null
  predictions?: null
  live_inference: { enabled: boolean; gate_allowed: boolean; reasons: string[]; note: string }
}

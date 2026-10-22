# Live / PCAP Feature Compatibility

Status (2026-10-22): **not compatible. Model scoring of extracted flows is disabled.**

This document explains why flows extracted from real packets cannot be scored by the trained Random
Forest. It also describes how the application demonstrates and enforces that.

## 1. What the model expects

The pipeline takes the dataset's 35 flow features (`GET /api/model/info`). Analysis of the training
split (`scripts/build_training_reference.py` → `src/major_project/evaluation/training_reference.json`)
shows these definitions hold on **every** training row:

| Invariant | Training rows satisfying it |
|---|---|
| `spkts == dpkts` | 100 % |
| `spkts == pkts // 2` | 100 % |
| `sbytes == dbytes == bytes // 2` | 100 % |
| `srate == drate` | 100 % |
| `sum == bytes` | 100 % |
| `mean == bytes / pkts` | 100 % |
| `rate == bytes / dur` (bytes per second) | 100 % |
| `min <= mean <= max` | **76.3 %**: impossible for packet sizes on the other 23.7 % |

- `flgs` is fixed by protocol: TCP→`PA`, UDP→`U`, ICMP→`S`.
- Every application label maps to one destination port (SMB uses 139/445; "TCP" uses 445).
- `flgs_number` and 14 per-host/protocol aggregates are always `1`.

## 2. How each input can be produced from packets

The extractor (`services/flow_features.py`) builds bidirectional 5-tuple flows from packet headers:

- Idle timeout 60 s, active timeout 300 s, on-the-wire byte counts. These are configurable, and
  the training data's own window is unknown.
- The first sender is the source.

`services/compatibility.py` then assigns each model input one of four statuses:

| Status | Features | Value sent to validation |
|---|---|---|
| **derived**: same formula as training | `proto_number, sport, dport, pkts, bytes, dur, mean, sum, rate` | measured value |
| **approximated**: heuristic | `proto` (label from destination port; empty for port 445 and unknown ports) | label or empty |
| **incompatible** | `flgs, spkts, dpkts, sbytes, dbytes, srate, drate, min, max, stddev` | **empty** |
| **not_computed** | `flgs_number` + 14 aggregates (constant 1 in training) | **empty** |

Empty values are never filled. Writing `pkts // 2` into `spkts`, or `1` into the aggregates, would
make records *look* valid while carrying invented data.

## 3. How incompatibility is demonstrated

`POST /api/network/pcap` returns, for every analysed capture:

1. **Per-feature table:** status, method, reason, how many flows have a value, the training range,
   and the share of measured values inside it.
2. **Invariant comparison:** for each training invariant, the training share (1.0) next to the share
   of extracted flows that satisfy it. On the synthetic test capture, `spkts == dpkts` holds for
   0 % of TCP flows.
3. **Schema validation:** the candidate records are passed to the same validator used by the API.
   They fail with "missing value" errors for every empty feature, so they cannot reach the model.
4. **Inference gate:** `allowed` only if the report is compatible **and**
   `NIDS_LIVE_INFERENCE_ENABLED=true`. Tests confirm the gate stays closed even when the flag is on.

## 4. Verified so far

| Item | Evidence |
|---|---|
| Flow extraction, timeouts, eviction accounting, malformed / non-IP / truncated-record counting | `tests/test_flow_features.py`, `tests/test_network_api.py` (synthetic packets and PCAPs) |
| No IP/MAC addresses in API responses or the database | asserted in `tests/test_network_api.py` |
| Incompatible features never filled; gate closed | asserted in tests |
| Npcap 1.90 present; a non-admin capture socket opens on Wi-Fi | `python -m major_project.services.capture_diagnostics` (2026-10-22) |

**Not verified:** analysis of a real traffic capture from this machine. No real PCAP has been
processed yet, and live capture has not been run. The incompatibility verdict above follows from the
feature definitions and does not depend on the traffic.

## 5. What would make live inference possible

Live inference would need a model trained on features that the extractor actually computes from
packets: per-direction counts, packet-size statistics and real TCP flags. That means retraining. It
is a change to the production model and **requires the project owner's explicit approval**.

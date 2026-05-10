# Performance Budgets

> Generated: 2026-05-10T00:48:04Z

> Run ID: bd-2zcs5.51-darkgoose-20260510T0021Z

## Summary

| Metric | Value |
|---|---|
| Total budgets | 13 |
| CI-enforced | 8 |
| CI-enforced with data | 8 |
| CI-enforced FAIL | 0 |
| CI-enforced NO_DATA | 0 |
| PASS | 11 |
| FAIL | 0 |
| No data | 2 |

| Failing data contracts | 2 |

## Startup

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `startup_version_p95` | p95 latency | 100 ms | 2.3 | PASS | Yes |
| `startup_full_agent_p95` | p95 latency | 200 ms | 2.5 | PASS | No |

## Extension

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `ext_cold_load_simple_p95` | p95 cold load time | 5 ms | 1.1 | PASS | Yes |
| `ext_cold_load_complex_p95` | p95 cold load time | 50 ms | - | NO_DATA | No |
| `ext_load_60_total` | total load time (60 official extensions) | 10000 ms | 6198.0 | PASS | No |

## Tool_call

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `tool_call_latency_p99` | p99 per-call latency | 200 us | 8 | PASS | Yes |
| `tool_call_throughput_min` | minimum calls/sec | 5000 calls/sec | 112722 | PASS | Yes |

## Event_dispatch

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `event_dispatch_p99` | p99 dispatch latency | 5000 us | - | NO_DATA | No |

## Policy

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `policy_eval_p99` | p99 evaluation time | 500 ns | 30 | PASS | Yes |

## Memory

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `idle_memory_rss` | RSS at idle | 50 MB | 3.5 | PASS | Yes |
| `sustained_load_rss_growth` | RSS growth under 30s sustained load | 5 percent | 0.0 | PASS | No |

## Binary

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `binary_size_release` | release binary size | 22 MB | 21.2 | PASS | Yes |

## Protocol

| Budget | Metric | Threshold | Actual | Status | CI |
|---|---|---|---|---|---|
| `protocol_parse_p99` | p99 parse+validate time | 50 us | 3 | PASS | Yes |

## Failing Data Contracts

- `missing_required_e2e_or_ratio_outputs` (`global`): full_e2e_long_session evidence has invalid required values (absolute_metrics.value=valid, rust_vs_node_ratio=missing_or_non_numeric, rust_vs_bun_ratio=missing_or_non_numeric) in /data/tmp/pi_agent_rust_cargo/darkgoose-bd-2zcs5-51/target/perf/extension_benchmark_stratification.json
  - Remediation: Emit full_e2e_long_session absolute latency and Rust-vs-Node/Bun ratios as finite positive numbers.
- `invalid_claim_integrity_guard` (`global`): claim_integrity.cherry_pick_guard requires global_claim_valid=true and layer_coverage.full_e2e_long_session=true (global_claim_valid=false, full_e2e_layer_coverage=false) in /data/tmp/pi_agent_rust_cargo/darkgoose-bd-2zcs5-51/target/perf/extension_benchmark_stratification.json
  - Remediation: Emit claim_integrity.cherry_pick_guard.global_claim_valid=true and layer_coverage.full_e2e_long_session=true for valid global claims.

## Measurement Methodology

- **`startup_version_p95`**: hyperfine: `pi --version` (10 runs, 3 warmup)
- **`startup_full_agent_p95`**: hyperfine: `pi --print '.'` with full init (10 runs, 3 warmup)
- **`ext_cold_load_simple_p95`**: criterion: load_init_cold for simple single-file extensions (10 samples)
- **`ext_cold_load_complex_p95`**: criterion: load_init_cold for multi-registration extensions (10 samples)
- **`ext_load_60_total`**: conformance runner: sequential load of all 60 official extensions
- **`tool_call_latency_p99`**: pijs_workload: 2000 iterations x 1 tool call, perf profile
- **`tool_call_throughput_min`**: pijs_workload: 2000 iterations x 10 tool calls, perf profile
- **`event_dispatch_p99`**: criterion: event_hook dispatch for before_agent_start (100 samples)
- **`policy_eval_p99`**: criterion: ext_policy/evaluate with various modes and capabilities
- **`idle_memory_rss`**: sysinfo: measure RSS after startup, before any user input
- **`sustained_load_rss_growth`**: stress test: 15 extensions, 50 events/sec for 30 seconds
- **`binary_size_release`**: ls -la target/release/pi (stripped)
- **`protocol_parse_p99`**: criterion: ext_protocol/parse_and_validate for host_call and log messages

## CI Enforcement

CI-enforced budgets are checked on every PR. A budget violation blocks the PR from merging. Non-CI budgets are informational and checked in nightly runs.

```bash
# Run budget checks
cargo test --test perf_budgets -- --nocapture

# Generate full budget report
cargo test --test perf_budgets generate_budget_report -- --nocapture
```

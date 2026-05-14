#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pi::validation_broker::{
    VALIDATION_BROKER_CLI_PLAN_SCHEMA, VALIDATION_BROKER_CLI_STATUS_SCHEMA,
    ValidationAdmissionRequestContext, ValidationBrokerInputParts, ValidationBrokerInputSnapshot,
    ValidationSlotArtifact, ValidationSlotRequest, ValidationSourceProvenance,
    normalize_available_source, normalize_beads_json, normalize_doctor_json,
    normalize_git_status_text, normalize_headroom_json, normalize_rch_queue_text,
};
use serde::Serialize;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const START: &str = "2026-05-14T07:00:00Z";
const HEARTBEAT: &str = "2026-05-14T07:05:00Z";
const EXPIRES: &str = "2026-05-14T07:30:00Z";
const PLAN_AT: &str = "2026-05-14T08:30:00Z";
const RENEWED_EXPIRES: &str = "2026-05-14T09:00:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pi"))
}

fn test_temp_dir() -> Result<TempDir, std::io::Error> {
    let root = repo_root().join("target").join("validation-broker-cli-tmp");
    fs::create_dir_all(&root)?;
    tempfile::Builder::new()
        .prefix("validation-broker-cli-")
        .tempdir_in(root)
}

fn output_text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

fn run_pi(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new(binary_path()) // ubs:ignore Cargo provides this test binary path.
        .current_dir(repo_root())
        .args(args)
        .output()
}

fn write_json(path: &Path, value: &impl Serialize) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn base_request(slot_id: &str) -> ValidationSlotRequest {
    let mut environment = BTreeMap::new();
    environment.insert(
        "CARGO_TARGET_DIR".to_string(),
        "/data/tmp/pi_agent_rust_cargo/codex/target".to_string(),
    );
    environment.insert(
        "TMPDIR".to_string(),
        "/data/tmp/pi_agent_rust_cargo/codex/tmp".to_string(),
    );

    ValidationSlotRequest {
        slot_id: slot_id.to_string(),
        owner_agent: "Codex".to_string(),
        bead_id: "bd-gusp4.5".to_string(),
        command: vec![
            "rch".to_string(),
            "exec".to_string(),
            "--".to_string(),
            "cargo".to_string(),
            "check".to_string(),
            "--all-targets".to_string(),
        ],
        command_class: "cargo_check".to_string(),
        cwd: "/data/projects/pi_agent_rust".to_string(),
        git_head: "3048e53f3".to_string(),
        feature_flags: vec!["default".to_string()],
        target_dir: "/data/tmp/pi_agent_rust_cargo/codex/target".to_string(),
        tmpdir: "/data/tmp/pi_agent_rust_cargo/codex/tmp".to_string(),
        runner: "rch_required".to_string(),
        rust_toolchain: Some("nightly".to_string()),
        rch_job_id: None,
        environment,
        expected_artifacts: vec![ValidationSlotArtifact {
            path: "target/debug/deps/pi.d".to_string(),
            sha256: None,
            schema: Some("cargo_metadata".to_string()),
        }],
        artifact_schema: Some("cargo_check_result.v1".to_string()),
        artifact_hash: Some("artifact-hash-1".to_string()),
    }
}

fn admission_context(slot_id: &str) -> ValidationAdmissionRequestContext {
    ValidationAdmissionRequestContext {
        request_id: "request-cli-plan".to_string(),
        request: base_request(slot_id),
        requested_at_utc: START.to_string(),
        bead_priority: 4,
    }
}

fn provenance(source: &str) -> Result<ValidationSourceProvenance, pi::error::Error> {
    ValidationSourceProvenance::new(
        source,
        vec![source.to_string(), "--json".to_string()],
        "/data/projects/pi_agent_rust",
        START,
        Some(format!("artifacts/{source}.json")),
    )
}

fn healthy_inputs() -> Result<ValidationBrokerInputSnapshot, pi::error::Error> {
    let rch = normalize_rch_queue_text(
        provenance("rch")?,
        "Build Queue\n  - 1 Active Build(s)\n  - 0 Queued Build(s)\nWorker Availability\n  -> 4 / 18 slots free\n",
    )?;
    let cargo_headroom = normalize_headroom_json(
        provenance("cargo_headroom")?,
        &json!({"available_bytes": 50_000_u64, "required_bytes": 10_000_u64}),
    )?;
    let doctor = normalize_doctor_json(
        provenance("doctor")?,
        &json!({"checks": [{"name": "scratch", "status": "ok"}]}),
    )?;
    let git =
        normalize_git_status_text(provenance("git")?, "3048e53f3", "## main...origin/main\n")?;
    let beads = normalize_beads_json(provenance("beads")?, &json!({"issues": []}), PLAN_AT, 3600)?;
    let scratch_headroom = normalize_headroom_json(
        provenance("scratch_headroom")?,
        &json!({"available_bytes": 50_000_u64, "required_bytes": 10_000_u64}),
    )?;
    let agent_mail = normalize_available_source(provenance("agent_mail")?)?;

    ValidationBrokerInputSnapshot::from_parts(ValidationBrokerInputParts {
        captured_at_utc: PLAN_AT.to_string(),
        rch,
        cargo_headroom,
        doctor,
        git,
        beads,
        scratch_headroom,
        agent_mail,
    })
}

fn value_from_stdout(output: &Output) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(&output.stdout)
}

#[test]
fn validation_broker_status_json_is_schema_stable_for_missing_store() -> TestResult {
    let temp = test_temp_dir()?;
    let store = temp.path().join("missing-slots.jsonl");
    let output = run_pi(&[
        "validation-broker",
        "status",
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--format",
        "json",
        "--generated-at",
        PLAN_AT,
    ])?;

    assert!(
        output.status.success(),
        "status command failed\nstdout:\n{}\nstderr:\n{}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    );
    let status = value_from_stdout(&output)?;
    assert_eq!(
        status.pointer("/schema").and_then(Value::as_str),
        Some(VALIDATION_BROKER_CLI_STATUS_SCHEMA)
    );
    assert_eq!(
        status.pointer("/store/status").and_then(Value::as_str),
        Some("available")
    );
    assert_eq!(
        status.pointer("/store/total_slots").and_then(Value::as_u64),
        Some(0)
    );
    Ok(())
}

#[test]
fn validation_broker_plan_is_read_only_and_explains_run_now() -> TestResult {
    let temp = test_temp_dir()?;
    let request_path = temp.path().join("request.json");
    let inputs_path = temp.path().join("inputs.json");
    let store = temp.path().join("slots.jsonl");
    write_json(&request_path, &admission_context("slot-plan"))?;
    write_json(&inputs_path, &healthy_inputs()?)?;

    let output = run_pi(&[
        "validation-broker",
        "plan",
        "--request",
        request_path.to_str().ok_or("request path is not UTF-8")?,
        "--inputs",
        inputs_path.to_str().ok_or("inputs path is not UTF-8")?,
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--format",
        "json",
        "--generated-at",
        PLAN_AT,
    ])?;

    assert!(
        output.status.success(),
        "plan command failed\nstdout:\n{}\nstderr:\n{}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    );
    assert!(
        !store.exists(),
        "plan mode should not create or append the slot store"
    );
    let plan = value_from_stdout(&output)?;
    assert_eq!(
        plan.pointer("/schema").and_then(Value::as_str),
        Some(VALIDATION_BROKER_CLI_PLAN_SCHEMA)
    );
    assert_eq!(
        plan.pointer("/read_only").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        plan.pointer("/decision/decision").and_then(Value::as_str),
        Some("allow")
    );
    assert_eq!(
        plan.pointer("/next_action").and_then(Value::as_str),
        Some("run_now")
    );
    assert_eq!(
        plan.pointer("/guards/live_mutations")
            .and_then(Value::as_u64),
        Some(0)
    );
    Ok(())
}

#[test]
fn validation_broker_acquire_renew_release_append_records() -> TestResult {
    let temp = test_temp_dir()?;
    let request_path = temp.path().join("request.json");
    let store = temp.path().join("slots.jsonl");
    write_json(&request_path, &base_request("slot-cli-mutate"))?;

    let acquire = run_pi(&[
        "validation-broker",
        "acquire",
        "--request",
        request_path.to_str().ok_or("request path is not UTF-8")?,
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--started-at",
        START,
        "--expires-at",
        EXPIRES,
        "--format",
        "json",
    ])?;
    assert!(
        acquire.status.success(),
        "acquire failed\nstdout:\n{}\nstderr:\n{}",
        output_text(&acquire.stdout),
        output_text(&acquire.stderr)
    );

    let renew = run_pi(&[
        "validation-broker",
        "renew",
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--slot-id",
        "slot-cli-mutate",
        "--owner",
        "Codex",
        "--heartbeat-at",
        HEARTBEAT,
        "--expires-at",
        RENEWED_EXPIRES,
        "--format",
        "json",
    ])?;
    assert!(
        renew.status.success(),
        "renew failed\nstdout:\n{}\nstderr:\n{}",
        output_text(&renew.stdout),
        output_text(&renew.stderr)
    );

    let release = run_pi(&[
        "validation-broker",
        "release",
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--slot-id",
        "slot-cli-mutate",
        "--owner",
        "Codex",
        "--at",
        PLAN_AT,
        "--reason",
        "focused gate finished",
        "--format",
        "json",
    ])?;
    assert!(
        release.status.success(),
        "release failed\nstdout:\n{}\nstderr:\n{}",
        output_text(&release.stdout),
        output_text(&release.stderr)
    );

    let status = run_pi(&[
        "validation-broker",
        "status",
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--format",
        "json",
        "--generated-at",
        PLAN_AT,
    ])?;
    assert!(status.status.success(), "status after release failed");
    let status_json = value_from_stdout(&status)?;
    assert_eq!(
        status_json
            .pointer("/store/state_counts/released")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        status_json
            .pointer("/store/total_records")
            .and_then(Value::as_u64),
        Some(3)
    );
    Ok(())
}

#[test]
fn validation_broker_plan_rejects_missing_and_malformed_inputs() -> TestResult {
    let temp = test_temp_dir()?;
    let malformed_request = temp.path().join("malformed-request.json");
    let missing_inputs = temp.path().join("missing-inputs.json");
    let store = temp.path().join("slots.jsonl");
    fs::write(&malformed_request, "{}")?;

    let output = run_pi(&[
        "validation-broker",
        "plan",
        "--request",
        malformed_request
            .to_str()
            .ok_or("malformed request path is not UTF-8")?,
        "--inputs",
        missing_inputs
            .to_str()
            .ok_or("missing inputs path is not UTF-8")?,
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--format",
        "json",
        "--generated-at",
        PLAN_AT,
    ])?;

    assert!(
        !output.status.success(),
        "malformed/missing input command unexpectedly succeeded"
    );
    Ok(())
}

#[test]
fn validation_broker_outputs_refuse_overwrite() -> TestResult {
    let temp = test_temp_dir()?;
    let store = temp.path().join("slots.jsonl");
    let out_json = temp.path().join("status.json");
    fs::write(&out_json, "{}")?;

    let output = run_pi(&[
        "validation-broker",
        "status",
        "--store",
        store.to_str().ok_or("store path is not UTF-8")?,
        "--out-json",
        out_json.to_str().ok_or("output path is not UTF-8")?,
        "--generated-at",
        PLAN_AT,
    ])?;

    assert!(
        !output.status.success(),
        "overwrite command unexpectedly succeeded"
    );
    assert!(
        output_text(&output.stderr)
            .contains("refusing to overwrite existing validation-broker JSON output"),
        "stderr did not explain overwrite refusal:\n{}",
        output_text(&output.stderr)
    );
    Ok(())
}

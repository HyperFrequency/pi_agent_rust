#!/usr/bin/env python3
"""Build a read-only semantic validation route plan.

The route plan maps touched paths to validation obligations, RCH-only command
templates, proof-memory reuse posture, cache/coalescing hints, and coordination
admission warnings. It never runs cargo/RCH, mutates Beads or Agent Mail, edits
git state, or deletes files.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROUTE_PLAN_SCHEMA = "pi.validation.semantic_route_plan.v1"
PURPOSE = "read_only_semantic_validation_route_planning"
DEFAULT_SOURCE_BEAD = "bd-4w2mw.2"
DEFAULT_SCHEDULER_PATH = Path("docs/evidence/validation-scheduler-plan.json")
DEFAULT_PROOF_MEMORY_PATH = Path("docs/evidence/validation-proof-memory-index.json")
DEFAULT_BEADS_PATH = Path(".beads/issues.jsonl")

REQUIRED_TOP_LEVEL_KEYS = (
    "schema",
    "generated_at",
    "status",
    "decision",
    "purpose",
    "source_bead",
    "inputs",
    "changed_path_classification",
    "proof_obligations",
    "proof_memory_assessment",
    "cache_heat",
    "coordination_admission",
    "would_run_order",
    "deferred_or_blocked",
    "negative_controls",
    "summary",
    "claim_boundaries",
)

RCH_ENV = {
    "CARGO_TARGET_DIR": "/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target",
    "TMPDIR": "/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp",
}

BUCKETS: tuple[dict[str, Any], ...] = (
    {
        "bucket": "provider",
        "patterns": (
            "src/providers/**",
            "src/provider.rs",
            "src/provider_metadata.rs",
            "src/sse.rs",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test provider_streaming",
    },
    {
        "bucket": "tools",
        "patterns": (
            "src/tools.rs",
            "tests/conformance*",
            "tests/fixtures/**",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test tools",
    },
    {
        "bucket": "session",
        "patterns": (
            "src/session.rs",
            "src/session_index.rs",
            "src/session_sqlite.rs",
            "docs/session.md",
        ),
        "proof_groups": ("focused_tests", "all_targets_check", "clippy"),
        "focused_command": "test session",
    },
    {
        "bucket": "extension",
        "patterns": (
            "src/extensions.rs",
            "src/extensions_js.rs",
            "src/extension_dispatcher.rs",
            "tests/ext_conformance/**",
            "docs/extension-*.md",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test extension",
    },
    {
        "bucket": "interactive_rpc",
        "patterns": (
            "src/interactive.rs",
            "src/interactive/**",
            "src/rpc.rs",
            "src/main.rs",
        ),
        "proof_groups": (
            "focused_tests",
            "e2e_conformance",
            "all_targets_check",
            "clippy",
        ),
        "focused_command": "test e2e_rpc",
    },
    {
        "bucket": "core_runtime",
        "patterns": ("src/*.rs", "src/http/**"),
        "proof_groups": ("focused_tests", "all_targets_check", "clippy"),
        "focused_command": "test --lib",
    },
    {
        "bucket": "scripts_docs_evidence",
        "patterns": ("scripts/**", "docs/**", "tests/golden_corpus/**", ".beads/**"),
        "proof_groups": ("fast_script_checks", "evidence_regeneration"),
        "focused_command": None,
    },
)

FALLBACK_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "id": "fast_script_checks",
        "title": "Fast script and metadata checks",
        "command_class": "fast_script",
        "dependency_rank": 1,
        "cache_reuse": "not_applicable",
        "requires_rch": False,
        "no_local_fallback": False,
        "exact_commands": [
            "python3 -m json.tool docs/evidence/semantic-validation-route-inventory.json >/dev/null",
            "git diff --check",
            "./scripts/reconcile_beads_ledger.sh",
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": {},
        "local_fallback_rejection_reason": None,
    },
    {
        "id": "evidence_regeneration",
        "title": "Runpack evidence regeneration self-test",
        "command_class": "script_self_test",
        "dependency_rank": 2,
        "cache_reuse": "not_applicable",
        "requires_rch": False,
        "no_local_fallback": False,
        "exact_commands": ["python3 scripts/build_swarm_operator_runpack.py --self-test"],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": {},
        "local_fallback_rejection_reason": None,
    },
    {
        "id": "focused_tests",
        "title": "Focused Rust tests for touched surfaces",
        "command_class": "cargo_test_focused",
        "dependency_rank": 3,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test <focused-target>"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "e2e_conformance",
        "title": "E2E and conformance validation",
        "command_class": "cargo_test_e2e_conformance",
        "dependency_rank": 4,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test conformance",
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo test e2e",
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "all_targets_check",
        "title": "All-targets compiler check",
        "command_class": "cargo_check_all_targets",
        "dependency_rank": 5,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo check --all-targets"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
    {
        "id": "clippy",
        "title": "All-targets clippy",
        "command_class": "cargo_clippy_all_targets",
        "dependency_rank": 6,
        "cache_reuse": "target_dir_reuse_if_clean",
        "requires_rch": True,
        "no_local_fallback": True,
        "exact_commands": [
            "rch exec -- env CARGO_TARGET_DIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/target TMPDIR=/data/tmp/pi_agent_rust_cargo/${USER:-agent}/tmp cargo clippy --all-targets -- -D warnings"
        ],
        "action": "would_run",
        "backoff_reasons": [],
        "required_env": RCH_ENV,
        "local_fallback_rejection_reason": "RCH-required validation must not fail open into a local cargo build.",
    },
)

NEGATIVE_CONTROLS: tuple[dict[str, str], ...] = (
    {
        "id": "missing_scheduler_plan_fails_closed",
        "expected_status": "blocked",
        "reason": "Missing scheduler input blocks authoritative import of current validation group semantics.",
    },
    {
        "id": "stale_proof_memory_fails_closed_for_reuse",
        "expected_status": "degraded",
        "reason": "Stale proof-memory can inform routing but cannot authorize proof reuse.",
    },
    {
        "id": "local_cargo_fallback_rejected",
        "expected_status": "blocked",
        "reason": "Heavy cargo groups require rch exec -- and no local fallback.",
    },
    {
        "id": "dirty_worktree_mismatch_denies_reuse",
        "expected_status": "degraded",
        "reason": "Dirty/mismatched worktree state invalidates proof-memory reuse.",
    },
    {
        "id": "agent_mail_degraded_uses_beads_soft_lock",
        "expected_status": "degraded",
        "reason": "Degraded coordination sources require Beads soft-lock or explicit blocker reporting.",
    },
    {
        "id": "advisory_route_as_authority_rejected",
        "expected_status": "blocked",
        "reason": "Route plans cannot claim, reserve, launch validation, mutate source systems, or certify claims.",
    },
)


class RoutePlanError(Exception):
    """Raised when route-plan inputs are unusable."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def json_dumps(value: Any, *, pretty: bool) -> str:
    if pretty:
        return json.dumps(value, indent=2, sort_keys=True) + "\n"
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RoutePlanError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RoutePlanError(f"malformed JSON file {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RoutePlanError(f"JSON file must contain an object: {path}")
    return payload


def load_optional_json(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    try:
        return load_json(path), {"path": str(path), "status": "loaded"}
    except RoutePlanError as exc:
        return None, {"path": str(path), "status": "missing_or_invalid", "reason": str(exc)}


def load_changed_paths_json(path: Path) -> list[str]:
    payload = load_json(path)
    raw = payload.get("changed_paths")
    if raw is None:
        raw = payload.get("paths")
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise RoutePlanError(f"{path} must contain changed_paths or paths as a string list")
    return sorted(set(raw))


def git_changed_paths(root: Path) -> list[str]:
    commands = (
        ("git", "diff", "--name-only"),
        ("git", "diff", "--cached", "--name-only"),
    )
    paths: set[str] = set()
    for command in commands:
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if result.returncode == 0:
            paths.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    return sorted(paths)


def normalize_path(raw: str) -> str:
    clean = raw.strip().replace("\\", "/")
    if clean.startswith("./"):
        return clean[2:]
    return clean


def matches_pattern(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        return path == pattern[:-3] or path.startswith(pattern[:-3] + "/")
    return fnmatch.fnmatchcase(path, pattern)


def classify_path(path: str) -> dict[str, Any]:
    clean = normalize_path(path)
    for spec in BUCKETS:
        for pattern in spec["patterns"]:
            if matches_pattern(clean, pattern):
                return {
                    "path": clean,
                    "bucket": spec["bucket"],
                    "matched_pattern": pattern,
                    "proof_groups": list(spec["proof_groups"]),
                    "focused_command": spec.get("focused_command"),
                    "status": "classified",
                }
    return {
        "path": clean,
        "bucket": "unknown",
        "matched_pattern": "*",
        "proof_groups": ["fast_script_checks", "all_targets_check"],
        "focused_command": None,
        "status": "unknown_path_bucket",
    }


def classify_changed_paths(paths: list[str]) -> dict[str, Any]:
    records = [classify_path(path) for path in sorted(set(map(normalize_path, paths)))]
    counts = Counter(record["bucket"] for record in records)
    unknown = [record["path"] for record in records if record["bucket"] == "unknown"]
    if not records:
        profile = "empty_queue"
    elif set(counts) == {"scripts_docs_evidence"}:
        profile = "docs_scripts_evidence_only"
    elif any(record["bucket"] != "scripts_docs_evidence" for record in records) and counts.get(
        "scripts_docs_evidence"
    ):
        profile = "mixed_source_and_docs"
    else:
        profile = "source_only"
    return {
        "changed_path_count": len(records),
        "profile_id": profile,
        "bucket_counts": dict(sorted(counts.items())),
        "records": records,
        "unknown_paths": unknown,
    }


def command_groups_from_scheduler(scheduler: dict[str, Any] | None) -> list[dict[str, Any]]:
    groups = scheduler.get("command_groups") if isinstance(scheduler, dict) else None
    if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
        return [dict(group) for group in FALLBACK_GROUPS]
    by_id = {str(group.get("id")): dict(group) for group in groups if group.get("id")}
    merged: list[dict[str, Any]] = []
    for fallback in FALLBACK_GROUPS:
        current = dict(fallback)
        current.update(by_id.get(fallback["id"], {}))
        current.setdefault("dependency_rank", fallback["dependency_rank"])
        current.setdefault("exact_commands", fallback["exact_commands"])
        current.setdefault("requires_rch", fallback["requires_rch"])
        current.setdefault("no_local_fallback", fallback["no_local_fallback"])
        current.setdefault("required_env", RCH_ENV if current.get("requires_rch") else {})
        current.setdefault(
            "local_fallback_rejection_reason",
            fallback["local_fallback_rejection_reason"],
        )
        merged.append(current)
    return merged


def focused_rch_command(cargo_args: str) -> str:
    return (
        "rch exec -- env "
        f"CARGO_TARGET_DIR={RCH_ENV['CARGO_TARGET_DIR']} "
        f"TMPDIR={RCH_ENV['TMPDIR']} cargo {cargo_args}"
    )


def required_group_ids(classification: dict[str, Any]) -> list[str]:
    ids: set[str] = set()
    for record in classification["records"]:
        ids.update(record["proof_groups"])
    if not ids:
        ids.add("fast_script_checks")
    return sorted(ids, key=lambda group_id: group_rank(group_id))


def group_rank(group_id: str) -> int:
    for group in FALLBACK_GROUPS:
        if group["id"] == group_id:
            return int(group["dependency_rank"])
    return 99


def build_proof_obligations(
    classification: dict[str, Any],
    command_groups: list[dict[str, Any]],
) -> dict[str, Any]:
    wanted = required_group_ids(classification)
    groups_by_id = {str(group["id"]): group for group in command_groups}
    obligations: list[dict[str, Any]] = []
    focused_commands = sorted(
        {
            focused_rch_command(str(record["focused_command"]))
            for record in classification["records"]
            if record.get("focused_command")
        }
    )
    for group_id in wanted:
        group = groups_by_id.get(group_id)
        if group is None:
            obligations.append(
                {
                    "group_id": group_id,
                    "status": "missing_group_definition",
                    "requires_rch": None,
                    "exact_commands": [],
                    "reasons": ["validation group is absent from scheduler/fallback catalog"],
                }
            )
            continue
        exact_commands = list(group.get("exact_commands") or [])
        if group_id == "focused_tests" and focused_commands:
            exact_commands = focused_commands
        obligations.append(
            {
                "group_id": group_id,
                "title": group.get("title"),
                "command_class": group.get("command_class"),
                "requires_rch": bool(group.get("requires_rch")),
                "no_local_fallback": bool(group.get("no_local_fallback")),
                "exact_commands": exact_commands,
                "required_env": group.get("required_env") or (RCH_ENV if group.get("requires_rch") else {}),
                "local_fallback_rejection_reason": group.get("local_fallback_rejection_reason"),
                "scheduler_action": group.get("action", "would_run"),
                "scheduler_backoff_reasons": group.get("backoff_reasons") or [],
                "cache_reuse": group.get("cache_reuse"),
                "status": "required",
            }
        )
    missing = [item["group_id"] for item in obligations if item["status"] != "required"]
    return {
        "required_group_ids": wanted,
        "groups": obligations,
        "missing_group_ids": missing,
        "heavy_group_count": sum(1 for item in obligations if item.get("requires_rch")),
    }


def proof_entry_touched_paths(entry: dict[str, Any]) -> set[str]:
    paths = entry.get("touched_paths")
    if isinstance(paths, list):
        return {normalize_path(path) for path in paths if isinstance(path, str)}
    coverage = entry.get("path_coverage")
    if isinstance(coverage, dict):
        covered = coverage.get("covered_paths")
        if isinstance(covered, list):
            return {normalize_path(path) for path in covered if isinstance(path, str)}
    return set()


def assess_proof_memory(
    proof_memory: dict[str, Any] | None,
    changed_paths: list[str],
) -> dict[str, Any]:
    if not isinstance(proof_memory, dict):
        return {
            "source_status": "missing_or_invalid",
            "entry_count": 0,
            "classification_counts": {},
            "reusable_records": [],
            "invalidating_records": [],
            "route_decision": "refresh_validation",
            "invalidation_reasons": ["proof_memory_missing_or_invalid"],
        }
    entries = proof_memory.get("entries")
    if not isinstance(entries, list):
        entries = []
    current_paths = {normalize_path(path) for path in changed_paths}
    reusable: list[dict[str, Any]] = []
    invalidating: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    reasons: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        classification = str(entry.get("classification") or "unknown")
        counts[classification] += 1
        eligibility = entry.get("reuse_eligibility")
        reusable_flag = bool(isinstance(eligibility, dict) and eligibility.get("reuse_allowed"))
        entry_paths = proof_entry_touched_paths(entry)
        path_covers_current = not current_paths or current_paths.issubset(entry_paths)
        record = {
            "record_id": entry.get("record_id"),
            "fixture_id": entry.get("fixture_id"),
            "classification": classification,
            "command": (entry.get("command") or {}).get("rendered")
            if isinstance(entry.get("command"), dict)
            else None,
            "path_covers_current": path_covers_current,
            "reuse_allowed": reusable_flag and path_covers_current,
        }
        if reusable_flag and path_covers_current:
            reusable.append(record)
        else:
            if classification != "reusable" or current_paths:
                invalidating.append(record)
            if classification in {
                "stale",
                "missing_artifact",
                "local_fallback",
                "dirty_worktree_mismatch",
                "command_mismatch",
                "path_coverage_mismatch",
                "not_authoritative",
            }:
                reasons.add(classification)
            if reusable_flag and not path_covers_current:
                reasons.add("path_coverage_mismatch")
    route_decision = "reuse_available" if reusable else "refresh_validation"
    return {
        "source_status": proof_memory.get("status", "unknown"),
        "source_decision": proof_memory.get("decision"),
        "entry_count": len(entries),
        "classification_counts": dict(sorted(counts.items())),
        "reusable_records": reusable[:5],
        "invalidating_records": invalidating[:8],
        "route_decision": route_decision,
        "invalidation_reasons": sorted(reasons),
    }


def build_cache_heat(obligations: dict[str, Any]) -> dict[str, Any]:
    groups = obligations["groups"]
    heat: list[dict[str, Any]] = []
    for group in groups:
        group_id = str(group["group_id"])
        requires_rch = bool(group.get("requires_rch"))
        if group_id in {"all_targets_check", "clippy"}:
            intensity = "high"
        elif requires_rch:
            intensity = "medium"
        else:
            intensity = "low"
        advice = "run_before_heavy_rust" if not requires_rch else "coalesce_with_same_target_dir"
        if group_id == "clippy":
            advice = "run_after_check_or_focused_tests_to_reuse_target_cache"
        heat.append(
            {
                "group_id": group_id,
                "cache_intensity": intensity,
                "cache_reuse": group.get("cache_reuse"),
                "advice": advice,
            }
        )
    return {
        "status": "ready",
        "items": heat,
        "coalescing_summary": "Run cheap scripts first; when heavy validation is admitted, keep RCH target/tmp env stable and coalesce Rust groups by touched surface.",
    }


def load_beads_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"source_status": "missing", "open_count": 0, "in_progress_count": 0, "ready_hint": None}
    open_count = 0
    in_progress_count = 0
    active: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                issue = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(issue, dict):
                continue
            status = issue.get("status")
            if status == "open":
                open_count += 1
            elif status == "in_progress":
                in_progress_count += 1
            if status in {"open", "in_progress"}:
                active.append(
                    {
                        "id": issue.get("id"),
                        "title": issue.get("title"),
                        "status": status,
                        "assignee": issue.get("assignee"),
                    }
                )
    return {
        "source_status": "loaded",
        "open_count": open_count,
        "in_progress_count": in_progress_count,
        "active_sample": active[:8],
    }


def build_coordination_admission(
    *,
    agent_mail_health: dict[str, Any] | None,
    beads_summary: dict[str, Any],
    classification: dict[str, Any],
) -> dict[str, Any]:
    health = agent_mail_health or {}
    health_level = health.get("health_level") or health.get("status") or "not_provided"
    reasons: list[str] = []
    recommended_action = "safe_to_claim_after_reservation"
    status = "ready"
    if health_level not in {"green", "ok"}:
        status = "degraded"
        recommended_action = "claim_with_beads_soft_lock"
        reasons.append(f"agent_mail_health={health_level}")
    if beads_summary.get("in_progress_count", 0) > 0:
        status = "degraded"
        reasons.append("active_in_progress_beads_present")
    if classification["unknown_paths"]:
        status = "blocked"
        recommended_action = "stop_surface_blocker"
        reasons.append("unknown_changed_path_bucket")
    reservation_paths = sorted(
        {
            record["path"]
            for record in classification["records"]
            if record["bucket"] != "unknown"
        }
    )
    if not reservation_paths:
        reservation_paths = ["docs/evidence/semantic-validation-route-inventory.json"]
    return {
        "status": status,
        "recommended_action": recommended_action,
        "agent_mail_health": health_level,
        "beads_source_status": beads_summary.get("source_status"),
        "open_bead_count": beads_summary.get("open_count", 0),
        "in_progress_bead_count": beads_summary.get("in_progress_count", 0),
        "reservation_paths": reservation_paths,
        "thread_id_hint": DEFAULT_SOURCE_BEAD,
        "reasons": reasons,
        "claim_boundary": "Advisory only; agents must claim with br and reserve with Agent Mail or Beads soft-lock explicitly.",
    }


def build_schedule(
    obligations: dict[str, Any],
    *,
    coordination: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    would_run: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    blocked_coordination = coordination["status"] == "blocked"
    for group in sorted(obligations["groups"], key=lambda item: group_rank(str(item["group_id"]))):
        action = "would_run"
        reasons = list(group.get("scheduler_backoff_reasons") or [])
        if blocked_coordination:
            action = "block"
            reasons.append("coordination_admission_blocked")
        elif group.get("scheduler_action") in {"block", "defer"}:
            action = str(group.get("scheduler_action"))
        target = deferred if action != "would_run" else would_run
        for command in group.get("exact_commands") or []:
            target.append(
                {
                    "rank": len(target) + 1,
                    "group_id": group["group_id"],
                    "action": action,
                    "command": command,
                    "requires_rch": bool(group.get("requires_rch")),
                    "required_env": group.get("required_env") or {},
                    "local_fallback_rejection_reason": group.get("local_fallback_rejection_reason"),
                    "rationale": route_rationale(group, action, reasons),
                    "reasons": sorted(set(reasons)),
                }
            )
    return would_run, deferred


def route_rationale(group: dict[str, Any], action: str, reasons: list[str]) -> str:
    title = group.get("title") or group["group_id"]
    if action == "would_run":
        return f"{title} is required by the changed-path route."
    joined = ", ".join(sorted(set(reasons))) if reasons else action
    return f"{title} is {action} because {joined}."


def claim_boundaries() -> dict[str, bool]:
    return {
        "read_only": True,
        "operator_evidence_only": True,
        "does_not_execute_commands": True,
        "does_not_launch_rch": True,
        "does_not_mutate_agent_mail": True,
        "does_not_mutate_beads": True,
        "does_not_mutate_git": True,
        "does_not_delete_files": True,
        "does_not_replace_validation_scheduler": True,
        "does_not_replace_validation_proof_memory": True,
        "does_not_replace_beads_or_agent_mail": True,
        "does_not_authorize_release_performance_claims": True,
        "does_not_authorize_dropin_claims": True,
        "beads_mutation_authorized": False,
        "agent_mail_authority_authorized": False,
        "rch_authority_authorized": False,
        "git_mutation_authorized": False,
        "file_deletion_authorized": False,
        "advisory_evidence_as_source_of_truth_authorized": False,
    }


def determine_status(
    *,
    source_issues: list[dict[str, str]],
    classification: dict[str, Any],
    proof_memory: dict[str, Any],
    coordination: dict[str, Any],
    deferred_or_blocked: list[dict[str, Any]],
) -> tuple[str, str]:
    if any(issue.get("severity") == "blocking" for issue in source_issues):
        return "blocked", "route_plan_blocked_refresh_sources"
    if classification["unknown_paths"]:
        return "blocked", "route_plan_blocked_refresh_sources"
    if coordination["status"] == "blocked":
        return "blocked", "route_plan_blocked_refresh_sources"
    if deferred_or_blocked or proof_memory.get("route_decision") == "refresh_validation":
        return "degraded", "route_plan_degraded_use_manual_validation"
    if coordination["status"] == "degraded":
        return "degraded", "route_plan_degraded_use_manual_validation"
    return "ready", "route_plan_ready"


def validate_plan_shape(plan: dict[str, Any]) -> None:
    missing = [key for key in REQUIRED_TOP_LEVEL_KEYS if key not in plan]
    if missing:
        raise RoutePlanError(f"route plan missing required keys: {', '.join(missing)}")
    boundaries = plan["claim_boundaries"]
    true_keys = (
        "read_only",
        "does_not_execute_commands",
        "does_not_launch_rch",
        "does_not_mutate_agent_mail",
        "does_not_mutate_beads",
        "does_not_mutate_git",
        "does_not_delete_files",
    )
    false_keys = (
        "beads_mutation_authorized",
        "agent_mail_authority_authorized",
        "rch_authority_authorized",
        "git_mutation_authorized",
        "file_deletion_authorized",
        "advisory_evidence_as_source_of_truth_authorized",
    )
    for key in true_keys:
        if boundaries.get(key) is not True:
            raise RoutePlanError(f"claim boundary must be true: {key}")
    for key in false_keys:
        if boundaries.get(key) is not False:
            raise RoutePlanError(f"claim boundary must be false: {key}")
    for item in plan["proof_obligations"]["groups"]:
        if item.get("requires_rch"):
            commands = item.get("exact_commands") or []
            if not commands or not all(str(command).startswith("rch exec --") for command in commands):
                raise RoutePlanError(f"RCH-required group lacks rch exec command: {item.get('group_id')}")
            if not item.get("local_fallback_rejection_reason"):
                raise RoutePlanError(f"RCH-required group lacks local fallback rejection: {item.get('group_id')}")


def build_route_plan(
    *,
    changed_paths: list[str],
    scheduler: dict[str, Any] | None,
    scheduler_source: dict[str, Any],
    proof_memory: dict[str, Any] | None,
    proof_memory_source: dict[str, Any],
    beads_summary: dict[str, Any],
    agent_mail_health: dict[str, Any] | None,
    generated_at: str,
    source_bead: str,
) -> dict[str, Any]:
    source_issues: list[dict[str, str]] = []
    if scheduler is None:
        source_issues.append(
            {
                "source": "validation_scheduler_plan",
                "severity": "blocking",
                "reason": scheduler_source["reason"],
            }
        )
    if proof_memory is None:
        source_issues.append(
            {
                "source": "validation_proof_memory_index",
                "severity": "warning",
                "reason": proof_memory_source["reason"],
            }
        )
    classification = classify_changed_paths(changed_paths)
    command_groups = command_groups_from_scheduler(scheduler)
    obligations = build_proof_obligations(classification, command_groups)
    proof_assessment = assess_proof_memory(proof_memory, changed_paths)
    cache_heat = build_cache_heat(obligations)
    coordination = build_coordination_admission(
        agent_mail_health=agent_mail_health,
        beads_summary=beads_summary,
        classification=classification,
    )
    would_run, deferred = build_schedule(obligations, coordination=coordination)
    status, decision = determine_status(
        source_issues=source_issues,
        classification=classification,
        proof_memory=proof_assessment,
        coordination=coordination,
        deferred_or_blocked=deferred,
    )
    plan = {
        "schema": ROUTE_PLAN_SCHEMA,
        "generated_at": generated_at,
        "status": status,
        "decision": decision,
        "purpose": PURPOSE,
        "source_bead": source_bead,
        "inputs": {
            "changed_paths": sorted(set(map(normalize_path, changed_paths))),
            "validation_scheduler_plan": scheduler_source,
            "validation_proof_memory_index": proof_memory_source,
            "beads": {
                "path": str(DEFAULT_BEADS_PATH),
                "status": beads_summary.get("source_status"),
            },
            "agent_mail_health": agent_mail_health or {"status": "not_provided"},
            "source_issues": source_issues,
        },
        "changed_path_classification": classification,
        "proof_obligations": obligations,
        "proof_memory_assessment": proof_assessment,
        "cache_heat": cache_heat,
        "coordination_admission": coordination,
        "would_run_order": would_run,
        "deferred_or_blocked": deferred,
        "negative_controls": list(NEGATIVE_CONTROLS),
        "summary": {
            "changed_path_count": classification["changed_path_count"],
            "required_group_count": len(obligations["required_group_ids"]),
            "would_run_count": len(would_run),
            "deferred_or_blocked_count": len(deferred),
            "unknown_path_count": len(classification["unknown_paths"]),
            "proof_memory_route_decision": proof_assessment["route_decision"],
            "coordination_status": coordination["status"],
            "heavy_group_count": obligations["heavy_group_count"],
        },
        "claim_boundaries": claim_boundaries(),
    }
    validate_plan_shape(plan)
    return plan


def no_overwrite_write(path: Path, text: str) -> None:
    if path.exists():
        raise RoutePlanError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fixture_scheduler(*, heavy_allowed: bool = True) -> dict[str, Any]:
    groups = []
    for group in FALLBACK_GROUPS:
        item = dict(group)
        if item["requires_rch"] and not heavy_allowed:
            item["action"] = "defer"
            item["backoff_reasons"] = ["slot_pressure=saturated"]
        groups.append(item)
    return {
        "schema": "pi.swarm.validation_scheduler_plan.v1",
        "status": "ready" if heavy_allowed else "degraded",
        "command_groups": groups,
        "rch_posture": {"heavy_validation_allowed": heavy_allowed},
    }


def fixture_proof_memory(*, reusable: bool = True) -> dict[str, Any]:
    classification = "reusable" if reusable else "stale"
    return {
        "schema": "pi.validation.proof_memory_index.v1",
        "status": "pass",
        "decision": "proof_memory_index_ready",
        "entries": [
            {
                "record_id": "fixture-proof",
                "fixture_id": "self_test",
                "classification": classification,
                "command": {"rendered": "rch exec -- cargo check --all-targets"},
                "touched_paths": ["src/providers/openai.rs", "src/doctor.rs"],
                "reuse_eligibility": {
                    "reuse_allowed": reusable,
                    "invalidation_reasons": [] if reusable else ["stale_proof"],
                },
            }
        ],
    }


def run_self_test() -> dict[str, Any]:
    cases = [
        {
            "id": "docs_only",
            "paths": ["docs/swarm-operations-runbook.md"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"ready", "degraded"},
            "expect_bucket": "scripts_docs_evidence",
        },
        {
            "id": "provider_rust",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"ready"},
            "expect_bucket": "provider",
        },
        {
            "id": "mixed_python_rust",
            "paths": ["src/doctor.rs", "scripts/new-tool.py"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"degraded"},
            "expect_bucket": "scripts_docs_evidence",
        },
        {
            "id": "unknown_path",
            "paths": ["weird.binary"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(),
            "expect_status": {"blocked"},
            "expect_bucket": "unknown",
        },
        {
            "id": "stale_proof",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(),
            "proof": fixture_proof_memory(reusable=False),
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
        },
        {
            "id": "rch_unavailable",
            "paths": ["src/providers/openai.rs"],
            "scheduler": fixture_scheduler(heavy_allowed=False),
            "proof": fixture_proof_memory(),
            "expect_status": {"degraded"},
            "expect_bucket": "provider",
        },
    ]
    results: list[dict[str, Any]] = []
    for case in cases:
        plan = build_route_plan(
            changed_paths=case["paths"],
            scheduler=case["scheduler"],
            scheduler_source={"path": "fixture", "status": "loaded"},
            proof_memory=case["proof"],
            proof_memory_source={"path": "fixture", "status": "loaded"},
            beads_summary={"source_status": "fixture", "open_count": 1, "in_progress_count": 0},
            agent_mail_health={"health_level": "green", "status": "ok"},
            generated_at="2026-05-19T00:00:00+00:00",
            source_bead=DEFAULT_SOURCE_BEAD,
        )
        buckets = set(plan["changed_path_classification"]["bucket_counts"])
        assertions = [
            {
                "id": "status_expected",
                "status": "pass" if plan["status"] in case["expect_status"] else "fail",
                "message": f"status={plan['status']}",
            },
            {
                "id": "bucket_expected",
                "status": "pass" if case["expect_bucket"] in buckets else "fail",
                "message": f"buckets={sorted(buckets)}",
            },
            {
                "id": "rch_commands_guarded",
                "status": "pass"
                if all(
                    (not item["requires_rch"]) or item["command"].startswith("rch exec --")
                    for item in plan["would_run_order"] + plan["deferred_or_blocked"]
                )
                else "fail",
                "message": "RCH-required commands use rch exec --",
            },
        ]
        results.append(
            {
                "case_id": case["id"],
                "status": "pass" if all(item["status"] == "pass" for item in assertions) else "fail",
                "assertions": assertions,
                "summary": plan["summary"],
            }
        )
    status = "pass" if all(item["status"] == "pass" for item in results) else "fail"
    return {
        "schema": "pi.validation.semantic_route_plan.self_test.v1",
        "generated_at": utc_now_iso(),
        "status": status,
        "case_count": len(results),
        "results": results,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed-path", action="append", default=[], help="Changed path to route; repeatable.")
    parser.add_argument("--changed-paths-json", type=Path, help="JSON object with changed_paths or paths list.")
    parser.add_argument(
        "--from-git",
        action="store_true",
        help="Read changed paths from git diff and git diff --cached.",
    )
    parser.add_argument("--source-root", type=Path, default=Path("."), help="Repository root.")
    parser.add_argument("--scheduler-json", type=Path, default=DEFAULT_SCHEDULER_PATH)
    parser.add_argument("--proof-memory-json", type=Path, default=DEFAULT_PROOF_MEMORY_PATH)
    parser.add_argument("--agent-mail-health-json", type=Path)
    parser.add_argument("--beads-jsonl", type=Path, default=DEFAULT_BEADS_PATH)
    parser.add_argument("--source-bead", default=DEFAULT_SOURCE_BEAD)
    parser.add_argument("--out", type=Path, help="Write JSON output; refuses to overwrite.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic built-in fixtures.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        payload = run_self_test()
        text = json_dumps(payload, pretty=True)
        if args.out:
            no_overwrite_write(args.out, text)
        else:
            sys.stdout.write(text)
        return 0 if payload["status"] == "pass" else 1

    root = args.source_root.resolve()
    changed_paths = [normalize_path(path) for path in args.changed_path]
    if args.changed_paths_json:
        changed_paths.extend(load_changed_paths_json(args.changed_paths_json))
    if args.from_git or not changed_paths:
        changed_paths.extend(git_changed_paths(root))
    changed_paths = sorted(set(path for path in changed_paths if path))

    scheduler, scheduler_source = load_optional_json(root / args.scheduler_json)
    proof_memory, proof_source = load_optional_json(root / args.proof_memory_json)
    agent_mail_health = load_json(root / args.agent_mail_health_json) if args.agent_mail_health_json else None
    beads_summary = load_beads_summary(root / args.beads_jsonl)
    plan = build_route_plan(
        changed_paths=changed_paths,
        scheduler=scheduler,
        scheduler_source=scheduler_source,
        proof_memory=proof_memory,
        proof_memory_source=proof_source,
        beads_summary=beads_summary,
        agent_mail_health=agent_mail_health,
        generated_at=utc_now_iso(),
        source_bead=args.source_bead,
    )
    text = json_dumps(plan, pretty=args.pretty)
    if args.out:
        no_overwrite_write(args.out, text)
    else:
        sys.stdout.write(text)
    return 0 if plan["status"] != "blocked" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RoutePlanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

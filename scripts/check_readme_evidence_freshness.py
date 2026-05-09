#!/usr/bin/env python3
"""Check README evidence artifact freshness for CI governance.

This guard enforces that artifact citations in README.md are fresh (<=14 days old).
Citations have the format `*(from artifact-path, run correlation-id)*` or
`*(from artifact-path, generated timestamp)*`.

If any cited artifact is missing, stale, missing the cited correlation id, or is
a budget summary with CI no-data/fail/data-contract failures, the check fails to
prevent stale or unverifiable evidence from misleading users about current
project capabilities.

Usage:
    python3 scripts/check_readme_evidence_freshness.py
    python3 scripts/check_readme_evidence_freshness.py --self-test

Exit codes:
    0 - All citations are fresh
    1 - One or more missing or stale citations found
    2 - Script error (missing files, parse failures, etc.)
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import NamedTuple


class CitationCheck(NamedTuple):
    """Result of checking a single citation."""
    artifact_path: str
    correlation_id: str
    file_exists: bool
    file_mtime: datetime | None
    days_old: float | None
    is_stale: bool
    content_errors: tuple[str, ...]


def strip_markdown_code(text: str) -> str:
    """Remove Markdown code blocks/spans so examples are not treated as claims."""
    without_fenced_blocks = re.sub(r"(?ms)^```.*?^```", "", text)
    return re.sub(r"`[^`\n]*`", "", without_fenced_blocks)


def is_placeholder_citation(artifact_path: str, correlation_id: str) -> bool:
    """Return true for documentation placeholders, not real evidence claims."""
    return artifact_path.startswith("[") or correlation_id.startswith("[")


def parse_citations(readme_text: str) -> list[tuple[str, str]]:
    """Parse real README artifact citations, excluding examples and placeholders."""
    # Pattern: *(from artifact-path, run correlation-id)*
    stripped = strip_markdown_code(readme_text)
    citations = []
    citation_patterns = [
        r'\*\(from ([^,]+), run ([^)]+)\)\*',
        r'\*\(from ([^,]+), generated `?([^`)]+)`?\)\*',
    ]
    seen: set[tuple[str, str]] = set()
    for citation_pattern in citation_patterns:
        for artifact_path, correlation_id in re.findall(citation_pattern, stripped):
            artifact_path = artifact_path.strip()
            correlation_id = correlation_id.strip()
            if is_placeholder_citation(artifact_path, correlation_id):
                continue
            citation = (artifact_path, correlation_id)
            if citation not in seen:
                seen.add(citation)
                citations.append(citation)
    return citations


def as_utc(value: datetime) -> datetime:
    """Normalize datetimes so age checks never mix naive and aware values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_iso_datetime(raw: object) -> datetime | None:
    """Parse RFC3339-ish timestamps, including Rust nanosecond precision."""
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = f"{value[:-1]}+00:00"
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", value)
    if match:
        prefix, fraction, suffix = match.groups()
        value = f"{prefix}.{fraction[:6].ljust(6, '0')}{suffix}"
    try:
        return as_utc(datetime.fromisoformat(value))
    except ValueError:
        return None


def read_artifact_text(path: Path) -> tuple[str | None, str | None]:
    """Read an artifact as UTF-8 text for correlation and metadata checks."""
    try:
        return path.read_text(encoding="utf-8"), None
    except UnicodeDecodeError:
        return None, "artifact is not UTF-8 text"
    except Exception as exc:
        return None, f"failed to read artifact: {exc}"


def load_json_object(artifact_path: str, text: str) -> tuple[dict[str, object] | None, str | None]:
    """Load a JSON object when the artifact is JSON; ignore other formats."""
    if not artifact_path.endswith(".json"):
        return None, None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"artifact JSON failed to parse: {exc}"
    if not isinstance(payload, dict):
        return None, "artifact JSON must be an object"
    return payload, None


def check_artifact_content(
    artifact_path: str,
    correlation_id: str,
    full_path: Path,
    now: datetime,
    staleness_threshold: timedelta,
) -> tuple[str, ...]:
    """Validate that a cited artifact actually supports the README claim."""
    errors: list[str] = []
    text, read_error = read_artifact_text(full_path)
    if read_error is not None:
        return (read_error,)
    assert text is not None

    if correlation_id not in text:
        errors.append(f"cited run {correlation_id!r} not found in artifact content")

    payload, json_error = load_json_object(artifact_path, text)
    if json_error is not None:
        errors.append(json_error)
        return tuple(errors)
    if payload is None:
        return tuple(errors)

    generated_at = parse_iso_datetime(payload.get("generated_at"))
    if generated_at is None:
        errors.append("JSON artifact missing parseable generated_at timestamp")
    elif now - generated_at > staleness_threshold:
        days_old = (now - generated_at).total_seconds() / 86400
        errors.append(f"artifact generated_at is stale: {days_old:.1f} days old")

    if payload.get("schema") == "pi.perf.budget_summary.v1":
        ci_no_data = int(payload.get("ci_no_data") or 0)
        ci_fail = int(payload.get("ci_fail") or 0)
        data_contract_failures = int(payload.get("data_contract_failures_count") or 0)
        if ci_no_data != 0:
            errors.append(f"budget summary has ci_no_data={ci_no_data}")
        if ci_fail != 0:
            errors.append(f"budget summary has ci_fail={ci_fail}")
        if data_contract_failures != 0:
            errors.append(
                f"budget summary has data_contract_failures_count={data_contract_failures}"
            )

    return tuple(errors)


def check_readme(repo_root: Path, now: datetime | None = None) -> int:
    """Check the README under repo_root for missing or stale artifact citations."""
    readme_path = repo_root / "README.md"
    if not readme_path.exists():
        print(f"ERROR: README.md not found at {readme_path}")
        return 2

    try:
        readme_text = readme_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"ERROR: Failed to read README.md: {e}")
        return 2

    citations = parse_citations(readme_text)

    if not citations:
        print("INFO: No artifact citations found in README.md")
        return 0

    print(f"INFO: Checking {len(citations)} artifact citations for freshness...")

    # Check each citation
    stale_count = 0
    missing_count = 0
    results: list[CitationCheck] = []

    # 14-day staleness threshold
    staleness_threshold = timedelta(days=14)
    now = as_utc(now or datetime.now(timezone.utc))
    content_error_count = 0

    for artifact_path, correlation_id in citations:
        # Resolve artifact path relative to repo root
        full_path = repo_root / artifact_path

        if not full_path.exists():
            print(f"WARNING: Cited artifact does not exist: {artifact_path}")
            missing_count += 1
            results.append(CitationCheck(
                artifact_path=artifact_path,
                correlation_id=correlation_id,
                file_exists=False,
                file_mtime=None,
                days_old=None,
                is_stale=False,
                content_errors=(),
            ))
            continue

        try:
            # Get file modification time
            mtime = datetime.fromtimestamp(full_path.stat().st_mtime, timezone.utc)
            age = now - mtime
            days_old = age.total_seconds() / 86400  # Convert to days
            is_stale = age > staleness_threshold

            if is_stale:
                print(f"STALE: {artifact_path} (age: {days_old:.1f} days, limit: 14 days)")
                stale_count += 1
            else:
                print(f"FRESH: {artifact_path} (age: {days_old:.1f} days)")

            content_errors = check_artifact_content(
                artifact_path,
                correlation_id,
                full_path,
                now,
                staleness_threshold,
            )
            if content_errors:
                content_error_count += len(content_errors)
                for error in content_errors:
                    print(f"INVALID: {artifact_path}: {error}")

            results.append(CitationCheck(
                artifact_path=artifact_path,
                correlation_id=correlation_id,
                file_exists=True,
                file_mtime=mtime,
                days_old=days_old,
                is_stale=is_stale,
                content_errors=content_errors,
            ))

        except Exception as e:
            print(f"ERROR: Failed to check {artifact_path}: {e}")
            return 2

    # Summary
    print(f"\nSUMMARY:")
    print(f"  Total citations: {len(citations)}")
    print(f"  Fresh artifacts: {len([r for r in results if r.file_exists and not r.is_stale])}")
    print(f"  Stale artifacts: {stale_count}")
    print(f"  Missing artifacts: {missing_count}")
    print(f"  Invalid artifact content checks: {content_error_count}")

    if stale_count > 0:
        print(f"\nFAIL: {stale_count} cited artifact(s) are >14 days stale.")
        print("Evidence claims in README must be backed by fresh artifacts.")
        print("Re-run evidence generation and update citations to resolve this.")
        return 1

    if missing_count > 0:
        print(f"\nFAIL: {missing_count} cited artifact(s) are missing.")
        print("Evidence claims in README must reference checked-in artifacts.")
        return 1

    if content_error_count > 0:
        print(f"\nFAIL: {content_error_count} cited artifact content check(s) failed.")
        print("Evidence claims must cite artifacts with matching run provenance and clean data.")
        return 1

    print("\nPASS: All cited artifacts are fresh and content-valid.")
    return 0


def run_self_test() -> int:
    """Run a small fixture test for examples, placeholders, freshness, and missing files."""
    with TemporaryDirectory() as temp_dir:
        repo_root = Path(temp_dir)
        artifact = repo_root / "tests/perf/reports/fresh.json"
        artifact.parent.mkdir(parents=True)
        now = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
        artifact.write_text(
            json.dumps(
                {
                    "generated_at": now.isoformat(),
                    "correlation_id": "fixture-run",
                    "ok": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        fresh_ts = now.timestamp()
        os.utime(artifact, (fresh_ts, fresh_ts))

        readme = repo_root / "README.md"
        readme.write_text(
            "\n".join([
                "Example: `*(from [artifact-path], run [correlation-id])*`",
                "```",
                "*(from missing-in-code-block.json, run example)*",
                "```",
                "Claim: *(from tests/perf/reports/fresh.json, run fixture-run)*",
                "",
            ]),
            encoding="utf-8",
        )

        first_output = io.StringIO()
        with contextlib.redirect_stdout(first_output):
            first_result = check_readme(repo_root, now=now)
        first_text = first_output.getvalue()
        if first_result != 0:
            print(first_text)
            print("SELF-TEST FAIL: fresh real citation should pass")
            return 2
        if "[artifact-path]" in first_text or "missing-in-code-block" in first_text:
            print(first_text)
            print("SELF-TEST FAIL: examples/placeholders must not be parsed as claims")
            return 2

        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "Broken claim: *(from tests/perf/reports/missing.json, run fixture-run)*\n",
            encoding="utf-8",
        )
        second_output = io.StringIO()
        with contextlib.redirect_stdout(second_output):
            second_result = check_readme(repo_root, now=now)
        if second_result != 1:
            print(second_output.getvalue())
            print("SELF-TEST FAIL: missing real citation should fail")
            return 2

        budget_summary = repo_root / "tests/perf/reports/budget_summary.json"
        budget_summary.write_text(
            json.dumps(
                {
                    "schema": "pi.perf.budget_summary.v1",
                    "generated_at": now.isoformat(),
                    "correlation_id": "budget-run",
                    "ci_no_data": 1,
                    "ci_fail": 0,
                    "data_contract_failures_count": 0,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.utime(budget_summary, (fresh_ts, fresh_ts))
        readme.write_text(
            "Claim: *(from tests/perf/reports/budget_summary.json, run budget-run)*\n",
            encoding="utf-8",
        )
        third_output = io.StringIO()
        with contextlib.redirect_stdout(third_output):
            third_result = check_readme(repo_root, now=now)
        if third_result != 1 or "ci_no_data=1" not in third_output.getvalue():
            print(third_output.getvalue())
            print("SELF-TEST FAIL: no-data budget summary citation should fail")
            return 2

        provenance_mismatch = repo_root / "tests/perf/reports/provenance_mismatch.json"
        provenance_mismatch.write_text(
            json.dumps(
                {
                    "generated_at": now.isoformat(),
                    "correlation_id": "actual-run",
                    "ok": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.utime(provenance_mismatch, (fresh_ts, fresh_ts))
        readme.write_text(
            "Claim: *(from tests/perf/reports/provenance_mismatch.json, run cited-run)*\n",
            encoding="utf-8",
        )
        fourth_output = io.StringIO()
        with contextlib.redirect_stdout(fourth_output):
            fourth_result = check_readme(repo_root, now=now)
        fourth_text = fourth_output.getvalue()
        if fourth_result != 1 or "cited run 'cited-run' not found" not in fourth_text:
            print(fourth_text)
            print("SELF-TEST FAIL: cited run mismatch should fail")
            return 2

        generated_stale = repo_root / "tests/perf/reports/generated_stale.json"
        generated_stale.write_text(
            json.dumps(
                {
                    "generated_at": (now - timedelta(days=30)).isoformat(),
                    "correlation_id": "stale-run",
                    "ok": True,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        os.utime(generated_stale, (fresh_ts, fresh_ts))
        readme.write_text(
            "Claim: *(from tests/perf/reports/generated_stale.json, run stale-run)*\n",
            encoding="utf-8",
        )
        fifth_output = io.StringIO()
        with contextlib.redirect_stdout(fifth_output):
            fifth_result = check_readme(repo_root, now=now)
        fifth_text = fifth_output.getvalue()
        if fifth_result != 1 or "artifact generated_at is stale" not in fifth_text:
            print(fifth_text)
            print("SELF-TEST FAIL: stale generated_at should fail even with fresh mtime")
            return 2

    print("SELF-TEST PASS")
    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run fixture-based checks for citation parsing behavior",
    )
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    repo_root = Path(__file__).resolve().parent.parent
    return check_readme(repo_root)


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo


SHANGHAI = ZoneInfo("Asia/Shanghai")
PROVIDER_AUTHORIZATION = False
ALLOWED_HORIZONS = {"D1", "D2", "D5"}
PRIVATE_MARKERS = (
    "K01-K14",
    "V15.1.1",
    "CUSTOM_GPT_FAST_RESEARCH_ADDENDUM",
    "private strategy thresholds",
    "private weighting",
)
SECRET_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{12,}"),
)
PERSONAL_PATH = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/")
EMAIL_ADDRESS = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def read_json(path: Path):
    def reject_constant(value: str):
        raise ValueError(f"non-finite JSON constant: {value}")

    return json.loads(path.read_text("utf-8"), parse_constant=reject_constant)


def canonical_hash(value) -> str:
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_action_contract(repo_root: Path) -> dict:
    contract_path = Path(__file__).resolve().parents[1] / "schemas" / "action-contract.json"
    contract = read_json(contract_path)
    expected = [
        ("GET", "/api/capabilities.json", "getCapabilities"),
        ("GET", "/api/coverage.json", "getCoverage"),
        ("GET", "/api/scan/normal.json", "getNormalMarketScan"),
        ("GET", "/api/scan/aggressive.json", "getAggressiveMarketScan"),
        ("GET", "/api/context/{symbol}/{horizon}.json", "getResearchContext"),
        ("GET", "/api/baseline/{symbol}/{horizon}.json", "getBaselineEvidence"),
    ]
    observed = [
        (item.get("method"), item.get("path"), item.get("operationId"))
        for item in contract.get("operations", [])
    ]
    if contract.get("base_url") != "https://l-zeus.github.io/gpt-quant-public-research-data":
        raise ValueError("frozen Pages Action host changed")
    if contract.get("auth") != "None" or observed != expected:
        raise ValueError("frozen Action paths, methods, auth, or operationIds changed")
    return {"operation_count": len(observed), "openapi_sha256": contract["openapi_sha256"]}


def scan_public_tree(docs: Path) -> dict[str, int]:
    counts = {
        "secret_leak_count": 0,
        "private_path_leak_count": 0,
        "private_instruction_leak_count": 0,
        "private_knowledge_leak_count": 0,
    }
    for path in sorted(docs.rglob("*")):
        if path.is_symlink():
            counts["private_path_leak_count"] += 1
            continue
        if not path.is_file():
            continue
        content = path.read_text("utf-8", errors="replace")
        counts["secret_leak_count"] += sum(len(pattern.findall(content)) for pattern in SECRET_PATTERNS)
        counts["private_path_leak_count"] += len(PERSONAL_PATH.findall(content))
        counts["private_instruction_leak_count"] += sum(
            content.casefold().count(marker.casefold()) for marker in PRIVATE_MARKERS[:3]
        )
        counts["private_knowledge_leak_count"] += sum(
            content.casefold().count(marker.casefold()) for marker in PRIVATE_MARKERS[3:]
        )
        counts["private_knowledge_leak_count"] += len(EMAIL_ADDRESS.findall(content))
    return counts


def validate_public_bundle(repo_root: Path) -> dict:
    docs = repo_root / "docs"
    api = docs / "api"
    if not api.is_dir():
        raise ValueError("docs/api is missing")

    json_files = sorted(api.rglob("*.json"))
    if not json_files:
        raise ValueError("public API has no JSON files")
    for path in json_files:
        if path.is_symlink():
            raise ValueError("symlinks are not allowed in the API tree")
        read_json(path)

    capabilities = read_json(api / "capabilities.json")
    coverage = read_json(api / "coverage.json")
    normal = read_json(api / "scan" / "normal.json")
    aggressive = read_json(api / "scan" / "aggressive.json")
    manifest_path = api / "static-manifest.json"
    static_manifest = read_json(manifest_path)
    action_contract = validate_action_contract(repo_root)
    context_schema_path = Path(__file__).resolve().parents[1] / "schemas" / "research-context.schema.json"
    context_schema = read_json(context_schema_path)

    research_n = capabilities.get("research_usable_symbol_n")
    scanner_n = capabilities.get("SCANNER_EVALUATED_N")
    data_as_of = capabilities.get("data_as_of")
    if not isinstance(research_n, int) or research_n < 1:
        raise ValueError("research_usable_symbol_n must be a positive integer")
    if coverage.get("research_usable_symbol_n") != research_n:
        raise ValueError("capability and coverage research counts differ")
    if not isinstance(data_as_of, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data_as_of):
        raise ValueError("data_as_of must be an ISO date")
    date.fromisoformat(data_as_of)
    if capabilities.get("backend_mode") != "GITHUB_PAGES_STATIC_READ":
        raise ValueError("unexpected backend mode")
    if capabilities.get("CUSTOM_GPT_RESEARCH_USABLE") is not True:
        raise ValueError("capabilities contradict the protected Custom GPT research-usable state")
    if capabilities.get("eligible_universe_status") not in {None, "NOT_ESTABLISHED"}:
        raise ValueError("formal eligible-universe status must remain not established")
    if (
        capabilities.get("eligible_universe_n") is not None
        or capabilities.get("research_coverage_ratio") is not None
        or capabilities.get("RESEARCH_COVERAGE_RATIO") is not None
    ):
        raise ValueError("unknown eligible-universe denominator and ratio must remain null")
    if coverage.get("eligible_universe_status") not in {None, "NOT_ESTABLISHED"}:
        raise ValueError("coverage must keep formal eligibility not established")
    if (
        coverage.get("eligible_universe_n") is not None
        or coverage.get("RESEARCH_COVERAGE_RATIO") is not None
        or coverage.get("research_coverage_ratio") is not None
    ):
        raise ValueError("coverage must not report an unsupported denominator or ratio")
    if capabilities.get("AUTO_ORDER") is not False or capabilities.get("ALPHA_PROVEN") is not False:
        raise ValueError("unsafe capability flags")
    if capabilities.get("FRESH_ENABLED") is not False:
        raise ValueError("FRESH_ENABLED must stay false")
    if capabilities.get("EXECUTION_USABLE") is not False:
        raise ValueError("static research data cannot be execution-usable")
    if capabilities.get("execution_status") != "EXECUTION_DATA_INSUFFICIENT":
        raise ValueError("execution status must fail closed")
    if not isinstance(scanner_n, int) or scanner_n < research_n:
        raise ValueError("scanner evaluated fewer symbols than the usable research set")

    coverage_records = coverage.get("records")
    if not isinstance(coverage_records, list):
        raise ValueError("coverage records must be an array")
    symbols = {
        item.get("symbol")
        for item in coverage_records
        if item.get("research_context_available") is True
    }
    if len(symbols) != research_n or None in symbols:
        raise ValueError("coverage records do not match the research usable count")
    if aggressive.get("coverage", {}).get("evaluated") != scanner_n:
        raise ValueError("aggressive scan count does not match capabilities")
    if aggressive.get("status") != "PASS":
        raise ValueError("aggressive scanner did not complete successfully")
    if normal.get("mode") != "NORMAL" or normal.get("status") not in {"PASS", "NOT_AVAILABLE"}:
        raise ValueError("normal scan response is malformed")

    contexts = sorted((api / "context").glob("*/*.json"))
    baselines = sorted((api / "baseline").glob("*/*.json"))
    if len(contexts) != research_n * 3 or len(baselines) != research_n * 3:
        raise ValueError("context or baseline count must equal research usable count times three")
    context_symbols = set()
    horizons: dict[str, int] = {h: 0 for h in sorted(ALLOWED_HORIZONS)}
    maximum_context_bytes = 0
    required_context_fields = set(context_schema.get("required", []))
    if not required_context_fields or context_schema.get("type") != "object":
        raise ValueError("research context schema is missing or malformed")
    for path in contexts:
        body = read_json(path)
        symbol, horizon = path.parent.name, path.stem
        if not required_context_fields.issubset(body):
            raise ValueError(f"context required fields are missing: {path.relative_to(repo_root)}")
        if horizon not in ALLOWED_HORIZONS or body.get("horizon") != horizon:
            raise ValueError(f"invalid context horizon: {path.relative_to(repo_root)}")
        if body.get("symbol") != symbol:
            raise ValueError(f"context symbol/path mismatch: {path.relative_to(repo_root)}")
        if body.get("RESEARCH_USABLE") is not True or body.get("EXECUTION_USABLE") is not False:
            raise ValueError(f"research/execution gate mismatch: {path.relative_to(repo_root)}")
        if body.get("execution_status") != "EXECUTION_DATA_INSUFFICIENT":
            raise ValueError(f"missing execution fail-closed status: {path.relative_to(repo_root)}")
        if body.get("prediction_decision") is not None:
            raise ValueError(f"static context cannot contain a prediction decision: {path.relative_to(repo_root)}")
        if body.get("data_as_of") != data_as_of:
            raise ValueError(f"context data_as_of mismatch: {path.relative_to(repo_root)}")
        for field in ("as_of", "generated_at", "retrieved_at"):
            timestamp = datetime.fromisoformat(body[field].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError(f"context {field} is not timezone-aware: {path.relative_to(repo_root)}")
        summary = body.get("daily_ohlcv_summary", {})
        if summary.get("observed_bar_count", 0) < 61:
            raise ValueError(f"context lacks the required observed bar window: {path.relative_to(repo_root)}")
        window_basis = summary.get("window_basis", "").casefold()
        if not all(token in window_basis for token in ("verified observed bars", "no interpolation", "forward fill", "synthetic prices")):
            raise ValueError(f"context does not state the no-imputation basis: {path.relative_to(repo_root)}")
        target_source = body.get("source_provenance", {}).get("target", {})
        if not target_source.get("data_manifest_id") or not target_source.get("retrieved_at"):
            raise ValueError(f"context target-source provenance is incomplete: {path.relative_to(repo_root)}")
        if body.get("PIT_status") != "PIT_APPROXIMATE":
            raise ValueError(f"context PIT status changed: {path.relative_to(repo_root)}")
        snapshot = {
            key: value
            for key, value in body.items()
            if key not in {"snapshot_hash", "evidence_manifest_hash"}
        }
        evidence = {key: value for key, value in body.items() if key != "evidence_manifest_hash"}
        if canonical_hash(snapshot) != body.get("snapshot_hash"):
            raise ValueError(f"context snapshot hash mismatch: {path.relative_to(repo_root)}")
        if canonical_hash(evidence) != body.get("evidence_manifest_hash"):
            raise ValueError(f"context evidence hash mismatch: {path.relative_to(repo_root)}")
        context_symbols.add(symbol)
        horizons[horizon] += 1
        maximum_context_bytes = max(maximum_context_bytes, path.stat().st_size)
        if path.stat().st_size > 100_000:
            raise ValueError(f"context exceeds 100 KB: {path.relative_to(repo_root)}")
    if context_symbols != symbols or any(horizons[h] != research_n for h in ALLOWED_HORIZONS):
        raise ValueError("context horizon coverage differs from the research symbol set")

    for candidate in aggressive.get("preliminary_top_candidates", []):
        symbol = candidate.get("symbol")
        if symbol not in context_symbols:
            raise ValueError("scanner candidate has no research context")
        context = read_json(api / "context" / symbol / "D1.json")
        signal = candidate.get("research_signal", {})
        target_id = context.get("source_provenance", {}).get("target", {}).get("data_manifest_id")
        returns = context.get("momentum", {}).get("observed_return_windows_pct", {})
        if candidate.get("source_snapshot_id") != target_id:
            raise ValueError("scanner candidate provenance does not match its context")
        if signal.get("momentum_20_pct") != returns.get("20_bar_pct"):
            raise ValueError("scanner 20-bar value does not match its context")
        if signal.get("momentum_60_pct") != returns.get("60_bar_pct"):
            raise ValueError("scanner 60-bar value does not match its context")
        if signal.get("liquidity_amount") != context.get("liquidity", {}).get("latest_observed_amount"):
            raise ValueError("scanner liquidity value does not match its context")
        if candidate.get("score_semantics") != "SCANNER_SCREENING_SCORE_NOT_PREDICTOR_SCORE":
            raise ValueError("scanner score semantics changed")

    for path in baselines:
        baseline = read_json(path)
        if baseline.get("status") != "NOT_AVAILABLE":
            raise ValueError(f"baseline evidence must stay explicitly unavailable: {path.relative_to(repo_root)}")

    listed = static_manifest.get("files")
    if not isinstance(listed, list):
        raise ValueError("static manifest files must be an array")
    expected = set()
    for entry in listed:
        relative = Path(entry.get("path", ""))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("static manifest contains an unsafe path")
        target = repo_root / relative
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"static manifest path is missing or unsafe: {relative}")
        if target.stat().st_size != entry.get("size_bytes"):
            raise ValueError(f"static manifest size mismatch: {relative}")
        if digest_file(target) != entry.get("sha256"):
            raise ValueError(f"static manifest SHA-256 mismatch: {relative}")
        expected.add(relative.as_posix())
    actual = {
        path.relative_to(repo_root).as_posix()
        for path in json_files
        if path != manifest_path
    }
    if expected != actual:
        raise ValueError("static manifest file set differs from the API JSON file set")
    if static_manifest.get("context_file_count") != len(contexts):
        raise ValueError("static manifest context count mismatch")
    if static_manifest.get("baseline_file_count") != len(baselines):
        raise ValueError("static manifest baseline count mismatch")

    unexpected_docs_files = [
        path.relative_to(docs).as_posix()
        for path in docs.rglob("*")
        if path.is_file() and path.suffix.lower() != ".json"
    ]
    if unexpected_docs_files:
        raise ValueError("unexpected non-JSON files in public Pages output")
    security = scan_public_tree(docs)
    if any(security.values()):
        raise ValueError("public static security scan found one or more findings")

    return {
        "status": "PASS",
        "data_as_of": data_as_of,
        "research_usable_n": research_n,
        "scanner_evaluated_n": scanner_n,
        "contexts": {key: horizons[key] for key in sorted(horizons)},
        "context_file_count": len(contexts),
        "baseline_file_count": len(baselines),
        "json_file_count": len(json_files),
        "manifest_entries_verified": len(expected),
        "static_manifest_sha256": digest_file(manifest_path),
        "maximum_context_bytes": maximum_context_bytes,
        "contract_operation_count": action_contract["operation_count"],
        "contract_openapi_sha256": action_contract["openapi_sha256"],
        "context_schema_required_field_count": len(required_context_fields),
        **security,
    }


def load_calendar(repo_root: Path) -> dict:
    path = repo_root / "data" / "trading_calendar" / "2026-10.json"
    value = read_json(path)
    if value.get("timezone") != "Asia/Shanghai":
        raise ValueError("calendar timezone must be Asia/Shanghai")
    return value


def decision_for(
    repo_root: Path,
    now: datetime,
    mode: str,
    target: str,
    dry_run: bool,
    publish_requested: bool,
) -> dict:
    if now.tzinfo is None:
        raise ValueError("clock override must include a timezone")
    now = now.astimezone(SHANGHAI)
    if mode not in {"refresh", "expand"}:
        raise ValueError("mode must be refresh or expand")
    if target not in {"300", "1000", "broader"}:
        raise ValueError("target coverage must be 300, 1000, or broader")

    calendar = load_calendar(repo_root)
    current_date = now.date()
    first = date.fromisoformat(calendar["range_start"])
    last = date.fromisoformat(calendar["range_end"])
    base = {
        "mode": mode,
        "target_coverage": target,
        "dry_run": dry_run,
        "publish_requested": publish_requested,
        "checked_at": now.isoformat(),
        "expected_session": None,
        "publish": False,
        "provider_authorized": PROVIDER_AUTHORIZATION,
    }
    if current_date < first or current_date > last:
        return {**base, "decision": "BLOCKED_CALENDAR_UNVERIFIED", "reason": "date outside the versioned official calendar"}
    sessions = set(calendar["sessions"])
    if current_date.isoformat() not in sessions:
        return {**base, "decision": "NO_OP_NON_TRADING_DAY", "reason": "official exchange calendar marks this date as closed"}
    if now.time() < time(19, 0):
        return {**base, "decision": "NO_OP_PUBLICATION_LAG_WINDOW", "reason": "do not fetch before the configured 19:00 Shanghai refresh window"}

    expected = current_date.isoformat()
    base["expected_session"] = expected
    capabilities = read_json(repo_root / "docs" / "api" / "capabilities.json")
    current_as_of = date.fromisoformat(capabilities["data_as_of"])
    if current_as_of >= date.fromisoformat(expected):
        return {**base, "decision": "NO_OP_ALREADY_CURRENT", "reason": "published data already covers the expected session"}
    if not PROVIDER_AUTHORIZATION:
        return {
            **base,
            "decision": "BLOCKED_PROVIDER_AUTHORIZATION",
            "reason": "no authorized/licensed production market-data gateway is configured",
        }
    return {
        **base,
        "decision": "BLOCKED_NO_PROVIDER_ADAPTER",
        "reason": "no public-safe provider adapter is present in this release branch",
    }


def write_report(repo_root: Path, report: dict) -> Path:
    output = repo_root / "run-artifacts" / "REFRESH_QUALITY_REPORT.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", "utf-8")
    return output


def append_github_output(path: str | None, report: dict) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as output:
        output.write(f"decision={report['decision']}\n")
        output.write(f"publish={'true' if report['publish'] else 'false'}\n")
        output.write(f"expected_session={report.get('expected_session') or ''}\n")


def append_summary(path: str | None, report: dict, validation: dict | None = None) -> None:
    if not path:
        return
    lines = [
        "## Static research refresh gate",
        "",
        f"- Decision: {report['decision']}",
        f"- Mode: {report['mode']}",
        f"- Expected session: {report.get('expected_session') or 'none'}",
        f"- Data as of: {report.get('previous_data_as_of') or 'unknown'}",
        f"- Research usable: {report.get('research_usable_n', 'unknown')}",
        f"- Scanner evaluated: {report.get('scanner_evaluated_n', 'unknown')}",
        "- Publish: no",
        f"- Reason: {report['reason']}",
    ]
    if validation:
        lines.extend(
            [
                f"- Validation: {validation['status']}",
                f"- Security scan: {'PASS' if not any(validation[key] for key in ('secret_leak_count', 'private_path_leak_count', 'private_instruction_leak_count', 'private_knowledge_leak_count')) else 'FAIL'}",
                f"- Release manifest hash: {validation['static_manifest_sha256']}",
            ]
        )
    with open(path, "a", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--root", type=Path, default=Path("."))
    decide = subparsers.add_parser("decide")
    decide.add_argument("--root", type=Path, default=Path("."))
    decide.add_argument("--mode", default="refresh")
    decide.add_argument("--target-coverage", default="300")
    decide.add_argument("--dry-run", default="false")
    decide.add_argument("--publish-requested", default="false")
    decide.add_argument("--now", default=None)
    run = subparsers.add_parser("run")
    run.add_argument("--root", type=Path, default=Path("."))
    run.add_argument("--mode", default="refresh")
    run.add_argument("--target-coverage", default="300")
    run.add_argument("--dry-run", default="false")
    run.add_argument("--publish-requested", default="false")
    run.add_argument("--now", default=None)

    args = parser.parse_args()
    repo_root = args.root.resolve()
    if args.command == "validate":
        result = validate_public_bundle(repo_root)
        print(json.dumps(result, sort_keys=True))
        return 0

    now = datetime.fromisoformat(args.now) if args.now else datetime.now(SHANGHAI)
    dry_run = args.dry_run.casefold() == "true"
    publish_requested = args.publish_requested.casefold() == "true"
    validation = None
    validation_error = None
    if args.command == "run":
        try:
            validation = validate_public_bundle(repo_root)
        except Exception as exc:
            validation_error = type(exc).__name__
    if validation_error:
        report = {
            "decision": "ABORT_VALIDATION",
            "reason": "static bundle or security validation failed",
            "expected_session": None,
            "publish": False,
            "provider_authorized": PROVIDER_AUTHORIZATION,
            "mode": args.mode,
            "target_coverage": args.target_coverage,
            "dry_run": dry_run,
            "publish_requested": publish_requested,
            "checked_at": now.astimezone(SHANGHAI).isoformat(),
        }
    else:
        report = decision_for(
            repo_root, now, args.mode, args.target_coverage, dry_run, publish_requested
        )
    try:
        capabilities = read_json(repo_root / "docs" / "api" / "capabilities.json")
    except Exception:
        capabilities = {}
    report.update(
        {
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "trigger": os.environ.get("GITHUB_EVENT_NAME", "local"),
            "started_at": now.isoformat(),
            "finished_at": datetime.now(SHANGHAI).isoformat(),
            "previous_data_as_of": capabilities.get("data_as_of"),
            "new_data_as_of": None,
            "symbols_attempted": 0,
            "symbols_updated": 0,
            "symbols_unchanged": 0,
            "symbols_failed": 0,
            "provider_failures": 0,
            "fallback_usage": 0,
            "contexts_generated": 0,
            "scanner_evaluated_n": capabilities.get("SCANNER_EVALUATED_N", 0),
            "research_usable_n": capabilities.get("research_usable_symbol_n", 0),
            "validation_status": "FAIL" if validation_error else (validation or {}).get("status", "NOT_RUN"),
            "security_status": "FAIL" if validation_error else (
                "PASS" if validation and not any(
                    validation[key] for key in (
                        "secret_leak_count",
                        "private_path_leak_count",
                        "private_instruction_leak_count",
                        "private_knowledge_leak_count",
                    )
                ) else "NOT_RUN"
            ),
            "publish_decision": "NO",
            "release_id": None,
            "failure_class": report["decision"] if report["decision"].startswith("BLOCKED_") else None,
            "reason": report["reason"],
        }
    )
    report_path = write_report(repo_root, report)
    append_github_output(os.environ.get("GITHUB_OUTPUT"), report)
    append_summary(os.environ.get("GITHUB_STEP_SUMMARY"), report, validation)
    print(json.dumps(report, sort_keys=True))
    print(f"quality_report={report_path.relative_to(repo_root)}")
    if validation_error:
        return 2
    return 0 if report["decision"].startswith("NO_OP_") else 2


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_ROOT = REPO_ROOT / "docs" / "api"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"release gate failed: {message}")


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text("utf-8"))
    except Exception as exc:
        raise SystemExit("release gate failed: invalid JSON payload") from exc
    require(isinstance(value, dict), "JSON documents must be objects")
    return value


def json_digest(value: dict) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_manifest(manifest: dict) -> None:
    entries = manifest.get("files")
    require(isinstance(entries, list), "static manifest entries missing")
    require(manifest.get("json_file_count") == len(entries), "static manifest count mismatch")
    seen: set[str] = set()
    for entry in entries:
        require(isinstance(entry, dict), "static manifest entry invalid")
        relative = entry.get("path")
        require(isinstance(relative, str), "static manifest path invalid")
        path = (REPO_ROOT / relative).resolve()
        require(path.is_relative_to(REPO_ROOT.resolve()), "static manifest path escapes repository")
        require(relative not in seen and path.is_file(), "static manifest path invalid")
        seen.add(relative)
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == entry.get("sha256"), "static manifest digest mismatch")
        require(len(raw) == entry.get("size_bytes"), "static manifest size mismatch")


def security_counts() -> dict[str, int]:
    secret_pattern = re.compile(
        r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
        r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----)"
    )
    private_path_pattern = re.compile(
        r"(?:/(?:Users|home)/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)",
        re.I,
    )
    private_instruction_pattern = re.compile(
        r"\b(?:confidential|private|internal)\s+(?:instructions?|prompt\s+rules|thresholds?)\b",
        re.I,
    )
    private_knowledge_pattern = re.compile(
        r"\b(?:private|internal)\s+knowledge(?:\s+base)?\b",
        re.I,
    )
    try:
        paths = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"], stderr=subprocess.DEVNULL
        ).decode("utf-8").split("\0")
    except Exception as exc:
        raise SystemExit("release gate failed: security scan could not enumerate public files") from exc
    counts = {
        "secret_leak_count": 0,
        "private_path_leak_count": 0,
        "private_instruction_leak_count": 0,
        "private_knowledge_leak_count": 0,
    }
    for relative in filter(None, paths):
        path = REPO_ROOT / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        counts["secret_leak_count"] += len(secret_pattern.findall(text))
        counts["private_path_leak_count"] += len(private_path_pattern.findall(text))
        counts["private_instruction_leak_count"] += len(private_instruction_pattern.findall(text))
        counts["private_knowledge_leak_count"] += len(private_knowledge_pattern.findall(text))
    return counts


def main() -> None:
    files = sorted(API_ROOT.rglob("*.json"))
    require(bool(files), "no API JSON files")
    for path in files:
        read_json(path)

    cap = read_json(API_ROOT / "capabilities.json")
    coverage = read_json(API_ROOT / "coverage.json")
    scan = read_json(API_ROOT / "scan" / "aggressive.json")
    status = read_json(API_ROOT / "status.json")
    static_manifest = read_json(API_ROOT / "static-manifest.json")

    require(cap.get("backend_mode") == "GITHUB_PAGES_STATIC_READ", "backend mode changed")
    research_n = cap.get("research_usable_symbol_n")
    scanner_n = cap.get("SCANNER_EVALUATED_N")
    require(isinstance(research_n, int) and research_n >= 100, "research coverage is below baseline")
    require(isinstance(scanner_n, int) and scanner_n >= research_n, "scanner coverage mismatch")
    require(coverage.get("research_usable_symbol_n") == research_n, "coverage count mismatch")
    require(scan.get("coverage", {}).get("evaluated") == scanner_n, "scanner evaluated count mismatch")

    require(cap.get("CUSTOM_GPT_PREVIEW_PASSED") is True, "verified Preview baseline missing")
    require(cap.get("CUSTOM_GPT_RESEARCH_USABLE") is True, "research chain must remain usable")
    require(cap.get("preview_verification_source") == "EXISTING_VERIFIED_PREVIEW_BASELINE", "Preview source label changed")
    require(cap.get("preview_verification_artifact") == "FAST_RESEARCH_RECOVERY_BASELINE_1", "Preview baseline artifact changed")
    require(cap.get("PREVIEW_REVERIFIED_THIS_RUN") is False, "Preview run provenance mismatch")
    require(cap.get("preview_verification_mode") == "EXISTING_VERIFIED_PREVIEW", "Preview mode changed")
    require(cap.get("preview_reverified_this_run") is False, "Preview run provenance mismatch")
    require(status.get("CUSTOM_GPT_PREVIEW_PASSED") is True, "status Preview flag mismatch")
    require(status.get("CUSTOM_GPT_RESEARCH_USABLE") is True, "status research flag mismatch")
    require(status.get("PREVIEW_REVERIFIED_THIS_RUN") is False, "status Preview provenance mismatch")
    require(status.get("preview_verification_source") == "EXISTING_VERIFIED_PREVIEW_BASELINE", "status Preview source label changed")
    require(status.get("preview_verification_artifact") == "FAST_RESEARCH_RECOVERY_BASELINE_1", "status Preview baseline artifact changed")
    require(status.get("preview_reverified_this_run") is False, "status Preview provenance mismatch")
    require(cap.get("CUSTOM_GPT_RESEARCH_USABLE") == status.get("CUSTOM_GPT_RESEARCH_USABLE"), "status semantics disagree")

    for key in ("EXECUTION_USABLE", "DYNAMIC_BACKTEST_AVAILABLE", "DEEP_AVAILABLE", "FRESH_ENABLED", "ALPHA_PROVEN", "AUTO_ORDER"):
        require(cap.get(key) is False, f"{key} must remain false")
    require(cap.get("PIT_STATUS") == "PIT_APPROXIMATE", "PIT status changed")
    for group, required_key in (
        ("SERVICE_READINESS", "CUSTOM_GPT_RESEARCH_USABLE"),
        ("DATA_FRESHNESS", "freshness_state"),
        ("EXECUTION_READINESS", "EXECUTION_USABLE"),
        ("STATISTICAL_VALIDATION", "PIT_STATUS"),
    ):
        require(isinstance(cap.get(group), dict) and required_key in cap[group], "capability semantic group missing")
    freshness = cap["DATA_FRESHNESS"]
    require(freshness.get("data_as_of") == cap.get("data_as_of"), "freshness data_as_of mismatch")
    require(freshness.get("generated_at") == cap.get("generated_at"), "freshness generated_at mismatch")
    require(freshness.get("latest_expected_session") == cap.get("latest_expected_session"), "expected session mismatch")
    require(isinstance(freshness.get("session_age"), int) and freshness["session_age"] >= 0, "session_age invalid")
    require(freshness.get("freshness_state") in {"LATEST_COMPLETE_SESSION", "STALE_USABLE", "STALE_BLOCKED"}, "freshness state invalid")
    require(cap.get("AUTO_ORDER") is False and cap.get("ALPHA_PROVEN") is False and cap.get("FRESH_ENABLED") is False, "safety gate changed")

    contexts = sorted((API_ROOT / "context").glob("*/*.json"))
    baselines = sorted((API_ROOT / "baseline").glob("*/*.json"))
    require(len(contexts) == research_n * 3, "context count mismatch")
    require(len(baselines) == research_n * 3, "baseline count mismatch")
    horizon_counts = {horizon: 0 for horizon in ("D1", "D2", "D5")}
    for path in contexts:
        body = read_json(path)
        require(body.get("RESEARCH_USABLE") is True, "context research gate changed")
        require(body.get("EXECUTION_USABLE") is False, "context execution gate changed")
        require(body.get("execution_status") == "EXECUTION_DATA_INSUFFICIENT", "context execution status changed")
        require(body.get("prediction_decision") is None, "predictor decision must remain absent")
        horizon = body.get("horizon")
        require(horizon in horizon_counts, "context horizon invalid")
        horizon_counts[horizon] += 1
        snapshot = {key: value for key, value in body.items() if key not in {"snapshot_hash", "evidence_manifest_hash"}}
        evidence = {key: value for key, value in body.items() if key != "evidence_manifest_hash"}
        require(json_digest(snapshot) == body.get("snapshot_hash"), "context snapshot hash mismatch")
        require(json_digest(evidence) == body.get("evidence_manifest_hash"), "context evidence hash mismatch")
    require(all(count == research_n for count in horizon_counts.values()), "per-horizon context count mismatch")
    for path in baselines:
        require(read_json(path).get("status") == "NOT_AVAILABLE", "baseline evidence must stay unavailable")

    validate_manifest(static_manifest)
    security = security_counts()
    require(all(count == 0 for count in security.values()), "public security gate failed")
    print(json.dumps({"status": "PASS", "json_file_count": len(files), "contexts": len(contexts), "contexts_by_horizon": horizon_counts, "baselines": len(baselines), "scanner_evaluated_n": scanner_n, **security}, sort_keys=True))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    from .research_release_gate import validate_public_bundle
except ImportError:
    from research_release_gate import validate_public_bundle


SHANGHAI = ZoneInfo("Asia/Shanghai")
GENERATOR_VERSION = "static-bundle-packager/0.1.0"


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def build_public_bundle(source_root: Path, output_docs: Path, expected_session: str) -> dict:
    source_root = source_root.resolve()
    source_docs = source_root / "docs"
    if not source_docs.is_dir():
        raise ValueError("source docs directory is missing")
    date.fromisoformat(expected_session)
    source_validation = validate_public_bundle(source_root)
    if source_validation["data_as_of"] != expected_session:
        raise ValueError("ABORT_DATA_AS_OF_NOT_EXPECTED_SESSION")

    capabilities = json.loads((source_docs / "api" / "capabilities.json").read_text("utf-8"))
    file_entries = []
    for path in sorted(item for item in source_docs.rglob("*") if item.is_file()):
        relative = path.relative_to(source_docs).as_posix()
        raw = path.read_bytes()
        file_entries.append(
            {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
        )
    tree_hash = hashlib.sha256(canonical_bytes(file_entries)).hexdigest()
    release_id = f"research-{expected_session.replace('-', '')}-{tree_hash[:8]}"
    manifest = {
        "schema_version": "PUBLIC_RELEASE_MANIFEST_V1",
        "release_id": release_id,
        "generated_at": datetime.now(SHANGHAI).isoformat(timespec="seconds"),
        "data_as_of": expected_session,
        "eligible_universe_n": capabilities.get("eligible_universe_n"),
        "eligible_universe_status": capabilities.get("eligible_universe_status") or "NOT_ESTABLISHED",
        "research_usable_n": capabilities["research_usable_symbol_n"],
        "research_coverage_ratio": capabilities.get("research_coverage_ratio"),
        "scanner_evaluated_n": capabilities["SCANNER_EVALUATED_N"],
        "context_count": source_validation["context_file_count"],
        "file_count": len(file_entries) + 1,
        "manifest_hash": tree_hash,
        "manifest_hash_semantics": "SHA-256 of sorted path, SHA-256, and size entries before this release manifest is added",
        "generator_version": GENERATOR_VERSION,
        "source_status": "PUBLIC_STATIC_SNAPSHOT_NO_PROVIDER_FETCH",
        "validation_status": "PASS_STATIC_BUNDLE; EXPECTED_SESSION_MATCH",
        "static_manifest_sha256": source_validation["static_manifest_sha256"],
    }

    output_docs = output_docs.resolve()
    output_docs.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="research-pages-stage-", dir=output_docs.parent) as temp:
        staging_root = Path(temp) / "release"
        staging_docs = staging_root / "docs"
        shutil.copytree(source_docs, staging_docs)
        (staging_docs / "PUBLIC_RELEASE_MANIFEST.json").write_bytes(
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        )
        staged_validation = validate_public_bundle(staging_root)
        if output_docs.exists():
            raise ValueError("output directory already exists; refusing to overwrite a staged release")
        os.replace(staging_docs, output_docs)
    return {
        "status": "PASS",
        "release_id": release_id,
        "data_as_of": expected_session,
        "manifest_hash": tree_hash,
        "file_count": manifest["file_count"],
        "research_usable_n": staged_validation["research_usable_n"],
        "scanner_evaluated_n": staged_validation["scanner_evaluated_n"],
        "context_file_count": staged_validation["context_file_count"],
        "source_status": manifest["source_status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True, help="new Pages docs directory")
    parser.add_argument("--expected-session", required=True)
    args = parser.parse_args()
    try:
        result = build_public_bundle(args.source_root, args.output, args.expected_session)
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations
import json
import hashlib
import json
from pathlib import Path

root = Path("docs/api")
files = sorted(root.rglob("*.json"))
if not files:
    raise SystemExit("no JSON files")
for path in files:
    json.loads(path.read_text("utf-8"))
cap = json.loads((root / "capabilities.json").read_text("utf-8"))
coverage = json.loads((root / "coverage.json").read_text("utf-8"))
scan = json.loads((root / "scan/aggressive.json").read_text("utf-8"))
assert cap["backend_mode"] == "GITHUB_PAGES_STATIC_READ"
assert cap["research_usable_symbol_n"] >= 100
assert cap["SCANNER_EVALUATED_N"] >= 100
assert coverage["research_usable_symbol_n"] == cap["research_usable_symbol_n"]
assert scan["coverage"]["evaluated"] == cap["SCANNER_EVALUATED_N"]
assert cap["AUTO_ORDER"] is False and cap["ALPHA_PROVEN"] is False and cap["FRESH_ENABLED"] is False
contexts = sorted((root / "context").glob("*/*.json"))
assert len(contexts) == cap["research_usable_symbol_n"] * 3
baselines = sorted((root / "baseline").glob("*/*.json"))
assert len(baselines) == cap["research_usable_symbol_n"] * 3
def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
for path in contexts:
    body = json.loads(path.read_text("utf-8"))
    assert body["RESEARCH_USABLE"] is True
    assert body["EXECUTION_USABLE"] is False
    assert body["execution_status"] == "EXECUTION_DATA_INSUFFICIENT"
    assert body["prediction_decision"] is None
    assert body["horizon"] in {"D1", "D2", "D5"}
    snapshot = {key: value for key, value in body.items() if key not in {"snapshot_hash", "evidence_manifest_hash"}}
    manifest = {key: value for key, value in body.items() if key != "evidence_manifest_hash"}
    assert digest(snapshot) == body["snapshot_hash"]
    assert digest(manifest) == body["evidence_manifest_hash"]
for path in baselines:
    assert json.loads(path.read_text("utf-8"))["status"] == "NOT_AVAILABLE"
print(f"validated {len(files)} JSON files, {len(contexts)} contexts, {len(baselines)} explicit baseline records")

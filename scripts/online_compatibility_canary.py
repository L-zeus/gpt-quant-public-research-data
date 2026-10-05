from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo


SHANGHAI = ZoneInfo("Asia/Shanghai")
FROZEN_BASE_URL = "https://l-zeus.github.io/gpt-quant-public-research-data"
SYMBOL_PATTERN = re.compile(r"^(?:sh|sz)\d{6}$")
HORIZONS = ("D1", "D2", "D5")
FIXED_PATHS = (
    "/api/capabilities.json",
    "/api/coverage.json",
    "/api/scan/normal.json",
    "/api/scan/aggressive.json",
)
CONTRACT_PATH = Path(__file__).resolve().parents[1] / "schemas" / "action-contract.json"


def validate_contract_file() -> dict:
    contract = json.loads(CONTRACT_PATH.read_text("utf-8"))
    operations = contract.get("operations", [])
    expected_ids = {
        "getCapabilities",
        "getCoverage",
        "getNormalMarketScan",
        "getAggressiveMarketScan",
        "getResearchContext",
        "getBaselineEvidence",
    }
    if contract.get("base_url") != FROZEN_BASE_URL or contract.get("auth") != "None":
        raise ValueError("frozen Action host or auth mode changed")
    if {item.get("operationId") for item in operations} != expected_ids or len(operations) != 6:
        raise ValueError("frozen Action operationIds changed")
    if {item.get("path") for item in operations if "{symbol}" not in item.get("path", "")} != set(FIXED_PATHS):
        raise ValueError("frozen fixed Action paths changed")
    return contract


def fetch_json(base_url: str, path: str, timeout: float) -> tuple[dict, int]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "static-research-canary/1"})
    with urlopen(request, timeout=timeout) as response:
        status = response.status
        body = json.loads(response.read().decode("utf-8"))
    if status != 200 or not isinstance(body, dict):
        raise ValueError(f"endpoint did not return a JSON object with HTTP 200: {path}")
    return body, status


def run(base_url: str, output_path: Path, timeout: float = 12.0) -> dict:
    contract = validate_contract_file()
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or parsed.netloc != "l-zeus.github.io":
        raise ValueError("canary host must remain the frozen GitHub Pages HTTPS host")
    if parsed.path.rstrip("/") != "/gpt-quant-public-research-data":
        raise ValueError("canary path must remain the frozen GitHub Pages repository path")

    probes = []
    responses: dict[str, dict] = {}
    semantic_mismatches = []
    for path in FIXED_PATHS:
        body, status = fetch_json(base_url, path, timeout)
        probes.append({"path": path, "status": status})
        responses[path] = body

    capabilities = responses["/api/capabilities.json"]
    coverage = responses["/api/coverage.json"]
    if capabilities.get("backend_mode") != "GITHUB_PAGES_STATIC_READ":
        raise ValueError("capabilities backend mode changed")
    if capabilities.get("EXECUTION_USABLE") is not False:
        raise ValueError("static Pages data must remain execution-disabled")
    if capabilities.get("execution_status") != "EXECUTION_DATA_INSUFFICIENT":
        raise ValueError("execution-data fail-closed status changed")
    if capabilities.get("AUTO_ORDER") is not False:
        raise ValueError("AUTO_ORDER must remain false")
    if capabilities.get("FRESH_ENABLED") is not False:
        raise ValueError("FRESH_ENABLED must remain false")
    if capabilities.get("CUSTOM_GPT_RESEARCH_USABLE") is not True:
        semantic_mismatches.append("CUSTOM_GPT_RESEARCH_USABLE is not true")

    records = coverage.get("records")
    if not isinstance(records, list):
        raise ValueError("coverage records are missing")
    symbols = sorted(
        {
            row.get("symbol")
            for row in records
            if row.get("research_context_available") is True
            and isinstance(row.get("symbol"), str)
            and SYMBOL_PATTERN.fullmatch(row["symbol"])
        }
    )
    if not symbols:
        raise ValueError("no research-usable symbol is available for canary probes")
    sample = symbols[:10]
    for symbol in sample:
        for horizon in HORIZONS:
            path = f"/api/context/{symbol}/{horizon}.json"
            body, status = fetch_json(base_url, path, timeout)
            if body.get("symbol") != symbol or body.get("horizon") != horizon:
                raise ValueError(f"context response does not match requested path: {path}")
            if body.get("RESEARCH_USABLE") is not True or body.get("EXECUTION_USABLE") is not False:
                raise ValueError(f"context research/execution gate changed: {path}")
            probes.append({"path": path, "status": status})

    for symbol in symbols[:3]:
        path = f"/api/baseline/{symbol}/D1.json"
        body, status = fetch_json(base_url, path, timeout)
        if body.get("status") != "NOT_AVAILABLE":
            raise ValueError(f"baseline endpoint no longer reports unavailable evidence: {path}")
        probes.append({"path": path, "status": status})

    report = {
        "schema_version": "STATIC_COMPATIBILITY_CANARY_V1",
        "checked_at": datetime.now(SHANGHAI).isoformat(),
        "base_url": FROZEN_BASE_URL,
        "auth": "None",
        "contract_operations": len(contract["operations"]),
        "fixed_endpoints": len(FIXED_PATHS),
        "context_symbol_sample": sample,
        "context_horizons_checked": list(HORIZONS),
        "baseline_symbols_checked": symbols[:3],
        "probe_count": len(probes),
        "all_http_200": all(item["status"] == 200 for item in probes),
        "capability_semantic_mismatches": semantic_mismatches,
        "status": "PASS" if not semantic_mismatches else "FAIL_CAPABILITY_SEMANTICS",
        "probes": probes,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", "utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=FROZEN_BASE_URL)
    parser.add_argument("--output", type=Path, default=Path("run-artifacts/STATIC_COMPATIBILITY_CANARY.json"))
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()
    try:
        report = run(args.base_url, args.output, args.timeout)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        failure = {
            "schema_version": "STATIC_COMPATIBILITY_CANARY_V1",
            "checked_at": datetime.now(SHANGHAI).isoformat(),
            "base_url": FROZEN_BASE_URL,
            "status": "FAIL",
            "probe_count": 0,
            "attempted_probe_count": 1 if isinstance(exc, (HTTPError, URLError, TimeoutError, OSError)) else 0,
            "failed_path": FIXED_PATHS[0] if isinstance(exc, (HTTPError, URLError, TimeoutError, OSError)) else None,
            "error_type": type(exc).__name__,
        }
        args.output.write_text(json.dumps(failure, ensure_ascii=False, indent=2) + "\n", "utf-8")
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "probe_count": report["probe_count"]}))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import logging
import math
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo

PROBE_DATE = "2026-09-30"
SYMBOL = "600004"
SHANGHAI = ZoneInfo("Asia/Shanghai")
OFFICIAL_NOTICES = (
    {
        "source": "sse_2026_holiday_notice",
        "url": "https://big5.sse.com.cn/site/cht/www.sse.com.cn/disclosure/announcement/general/c/c_20260915_10832273.shtml",
        "allowed_domain": "sse.com.cn",
    },
    {
        "source": "szse_2026_holiday_notice",
        "url": "https://www.szse.cn/www/disclosure/notice/general/t20260917_622911.html",
        "allowed_domain": "szse.cn",
    },
)
HISTORY_FIELDS = {
    "date": ("日期", "date"),
    "open": ("开盘", "open"),
    "high": ("最高", "high"),
    "low": ("最低", "low"),
    "close": ("收盘", "close"),
    "volume": ("成交量", "volume"),
    "amount": ("成交额", "amount"),
}


def now_shanghai() -> str:
    return datetime.now(timezone.utc).astimezone(SHANGHAI).isoformat(timespec="seconds")


def host_allowed(host: str | None, domain: str) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def safe_error_class(exc: BaseException) -> str:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, socket.gaierror):
            return "DNS_FAILURE"
        if isinstance(current, ssl.SSLError):
            return "TLS_FAILURE"
        if isinstance(current, ProbeRequestPolicyError):
            return "PROBE_REQUEST_POLICY_BLOCKED"
        if isinstance(current, (TimeoutError,)):
            return "SOURCE_TIMEOUT"
        name = type(current).__name__
        if name in {"ConnectTimeout", "ReadTimeout", "Timeout"}:
            return "SOURCE_TIMEOUT"
        if name in {"ProxyError", "ProxyConnectionError"}:
            return "PROXY_CONNECTION_FAILURE"
        response = getattr(current, "response", None)
        code = getattr(response, "status_code", None)
        if code == 429:
            return "SOURCE_RATE_LIMITED"
        if isinstance(code, int) and 400 <= code < 500:
            return "SOURCE_HTTP_4XX"
        if isinstance(code, int) and code >= 500:
            return "SOURCE_HTTP_5XX"
        current = current.__cause__ or current.__context__
    return type(exc).__name__


class ProbeRequestPolicyError(Exception):
    pass


class ProviderHTTPStatusError(Exception):
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.response = self


def base_record(source: str, adapter: str, upstream: str, started: float) -> dict:
    return {
        "source": source,
        "requested_adapter": adapter,
        "actual_upstream": upstream,
        "status": "NOT_RUN",
        "connectivity_status": "NOT_RUN",
        "latency_ms": None,
        "request_attempted": False,
        "request_response_received": False,
        "request_http_status": None,
        "network_request_count": 0,
        "retrieved_at": now_shanghai(),
        "requested_data_as_of": PROBE_DATE,
        "row_count": None,
        "schema_validation": "NOT_RUN",
        "schema_fingerprint": None,
        "content_hash": None,
        "price_semantics": "COMPLETED_DAILY_HISTORY_ONLY; NO_LIVE_OR_INTRADAY_DATA",
        "fallback_used": False,
        "fallback_reason": None,
        "error_class": None,
    }


def _column_lookup(columns) -> dict[str, str]:
    normalized = {str(column).strip().casefold(): str(column) for column in columns}
    lookup: dict[str, str] = {}
    for field, aliases in HISTORY_FIELDS.items():
        for alias in aliases:
            if alias.casefold() in normalized:
                lookup[field] = normalized[alias.casefold()]
                break
    return lookup


def validate_frame(frame) -> dict:
    columns = [str(column) for column in getattr(frame, "columns", [])]
    schema_fingerprint = hashlib.sha256(
        json.dumps(columns, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        row_count = int(len(frame))
    except Exception:
        row_count = None
    result = {
        "row_count": row_count,
        "schema_fingerprint": schema_fingerprint,
        "schema_validation": "FAIL",
        "content_hash": None,
        "error_class": None,
    }
    if row_count != 1:
        result["error_class"] = "ROW_COUNT_MISMATCH"
        return result
    columns_by_field = _column_lookup(columns)
    if set(columns_by_field) != set(HISTORY_FIELDS):
        result["error_class"] = "REQUIRED_COLUMN_MISSING"
        return result
    try:
        row = frame.iloc[0]
        date_value = str(row[columns_by_field["date"]]).strip()[:10]
        if date_value != PROBE_DATE:
            result["error_class"] = "DATA_AS_OF_MISMATCH"
            return result
        numeric = {
            field: float(row[columns_by_field[field]])
            for field in ("open", "high", "low", "close", "volume", "amount")
        }
        if not all(math.isfinite(value) for value in numeric.values()):
            result["error_class"] = "NON_FINITE_VALUE"
            return result
        if any(numeric[field] <= 0 for field in ("open", "high", "low", "close")):
            result["error_class"] = "NON_POSITIVE_OHLC"
            return result
        if numeric["high"] < numeric["low"]:
            result["error_class"] = "HIGH_BELOW_LOW"
            return result
        if numeric["volume"] < 0 or numeric["amount"] < 0:
            result["error_class"] = "NEGATIVE_VOLUME_OR_AMOUNT"
            return result
        canonical = {"date": date_value, **numeric}
        result["content_hash"] = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        ).hexdigest()
        result["schema_validation"] = "PASS"
        result["error_class"] = None
    except Exception as exc:
        result["error_class"] = safe_error_class(exc)
    return result


def _history_probe(source: str, method: str, upstream: str, call) -> dict:
    started = time.monotonic()
    record = base_record(source, method, upstream, started)
    try:
        import akshare as ak  # installed only in this workflow's hash-locked environment
        import requests

        original_get = requests.get
        request_count = 0

        def bounded_get(url, *args, **kwargs):
            nonlocal request_count
            request_count += 1
            record["network_request_count"] = request_count
            host = urlsplit(str(url)).hostname
            if request_count > 1 or not host_allowed(host, "eastmoney.com"):
                raise ProbeRequestPolicyError()
            kwargs["timeout"] = 12
            kwargs["allow_redirects"] = False
            response = original_get(url, *args, **kwargs)
            record["request_response_received"] = True
            record["request_http_status"] = int(response.status_code)
            if response.status_code != 200:
                raise ProviderHTTPStatusError(int(response.status_code))
            return response

        captured_out, captured_err = io.StringIO(), io.StringIO()
        logging.disable(logging.CRITICAL)
        requests.get = bounded_get
        try:
            with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
                record["request_attempted"] = True
                frame = call(ak)
        finally:
            requests.get = original_get
            logging.disable(logging.NOTSET)
        record["connectivity_status"] = "DATAFRAME_RETURNED"
        record.update(validate_frame(frame))
        record["status"] = "PASS" if record["schema_validation"] == "PASS" else "SCHEMA_FAIL"
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        record["connectivity_status"] = "HTTP_RESPONSE_RECEIVED" if record["request_response_received"] else "REQUEST_FAILED"
        record["schema_validation"] = "NOT_REACHED"
        record["status"] = "ERROR"
        record["error_class"] = safe_error_class(exc)
    finally:
        record["latency_ms"] = round((time.monotonic() - started) * 1000)
        record["retrieved_at"] = now_shanghai()
    return record


def _metadata_probe(spec: dict) -> dict:
    started = time.monotonic()
    record = base_record(spec["source"], "HTTPS_GET_OFFICIAL_NOTICE", spec["allowed_domain"], started)
    record["price_semantics"] = "EXCHANGE_HOLIDAY_NOTICE_METADATA; NOT_MARKET_DATA"
    record["schema_validation"] = "NOT_APPLICABLE"
    try:
        import requests
        current_url = spec["url"]
        response = None
        for redirect_count in range(2):
            response = requests.get(
                current_url,
                headers={"User-Agent": "gpt-quant-provider-probe/1", "Accept": "text/html"},
                timeout=(4, 12),
                allow_redirects=False,
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("Location")
            if not location or redirect_count >= 1:
                record["status"] = "FAIL"
                record["connectivity_status"] = "REDIRECT_LIMIT"
                record["error_class"] = "REDIRECT_LIMIT"
                return record
            next_url = urljoin(current_url, location)
            next_host = urlsplit(next_url).hostname
            if not host_allowed(next_host, spec["allowed_domain"]):
                record["status"] = "FAIL"
                record["connectivity_status"] = "REDIRECT_HOST_MISMATCH"
                record["error_class"] = "REDIRECT_HOST_MISMATCH"
                return record
            current_url = next_url
        assert response is not None
        final_host = urlsplit(current_url).hostname
        record["final_host"] = final_host
        record["http_status"] = int(response.status_code)
        if response.status_code == 200 and host_allowed(final_host, spec["allowed_domain"]):
            record["status"] = "PASS"
            record["connectivity_status"] = "HTTP_200_TLS_OK"
            record["content_hash"] = hashlib.sha256(response.content).hexdigest()
            record["row_count"] = None
        else:
            record["status"] = "FAIL"
            record["connectivity_status"] = "HTTP_OR_HOST_CHECK_FAILED"
            record["error_class"] = "SOURCE_HTTP_OR_HOST_FAILURE"
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        record["status"] = "ERROR"
        record["connectivity_status"] = "REQUEST_FAILED"
        record["error_class"] = safe_error_class(exc)
    finally:
        record["latency_ms"] = round((time.monotonic() - started) * 1000)
        record["retrieved_at"] = now_shanghai()
    return record


def validate_configuration() -> None:
    assert PROBE_DATE == "2026-09-30"
    assert SYMBOL == "600004"
    assert len(OFFICIAL_NOTICES) == 2
    assert host_allowed(urlsplit(OFFICIAL_NOTICES[0]["url"]).hostname, "sse.com.cn")
    assert host_allowed(urlsplit(OFFICIAL_NOTICES[1]["url"]).hostname, "szse.cn")
    assert all(len(aliases) == 2 for aliases in HISTORY_FIELDS.values())


def skipped_sina_record() -> dict:
    record = base_record(
        "sina_daily_via_akshare",
        "akshare.stock_zh_a_daily (not invoked)",
        "Sina Finance",
        time.monotonic(),
    )
    record.update(
        {
            "status": "SKIPPED",
            "connectivity_status": "NOT_ATTEMPTED",
            "latency_ms": 0,
            "schema_validation": "NOT_REACHED",
            "error_class": "AKSHARE_INTERFACE_EXCEEDS_SINGLE_REQUEST_BOUND",
        }
    )
    return record


def run_probe(output_path: Path) -> dict:
    validate_configuration()
    records: list[dict] = []
    try:
        import akshare as ak
        records.append(
            _history_probe(
                "eastmoney_daily_via_akshare",
                "akshare.stock_zh_a_hist",
                "Eastmoney via documented AKShare daily-history adapter",
                lambda ak: ak.stock_zh_a_hist(
                    symbol=SYMBOL,
                    period="daily",
                    start_date=PROBE_DATE.replace("-", ""),
                    end_date=PROBE_DATE.replace("-", ""),
                    adjust="",
                    timeout=12,
                ),
            )
        )
        # AKShare's documented Sina adapter issues a second request for
        # outstanding-share metadata and does not set request timeouts. That
        # exceeds this probe's one-request-per-source limit, so do not invoke it.
        records.append(skipped_sina_record())
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        error = "PROBE_DEPENDENCY_UNAVAILABLE"
        records.extend(
            {
                **base_record(source, adapter, upstream, time.monotonic()),
                "status": "ERROR",
                "connectivity_status": "NOT_ATTEMPTED",
                "schema_validation": "NOT_REACHED",
                "error_class": error,
                "latency_ms": 0,
                "retrieved_at": now_shanghai(),
            }
            for source, adapter, upstream in (
                ("eastmoney_daily_via_akshare", "akshare.stock_zh_a_hist", "Eastmoney via documented AKShare daily-history adapter"),
            )
        )
        records.append(skipped_sina_record())
    for spec in OFFICIAL_NOTICES:
        records.append(_metadata_probe(spec))

    market_records = records[:2]
    runner_reachable = any(bool(row.get("request_response_received")) for row in market_records)
    all_pass = all(row["status"] == "PASS" for row in records)
    result = {
        "schema_version": "PROVIDER_CONNECTIVITY_PROBE_V1",
        "generated_at": now_shanghai(),
        "probe_date": PROBE_DATE,
        "probe_runner": "GitHub-hosted ubuntu-24.04",
        "provider_probe_dispatched": True,
        "provider_runner_reachable": runner_reachable,
        "overall_status": "PASS" if all_pass else ("PARTIAL" if any(row["status"] == "PASS" for row in records) else "FAIL"),
        "market_data_api_calls": sum(bool(row.get("request_attempted")) for row in records),
        "raw_price_rows_persisted": 0,
        "raw_price_payload_logged": False,
        "automatic_retries": 0,
        "automatic_fallbacks": 0,
        "provider_terms_status": "TERMS_UNVERIFIED",
        "provider_production_approved": False,
        "publication_mode": "NOT_APPROVED",
        "provider_primary": None,
        "provider_fallback": None,
        "provider_research_refresh_ready": False,
        "sources": records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        lines = ["## Provider connectivity probe", "", f"Overall status: **{result['overall_status']}**", "", "| Source | Status | Latency ms | Rows | Schema | Error class |", "|---|---|---:|---:|---|---|"]
        for row in records:
            lines.append(f"| {row['source']} | {row['status']} | {row['latency_ms']} | {row['row_count']} | {row['schema_validation']} | {row['error_class'] or ''} |")
        lines.extend(["", "Provider terms remain unverified; this probe does not authorize publication."])
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    print(json.dumps({"overall_status": result["overall_status"], "provider_runner_reachable": runner_reachable, "source_statuses": {row["source"]: row["status"] for row in records}}))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("run-artifacts/provider-probe/PROVIDER_PROBE.json"))
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    if args.validate_only:
        validate_configuration()
        print(json.dumps({"status": "PASS_CONFIG_ONLY", "market_data_requests": 0}))
        return 0
    run_probe(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline and non-delivering validation for YetAnotherSMSBomber service YAML.

Every HTTP request runs through an in-process MockTransport. No external
services are contacted, and no SMS/call/e-mail is sent.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml


EXPECTED_METHODS = {"GET", "POST"}
KNOWN_KEYS = {
    "name", "method", "url", "params", "data", "headers", "cookies",
    "data_type", "identifier", "cc_target",
}


def load_services(path: Path) -> dict[str, list[dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("providers"), dict):
        raise ValueError("Expected a YAML mapping containing 'providers'")
    providers = document["providers"]
    if not providers or any(not isinstance(value, list) for value in providers.values()):
        raise ValueError("Each provider country group must be a list")
    return {str(key): value for key, value in providers.items()}


def substitute(value: Any, *, country: str, target: str) -> Any:
    if isinstance(value, str):
        return value.replace("{cc}", country).replace("{target}", target)
    if isinstance(value, dict):
        return {str(k): substitute(v, country=country, target=target) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, country=country, target=target) for v in value]
    return value


def audit_one(service: dict[str, Any], country: str) -> dict[str, Any]:
    name = str(service.get("name", "<unnamed>"))
    findings: list[str] = []
    request_built = False
    if any(not isinstance(key, str) for key in service):
        return {"name": name, "group": country, "request_built": False,
                "findings": ["INVALID_FIELD_NAME"]}
    if not isinstance(service.get("url"), str) or not service["url"]:
        return {"name": name, "group": country, "request_built": False, "findings": ["MISSING_URL"]}
    url = service["url"]
    try:
        url_info = urlsplit(url)
        # Accessing port also validates malformed/out-of-range port values.
        _ = url_info.port
    except ValueError:
        return {"name": name, "group": country, "request_built": False,
                "findings": ["NOT_HTTPS_OR_INVALID_URL"]}
    if url_info.scheme != "https" or not url_info.hostname:
        findings.append("NOT_HTTPS_OR_INVALID_URL")
    method = str(service.get("method", "")).upper()
    if method not in EXPECTED_METHODS:
        findings.append("UNSUPPORTED_METHOD")
    if not service.get("identifier"):
        findings.append("MISSING_RESPONSE_IDENTIFIER")
    if str(service.get("identifier", "")).lower() in {"true", "false", "1", "200", "202", "sent"}:
        findings.append("WEAK_RESPONSE_IDENTIFIER_NOT_DELIVERY_PROOF")
    if "cc_target" in service:
        findings.append("LEGACY_CC_TARGET_FIELD_NEEDS_REVIEW")
    if method == "GET" and any(term in url.lower() for term in ("otp", "register", "sendvcode")):
        findings.append("GET_WITH_NOTIFICATION_SIDE_EFFECT")
    headers = service.get("headers")
    if headers is not None and (not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in headers.items()
    )):
        findings.append("INVALID_HEADERS")
    elif any(any(term in key.lower() for term in ("key", "token", "secret", "authorization"))
             for key in (headers or {})):
        findings.append("EMBEDDED_AUTH_HEADER_NEEDS_REVIEW")
    for unknown in sorted(set(service) - KNOWN_KEYS):
        findings.append(f"UNKNOWN_FIELD:{unknown}")
    if method not in EXPECTED_METHODS or any(finding in findings for finding in (
        "NOT_HTTPS_OR_INVALID_URL", "INVALID_HEADERS"
    )):
        return {"name": name, "group": country, "request_built": False,
                "hostname": url_info.hostname, "findings": findings}

    # Use obviously fake placeholders. The transport does not reach the network.
    fake_target = "000000000"
    fake_country = "33"
    params = substitute(service.get("params") or {}, country=fake_country, target=fake_target)
    data = substitute(service.get("data") or {}, country=fake_country, target=fake_target)
    headers = substitute(service.get("headers") or {}, country=fake_country, target=fake_target)
    cookies = substitute(service.get("cookies") or {}, country=fake_country, target=fake_target)
    data_type = str(service.get("data_type", "form")).lower()
    if data_type not in {"form", "json"}:
        findings.append("UNKNOWN_DATA_TYPE")
        return {"name": name, "group": country, "hostname": url_info.hostname,
                "request_built": False, "findings": findings}

    captured: list[httpx.Request] = []

    def mocked_response(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"simulated": True}, request=request)

    try:
        with httpx.Client(
            transport=httpx.MockTransport(mocked_response),
            cookies=cookies,
            http2=True,
            follow_redirects=False,
            trust_env=False,
            timeout=5.0,
        ) as client:
            keyword_args: dict[str, Any] = {"headers": headers}
            if method == "GET":
                keyword_args["params"] = params
            elif data_type == "json":
                keyword_args["json"] = data
            else:
                keyword_args["data"] = data
            response = client.request(method, url, **keyword_args)
            request_built = response.status_code == 200 and len(captured) == 1
    except (httpx.HTTPError, TypeError, ValueError, UnicodeError) as exc:
        findings.append(f"REQUEST_CONSTRUCTION_ERROR:{type(exc).__name__}")
    return {"name": name, "group": country, "hostname": url_info.hostname,
            "request_built": request_built, "findings": findings}


def audit_file(path: Path) -> dict[str, Any]:
    providers = load_services(path)
    results = []
    for country, services in providers.items():
        for item in services:
            if not isinstance(item, dict):
                results.append({"name": "<invalid>", "group": country,
                                "request_built": False, "findings": ["NOT_A_MAPPING"]})
            else:
                results.append(audit_one(item, country))
    return {
        "mode": "OFFLINE_MOCK_ONLY",
        "network_requests": 0,
        "messages_sent": 0,
        "total_services": len(results),
        "mock_requests_constructed": sum(bool(r["request_built"]) for r in results),
        "groups": {key: len(value) for key, value in providers.items()},
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive, offline YAML/API-configuration audit")
    parser.add_argument("--config", type=Path, default=Path("services.yaml"))
    parser.add_argument("--json", action="store_true", help="Print machine-readable results")
    args = parser.parse_args()
    try:
        report = audit_file(args.config)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        parser.exit(2, f"Configuration audit failed: {exc}\n")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Mode: {report['mode']} (no network, no SMS sent)")
        print(f"Services: {report['total_services']} | Mock requests built: {report['mock_requests_constructed']}")
        for result in report["results"]:
            findings = ", ".join(result["findings"]) if result["findings"] else "schema OK"
            status = "MOCK OK" if result["request_built"] else "INVALID"
            print(f"[{result['group']}] {result['name']}: {status} — {findings}")
    return 0 if report["mock_requests_constructed"] == report["total_services"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

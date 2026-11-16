from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..assets import AssetReport
from ..exclude import is_excluded
from ..http_client import HttpSession, ResponseData
from ..models import Discovery, Endpoint, Finding, ScanConfig

LogFn = Callable[[str, str], Awaitable[None]]

SENSITIVE_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token", "set-cookie"}


def mask_value(value: str) -> str:
    value = (value or "").strip()
    if len(value) <= 10:
        return value[:3] + "***"
    return value[:10] + "***" + value[-4:]


def format_request(method: str, url: str, headers: dict[str, str] | None = None, body: str = "") -> str:
    parsed = urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [f"{method.upper()} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
    for name, value in (headers or {}).items():
        lowered = name.lower()
        if lowered in ("host", "connection", "content-length"):
            continue
        shown = mask_value(value) if lowered in SENSITIVE_HEADERS else value
        lines.append(f"{name}: {shown}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)[:6000]


def format_response(resp: ResponseData, body_limit: int = 900) -> str:
    lines = [f"HTTP/1.1 {resp.status}"]
    interesting = [
        "server", "content-type", "content-length", "location", "content-encoding",
        "access-control-allow-origin", "access-control-allow-credentials",
        "www-authenticate", "x-powered-by",
    ]
    for name in interesting:
        value = resp.headers.get(name)
        if value:
            lines.append(f"{name.title()}: {mask_value(value) if name == 'www-authenticate' else value}")
    if resp.set_cookie:
        lines.append("Set-Cookie: " + mask_value(resp.set_cookie[0]))
    lines.append("")
    if resp.text:
        lines.append(truncate(resp.text, body_limit))
    return "\n".join(lines)[:6000]


def build_curl(method: str, url: str, headers: dict[str, str] | None = None) -> str:
    parts = ["curl -i -sS", "-X", method.upper(), f"'{url}'"]
    for name, value in (headers or {}).items():
        lowered = name.lower()
        if lowered in ("connection", "content-length"):
            continue
        shown = mask_value(value) if lowered in SENSITIVE_HEADERS else value
        parts.append(f"-H '{name}: {shown}'")
    return " ".join(parts)


def capture(
    resp: ResponseData,
    *,
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
) -> dict[str, str]:
    """生成用于复现的请求、响应原文与 cURL。"""
    target = url or resp.url
    return {
        "request": format_request(method, target, headers, body),
        "response": format_response(resp),
        "curl": build_curl(method, target, headers),
    }


@dataclass
class CheckContext:
    config: ScanConfig
    session: HttpSession
    discovery: Discovery
    assets: AssetReport
    log: LogFn
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def root_page(self):
        return next(iter(self.discovery.pages.values()), None)

    def excluded(self, url: str) -> bool:
        return is_excluded(url, self.config.exclude_paths)

    def param_candidates(self, limit: int = 40) -> list[tuple[str, str]]:
        seen: set[tuple[str, str, str, str]] = set()
        candidates: list[tuple[str, str]] = []
        endpoints = sorted(
            self.discovery.endpoints.values(),
            key=lambda item: (0 if "openapi" in item.source else 1, item.url),
        )
        for endpoint in endpoints:
            if endpoint.method.upper() != "GET":
                continue
            if self.excluded(endpoint.url):
                continue
            parsed = urlparse(endpoint.url)
            for name in parse_qs(parsed.query).keys():
                signature = (parsed.scheme, parsed.netloc, parsed.path, name)
                if signature not in seen:
                    seen.add(signature)
                    candidates.append((endpoint.url, name))
            if len(candidates) >= limit:
                return candidates
        for form in self.discovery.forms:
            if form.method.upper() != "GET":
                continue
            if self.excluded(form.action):
                continue
            parsed = urlparse(form.action)
            for name in form.inputs:
                signature = (parsed.scheme, parsed.netloc, parsed.path, name)
                if signature not in seen:
                    seen.add(signature)
                    candidates.append((form.action, name))
            if len(candidates) >= limit:
                return candidates
        return candidates


CheckFn = Callable[[CheckContext], Awaitable[list[Finding]]]


def truncate(text: str, limit: int = 900) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n…（已截断）"


def replace_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[name] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def finding(
    *,
    check_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    remediation: str,
    confidence: str = "high",
    url: str = "",
    method: str = "GET",
    param: str = "",
    evidence: str = "",
    cwe: str = "",
    owasp: str = "",
    references: list[str] | None = None,
    fingerprint: str = "",
    request: str = "",
    response: str = "",
    curl: str = "",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        category=category,
        confidence=confidence,
        url=url,
        method=method,
        param=param,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        owasp=owasp,
        references=references or [],
        fingerprint=fingerprint,
        request=request,
        response=response,
        curl=curl,
    )


def unique_endpoints(discovery: Discovery) -> list[Endpoint]:
    seen: set[str] = set()
    endpoints: list[Endpoint] = []
    for endpoint in discovery.endpoints.values():
        if endpoint.url in seen:
            continue
        seen.add(endpoint.url)
        endpoints.append(endpoint)
    return endpoints

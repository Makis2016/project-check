from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..assets import AssetReport
from ..http_client import HttpSession
from ..models import Discovery, Endpoint, Finding, ScanConfig

LogFn = Callable[[str, str], Awaitable[None]]


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

    def param_candidates(self, limit: int = 40) -> list[tuple[str, str]]:
        seen: set[tuple[str, str, str, str]] = set()
        candidates: list[tuple[str, str]] = []
        for endpoint in self.discovery.endpoints.values():
            if endpoint.method.upper() != "GET":
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

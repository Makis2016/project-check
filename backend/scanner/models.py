from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
SEVERITY_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
CONFIDENCE_LABEL = {"high": "高", "medium": "中", "low": "低"}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211, 27017, 5000]
EXTENDED_PORTS = COMMON_PORTS + [444, 873, 1080, 1433, 1521, 2181, 2375, 3000, 5000, 5601, 6379, 7001, 8000, 8009, 9000, 9042, 9090, 10000, 15672, 25565]


@dataclass
class ScanConfig:
    target: str
    preset: str = "standard"
    scan_type: str = "web"
    authorization_confirmed: bool = False
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    rate_limit: float = 5.0
    max_pages: int = 60
    max_requests: int = 3000
    ports: list[int] = field(default_factory=lambda: list(COMMON_PORTS))
    scan_ports: bool = True
    subdomain_enum: bool = False
    active_checks: bool = True
    api_scan: bool = True
    quality_checks: bool = True
    auth_checks: bool = False
    intrusive_checks: bool = False
    ignore_tls: bool = False
    max_js_files: int = 40
    proxy: str = ""
    exclude_paths: list[str] = field(default_factory=list)
    secondary_cookie: str = ""
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_password: str = ""
    ssh_key_path: str = ""
    ssh_key_passphrase: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("ssh_password", None)
        data.pop("ssh_key_passphrase", None)
        return data


PRESET_DEFAULTS: dict[str, dict[str, Any]] = {
    "quick": {
        "max_pages": 20,
        "max_requests": 1200,
        "rate_limit": 5.0,
        "scan_ports": False,
        "subdomain_enum": False,
        "active_checks": False,
        "api_scan": False,
        "quality_checks": False,
        "max_js_files": 20,
    },
    "standard": {
        "max_pages": 60,
        "max_requests": 3000,
        "rate_limit": 5.0,
        "scan_ports": True,
        "subdomain_enum": False,
        "active_checks": True,
        "api_scan": True,
        "quality_checks": True,
        "max_js_files": 40,
    },
    "deep": {
        "max_pages": 150,
        "max_requests": 8000,
        "rate_limit": 8.0,
        "scan_ports": True,
        "subdomain_enum": True,
        "active_checks": True,
        "api_scan": True,
        "quality_checks": True,
        "max_js_files": 80,
        "ports": EXTENDED_PORTS,
    },
}


def _parse_exclude(raw: Any) -> list[str]:
    if isinstance(raw, str):
        parts = raw.replace("\n", ",").split(",")
    elif isinstance(raw, (list, tuple)):
        parts = [str(item) for item in raw]
    else:
        parts = []
    cleaned: list[str] = []
    for part in parts:
        value = part.strip()
        if value and value not in cleaned:
            cleaned.append(value[:200])
    return cleaned[:50]


def _clamp_port(raw: Any) -> int:
    try:
        port = int(raw or 22)
    except (TypeError, ValueError):
        port = 22
    return min(max(port, 1), 65535)


def build_config(payload: dict[str, Any]) -> ScanConfig:
    preset = payload.get("preset") or "standard"
    if preset not in PRESET_DEFAULTS:
        preset = "standard"
    defaults = PRESET_DEFAULTS[preset]
    scan_type = str(payload.get("scan_type") or "web")
    if scan_type not in ("web", "linux", "windows"):
        scan_type = "web"
    cfg = ScanConfig(
        target=str(payload.get("target") or "").strip(),
        preset=preset,
        scan_type=scan_type,
        authorization_confirmed=bool(payload.get("authorization_confirmed")),
        cookie=str(payload.get("cookie") or "").strip(),
        headers={str(k): str(v) for k, v in (payload.get("headers") or {}).items() if k},
        rate_limit=float(payload.get("rate_limit") or defaults["rate_limit"]),
        max_pages=int(payload.get("max_pages") or defaults["max_pages"]),
        max_requests=int(payload.get("max_requests") or defaults["max_requests"]),
        ports=[int(p) for p in (payload.get("ports") or defaults.get("ports") or COMMON_PORTS)],
        scan_ports=bool(payload.get("scan_ports", defaults["scan_ports"])),
        subdomain_enum=bool(payload.get("subdomain_enum", defaults["subdomain_enum"])),
        active_checks=bool(payload.get("active_checks", defaults["active_checks"])),
        api_scan=bool(payload.get("api_scan", defaults.get("api_scan", True))),
        quality_checks=bool(payload.get("quality_checks", defaults.get("quality_checks", True))),
        auth_checks=bool(payload.get("auth_checks")),
        intrusive_checks=bool(payload.get("intrusive_checks")),
        ignore_tls=bool(payload.get("ignore_tls")),
        max_js_files=int(payload.get("max_js_files") or defaults["max_js_files"]),
        proxy=str(payload.get("proxy") or "").strip(),
        exclude_paths=_parse_exclude(payload.get("exclude_paths")),
        secondary_cookie=str(payload.get("secondary_cookie") or "").strip()[:6000],
        ssh_port=_clamp_port(payload.get("ssh_port")),
        ssh_user=str(payload.get("ssh_user") or "").strip()[:128],
        ssh_password=str(payload.get("ssh_password") or ""),
        ssh_key_path=str(payload.get("ssh_key_path") or "").strip()[:1000],
        ssh_key_passphrase=str(payload.get("ssh_key_passphrase") or ""),
    )
    cfg.rate_limit = min(max(cfg.rate_limit, 0.5), 30.0)
    cfg.max_pages = min(max(cfg.max_pages, 1), 500)
    cfg.max_requests = min(max(cfg.max_requests, 50), 20000)
    return cfg


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str = "config"
    confidence: str = "high"
    url: str = ""
    method: str = "GET"
    param: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    references: list[str] = field(default_factory=list)
    fingerprint: str = ""
    request: str = ""
    response: str = ""
    curl: str = ""

    def key(self) -> str:
        return "|".join([self.check_id, self.url, self.param, self.fingerprint or self.title])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: str = "crawl"
    params: list[str] = field(default_factory=list)
    status: int | None = None
    content_type: str = ""

    def key(self) -> str:
        return f"{self.method.upper()} {self.url}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    html: str = ""
    content_type: str = ""
    set_cookie: list[str] = field(default_factory=list)


@dataclass
class Form:
    action: str
    method: str = "GET"
    inputs: list[str] = field(default_factory=list)
    source_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CookieInfo:
    name: str
    secure: bool
    http_only: bool
    same_site: str
    raw: str = ""
    source_url: str = ""


@dataclass
class Tech:
    name: str
    version: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Discovery:
    pages: dict[str, Page] = field(default_factory=dict)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    js_files: list[str] = field(default_factory=list)
    js_text: dict[str, str] = field(default_factory=dict)
    docs: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    cookies: list[CookieInfo] = field(default_factory=list)
    tech: list[Tech] = field(default_factory=list)
    robots: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)

    def add_endpoint(self, ep: Endpoint) -> None:
        key = ep.key()
        existing = self.endpoints.get(key)
        if existing is None:
            self.endpoints[key] = ep
        else:
            if ep.source not in existing.source.split(","):
                existing.source = f"{existing.source},{ep.source}"
            for p in ep.params:
                if p not in existing.params:
                    existing.params.append(p)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pages": [p.to_dict() if hasattr(p, "to_dict") else p.__dict__ for p in self.pages.values()],
            "endpoints": [e.to_dict() for e in self.endpoints.values()],
            "js_files": self.js_files,
            "docs": self.docs,
            "forms": [f.to_dict() for f in self.forms],
            "cookies": [c.__dict__ for c in self.cookies],
            "tech": [t.to_dict() for t in self.tech],
            "robots": self.robots,
            "sitemaps": self.sitemaps,
        }


@dataclass
class AssetReport:
    resolved_ips: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    tls: dict[str, Any] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Summary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    endpoint_count: int = 0
    page_count: int = 0
    request_count: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_findings(cls, findings: list[Finding], **extra: Any) -> "Summary":
        data = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            data[f.severity] = data.get(f.severity, 0) + 1
        return cls(total=len(findings), **data, **extra)


def new_scan_id() -> str:
    return time.strftime("%Y%m%d%H%M%S", time.localtime()) + "-" + uuid.uuid4().hex[:8]

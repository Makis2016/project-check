from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Tech

DB_PATH = Path(__file__).with_name("cve_db.json")

SERVER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("nginx", re.compile(r"nginx/([\d.]+)", re.I)),
    ("openresty", re.compile(r"openresty/([\d.]+)", re.I)),
    ("apache", re.compile(r"apache/([\d.]+)", re.I)),
    ("iis", re.compile(r"microsoft-iis/([\d.]+)", re.I)),
    ("tomcat", re.compile(r"tomcat/?([\d.]+)?", re.I)),
    ("caddy", re.compile(r"caddy/?([\d.]+)?", re.I)),
    ("gunicorn", re.compile(r"gunicorn/?([\d.]+)?", re.I)),
    ("uvicorn", re.compile(r"uvicorn/?([\d.]+)?", re.I)),
]

JS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jquery", re.compile(r"jquery[-.]?v?([\d]+\.[\d]+\.[\d]+)", re.I)),
    ("jquery", re.compile(r"/jquery/([\d]+\.[\d]+\.[\d]+)/", re.I)),
    ("bootstrap", re.compile(r"bootstrap[-./]?v?([\d]+\.[\d]+\.[\d]+)", re.I)),
    ("vue", re.compile(r"vue[@/.-]?v?([\d]+\.[\d]+\.[\d]+)", re.I)),
    ("react", re.compile(r"react[@/.-]?v?([\d]+\.[\d]+\.[\d]+)", re.I)),
    ("angular", re.compile(r"angular[@/.-]?v?([\d]+\.[\d]+\.[\d]+)", re.I)),
    ("next.js", re.compile(r"/_next/static/", re.I)),
]

HTML_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    ("wordpress", re.compile(r"wp-content|wp-includes", re.I), True),
    ("drupal", re.compile(r"drupal\.js|sites/default/files", re.I), True),
    ("joomla", re.compile(r"/media/jui/|joomla", re.I), True),
    ("next.js", re.compile(r"__NEXT_DATA__|/_next/", re.I), True),
    ("django", re.compile(r"csrfmiddlewaretoken", re.I), True),
    ("laravel", re.compile(r"laravel", re.I), True),
    ("thinkphp", re.compile(r"thinkphp", re.I), True),
]

COOKIE_MAP = {
    "phpsessid": "php",
    "jsessionid": "java",
    "asp.net_sessionid": "asp.net",
    "laravel_session": "laravel",
    "ci_session": "codeigniter",
    "django_session": "django",
    "wordpress_logged_in": "wordpress",
    "connect.sid": "express",
}


def _clean_version(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().strip(".-")


def detect_tech(
    *,
    headers: dict[str, str],
    html: str,
    js_files: list[str],
    cookies: list[str],
    extra: list[str] | None = None,
) -> list[Tech]:
    found: dict[str, Tech] = {}

    def add(name: str, version: str = "", evidence: str = "") -> None:
        key = name.lower()
        existing = found.get(key)
        if existing is None:
            found[key] = Tech(name=name, version=_clean_version(version), evidence=evidence[:180])
        elif not existing.version and version:
            existing.version = _clean_version(version)

    server = headers.get("server", "")
    if server:
        for name, pattern in SERVER_PATTERNS:
            match = pattern.search(server)
            if match:
                add(name, match.group(1) if match.groups() else "", f"Server: {server}")
    powered = headers.get("x-powered-by", "")
    if powered:
        match = re.search(r"PHP/([\d.]+)", powered, re.I)
        if match:
            add("php", match.group(1), f"X-Powered-By: {powered}")
        if "express" in powered.lower():
            add("express", "", f"X-Powered-By: {powered}")
        if "asp.net" in powered.lower():
            add("asp.net", "", f"X-Powered-By: {powered}")

    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if generator:
        content = generator.group(1)
        match = re.search(r"wordpress\s*([\d.]+)?", content, re.I)
        if match:
            add("wordpress", match.group(1) or "", f"meta generator: {content}")
        match = re.search(r"drupal\s*([\d.]+)?", content, re.I)
        if match:
            add("drupal", match.group(1) or "", f"meta generator: {content}")
        match = re.search(r"joomla!?\s*([\d.]+)?", content, re.I)
        if match:
            add("joomla", match.group(1) or "", f"meta generator: {content}")

    for name, pattern, _ in HTML_PATTERNS:
        match = pattern.search(html)
        if match:
            add(name, "", f"HTML: {match.group(0)[:80]}")

    for url in js_files:
        for name, pattern in JS_PATTERNS:
            match = pattern.search(url)
            if match:
                version = match.group(1) if match.groups() else ""
                add(name, version, url)

    for cookie in cookies:
        mapped = COOKIE_MAP.get(cookie.lower())
        if mapped:
            add(mapped, "", f"Cookie: {cookie}")

    return sorted(found.values(), key=lambda t: t.name)


def version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:4]) if parts else ()


def version_lt(left: str, right: str) -> bool:
    lparts, rparts = version_tuple(left), version_tuple(right)
    if not lparts or not rparts:
        return False
    length = max(len(lparts), len(rparts))
    lpad = lparts + (0,) * (length - len(lparts))
    rpad = rparts + (0,) * (length - len(rparts))
    return lpad < rpad


def version_gte(left: str, right: str) -> bool:
    lparts, rparts = version_tuple(left), version_tuple(right)
    if not lparts or not rparts:
        return False
    length = max(len(lparts), len(rparts))
    lpad = lparts + (0,) * (length - len(lparts))
    rpad = rparts + (0,) * (length - len(rparts))
    return lpad >= rpad


_cve_cache: list[dict[str, Any]] | None = None


def load_cve_db() -> list[dict[str, Any]]:
    global _cve_cache
    if _cve_cache is None:
        try:
            data = json.loads(DB_PATH.read_text(encoding="utf-8"))
            _cve_cache = data.get("entries", [])
        except Exception:
            _cve_cache = []
    return _cve_cache


def match_cves(tech: Tech) -> list[dict[str, Any]]:
    if not tech.version:
        return []
    name = tech.name.lower()
    matches = []
    for entry in load_cve_db():
        if entry.get("product", "").lower() != name:
            continue
        max_version = entry.get("max_version_exclusive")
        min_version = entry.get("min_version")
        if max_version and not version_lt(tech.version, max_version):
            continue
        if min_version and not version_gte(tech.version, min_version):
            continue
        matches.append(entry)
    return matches

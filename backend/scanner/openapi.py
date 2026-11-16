from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from .models import Endpoint

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
MAX_ENDPOINTS = 300


def _load(text: str) -> dict[str, Any] | None:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        try:
            import yaml

            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None
    try:
        data = json.loads(text)
    except Exception:
        try:
            import yaml

            data = yaml.safe_load(text)
        except Exception:
            return None
    return data if isinstance(data, dict) else None


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def _base_url(spec: dict[str, Any], doc_url: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict) and first.get("url"):
            return urljoin(_origin(doc_url) + "/", str(first["url"]).rstrip("/"))
    if spec.get("swagger"):
        scheme = (spec.get("schemes") or ["https"])[0]
        host = spec.get("host")
        if host:
            return f"{scheme}://{host}{str(spec.get('basePath') or '').rstrip('/')}"
    return _origin(doc_url)


def _resolve_ref(spec: dict[str, Any], item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    ref = item.get("$ref")
    if not ref or not isinstance(ref, str) or not ref.startswith("#/"):
        return item
    node: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _params(spec: dict[str, Any], groups: list[Any]) -> tuple[list[str], list[str]]:
    query: list[str] = []
    path: list[str] = []
    for group in groups:
        if not isinstance(group, list):
            continue
        for raw in group:
            param = _resolve_ref(spec, raw)
            if not param:
                continue
            name = param.get("name")
            location = param.get("in")
            if not isinstance(name, str) or not name:
                continue
            if location == "query" and name not in query:
                query.append(name)
            elif location == "path" and name not in path:
                path.append(name)
    return query, path


def parse_spec(text: str, doc_url: str) -> list[Endpoint]:
    """从 Swagger 2.0 / OpenAPI 3.x 文档中提取可扫描的接口。"""
    spec = _load(text)
    if not spec:
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    base = _base_url(spec, doc_url)
    endpoints: list[Endpoint] = []
    seen: set[str] = set()

    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        shared_params = item.get("parameters")
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            query, path_params = _params(spec, [shared_params, operation.get("parameters")])
            resolved = raw_path
            for name in path_params:
                resolved = resolved.replace("{" + name + "}", "1")
            if "{" in resolved or "}" in resolved:
                continue
            url = base.rstrip("/") + "/" + resolved.lstrip("/")
            if query:
                url += "?" + "&".join(f"{name}=1" for name in query)
            key = f"{method.upper()} {url}"
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                Endpoint(
                    url=url,
                    method=method.upper(),
                    source="openapi",
                    params=query + path_params,
                )
            )
            if len(endpoints) >= MAX_ENDPOINTS:
                return endpoints
    return endpoints

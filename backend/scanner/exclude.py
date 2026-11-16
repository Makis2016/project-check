from __future__ import annotations

import fnmatch
from urllib.parse import urlparse


def is_excluded(url: str, patterns: list[str]) -> bool:
    """按域名 / 路径前缀 / 通配符判断 URL 是否在排除范围内。"""
    if not patterns:
        return False
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    lowered_path = path.lower()
    for raw in patterns:
        pattern = (raw or "").strip().lower()
        if not pattern:
            continue
        if "://" in pattern:
            if url.lower().startswith(pattern.rstrip("/")):
                return True
        elif "/" in pattern or "*" in pattern:
            if fnmatch.fnmatch(lowered_path, pattern) or lowered_path.startswith(pattern.rstrip("*")):
                return True
        elif "." in pattern:
            if host == pattern or host.endswith("." + pattern):
                return True
        elif lowered_path.startswith(pattern):
            return True
    return False

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

import httpx

USER_AGENT = "VulnLens/1.0 (authorized security check; +https://localhost)"


class ScanLimitReached(Exception):
    """Raised when the per-scan request budget is exhausted."""


@dataclass
class ResponseData:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    content_type: str = ""
    elapsed_ms: int = 0
    history: list[int] = field(default_factory=list)
    truncated: bool = False
    error: str = ""
    set_cookie: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _decode(content: bytes, content_type: str) -> str:
    charset = "utf-8"
    lowered = content_type.lower()
    if "charset=" in lowered:
        charset = lowered.split("charset=", 1)[1].split(";", 1)[0].strip().strip('"\'')
    try:
        return content.decode(charset, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


class HttpSession:
    """Rate-limited HTTP client shared by every scanner stage."""

    def __init__(
        self,
        *,
        rate_limit: float = 5.0,
        max_requests: int = 3000,
        ignore_tls: bool = False,
        headers: dict[str, str] | None = None,
        cookie: str = "",
        proxy: str = "",
        timeout: float = 12.0,
        on_request: Callable[[int], Awaitable[None]] | None = None,
    ) -> None:
        self.rate_limit = max(rate_limit, 0.5)
        self.max_requests = max_requests
        self.request_count = 0
        self.bytes_read = 0
        self.started_at = time.monotonic()
        self._interval = 1.0 / self.rate_limit
        self._last_slot = 0.0
        self._throttle_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(8)
        self._on_request = on_request
        self._closed = False

        default_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "close",
        }
        if cookie:
            default_headers["Cookie"] = cookie
        if headers:
            default_headers.update(headers)

        self.default_headers = dict(default_headers)
        self.proxy = proxy

        self.client = httpx.AsyncClient(
            verify=not ignore_tls,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
            trust_env=False,
            headers=default_headers,
            proxy=proxy or None,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=0),
        )

    async def _throttle(self) -> None:
        async with self._throttle_lock:
            if self.request_count >= self.max_requests:
                raise ScanLimitReached(f"已达到单次扫描请求上限 {self.max_requests}")
            now = time.monotonic()
            wait = self._last_slot + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_slot = time.monotonic()
            self.request_count += 1
            if self._on_request and self.request_count % 10 == 0:
                await self._on_request(self.request_count)

    async def fetch(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        max_redirects: int = 5,
        max_bytes: int = 1_500_000,
        headers: dict[str, str] | None = None,
        data: Any = None,
        json: Any = None,
    ) -> ResponseData:
        current_url = url
        current_method = method.upper()
        history: list[int] = []
        started = time.monotonic()

        for hop in range(max_redirects + 1):
            await self._throttle()
            async with self._semaphore:
                try:
                    async with self.client.stream(
                        current_method, current_url, headers=headers, data=data, json=json
                    ) as response:
                        chunks: list[bytes] = []
                        size = 0
                        truncated = False
                        async for chunk in response.aiter_bytes():
                            chunks.append(chunk)
                            size += len(chunk)
                            if size >= max_bytes:
                                truncated = True
                                break
                        content = b"".join(chunks)
                        self.bytes_read += len(content)
                        content_type = response.headers.get("content-type", "")
                        text = _decode(content, content_type)
                        set_cookie = response.headers.get_list("set-cookie")
                        resp_headers = {k.lower(): v for k, v in response.headers.items()}

                        if (
                            allow_redirects
                            and response.status_code in (301, 302, 303, 307, 308)
                            and resp_headers.get("location")
                            and hop < max_redirects
                        ):
                            history.append(response.status_code)
                            current_url = urljoin(current_url, resp_headers["location"])
                            if response.status_code in (301, 302, 303) and current_method not in ("GET", "HEAD"):
                                current_method = "GET"
                                data = None
                                json = None
                            continue

                        return ResponseData(
                            url=str(response.url),
                            status=response.status_code,
                            headers=resp_headers,
                            text=text,
                            content_type=content_type,
                            elapsed_ms=int((time.monotonic() - started) * 1000),
                            history=history,
                            truncated=truncated,
                            set_cookie=set_cookie,
                        )
                except (httpx.HTTPError, OSError, ValueError) as exc:
                    return ResponseData(
                        url=current_url,
                        status=0,
                        headers={},
                        text="",
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                        history=history,
                        error=f"{type(exc).__name__}: {exc}",
                    )

        return ResponseData(
            url=current_url,
            status=0,
            headers={},
            text="",
            elapsed_ms=int((time.monotonic() - started) * 1000),
            history=history,
            error="too many redirects",
        )

    async def get(self, url: str, **kwargs: Any) -> ResponseData:
        return await self.fetch("GET", url, **kwargs)

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self.client.aclose()

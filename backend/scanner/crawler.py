from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from collections import deque
from typing import Awaitable, Callable
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from .assets import parse_target
from .fingerprints import detect_tech
from .http_client import HttpSession, ResponseData, ScanLimitReached
from .models import CookieInfo, Discovery, Endpoint, Form, Page, ScanConfig

LogFn = Callable[[str, str], Awaitable[None]]

DOC_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-ui/",
    "/swagger.json",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/redoc",
    "/docs",
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".css", ".scss", ".less", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".wmv", ".flv", ".m4a",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dmg", ".apk", ".ipa", ".msi", ".deb", ".rpm",
}

SKIP_KEYWORDS = ("logout", "signout", "sign-out", "log-out", "deleteaccount", "unsubscribe")

STRING_RE = re.compile(r"""["'`]([^"'`\s<>]{2,300})["'`]""")
PATH_RE = re.compile(r"^/(?:[A-Za-z0-9_\-./{}~%:@!$&'()*+,;=]*)(?:\?[^\s#]*)?$")
STATIC_HINT_RE = re.compile(r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|json)(?:$|\?)", re.I)


class CrawlError(Exception):
    pass


def normalize_url(base: str, candidate: str, origin: tuple[str, str]) -> str | None:
    if not candidate:
        return None
    candidate = candidate.strip()
    if candidate.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    absolute = urljoin(base, candidate)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    if (parsed.scheme, parsed.netloc.lower()) != origin:
        return None
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def should_crawl(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if is_static(url):
        return False
    lowered = path.lower()
    if any(keyword in lowered for keyword in SKIP_KEYWORDS):
        return False
    if "{" in path or "}" in path or "$" in path:
        return False
    return True


def extract_paths(text: str, base_url: str, origin: tuple[str, str]) -> set[str]:
    found: set[str] = set()
    for match in STRING_RE.finditer(text):
        candidate = match.group(1).strip()
        if candidate.startswith(("//", "data:", "javascript:")):
            continue
        if candidate.startswith(("http://", "https://")):
            normalized = normalize_url(base_url, candidate, origin)
            if normalized and not is_static(normalized):
                found.add(normalized)
            continue
        if not candidate.startswith("/"):
            continue
        if not PATH_RE.match(candidate):
            continue
        if STATIC_HINT_RE.search(candidate) and ".json" not in candidate:
            continue
        if len(candidate) <= 1 or candidate.startswith("//"):
            continue
        normalized = normalize_url(base_url, candidate, origin)
        if normalized and not is_static(normalized):
            found.add(normalized)
    return found


def parse_set_cookie(raw: str, url: str) -> CookieInfo | None:
    pair = raw.split(";", 1)[0].strip()
    if "=" not in pair:
        return None
    name = pair.split("=", 1)[0].strip()
    if not name:
        return None
    lowered = raw.lower()
    same_site = ""
    if "samesite=" in lowered:
        same_site = lowered.split("samesite=", 1)[1].split(";", 1)[0].strip()
    return CookieInfo(
        name=name,
        secure="secure" in lowered,
        http_only="httponly" in lowered,
        same_site=same_site,
        raw=raw,
        source_url=url,
    )


class Crawler:
    def __init__(self, config: ScanConfig, session: HttpSession, log: LogFn) -> None:
        self.config = config
        self.session = session
        self.log = log
        self.root_url = parse_target(config.target)
        parsed = urlparse(self.root_url)
        if not parsed.path:
            self.root_url += "/"
            parsed = urlparse(self.root_url)
        self.origin = (parsed.scheme, parsed.netloc.lower())
        self.visited: set[str] = set()
        self.queue: deque[str] = deque()
        self.queued: set[str] = set()

    async def run(self) -> Discovery:
        discovery = Discovery()
        await self.log("info", f"抓取入口页面 {self.root_url}")
        root_resp = await self.session.get(self.root_url)
        if root_resp.error or root_resp.status == 0:
            raise CrawlError(f"目标不可访问：{root_resp.error or '无响应'}")

        if root_resp.url and root_resp.url.rstrip("/") != self.root_url:
            self.root_url = root_resp.url.rstrip("/")
            redirected = urlparse(self.root_url)
            self.origin = (redirected.scheme, redirected.netloc.lower())

        self.visited.add(self.root_url)
        self._record_response(discovery, self.root_url, root_resp, is_root=True)
        self._parse_html(discovery, self.root_url, root_resp)

        await self._parse_robots(discovery)
        await self._parse_sitemaps(discovery)
        await self._probe_docs(discovery)

        batch_size = 6
        while self.queue and len(self.visited) < self.config.max_pages:
            batch: list[str] = []
            while self.queue and len(batch) < batch_size and len(self.visited) < self.config.max_pages:
                url = self.queue.popleft()
                if url in self.visited:
                    continue
                self.visited.add(url)
                batch.append(url)
            if not batch:
                break
            try:
                responses = await self._fetch_batch(batch)
            except ScanLimitReached:
                await self.log("warn", "请求预算耗尽，停止继续爬取")
                break
            for url, resp in responses:
                if resp.error or resp.status == 0:
                    continue
                self._record_response(discovery, url, resp)
                if "html" in resp.content_type.lower():
                    self._parse_html(discovery, url, resp)

        await self.log("success", f"页面抓取完成：{len(discovery.pages)} 个页面，{len(self.visited)} 次访问")
        await self._analyze_js(discovery)
        await self._build_tech(discovery)
        return discovery

    async def _fetch_batch(self, urls: list[str]) -> list[tuple[str, ResponseData]]:
        return list(await asyncio.gather(*(self._fetch_one(u) for u in urls)))

    async def _fetch_one(self, url: str) -> tuple[str, ResponseData]:
        return url, await self.session.get(url)

    def _record_response(self, discovery: Discovery, url: str, resp: ResponseData, is_root: bool = False) -> None:
        page = Page(
            url=url,
            status=resp.status,
            headers=resp.headers,
            html=resp.text if "html" in resp.content_type.lower() else "",
            content_type=resp.content_type,
            set_cookie=resp.set_cookie,
        )
        discovery.pages[url] = page
        for raw in resp.set_cookie:
            cookie = parse_set_cookie(raw, url)
            if cookie and not any(c.name == cookie.name and c.source_url == url for c in discovery.cookies):
                discovery.cookies.append(cookie)
        params = list(parse_qs(urlparse(url).query).keys())
        discovery.add_endpoint(
            Endpoint(url=url, method="GET", source="root" if is_root else "crawl", params=params, status=resp.status, content_type=resp.content_type)
        )

    def _parse_html(self, discovery: Discovery, page_url: str, resp: ResponseData) -> None:
        if not resp.text:
            return
        content_type = resp.content_type.lower()
        if content_type and "html" not in content_type and "xml" not in content_type:
            return
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        for tag in soup.find_all(["a", "area"], href=True):
            url = normalize_url(page_url, tag.get("href", ""), self.origin)
            if url:
                params = list(parse_qs(urlparse(url).query).keys())
                discovery.add_endpoint(Endpoint(url=url, source="crawl", params=params))
                if should_crawl(url) and url not in self.queued and len(self.queued) < 800:
                    self.queued.add(url)
                    self.queue.append(url)

        for tag in soup.find_all(["iframe", "frame"], src=True):
            url = normalize_url(page_url, tag.get("src", ""), self.origin)
            if url and not is_static(url):
                discovery.add_endpoint(Endpoint(url=url, source="crawl"))

        for tag in soup.find_all("script", src=True):
            url = normalize_url(page_url, tag.get("src", ""), self.origin)
            if url and url not in discovery.js_files and len(discovery.js_files) < self.config.max_js_files:
                discovery.js_files.append(url)

        for tag in soup.find_all("script"):
            inline = tag.string or tag.get_text() or ""
            if len(inline.strip()) > 30:
                key = f"inline:{page_url}"
                discovery.js_text[key] = (discovery.js_text.get(key, "") + "\n" + inline)[:800_000]
                for path in extract_paths(inline, page_url, self.origin):
                    discovery.add_endpoint(Endpoint(url=path, source="js", params=list(parse_qs(urlparse(path).query).keys())))

        for form in soup.find_all("form"):
            action = form.get("action") or page_url
            action_url = normalize_url(page_url, action, self.origin) or page_url
            method = (form.get("method") or "GET").upper()
            inputs = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    inputs.append(name)
            discovery.forms.append(Form(action=action_url, method=method, inputs=inputs, source_url=page_url))
            discovery.add_endpoint(Endpoint(url=action_url, method=method, source="form", params=inputs))

    async def _parse_robots(self, discovery: Discovery) -> None:
        robots_url = f"{self.origin[0]}://{self.origin[1]}/robots.txt"
        try:
            resp = await self.session.get(robots_url, max_bytes=200_000)
        except ScanLimitReached:
            return
        if resp.status != 200 or resp.error:
            return
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lowered = line.lower()
            if lowered.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path:
                    url = normalize_url(robots_url, path, self.origin)
                    if url:
                        discovery.robots.append(url)
                        discovery.add_endpoint(Endpoint(url=url, source="robots"))
            elif lowered.startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                if sitemap not in discovery.sitemaps:
                    discovery.sitemaps.append(sitemap)
        if discovery.robots:
            await self.log("info", f"robots.txt 暴露 {len(discovery.robots)} 条路径")

    async def _parse_sitemaps(self, discovery: Discovery) -> None:
        candidates = list(discovery.sitemaps)
        if not candidates:
            candidates = [f"{self.origin[0]}://{self.origin[1]}/sitemap.xml"]
        fetched = 0
        for sitemap_url in candidates[:3]:
            if fetched >= 3:
                break
            try:
                resp = await self.session.get(sitemap_url, max_bytes=800_000)
            except ScanLimitReached:
                return
            fetched += 1
            if resp.status != 200 or resp.error:
                continue
            try:
                root = ET.fromstring(resp.text.encode("utf-8", errors="ignore"))
            except Exception:
                continue
            locs = [el.text.strip() for el in root.iter() if el.tag.endswith("loc") and el.text]
            for loc in locs[:80]:
                url = normalize_url(sitemap_url, loc, self.origin)
                if url and should_crawl(url):
                    discovery.add_endpoint(Endpoint(url=url, source="sitemap"))
                    if url not in self.queued and len(self.queued) < 800:
                        self.queued.add(url)
                        self.queue.append(url)

    async def _probe_docs(self, discovery: Discovery) -> None:
        base = f"{self.origin[0]}://{self.origin[1]}"
        for path in DOC_PATHS:
            url = base + path
            try:
                resp = await self.session.get(url, allow_redirects=True, max_bytes=600_000)
            except ScanLimitReached:
                return
            if resp.error or resp.status != 200 or not resp.text:
                continue
            body = resp.text[:3000]
            lowered = body.lower()
            content_type = resp.content_type.lower()
            looks_json = "json" in content_type or lowered.lstrip().startswith(("{", "["))
            looks_swagger = '"swagger"' in lowered or '"openapi"' in lowered or "swagger-ui" in lowered or "swagger ui" in lowered
            if looks_swagger or (looks_json and ('"paths"' in lowered and '"info"' in lowered)):
                discovery.docs.append(resp.url)
                discovery.add_endpoint(Endpoint(url=resp.url, source="docs", status=resp.status, content_type=resp.content_type))
                await self.log("success", f"发现接口文档：{resp.url}")
                break

    async def _analyze_js(self, discovery: Discovery) -> None:
        if not discovery.js_files:
            return
        await self.log("info", f"分析前端 JS：{len(discovery.js_files)} 个文件")
        for js_url in discovery.js_files[: self.config.max_js_files]:
            try:
                resp = await self.session.get(js_url, max_bytes=2_000_000)
            except ScanLimitReached:
                return
            if resp.error or resp.status != 200 or not resp.text:
                continue
            discovery.js_text[js_url] = resp.text
            for path in extract_paths(resp.text, js_url, self.origin):
                discovery.add_endpoint(
                    Endpoint(url=path, source="js", params=list(parse_qs(urlparse(path).query).keys()))
                )

    async def _build_tech(self, discovery: Discovery) -> None:
        root = discovery.pages.get(self.root_url)
        discovery.tech = detect_tech(
            headers=root.headers if root else {},
            html=root.html if root else "",
            js_files=discovery.js_files,
            cookies=[c.name for c in discovery.cookies],
            extra=root.set_cookie if root else [],
        )
        if discovery.tech:
            names = "、".join(t.name + (f" {t.version}" if t.version else "") for t in discovery.tech[:6])
            await self.log("info", f"识别到组件：{names}")

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..http_client import ScanLimitReached
from ..models import Finding
from .base import CheckContext, capture, finding, truncate

DESTRUCTIVE_ACTIONS = ("logout", "signout", "delete", "remove", "unsubscribe", "reset", "destroy")

CSRF_TOKEN_NAMES = {
    "csrf",
    "csrf_token",
    "csrftoken",
    "_csrf",
    "xsrf",
    "xsrf_token",
    "x-xsrf-token",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "anti-forgery-token",
}

ENV_RE = re.compile(r"(?m)^[A-Z0-9_]{2,}=")

BACKUP_PATHS = [
    ("/.env.bak", ".env 备份文件泄露", "critical", lambda r: len(ENV_RE.findall(r.text)) >= 2, "CWE-538"),
    ("/.env.save", ".env.save 备份文件泄露", "critical", lambda r: len(ENV_RE.findall(r.text)) >= 2, "CWE-538"),
    ("/index.php.bak", "PHP 源码备份泄露", "high", lambda r: "<?php" in r.text or "<?=" in r.text, "CWE-538"),
    ("/config.php.bak", "配置文件备份泄露", "high", lambda r: "<?php" in r.text and ("password" in r.text.lower() or "db_" in r.text.lower()), "CWE-538"),
    ("/web.config.bak", "IIS 配置备份泄露", "high", lambda r: "<configuration" in r.text.lower(), "CWE-538"),
    ("/appsettings.json.bak", "应用配置备份泄露", "high", lambda r: "connectionstrings" in r.text.lower(), "CWE-538"),
    ("/.index.php.swp", "编辑器交换文件泄露", "high", lambda r: "b0VIM" in r.text, "CWE-538"),
    ("/backup.tar.gz", "备份压缩包可下载", "high", lambda r: any(x in (r.content_type or "").lower() for x in ("gzip", "tar", "octet-stream")), "CWE-552"),
    ("/wwwroot.zip", "站点压缩包可下载", "high", lambda r: "zip" in (r.content_type or "").lower(), "CWE-552"),
]


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_origin(left: str, right: str) -> bool:
    parsed_left = urlparse(left)
    parsed_right = urlparse(right)
    return parsed_left.scheme == parsed_right.scheme and parsed_left.netloc.lower() == parsed_right.netloc.lower()


def _snippet(text: str, needle: str, before: int = 120, after: int = 220) -> str:
    index = text.find(needle)
    if index < 0:
        return truncate(text, 300)
    return truncate(text[max(0, index - before): index + after], 360)


async def check_graphql(ctx: CheckContext) -> list[Finding]:
    candidates = [
        endpoint.url
        for endpoint in ctx.discovery.endpoints.values()
        if any(key in urlparse(endpoint.url).path.lower() for key in ("graphql", "gql"))
        and not ctx.excluded(endpoint.url)
    ]
    results: list[Finding] = []
    seen: set[str] = set()
    for url in candidates:
        if url in seen or len(results) >= 3:
            continue
        seen.add(url)
        query = "query VulnLensProbe { __schema { queryType { name } types { name kind } } }"
        body = '{"query": "' + query + '"}'
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        try:
            resp = await ctx.session.fetch("POST", url, json={"query": query}, headers=headers, max_bytes=400_000)
        except ScanLimitReached:
            break
        if resp.error or resp.status not in (200, 400):
            continue
        lowered = resp.text.lower()
        if '"__schema"' not in lowered or "querytype" not in lowered:
            continue
        results.append(
            finding(
                check_id="exposure.graphql",
                title="GraphQL introspection 未关闭",
                severity="medium",
                category="exposure",
                confidence="high",
                description="GraphQL 端点允许执行 __schema 查询，攻击者可以枚举全部类型、字段与参数，为后续越权与注入提供地图。",
                remediation="生产环境关闭 introspection（如 Apollo 的 introspection: false），并对 GraphQL 端点增加鉴权、查询深度与复杂度限制。",
                url=url,
                method="POST",
                evidence=_snippet(resp.text, "__schema"),
                cwe="CWE-200",
                owasp="A05:2021",
                fingerprint=urlparse(url).path,
                **capture(resp, method="POST", url=url, headers=headers, body=body),
            )
        )
    return results


async def check_host_header(ctx: CheckContext) -> list[Finding]:
    root = ctx.root_page
    if root is None or ctx.excluded(root.url):
        return []
    probe = "vulnlens-probe.example"
    results: list[Finding] = []
    variants = [
        ("Host", {"Host": probe}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": probe}),
    ]
    for label, headers in variants:
        try:
            resp = await ctx.session.get(root.url, headers=headers, max_bytes=300_000)
        except ScanLimitReached:
            break
        if resp.error or not resp.text:
            continue
        location = resp.header("location")
        reflected = probe in resp.text or probe in location
        if not reflected:
            continue
        results.append(
            finding(
                check_id="headers.host_injection",
                title=f"HOST 头注入（{label} 被反射）",
                severity="medium",
                category="headers",
                confidence="medium",
                description=f"服务端直接信任 {label} 请求头并写入响应或跳转地址。若用于密码重置链接、缓存键或绝对 URL，可能导致链接投毒与缓存污染。",
                remediation="不要使用客户端可控的 Host/X-Forwarded-Host 生成链接；配置可信 Host 白名单，并在反向代理层覆盖/校验该头。",
                url=root.url,
                evidence=_snippet(resp.text, probe) if probe in resp.text else f"Location: {location}",
                cwe="CWE-20",
                owasp="A05:2021",
                fingerprint=label,
                **capture(resp, url=root.url, headers={**ctx.session.default_headers, **headers}),
            )
        )
    return results


async def check_csrf(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    seen: set[str] = set()
    for form in ctx.discovery.forms:
        if form.method.upper() != "POST" or len(results) >= 8:
            continue
        if not _same_origin(form.action, form.source_url):
            continue
        action_lower = form.action.lower()
        if any(word in action_lower for word in DESTRUCTIVE_ACTIONS) or ctx.excluded(form.action):
            continue
        names = {name.lower() for name in form.inputs}
        if names & CSRF_TOKEN_NAMES:
            continue
        key = form.action
        if key in seen:
            continue
        seen.add(key)
        results.append(
            finding(
                check_id="csrf.missing_token",
                title="表单缺少 CSRF Token",
                severity="low",
                category="csrf",
                confidence="medium",
                description="POST 表单未包含常见 CSRF token 字段。若服务端也未校验 Origin/Referer，且会话 Cookie 的 SameSite 为 None 或缺失，则可能被跨站伪造请求。",
                remediation="为状态变更表单加入一次性 CSRF token 并在服务端校验；同时将会话 Cookie 设置为 SameSite=Lax/Strict，并校验 Origin/Referer。",
                url=form.action,
                method="POST",
                evidence=f"表单来源：{form.source_url}\n字段：{', '.join(form.inputs[:12]) or '无'}",
                cwe="CWE-352",
                owasp="A01:2021",
                fingerprint=form.action,
            )
        )
    return results


async def check_backup_files(ctx: CheckContext) -> list[Finding]:
    root = ctx.root_page
    if root is None:
        return []
    base = _origin(root.url)
    results: list[Finding] = []
    candidates: list[tuple] = []
    for path, title, severity, test, cwe in BACKUP_PATHS:
        url = base + path
        if not ctx.excluded(url):
            candidates.append((url, title, severity, cwe, test))
    for page in list(ctx.discovery.pages.values())[:6]:
        parsed = urlparse(page.url)
        if parsed.path.lower().endswith((".php", ".asp", ".aspx", ".jsp", ".do", ".action")):
            for suffix in (".bak", "~"):
                url = page.url.split("?", 1)[0] + suffix
                if not ctx.excluded(url):
                    candidates.append((url, "页面源码备份泄露", "high", "CWE-538", lambda r: "<?php" in r.text or "<%" in r.text))
    seen: set[str] = set()
    for url, title, severity, cwe, test in candidates:
        if url in seen or len(results) >= 8:
            continue
        seen.add(url)
        try:
            resp = await ctx.session.get(url, max_bytes=300_000, allow_redirects=False)
        except ScanLimitReached:
            break
        if resp.error or resp.status != 200 or not resp.text:
            continue
        try:
            if not test(resp):
                continue
        except Exception:
            continue
        results.append(
            finding(
                check_id="exposure.backup_file",
                title=title,
                severity=severity,
                category="exposure",
                confidence="high",
                description=f"访问 {urlparse(url).path} 可直接下载备份或源码文件，可能泄露数据库凭据、密钥与完整代码。",
                remediation="从 Web 根目录移除备份、交换文件与源码副本；在服务器层禁止访问 .bak/.swp/~ 等后缀，并轮换已泄露的凭据。",
                url=url,
                evidence=truncate(resp.text, 400),
                cwe=cwe,
                owasp="A01:2021",
                fingerprint=urlparse(url).path,
                **capture(resp, url=url, headers=ctx.session.default_headers),
            )
        )
    return results


async def check_page_quality(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.quality_checks or not ctx.discovery.pages:
        return []

    results: list[Finding] = []
    pages = list(ctx.discovery.pages.values())[:25]
    resources: dict[str, str] = {}
    anchors: dict[str, str] = {}
    mixed: list[tuple[str, str]] = []

    for page in pages:
        if page.status >= 500:
            results.append(
                finding(
                    check_id="quality.server_error",
                    title="页面返回 5xx 服务器错误",
                    severity="medium",
                    category="quality",
                    confidence="high",
                    description="页面在抓取时返回 5xx。可能是未处理异常、依赖故障或路由配置错误，也会影响搜索引擎与用户访问。",
                    remediation="检查服务端日志与依赖状态，为异常增加兜底处理；对用户展示统一错误页，避免堆栈或内部信息泄露。",
                    url=page.url,
                    evidence=f"HTTP {page.status}",
                    fingerprint=page.url,
                )
            )
        if not page.html:
            continue
        page_https = urlparse(page.url).scheme == "https"
        try:
            soup = BeautifulSoup(page.html, "html.parser")
        except Exception:
            continue
        for tag, attr, kind in (
            ("script", "src", "script"),
            ("link", "href", "style"),
            ("img", "src", "image"),
            ("iframe", "src", "iframe"),
        ):
            for node in soup.find_all(tag):
                raw = (node.get(attr) or "").strip()
                if not raw or raw.startswith(("data:", "javascript:", "#")):
                    continue
                url = urljoin(page.url, raw).split("#", 1)[0]
                if not url.startswith(("http://", "https://")):
                    continue
                if page_https and url.startswith("http://"):
                    mixed.append((page.url, url))
                if _same_origin(url, page.url) and not ctx.excluded(url):
                    resources.setdefault(url, kind)
        for node in soup.find_all("a", href=True):
            raw = node.get("href", "").strip()
            if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            url = urljoin(page.url, raw).split("#", 1)[0]
            if url.startswith(("http://", "https://")) and _same_origin(url, page.url) and not ctx.excluded(url):
                anchors.setdefault(url, page.url)

    seen_mixed: set[tuple[str, str]] = set()
    for page_url, resource_url in mixed[:8]:
        if (page_url, resource_url) in seen_mixed:
            continue
        seen_mixed.add((page_url, resource_url))
        results.append(
            finding(
                check_id="quality.mixed_content",
                title="HTTPS 页面加载 HTTP 资源（混合内容）",
                severity="low",
                category="quality",
                confidence="high",
                description="HTTPS 页面引用了明文 HTTP 资源，浏览器可能拦截或标记为不安全，且资源可被中间人篡改。",
                remediation="将所有资源改为 HTTPS 或使用协议相对/站内相对地址，并启用 CSP upgrade-insecure-requests。",
                url=resource_url,
                evidence=f"页面：{page_url}\n资源：{resource_url}",
                cwe="CWE-319",
                owasp="A02:2021",
                fingerprint=resource_url,
            )
        )

    checked = 0
    for url, kind in list(resources.items())[:40]:
        if checked >= 60:
            break
        checked += 1
        try:
            resp = await ctx.session.get(url, max_bytes=20_000)
        except ScanLimitReached:
            break
        if resp.status == 0 or resp.status >= 400:
            results.append(
                finding(
                    check_id="quality.js_load_error" if kind == "script" else "quality.broken_resource",
                    title="脚本资源加载失败" if kind == "script" else "静态资源加载失败",
                    severity="low",
                    category="quality",
                    confidence="high",
                    description=(
                        "脚本返回 4xx/5xx 或无法连接，页面可能出现 JS 报错、白屏或交互失效。"
                        if kind == "script"
                        else "样式、图片或 iframe 资源返回 4xx/5xx，页面可能缺图或样式错乱。"
                    ),
                    remediation="检查静态资源路径、构建产物与部署配置，确保资源可访问且 MIME 类型正确。",
                    url=url,
                    evidence=f"HTTP {resp.status or '连接失败'}",
                    fingerprint=url,
                )
            )
        elif kind == "script" and "html" in (resp.content_type or "").lower() and resp.text.lstrip().lower().startswith(("<!doctype", "<html")):
            results.append(
                finding(
                    check_id="quality.js_load_error",
                    title="脚本地址返回 HTML（可能被软 404 拦截）",
                    severity="low",
                    category="quality",
                    confidence="high",
                    description="预期返回 JavaScript 的地址返回了 HTML，浏览器会报 MIME 类型或语法错误，导致页面脚本失效。",
                    remediation="修正静态资源路由，避免把 404 页面以 200 返回；确保 JS 文件以 application/javascript 输出。",
                    url=url,
                    evidence=truncate(resp.text, 200),
                    fingerprint=url,
                )
            )

    for url, source in list(anchors.items())[:25]:
        try:
            resp = await ctx.session.get(url, max_bytes=20_000)
        except ScanLimitReached:
            break
        if resp.status in (401, 403, 405, 429) or resp.status < 400:
            continue
        results.append(
            finding(
                check_id="quality.broken_link",
                title="站内链接返回错误",
                severity="low",
                category="quality",
                confidence="high",
                description="站内链接指向的页面返回 4xx/5xx，用户点击后会看到错误页，也可能是旧链接未做重定向。",
                remediation="修复或移除失效链接；对已下线页面配置 301 跳转；为 404 提供友好页面。",
                url=url,
                evidence=f"来源页面：{source}\nHTTP {resp.status}",
                fingerprint=url,
            )
        )
    return results

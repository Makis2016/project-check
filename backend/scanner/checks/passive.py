from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import string
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from ..assets import base_domain, is_ip, tls_findings as build_tls_findings
from ..fingerprints import match_cves
from ..http_client import ScanLimitReached
from ..models import Finding
from .base import CheckContext, capture, finding, truncate

TRACE_PATTERNS = [
    ("Python", re.compile(r"Traceback \(most recent call last\)")),
    ("Java", re.compile(r"\bat (?:java|javax|org|com)\.[\w.$]+\(")),
    ("Spring", re.compile(r"org\.springframework[\w.]*Exception")),
    ("PHP", re.compile(r"(?:Fatal error|Parse error|Warning):\s+\w+.*? on line \d+")),
    ("SQL", re.compile(r"(?:SQLSTATE\[|ORA-\d{4,}|Microsoft OLE DB|You have an error in your SQL syntax|PostgreSQL.*?ERROR)")),
    ("ASP.NET", re.compile(r"System\.(?:Data|Web|Exception)[\w.]*Exception")),
    ("Node.js", re.compile(r"at\s+\w+\s+\(/[^)]+:\d+:\d+\)")),
]

DEFAULT_PAGES = [
    ("nginx 默认欢迎页", re.compile(r"Welcome to nginx!", re.I)),
    ("Apache 默认页", re.compile(r"Apache2? (?:Ubuntu|Debian)? ?Default Page|It works!", re.I)),
    ("IIS 默认页", re.compile(r"IIS Windows Server|iisstart\.htm", re.I)),
    ("Tomcat 默认页", re.compile(r"Apache Tomcat/?\d*|Tomcat Manager", re.I)),
    ("Spring 默认错误页", re.compile(r"Whitelabel Error Page", re.I)),
    ("Weblogic 默认页", re.compile(r"Oracle WebLogic Server", re.I)),
]

RISKY_PORTS = {
    2375: "Docker API",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    15672: "RabbitMQ 管理台",
    1433: "MSSQL",
    1521: "Oracle",
    2181: "ZooKeeper",
}

SECRET_PATTERNS = [
    ("AWS Access Key", "high", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", "medium", "high", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Secret Key", "high", "high", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("GitHub Token", "high", "high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("RSA/EC 私钥", "high", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT Token", "low", "low", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    (
        "疑似硬编码密钥",
        "medium",
        "low",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
    ),
]


def _is_text(resp) -> bool:
    content_type = (resp.content_type or "").lower()
    return "html" not in content_type and "json" not in content_type


def _snippet(text: str, keyword: str, radius: int = 160) -> str:
    index = text.lower().find(keyword.lower())
    if index < 0:
        return truncate(text, 240)
    start = max(0, index - radius)
    return truncate(text[start: index + radius * 2], 420)


async def check_security_headers(ctx: CheckContext) -> list[Finding]:
    page = ctx.root_page
    if page is None:
        return []
    headers = page.headers
    url = page.url
    is_https = url.startswith("https://")
    results: list[Finding] = []

    def missing(header: str, title: str, severity: str, remediation: str, cwe: str = "") -> None:
        if header not in headers:
            results.append(
                finding(
                    check_id=f"headers.{header}",
                    title=title,
                    severity=severity,
                    category="headers",
                    description=f"响应中缺少 {header} 响应头。",
                    remediation=remediation,
                    url=url,
                    evidence=f"响应头中未找到 {header}",
                    cwe=cwe,
                    owasp="A05:2021",
                    fingerprint=header,
                )
            )

    if is_https:
        missing(
            "strict-transport-security",
            "缺少 HSTS，HTTPS 可被降级",
            "medium",
            "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains。先确认全站 HTTPS 可用再加 includeSubDomains。",
            "CWE-319",
        )
    csp = headers.get("content-security-policy", "")
    if not csp:
        results.append(
            finding(
                check_id="headers.csp",
                title="缺少内容安全策略（CSP）",
                severity="medium",
                category="headers",
                description="未设置 Content-Security-Policy，无法有效限制恶意脚本执行与资源加载。",
                remediation="配置 Content-Security-Policy，例如 default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'。上线前用 Report-Only 模式观察误报。",
                url=url,
                evidence="响应头中未找到 content-security-policy",
                cwe="CWE-693",
                owasp="A05:2021",
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        results.append(
            finding(
                check_id="headers.frame",
                title="缺少点击劫持防护",
                severity="medium",
                category="headers",
                description="既未设置 X-Frame-Options，也未在 CSP 中声明 frame-ancestors，页面可被第三方站点嵌套。",
                remediation="设置 X-Frame-Options: DENY 或 SAMEORIGIN；推荐同时配置 CSP frame-ancestors 'self'。",
                url=url,
                evidence="缺少 X-Frame-Options 与 CSP frame-ancestors",
                cwe="CWE-1021",
                owasp="A05:2021",
            )
        )
    missing(
        "x-content-type-options",
        "缺少 X-Content-Type-Options",
        "low",
        "添加 X-Content-Type-Options: nosniff，防止浏览器 MIME 嗅探导致脚本执行。",
        "CWE-693",
    )
    missing(
        "referrer-policy",
        "缺少 Referrer-Policy",
        "low",
        "添加 Referrer-Policy: strict-origin-when-cross-origin 或 no-referrer，避免敏感 URL 通过 Referer 泄露。",
        "CWE-200",
    )
    missing(
        "permissions-policy",
        "缺少 Permissions-Policy",
        "info",
        "按需添加 Permissions-Policy，例如 geolocation=(), camera=(), microphone=()。",
        "CWE-693",
    )

    server = headers.get("server", "")
    if server and re.search(r"/\d", server):
        results.append(
            finding(
                check_id="headers.server_version",
                title="Server 响应头泄露版本号",
                severity="low",
                category="headers",
                description=f"Server 响应头暴露了服务端软件及版本：{server}",
                remediation="在 nginx 配置 server_tokens off，或由网关统一移除/改写 Server 与 X-Powered-By 响应头。",
                url=url,
                evidence=f"Server: {server}",
                cwe="CWE-200",
                fingerprint="server",
            )
        )
    powered = headers.get("x-powered-by", "")
    if powered:
        results.append(
            finding(
                check_id="headers.x_powered_by",
                title="X-Powered-By 泄露技术栈",
                severity="low",
                category="headers",
                description=f"X-Powered-By 响应头暴露了后端技术：{powered}",
                remediation="关闭框架的 X-Powered-By 输出（如 Express: app.disable('x-powered-by')；PHP: expose_php=Off），并在网关层移除。",
                url=url,
                evidence=f"X-Powered-By: {powered}",
                cwe="CWE-200",
                fingerprint="x-powered-by",
            )
        )

    target_scheme = urlparse(ctx.config.target if "://" in ctx.config.target else "https://" + ctx.config.target).scheme
    if target_scheme == "http" and url.startswith("http://"):
        results.append(
            finding(
                check_id="headers.https",
                title="站点未强制使用 HTTPS",
                severity="medium",
                category="headers",
                description="入口地址仍通过明文 HTTP 提供，流量可能被窃听或篡改。",
                remediation="部署有效证书并将 HTTP 301 跳转到 HTTPS，同时开启 HSTS。",
                url=url,
                evidence="最终落地页仍为 http://",
                cwe="CWE-319",
                owasp="A02:2021",
            )
        )
    return results


async def check_cors(ctx: CheckContext) -> list[Finding]:
    page = ctx.root_page
    if page is None:
        return []
    origin = "https://vulnlens-probe.example"
    probe_headers = {**ctx.session.default_headers, "Origin": origin}
    try:
        resp = await ctx.session.get(page.url, headers={"Origin": origin})
    except ScanLimitReached:
        return []
    acao = resp.header("access-control-allow-origin")
    acac = resp.header("access-control-allow-credentials").lower()
    if not acao:
        return []
    if acao == origin and acac == "true":
        return [
            finding(
                check_id="cors.credentials",
                title="CORS 允许任意来源携带凭据",
                severity="high",
                category="cors",
                description="服务端将请求 Origin 原样回写，并允许携带 Cookie 凭据。任意网站都可读取已登录用户的敏感数据。",
                remediation="使用来源白名单校验 Origin，仅允许可信域名；不要将请求 Origin 直接回写。若无需跨域携带凭据，保持 allow-credentials=false。",
                url=page.url,
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                cwe="CWE-942",
                owasp="A05:2021",
                **capture(resp, url=page.url, headers=probe_headers),
            )
        ]
    if acao == "*" and acac == "true":
        return [
            finding(
                check_id="cors.wildcard_credentials",
                title="CORS 通配来源且允许凭据",
                severity="medium",
                category="cors",
                description="Access-Control-Allow-Origin 为 * 且允许凭据，浏览器会拒绝该组合，但配置本身说明跨域策略存在缺陷。",
                remediation="改为固定可信来源白名单，并按需开启 credentials。",
                url=page.url,
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                cwe="CWE-942",
                **capture(resp, url=page.url, headers=probe_headers),
            )
        ]
    if acao == origin:
        return [
            finding(
                check_id="cors.reflect",
                title="CORS 反射任意来源",
                severity="medium",
                category="cors",
                description="服务端将任意请求 Origin 原样回写为允许来源，可能被用于跨域读取非敏感响应。",
                remediation="只允许白名单来源，拒绝未知 Origin。",
                url=page.url,
                evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                cwe="CWE-942",
                **capture(resp, url=page.url, headers=probe_headers),
            )
        ]
    return []


async def check_cookie_flags(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    is_https = (ctx.root_page.url if ctx.root_page else "").startswith("https://")
    for cookie in ctx.discovery.cookies:
        issues: list[str] = []
        if is_https and not cookie.secure:
            issues.append("缺少 Secure")
        if not cookie.http_only:
            issues.append("缺少 HttpOnly")
        if not cookie.same_site:
            issues.append("缺少 SameSite")
        if not issues:
            continue
        severity = "medium" if (is_https and "缺少 Secure" in issues) else "low"
        results.append(
            finding(
                check_id="cookie.flags",
                title=f"Cookie {cookie.name} 安全属性不完整",
                severity=severity,
                category="cookies",
                description=f"Cookie {cookie.name} 存在以下问题：{'、'.join(issues)}。",
                remediation="为会话 Cookie 设置 Secure、HttpOnly 与 SameSite=Lax/Strict；跨站点必需时使用 SameSite=None; Secure。",
                url=cookie.source_url,
                evidence=truncate(cookie.raw, 300),
                cwe="CWE-1004",
                owasp="A05:2021",
                fingerprint=cookie.name,
            )
        )
    return results


async def check_http_methods(ctx: CheckContext) -> list[Finding]:
    page = ctx.root_page
    if page is None:
        return []
    results: list[Finding] = []
    try:
        options = await ctx.session.fetch("OPTIONS", page.url, max_bytes=60_000)
        allow = options.header("allow")
        if allow:
            upper = allow.upper()
            if "TRACE" in upper:
                results.append(
                    finding(
                        check_id="methods.trace_allowed",
                        title="允许 TRACE 方法",
                        severity="medium",
                        category="methods",
                        description="OPTIONS 响应声明支持 TRACE，可能用于跨站追踪攻击。",
                        remediation="在 Web 服务器或框架中禁用 TRACE 方法（如 Apache TraceEnable Off）。",
                        url=page.url,
                        evidence=f"Allow: {allow}",
                        cwe="CWE-749",
                        **capture(options, method="OPTIONS", url=page.url, headers=ctx.session.default_headers),
                    )
                )
            risky = [m.strip() for m in upper.split(",") if m.strip() in ("PUT", "DELETE")]
            if risky:
                results.append(
                    finding(
                        check_id="methods.risky",
                        title=f"入口允许 {', '.join(risky)} 方法",
                        severity="low",
                        category="methods",
                        description="入口页面声明支持写/删方法，若鉴权不足可能造成未授权变更。",
                        remediation="仅对确实需要的路径开放 PUT/DELETE，并在网关层校验鉴权与 CSRF/来源。",
                        url=page.url,
                        evidence=f"Allow: {allow}",
                        cwe="CWE-749",
                        **capture(options, method="OPTIONS", url=page.url, headers=ctx.session.default_headers),
                    )
                )
        trace = await ctx.session.fetch("TRACE", page.url, max_bytes=60_000)
        if trace.status == 200 and "TRACE" in trace.text.upper():
            results.append(
                finding(
                    check_id="methods.trace_enabled",
                    title="TRACE 方法实际可用",
                    severity="medium",
                    category="methods",
                    description="服务器对 TRACE 请求返回 200 并回显请求内容，存在跨站追踪（XST）风险。",
                    remediation="在服务器层禁用 TRACE，或限制为内部地址。",
                    url=page.url,
                    evidence=truncate(trace.text, 300),
                    cwe="CWE-749",
                    **capture(trace, method="TRACE", url=page.url, headers=ctx.session.default_headers),
                )
            )
    except ScanLimitReached:
        pass
    return results


async def check_tls(ctx: CheckContext) -> list[Finding]:
    results = []
    for item in build_tls_findings(ctx.assets):
        item.setdefault("url", ctx.config.target)
        results.append(Finding(**item))
    return results


async def check_ports(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    for item in ctx.assets.open_ports:
        port = item.get("port")
        if port not in RISKY_PORTS:
            continue
        service = item.get("service") or RISKY_PORTS[port]
        severity = "high" if port in (2375, 6379, 9200, 11211, 27017, 3306) else "medium"
        results.append(
            finding(
                check_id="ports.exposed",
                title=f"高危服务端口对外开放：{service} ({port})",
                severity=severity,
                category="assets",
                confidence="medium",
                description=f"扫描发现 {port} 端口可建立 TCP 连接，该端口通常对应 {service}。若未限制来源，可能导致数据泄露或未授权操作。",
                remediation="通过防火墙/安全组限制来源 IP，服务仅监听 127.0.0.1 或内网地址，并开启认证与最小权限。",
                url=f"{ctx.config.target}",
                evidence=f"{ctx.assets.resolved_ips[:3]} 端口 {port} 可连接",
                cwe="CWE-668",
                fingerprint=str(port),
            )
        )
    return results


SENSITIVE_FILES = [
    {
        "path": "/.git/config",
        "title": "Git 仓库配置可公开访问",
        "severity": "high",
        "test": lambda r: "[core]" in r.text and "repositoryformatversion" in r.text.lower(),
        "remediation": "在 Web 服务器禁止访问 .git 目录（如 Nginx location ~ /\\.git { deny all; }），并检查是否可进一步下载完整源码。",
        "cwe": "CWE-538",
    },
    {
        "path": "/.git/HEAD",
        "title": "Git 仓库 HEAD 可公开访问",
        "severity": "high",
        "test": lambda r: r.text.strip().startswith("ref: refs/"),
        "remediation": "禁止 Web 访问 .git 目录，并清理部署目录中的版本库文件。",
        "cwe": "CWE-538",
    },
    {
        "path": "/.env",
        "title": ".env 环境变量文件泄露",
        "severity": "critical",
        "test": lambda r: len(re.findall(r"(?m)^[A-Z0-9_]{2,}=", r.text)) >= 3,
        "remediation": "立即禁止访问 .env，并轮换其中泄露的密钥与数据库口令；部署时不要将 .env 放入 Web 根目录。",
        "cwe": "CWE-538",
    },
    {
        "path": "/.env.local",
        "title": ".env.local 环境变量文件泄露",
        "severity": "critical",
        "test": lambda r: len(re.findall(r"(?m)^[A-Z0-9_]{2,}=", r.text)) >= 3,
        "remediation": "禁止 Web 访问 .env* 文件，并轮换已泄露凭据。",
        "cwe": "CWE-538",
    },
    {
        "path": "/.env.production",
        "title": ".env.production 环境变量文件泄露",
        "severity": "critical",
        "test": lambda r: len(re.findall(r"(?m)^[A-Z0-9_]{2,}=", r.text)) >= 3,
        "remediation": "禁止 Web 访问 .env* 文件，并轮换已泄露凭据。",
        "cwe": "CWE-538",
    },
    {
        "path": "/backup.zip",
        "title": "备份压缩包可下载",
        "severity": "high",
        "test": lambda r: "zip" in (r.content_type or "").lower(),
        "remediation": "删除或移出 Web 根目录中的备份文件，并为备份存储增加鉴权。",
        "cwe": "CWE-552",
    },
    {
        "path": "/www.zip",
        "title": "站点源码压缩包可下载",
        "severity": "high",
        "test": lambda r: "zip" in (r.content_type or "").lower(),
        "remediation": "删除或移出 Web 根目录中的源码压缩包，禁止目录内可执行/可下载的归档文件。",
        "cwe": "CWE-552",
    },
    {
        "path": "/backup.sql",
        "title": "数据库备份可下载",
        "severity": "critical",
        "test": lambda r: "CREATE TABLE" in r.text.upper() or "INSERT INTO" in r.text.upper(),
        "remediation": "立即移除公网可访问的数据库备份，轮换数据库凭据，并检查日志是否有异常下载。",
        "cwe": "CWE-552",
    },
    {
        "path": "/db.sql",
        "title": "数据库导出文件可下载",
        "severity": "critical",
        "test": lambda r: "CREATE TABLE" in r.text.upper() or "INSERT INTO" in r.text.upper(),
        "remediation": "移除公网可访问的 SQL 导出文件，并将备份放到受控存储。",
        "cwe": "CWE-552",
    },
    {
        "path": "/.svn/entries",
        "title": "SVN 元数据泄露",
        "severity": "medium",
        "test": lambda r: r.status == 200 and ("dir" in r.text or "svn" in r.text.lower()),
        "remediation": "禁止访问 .svn 目录，使用导出（export）方式部署而非检出。",
        "cwe": "CWE-538",
    },
    {
        "path": "/.DS_Store",
        "title": ".DS_Store 泄露目录结构",
        "severity": "low",
        "test": lambda r: "Bud1" in r.text,
        "remediation": "禁止访问或删除 .DS_Store 文件，部署前清理系统隐藏文件。",
        "cwe": "CWE-538",
    },
    {
        "path": "/WEB-INF/web.xml",
        "title": "WEB-INF/web.xml 可访问",
        "severity": "medium",
        "test": lambda r: "<web-app" in r.text,
        "remediation": "限制 WEB-INF 目录访问，确认容器未将敏感配置暴露给外部。",
        "cwe": "CWE-538",
    },
    {
        "path": "/actuator/env",
        "title": "Spring Actuator 环境变量暴露",
        "severity": "high",
        "test": lambda r: "propertySources" in r.text or ("activeProfiles" in r.text and "systemProperties" in r.text),
        "remediation": "生产环境关闭 actuator/env，或通过 management.endpoints.web.exposure.include 最小化暴露并加鉴权。",
        "cwe": "CWE-200",
    },
    {
        "path": "/actuator/health",
        "title": "Spring Actuator 健康端点公开",
        "severity": "info",
        "test": lambda r: '"status"' in r.text and ("UP" in r.text or "DOWN" in r.text),
        "remediation": "如无需公开监控，限制 actuator/health 来源，或仅暴露最小信息。",
        "cwe": "CWE-200",
    },
    {
        "path": "/server-status",
        "title": "Apache 状态页公开",
        "severity": "medium",
        "test": lambda r: "Apache Server Status" in r.text,
        "remediation": "将 server-status 限制为内网访问，或关闭 mod_status。",
        "cwe": "CWE-200",
    },
    {
        "path": "/phpinfo.php",
        "title": "phpinfo 页面公开",
        "severity": "medium",
        "test": lambda r: "phpinfo()" in r.text or "PHP Version" in r.text,
        "remediation": "删除生产环境中的 phpinfo 文件，避免泄露路径、扩展与配置信息。",
        "cwe": "CWE-200",
    },
    {
        "path": "/composer.json",
        "title": "composer.json 可公开访问",
        "severity": "low",
        "test": lambda r: '"require"' in r.text,
        "remediation": "禁止访问 composer.json 等依赖清单，或将其移出 Web 根目录。",
        "cwe": "CWE-538",
    },
]


async def check_sensitive_files(ctx: CheckContext) -> list[Finding]:
    base = f"{urlparse(ctx.root_page.url).scheme}://{urlparse(ctx.root_page.url).netloc}" if ctx.root_page else ctx.config.target
    results: list[Finding] = []
    for item in SENSITIVE_FILES:
        target_url = base + item["path"]
        if ctx.excluded(target_url):
            continue
        try:
            resp = await ctx.session.get(target_url, max_bytes=200_000)
        except ScanLimitReached:
            break
        if resp.error or resp.status != 200 or not resp.text:
            continue
        try:
            matched = item["test"](resp)
        except Exception:
            matched = False
        if not matched:
            continue
        results.append(
            finding(
                check_id=f"exposure{re.sub(r'[^a-z0-9]+', '.', item['path'].lower())}",
                title=item["title"],
                severity=item["severity"],
                category="exposure",
                description=f"访问 {item['path']} 返回 200 且匹配到敏感内容特征，确认该文件可被外部下载。",
                remediation=item["remediation"],
                url=target_url,
                evidence=truncate(resp.text, 400),
                cwe=item["cwe"],
                owasp="A01:2021",
                **capture(resp, url=target_url, headers=ctx.session.default_headers),
            )
        )
    return results


async def check_directory_listing(ctx: CheckContext) -> list[Finding]:
    if ctx.root_page is None:
        return []
    parsed_root = urlparse(ctx.root_page.url)
    directories: list[str] = []
    for page_url in ctx.discovery.pages:
        path = urlparse(page_url).path
        directory = path.rsplit("/", 1)[0] + "/" if "/" in path else "/"
        if directory not in directories:
            directories.append(directory)
    directories = directories[:8]
    results: list[Finding] = []
    for directory in directories:
        url = urlunparse((parsed_root.scheme, parsed_root.netloc, directory, "", "", ""))
        if ctx.excluded(url):
            continue
        try:
            resp = await ctx.session.get(url, max_bytes=300_000)
        except ScanLimitReached:
            break
        if resp.error or resp.status != 200:
            continue
        lowered = resp.text.lower()
        if "<title>index of" in lowered or "directory listing for" in lowered or "[to parent directory]" in lowered:
            results.append(
                finding(
                    check_id="exposure.directory_listing",
                    title="目录列表（Directory Listing）开启",
                    severity="medium",
                    category="exposure",
                    description=f"目录 {directory} 直接列出文件清单，攻击者可快速定位源码、备份与配置文件。",
                    remediation="关闭 Web 服务器目录浏览（Nginx: autoindex off；Apache: Options -Indexes），并为目录设置默认首页。",
                    url=url,
                    evidence=truncate(resp.text, 400),
                    cwe="CWE-548",
                    owasp="A01:2021",
                    fingerprint=directory,
                    **capture(resp, url=url, headers=ctx.session.default_headers),
                )
            )
    return results


async def check_error_leak(ctx: CheckContext) -> list[Finding]:
    if ctx.root_page is None:
        return []
    parsed = urlparse(ctx.root_page.url)
    random_path = "/vulnlens-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    url = urlunparse((parsed.scheme, parsed.netloc, random_path, "", "", ""))
    if ctx.excluded(url):
        return []
    try:
        resp = await ctx.session.get(url, max_bytes=300_000)
    except ScanLimitReached:
        return []
    if resp.error or not resp.text:
        return []
    for label, pattern in TRACE_PATTERNS:
        match = pattern.search(resp.text)
        if match:
            return [
                finding(
                    check_id="exposure.stack_trace",
                    title=f"错误页面泄露 {label} 堆栈信息",
                    severity="medium",
                    category="exposure",
                    description="访问不存在的路径时，服务端返回了包含堆栈/数据库错误的详细异常信息，可辅助攻击者推断技术栈与内部路径。",
                    remediation="生产环境关闭调试模式（如 Flask/Django DEBUG=False、Spring server.error.include-stacktrace=never），统一返回自定义错误页并记录详细日志到服务端。",
                    url=url,
                    evidence=_snippet(resp.text, match.group(0)),
                    cwe="CWE-209",
                    owasp="A05:2021",
                    fingerprint=label,
                    **capture(resp, url=url, headers=ctx.session.default_headers),
                )
            ]
    return []


async def check_default_page(ctx: CheckContext) -> list[Finding]:
    page = ctx.root_page
    if page is None:
        return []
    body = page.html[:20000]
    results: list[Finding] = []
    for label, pattern in DEFAULT_PAGES:
        if pattern.search(body):
            results.append(
                finding(
                    check_id="exposure.default_page",
                    title=f"检测到{label}",
                    severity="low",
                    category="exposure",
                    confidence="medium",
                    description="入口页面疑似服务器/中间件默认页，说明站点可能尚未完成安全加固或存在未清理的默认内容。",
                    remediation="移除默认欢迎页与示例应用，替换为正式业务页面；关闭管理台公网访问。",
                    url=page.url,
                    evidence=truncate(body[:400], 400),
                    cwe="CWE-1188",
                    fingerprint=label,
                )
            )
    return results


async def check_exposed_docs(ctx: CheckContext) -> list[Finding]:
    if not ctx.discovery.docs:
        return []
    urls = ctx.discovery.docs[:5]
    return [
        finding(
            check_id="exposure.api_docs",
            title="接口文档（Swagger/OpenAPI）公开暴露",
            severity="medium",
            category="exposure",
            description="接口文档可被匿名访问，完整暴露了接口路径、参数、数据模型与可能的内部地址，显著降低攻击成本。",
            remediation="生产环境关闭接口文档（如 Spring: springdoc.api-docs.enabled=false），或仅允许内网/白名单访问并增加认证。",
            url=urls[0],
            evidence="\n".join(urls),
            cwe="CWE-200",
            owasp="A05:2021",
            fingerprint="docs",
        )
    ]


async def check_sourcemap(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    checked: set[str] = set()
    map_pattern = re.compile(r"sourceMappingURL=([^\s*'\"]+)")
    for js_url, text in list(ctx.discovery.js_text.items())[:30]:
        if js_url.startswith("inline:"):
            continue
        match = map_pattern.search(text[-4000:])
        map_url = urljoin(js_url, match.group(1)) if match else js_url + ".map"
        if map_url in checked:
            continue
        checked.add(map_url)
        try:
            resp = await ctx.session.get(map_url, max_bytes=1_000_000)
        except ScanLimitReached:
            break
        if resp.error or resp.status != 200 or '"sources"' not in resp.text[:5000]:
            continue
        results.append(
            finding(
                check_id="exposure.sourcemap",
                title="前端 SourceMap 可公开下载",
                severity="low",
                category="exposure",
                description="生产环境暴露了 SourceMap，攻击者可还原未压缩的前端源码与注释，辅助发现接口与逻辑缺陷。",
                remediation="生产构建关闭 sourcemap（Vite: build.sourcemap=false），或仅上传到错误监控平台而不随站点发布。",
                url=map_url,
                evidence=truncate(resp.text[:600], 400),
                cwe="CWE-540",
                fingerprint=js_url,
            )
        )
        if len(results) >= 5:
            break
    return results


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 10:
        return value[:3] + "***"
    return value[:8] + "***" + value[-3:]


async def check_js_secrets(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for source, text in ctx.discovery.js_text.items():
        for name, severity, confidence, pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            key = (source, name)
            if key in seen:
                continue
            seen.add(key)
            secret = match.group(0)
            results.append(
                finding(
                    check_id="exposure.js_secret",
                    title=f"前端代码中发现{name}",
                    severity=severity,
                    category="exposure",
                    confidence=confidence,
                    description=f"在 {source} 中匹配到疑似敏感凭据。前端代码对访问者完全可见，任何写入前端的密钥都应视为已泄露。",
                    remediation="立即轮换该凭据；将密钥调用迁移到后端，前端只使用受限的短期令牌；构建时通过环境变量注入并避免硬编码。",
                    url=source if not source.startswith("inline:") else source.replace("inline:", ""),
                    evidence=_mask(secret),
                    cwe="CWE-798",
                    owasp="A07:2021",
                    fingerprint=name,
                )
            )
            if len(results) >= 12:
                return results
    return results


async def check_tech_cve(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    for tech in ctx.discovery.tech:
        for entry in match_cves(tech):
            results.append(
                finding(
                    check_id="fingerprint.cve",
                    title=f"{tech.name} {tech.version} 命中 {entry['cve']}",
                    severity=entry.get("severity", "medium"),
                    category="fingerprint",
                    confidence="medium",
                    description=f"{entry.get('title', '')} {entry.get('description', '')}".strip(),
                    remediation=entry.get("remediation", "升级到不受影响的版本。"),
                    url=ctx.root_page.url if ctx.root_page else "",
                    evidence=f"{tech.name} {tech.version}\n指纹依据：{tech.evidence}",
                    cwe="CWE-1104",
                    owasp="A06:2021",
                    references=[entry["reference"]] if entry.get("reference") else [],
                    fingerprint=entry["cve"],
                )
            )
    return results


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
JWT_SENSITIVE_CLAIMS = ("password", "passwd", "secret", "api_key", "apikey", "private_key", "access_key")


def _jwt_decode(part: str) -> dict | None:
    padded = part + "=" * (-len(part) % 4)
    try:
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(data.decode("utf-8", errors="replace"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _jwt_tokens(ctx: CheckContext) -> list[tuple[str, str, str]]:
    sources: list[tuple[str, str, str]] = []
    for cookie in ctx.discovery.cookies:
        sources.append((cookie.source_url, f"Cookie {cookie.name}", cookie.raw))
    for source, text in list(ctx.discovery.js_text.items())[:40]:
        sources.append((source.replace("inline:", ""), "前端代码", text))
    tokens: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for source_url, label, text in sources:
        for match in JWT_RE.finditer(text):
            token = match.group(0)
            if token in seen:
                continue
            seen.add(token)
            tokens.append((source_url, label, token))
    return tokens


async def check_jwt(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    for source_url, label, token in _jwt_tokens(ctx):
        if len(results) >= 8:
            break
        header = _jwt_decode(token.split(".")[0])
        payload = _jwt_decode(token.split(".")[1])
        if not header or not payload:
            continue
        alg = str(header.get("alg") or "").lower()
        token_hash = hashlib.sha1(token.encode("utf-8", errors="ignore")).hexdigest()[:8]
        evidence = "Header: " + json.dumps(header, ensure_ascii=False) + "\nPayload: " + json.dumps(payload, ensure_ascii=False)
        base = {
            "category": "auth",
            "confidence": "high",
            "url": source_url,
            "evidence": truncate(evidence, 600),
            "owasp": "A07:2021",
            "fingerprint": token_hash,
        }
        if alg in ("none", "") or "alg" not in header:
            results.append(
                finding(
                    check_id="jwt.alg_none",
                    title="JWT 未签名或使用 alg=none",
                    severity="critical",
                    description=f"在{label}中发现 JWT，其算法为 {alg or '缺失'}。服务端若接受该令牌，攻击者可自行伪造任意身份。",
                    remediation="服务端强制校验签名算法白名单（如 RS256/HS256），拒绝 alg=none 与空签名；升级 JWT 库并校验 issuers/audience。",
                    cwe="CWE-347",
                    **base,
                )
            )
        if "exp" not in payload:
            results.append(
                finding(
                    check_id="jwt.no_exp",
                    title="JWT 未设置过期时间",
                    severity="medium",
                    description=f"{label}中的 JWT 没有 exp 声明。令牌一旦泄露可长期使用，无法通过过期机制降低风险。",
                    remediation="签发令牌时设置较短的 exp（如 15-60 分钟），并配合刷新令牌与吊销列表。",
                    cwe="CWE-613",
                    **base,
                )
            )
        sensitive = [key for key in payload if str(key).lower() in JWT_SENSITIVE_CLAIMS]
        if sensitive:
            results.append(
                finding(
                    check_id="jwt.sensitive_claims",
                    title="JWT 载荷包含敏感字段",
                    severity="high",
                    description=f"{label}中的 JWT 载荷包含敏感字段：{'、'.join(sensitive)}。JWT 仅做 Base64 编码，任何持有者都可直接读取。",
                    remediation="不要把口令、密钥等敏感信息写入 JWT 载荷；只保留必要的标识与权限声明，服务端按需查询敏感数据。",
                    cwe="CWE-522",
                    **base,
                )
            )
    return results


async def _resolve_txt(domain: str) -> list[str] | None:
    try:
        import dns.asyncresolver
    except Exception:
        return None
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 4.0
        answers = await resolver.resolve(domain, "TXT")
    except Exception:
        return []
    records: list[str] = []
    for rdata in answers:
        text = rdata.to_text()
        parts = re.findall(r'"([^"]*)"', text)
        records.append("".join(parts) if parts else text.strip('"'))
    return records


async def check_email_dns(ctx: CheckContext) -> list[Finding]:
    parsed = urlparse(ctx.config.target if "://" in ctx.config.target else "https://" + ctx.config.target)
    host = parsed.hostname or ""
    if not host or is_ip(host) or host == "localhost" or "." not in host:
        return []
    domain = base_domain(host)
    records = await _resolve_txt(domain)
    results: list[Finding] = []
    if records is None:
        return results

    spf = [record for record in records if record.lower().startswith("v=spf1")]
    if not spf:
        results.append(
            finding(
                check_id="dns.spf_missing",
                title="域名未配置 SPF 记录",
                severity="low",
                category="dns",
                confidence="medium",
                description=f"{domain} 的 TXT 记录中没有 v=spf1。若该域名用于收发邮件，攻击者更容易伪造发件人。",
                remediation="配置 SPF，例如 v=spf1 include:_spf.example.com -all，将授权的发信服务器列入并通过 -all 拒绝其他来源。",
                url=ctx.config.target,
                evidence=f"TXT({domain}) 未匹配 v=spf1",
                cwe="CWE-290",
                owasp="A07:2021",
                fingerprint="spf",
            )
        )
    else:
        if len(spf) > 1:
            results.append(
                finding(
                    check_id="dns.spf_multiple",
                    title="存在多条 SPF 记录",
                    severity="medium",
                    category="dns",
                    confidence="high",
                    description=f"{domain} 发布了 {len(spf)} 条 v=spf1 记录。多条 SPF 会导致校验失败，收件方可能直接判为伪造。",
                    remediation="合并为唯一一条 SPF 记录，包含全部授权发信源。",
                    url=ctx.config.target,
                    evidence="\n".join(spf),
                    cwe="CWE-290",
                    fingerprint="spf-multiple",
                )
            )
        if any(re.search(r"(?:^|\s)\+all(?:\s|$)", record, re.I) for record in spf):
            results.append(
                finding(
                    check_id="dns.spf_allow_all",
                    title="SPF 使用 +all，允许任意服务器发信",
                    severity="high",
                    category="dns",
                    confidence="high",
                    description=f"{domain} 的 SPF 以 +all 结尾，等于声明全世界任何服务器都可以代表该域名发信，SPF 防护形同虚设。",
                    remediation="将 +all 改为 -all（严格拒绝）或 ~all（软失败），并确认授权发信源已全部列入。",
                    url=ctx.config.target,
                    evidence="\n".join(spf),
                    cwe="CWE-290",
                    owasp="A07:2021",
                    fingerprint="spf-all",
                )
            )

    dmarc_records = await _resolve_txt("_dmarc." + domain)
    dmarc = [record for record in (dmarc_records or []) if record.lower().startswith("v=dmarc1")]
    if not dmarc:
        results.append(
            finding(
                check_id="dns.dmarc_missing",
                title="域名未配置 DMARC 记录",
                severity="low",
                category="dns",
                confidence="medium",
                description=f"未在 _dmarc.{domain} 找到 DMARC 策略。缺少 DMARC 时，收件方无法依据域名所有者策略处置伪造邮件。",
                remediation="发布 DMARC 记录，例如 _dmarc 的 TXT：v=DMARC1; p=none; rua=mailto:dmarc@example.com，先观察再逐步收紧到 quarantine/reject。",
                url=ctx.config.target,
                evidence=f"TXT(_dmarc.{domain}) 未匹配 v=DMARC1",
                cwe="CWE-290",
                owasp="A07:2021",
                fingerprint="dmarc",
            )
        )
    elif any("p=none" in record.replace(" ", "").lower() for record in dmarc):
        results.append(
            finding(
                check_id="dns.dmarc_none",
                title="DMARC 策略为 p=none（仅监控）",
                severity="low",
                category="dns",
                confidence="high",
                description=f"{domain} 的 DMARC 策略为 p=none，不会拦截伪造邮件，仅发送报告。",
                remediation="确认报告数据后，将策略调整为 p=quarantine 或 p=reject，并配合 SPF/DKIM。",
                url=ctx.config.target,
                evidence="\n".join(dmarc),
                cwe="CWE-290",
                fingerprint="dmarc-none",
            )
        )
    return results


TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "there isn't a github pages site here"),
    "herokuapp.com": ("Heroku", "no such app"),
    "s3.amazonaws.com": ("AWS S3", "nosuchbucket"),
    "amazonaws.com": ("AWS S3", "nosuchbucket"),
    "azurewebsites.net": ("Azure Web App", "error 404 - web app not found"),
    "cloudfront.net": ("CloudFront", "bad request"),
    "netlify.app": ("Netlify", "not found - request id"),
    "surge.sh": ("Surge", "project not found"),
    "readme.io": ("ReadMe", "project doesn't exist"),
    "bitbucket.io": ("Bitbucket", "repository not found"),
    "ghost.io": ("Ghost", "domain error"),
    "fastly.net": ("Fastly", "fastly error: unknown domain"),
}


async def _resolve_cname(host: str) -> str:
    try:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 4.0
        answers = await resolver.resolve(host, "CNAME")
        return str(answers[0].target).rstrip(".").lower()
    except Exception:
        return ""


async def check_subdomain_takeover(ctx: CheckContext) -> list[Finding]:
    subdomains = [item for item in ctx.assets.subdomains if not ctx.excluded("https://" + item)][:10]
    if not subdomains:
        return []
    results: list[Finding] = []
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(8.0, connect=5.0),
        trust_env=False,
        proxy=ctx.config.proxy or None,
        headers={"User-Agent": "VulnLens/1.1 (authorized takeover check)"},
    ) as client:
        for subdomain in subdomains:
            cname = await _resolve_cname(subdomain)
            if not cname:
                continue
            service = next((value for suffix, value in TAKEOVER_FINGERPRINTS.items() if cname.endswith(suffix)), None)
            if service is None:
                continue
            name, marker = service
            status = 0
            body = ""
            try:
                resp = await client.get("https://" + subdomain)
                status = resp.status_code
                body = resp.text[:200_000]
            except Exception:
                try:
                    resp = await client.get("http://" + subdomain)
                    status = resp.status_code
                    body = resp.text[:200_000]
                except Exception:
                    continue
            matched = marker in body.lower()
            if not matched and status != 404:
                continue
            results.append(
                finding(
                    check_id="takeover.dangling_cname",
                    title=f"子域名可能被接管：{subdomain}",
                    severity="high" if matched else "medium",
                    category="dns",
                    confidence="high" if matched else "low",
                    description=(
                        f"{subdomain} 的 CNAME 指向 {name}（{cname}），但该托管空间未绑定有效站点。"
                        "攻击者可在第三方平台注册同名资源并接管该子域名，用于钓鱼或窃取 Cookie。"
                    ),
                    remediation=f"从 DNS 中删除指向 {cname} 的 CNAME，或在 {name} 平台重新绑定并占用该资源；建立子域名下线清理流程。",
                    url="https://" + subdomain,
                    evidence=f"CNAME: {subdomain} -> {cname}\nHTTP {status}\n匹配特征：{'是' if matched else '否（仅 404）'}",
                    cwe="CWE-284",
                    owasp="A05:2021",
                    fingerprint=subdomain,
                )
            )
    return results


PASSIVE_CHECKS = [
    check_security_headers,
    check_cors,
    check_cookie_flags,
    check_http_methods,
    check_tls,
    check_ports,
    check_sensitive_files,
    check_directory_listing,
    check_error_leak,
    check_default_page,
    check_exposed_docs,
    check_sourcemap,
    check_js_secrets,
    check_tech_cve,
    check_jwt,
    check_email_dns,
    check_subdomain_takeover,
]

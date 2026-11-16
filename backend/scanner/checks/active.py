from __future__ import annotations

import random
import string
from urllib.parse import quote, urlparse

from ..http_client import ScanLimitReached
from ..models import Finding
from .base import CheckContext, capture, finding, replace_query_param, truncate

DESTRUCTIVE = ("delete", "remove", "logout", "signout", "unsubscribe", "drop", "reset")

REDIRECT_PARAMS = {
    "url", "uri", "redirect", "redirect_uri", "redirect_url", "next", "return", "returnurl",
    "return_url", "continue", "target", "dest", "destination", "goto", "out", "link", "callback",
    "callback_url", "forward", "to", "back", "r", "u",
}

SQL_ERRORS = [
    "SQLSTATE[",
    "You have an error in your SQL syntax",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ORA-00933",
    "ORA-00936",
    "ORA-01756",
    "PostgreSQL.*ERROR",
    "pg_query()",
    "Warning: mysqli",
    "Warning: mysql_",
    "mysql_fetch",
    "SQLite3::",
    "java.sql.SQLException",
    "Microsoft OLE DB Provider for SQL Server",
    "Incorrect syntax near",
]


def _random_token(prefix: str = "vlq", length: int = 6) -> str:
    return prefix + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _is_destructive(param: str) -> bool:
    lowered = param.lower()
    return any(word in lowered for word in DESTRUCTIVE)


async def check_reflected_xss(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    tested = 0
    for url, param in ctx.param_candidates(limit=60):
        if tested >= 12:
            break
        if _is_destructive(param):
            continue
        marker = _random_token() + "'\"<v>"
        target = replace_query_param(url, param, marker)
        try:
            resp = await ctx.session.get(target, max_bytes=800_000)
        except ScanLimitReached:
            break
        tested += 1
        if resp.error or "html" not in (resp.content_type or "").lower():
            continue
        if marker not in resp.text:
            continue
        index = resp.text.find(marker)
        results.append(
            finding(
                check_id="active.xss_reflected",
                title="反射型跨站脚本（XSS）",
                severity="high",
                category="active",
                confidence="medium",
                description=f"参数 {param} 的值被原样写入 HTML 响应，特殊字符 '\"< 未被编码。攻击者可构造链接在受害者浏览器执行脚本。",
                remediation="对输出到 HTML 的数据做上下文相关编码（HTML 实体编码），使用框架默认转义；增加 CSP 作为纵深防御，并对输入做白名单校验。",
                url=target,
                param=param,
                method="GET",
                evidence=truncate(resp.text[max(0, index - 120): index + 200], 420),
                cwe="CWE-79",
                owasp="A03:2021",
                fingerprint=param,
                **capture(resp, url=target, headers=ctx.session.default_headers),
            )
        )
    return results


async def check_sqli_error(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    tested = 0
    for url, param in ctx.param_candidates(limit=60):
        if tested >= 10:
            break
        if _is_destructive(param):
            continue
        target = replace_query_param(url, param, _random_token("1") + "'")
        try:
            resp = await ctx.session.get(target, max_bytes=800_000)
        except ScanLimitReached:
            break
        tested += 1
        if resp.error or not resp.text:
            continue
        lowered = resp.text.lower()
        matched = next((err for err in SQL_ERRORS if err.lower() in lowered), None)
        if not matched:
            continue
        index = lowered.find(matched.lower())
        results.append(
            finding(
                check_id="active.sqli_error",
                title="SQL 注入（报错型）",
                severity="high",
                category="active",
                confidence="medium",
                description=f"向参数 {param} 注入单引号后，响应中出现数据库错误特征（{matched}），说明输入可能直接进入 SQL 查询。",
                remediation="使用参数化查询/预编译语句，禁止字符串拼接 SQL；对输入做类型与格式校验；生产环境关闭详细数据库错误回显。",
                url=target,
                param=param,
                method="GET",
                evidence=truncate(resp.text[max(0, index - 150): index + 250], 420),
                cwe="CWE-89",
                owasp="A03:2021",
                fingerprint=param,
                **capture(resp, url=target, headers=ctx.session.default_headers),
            )
        )
    return results


async def check_open_redirect(ctx: CheckContext) -> list[Finding]:
    results: list[Finding] = []
    tested = 0
    payload = "https://example.com/vulnlens-redirect"
    for url, param in ctx.param_candidates(limit=80):
        if tested >= 12:
            break
        if param.lower() not in REDIRECT_PARAMS:
            continue
        target = replace_query_param(url, param, payload)
        try:
            resp = await ctx.session.get(target, allow_redirects=False, max_bytes=200_000)
        except ScanLimitReached:
            break
        tested += 1
        if resp.error or resp.status not in (301, 302, 303, 307, 308):
            continue
        location = resp.header("location")
        if "example.com/vulnlens-redirect" not in location:
            continue
        results.append(
            finding(
                check_id="active.open_redirect",
                title="开放重定向",
                severity="medium",
                category="active",
                confidence="high",
                description=f"参数 {param} 可将用户重定向到任意外部域名，常被用于钓鱼、OAuth 令牌窃取与绕过安全校验。",
                remediation="重定向目标使用固定白名单或仅允许站内相对路径；禁止直接使用请求参数作为 Location。",
                url=target,
                param=param,
                method="GET",
                evidence=f"HTTP {resp.status}\nLocation: {location}",
                cwe="CWE-601",
                owasp="A01:2021",
                fingerprint=param,
                **capture(resp, url=target, headers=ctx.session.default_headers),
            )
        )
    return results


ACTIVE_CHECKS = [check_reflected_xss, check_sqli_error, check_open_redirect]

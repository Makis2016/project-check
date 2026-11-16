from __future__ import annotations

import asyncio
import difflib
import random
import re
import string
from urllib.parse import parse_qs, urlparse

from ..http_client import ScanLimitReached
from ..models import Finding
from .base import CheckContext, capture, finding, format_request, truncate

SENSITIVE_RE = re.compile(
    r'"(email|phone|mobile|address|token|secret|password|balance|owner|user_?id|account_?id|order_?id|tenant_?id)"\s*:',
    re.I,
)
RESOURCE_HINTS = (
    "/api/",
    "/admin/",
    "/internal/",
    "/account",
    "/user",
    "/order",
    "/profile",
    "/tenant",
    "/member",
    "/invoice",
)
ID_PARAMS = {"id", "uid", "user_id", "order_id", "account_id", "tenant_id", "pid", "no", "uuid", "guid"}
DESTRUCTIVE_ACTIONS = ("logout", "signout", "delete", "remove", "unsubscribe", "reset", "destroy")
STORED_FIELDS = (
    "comment",
    "message",
    "content",
    "body",
    "title",
    "name",
    "text",
    "feedback",
    "review",
    "desc",
    "description",
    "note",
    "q",
    "search",
    "nickname",
)
UNSAFE_FIELDS = ("password", "passwd", "csrf", "token", "captcha", "file", "email", "submit", "phone")


def _same_origin(left: str, right: str) -> bool:
    parsed_left = urlparse(left)
    parsed_right = urlparse(right)
    return parsed_left.scheme == parsed_right.scheme and parsed_left.netloc.lower() == parsed_right.netloc.lower()


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left[:5000], right[:5000]).ratio()


def _is_resource_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if re.search(r"/\d+(/|$)", path) or re.search(r"/[0-9a-f]{8}-[0-9a-f-]{27}(/|$)", path):
        return True
    params = {name.lower() for name in parse_qs(parsed.query)}
    return bool(params & ID_PARAMS)


def _is_candidate(url: str) -> bool:
    path = urlparse(url).path.lower()
    if "{" in path or "}" in path:
        return False
    if any(hint in path for hint in RESOURCE_HINTS):
        return True
    return _is_resource_url(url)


async def check_access_control(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.auth_checks or not ctx.config.cookie:
        return []

    results: list[Finding] = []
    candidates: list[str] = []
    seen: set[str] = set()
    for endpoint in ctx.discovery.endpoints.values():
        url = endpoint.url
        path_key = urlparse(url).path
        if url in seen or path_key in seen or ctx.excluded(url):
            continue
        if not _is_candidate(url):
            continue
        seen.add(url)
        seen.add(path_key)
        candidates.append(url)
        if len(candidates) >= 16:
            break

    for url in candidates:
        if not _is_candidate(url):
            continue
        try:
            authed = await ctx.session.get(url, max_bytes=250_000)
        except ScanLimitReached:
            break
        if authed.status != 200 or "json" not in (authed.content_type or "").lower():
            continue
        if not SENSITIVE_RE.search(authed.text):
            continue

        if len([item for item in results if item.check_id == "auth.unauthorized_api"]) < 8:
            try:
                anon = await ctx.session.get(url, cookie="", max_bytes=250_000)
            except ScanLimitReached:
                break
            if (
                anon.status == 200
                and "json" in (anon.content_type or "").lower()
                and len(anon.text.strip()) >= 40
                and SENSITIVE_RE.search(anon.text)
            ):
                results.append(
                    finding(
                        check_id="auth.unauthorized_api",
                        title="接口可能未授权即可访问",
                        severity="medium",
                        category="auth",
                        confidence="low",
                        description="携带登录 Cookie 可访问的 JSON 接口，在移除 Cookie 后仍返回 200 且包含用户/订单等敏感字段。若该接口本应要求登录，则存在未授权访问。",
                        remediation="在服务端统一鉴权中间件中校验会话与权限，默认拒绝匿名访问敏感接口；不要把权限判断放在前端。",
                        url=url,
                        evidence=truncate(anon.text, 400),
                        cwe="CWE-306",
                        owasp="A01:2021",
                        fingerprint=url,
                        **capture(anon, url=url, headers={**ctx.session.default_headers, "Cookie": ""}),
                    )
                )

        if ctx.config.secondary_cookie and _is_resource_url(url):
            if len([item for item in results if item.check_id == "auth.idor"]) >= 6:
                continue
            try:
                other = await ctx.session.get(url, cookie=ctx.config.secondary_cookie, max_bytes=250_000)
            except ScanLimitReached:
                break
            if (
                other.status == 200
                and "json" in (other.content_type or "").lower()
                and SENSITIVE_RE.search(other.text)
                and _similarity(authed.text, other.text) >= 0.8
            ):
                results.append(
                    finding(
                        check_id="auth.idor",
                        title="疑似越权访问（双账号对比）",
                        severity="high",
                        category="auth",
                        confidence="low",
                        description="使用第二个账号的 Cookie 访问同一资源 URL，仍返回 200 且响应结构/敏感字段与主账号高度相似。若该资源属于主账号，则存在 IDOR/水平越权；请人工确认资源归属。",
                        remediation="对每个资源请求校验当前用户与资源属主关系，使用不可枚举的随机 ID，并在服务端做对象级权限检查。",
                        url=url,
                        evidence=truncate(other.text, 400),
                        cwe="CWE-639",
                        owasp="A01:2021",
                        fingerprint=url,
                        **capture(
                            other,
                            url=url,
                            headers={**ctx.session.default_headers, "Cookie": ctx.config.secondary_cookie},
                        ),
                    )
                )
    return results


async def check_stored_xss(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks:
        return []

    results: list[Finding] = []
    submitted = 0
    seen_forms: set[tuple[str, str]] = set()
    for form in ctx.discovery.forms:
        if submitted >= 3 or len(results) >= 3:
            break
        if form.method.upper() != "POST" or not _same_origin(form.action, form.source_url):
            continue
        action_lower = form.action.lower()
        if any(word in action_lower for word in DESTRUCTIVE_ACTIONS) or ctx.excluded(form.action):
            continue
        fields = [
            name
            for name in form.inputs
            if name.lower() in STORED_FIELDS and not any(bad in name.lower() for bad in UNSAFE_FIELDS)
        ]
        if not fields:
            continue
        field = fields[0]
        form_key = (form.action, field)
        if form_key in seen_forms:
            continue
        seen_forms.add(form_key)
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        marker = f"<vlm{token}>"
        data = {field: marker}
        submitted += 1
        try:
            posted = await ctx.session.fetch(
                "POST",
                form.action,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                max_bytes=200_000,
            )
        except ScanLimitReached:
            break
        if posted.error or posted.status >= 400:
            continue
        try:
            await asyncio.sleep(0.3)
        except asyncio.CancelledError:
            raise
        targets = [form.action, form.source_url]
        seen: set[str] = set()
        for target in targets:
            if not target or target in seen:
                continue
            seen.add(target)
            try:
                resp = await ctx.session.get(target, max_bytes=400_000)
            except ScanLimitReached:
                break
            if marker not in resp.text:
                continue
            index = resp.text.find(marker)
            repro = capture(resp, url=target)
            repro["request"] = format_request(
                "POST",
                form.action,
                {**ctx.session.default_headers, "Content-Type": "application/x-www-form-urlencoded"},
                f"{field}={marker}",
            )
            results.append(
                finding(
                    check_id="active.stored_xss",
                    title="存储型跨站脚本（XSS）",
                    severity="high",
                    category="active",
                    confidence="medium",
                    description=f"向表单字段 {field} 提交的测试标记未经 HTML 编码就出现在页面中，可能构成存储型 XSS。测试过程可能向目标写入了一条测试数据，请人工确认并在需要时清理。",
                    remediation="对用户提交内容在输出时做上下文相关编码，使用 HTML 白名单清洗富文本；对富文本使用独立的沙箱域展示。",
                    url=target,
                    method="POST",
                    param=field,
                    evidence=truncate(resp.text[max(0, index - 120): index + 220], 380),
                    cwe="CWE-79",
                    owasp="A03:2021",
                    fingerprint=f"{form.action}|{field}",
                    **repro,
                )
            )
            break
    return results

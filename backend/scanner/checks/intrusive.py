from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlparse

from ..http_client import ScanLimitReached
from ..models import Finding
from .base import CheckContext, capture, finding, replace_query_param, truncate

SSRF_PARAMS = {
    "url", "uri", "link", "src", "source", "target", "dest", "destination", "redirect",
    "redirect_uri", "next", "continue", "callback", "callback_url", "webhook", "image",
    "avatar", "feed", "proxy", "host", "domain", "site", "api", "endpoint", "return",
    "returnurl", "u", "path",
}
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
]
SSRF_MARKERS = ("ami-id", "instance-id", "security-credentials", "computemetadata", "metadata-flavor")

FILE_PARAMS = {
    "file", "filename", "filepath", "path", "page", "template", "include", "download",
    "doc", "document", "folder", "dir", "load", "read", "attachment", "img", "image", "src",
}
TRAVERSAL_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//etc/passwd",
]
TRAVERSAL_MARKERS = ("root:x:0:0", "[extensions]", "[fonts]")

DESTRUCTIVE = ("delete", "remove", "logout", "signout", "unsubscribe", "drop", "reset", "destroy")
SUM = "1384824"
SHELL_PAYLOADS = [
    ";expr 913571 + 471253",
    "|expr 913571 + 471253",
    "$(expr 913571 + 471253)",
    "`expr 913571 + 471253`",
]
SSTI_PAYLOADS = [
    "{{913571+471253}}",
    "${913571+471253}",
    "<%= 913571+471253 %>",
    "#{913571+471253}",
]


def _is_destructive(param: str) -> bool:
    lowered = param.lower()
    return any(word in lowered for word in DESTRUCTIVE)


def _is_destructive_url(url: str) -> bool:
    lowered = urlparse(url).path.lower()
    return any(word in lowered for word in DESTRUCTIVE)


async def check_ssrf(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks:
        return []
    results: list[Finding] = []
    tested = 0
    for url, param in ctx.param_candidates(limit=80):
        if tested >= 6 or len(results) >= 3:
            break
        if param.lower() not in SSRF_PARAMS or _is_destructive(param):
            continue
        if _is_destructive_url(url):
            continue
        for payload in SSRF_PAYLOADS:
            if tested >= 6:
                break
            target = replace_query_param(url, param, payload)
            if ctx.excluded(target):
                continue
            try:
                resp = await ctx.session.get(target, max_bytes=400_000, allow_redirects=False)
            except ScanLimitReached:
                return results
            tested += 1
            if resp.error or not resp.text:
                continue
            lowered = resp.text.lower()
            matched = next((marker for marker in SSRF_MARKERS if marker in lowered), None)
            if not matched:
                continue
            index = lowered.find(matched)
            results.append(
                finding(
                    check_id="active.ssrf",
                    title="SSRF（服务端请求伪造）",
                    severity="high",
                    category="active",
                    confidence="medium",
                    description=f"参数 {param} 接受 URL 后，服务端成功请求了云元数据地址并返回特征内容（{matched}）。攻击者可能读取实例凭据、探测内网服务。",
                    remediation="对服务端出站请求做目标白名单，禁止访问链路本地/内网地址；解析 DNS 后校验 IP，并禁用不必要的 URL 协议。",
                    url=target,
                    param=param,
                    evidence=truncate(resp.text[max(0, index - 100): index + 300], 400),
                    cwe="CWE-918",
                    owasp="A10:2021",
                    fingerprint=param,
                    **capture(resp, url=target, headers=ctx.session.default_headers),
                )
            )
            break
    return results


async def check_path_traversal(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks:
        return []
    results: list[Finding] = []
    tested = 0
    for url, param in ctx.param_candidates(limit=80):
        if tested >= 9 or len(results) >= 3:
            break
        if param.lower() not in FILE_PARAMS or _is_destructive(param):
            continue
        if _is_destructive_url(url):
            continue
        for payload in TRAVERSAL_PAYLOADS:
            if tested >= 9:
                break
            target = replace_query_param(url, param, payload)
            if ctx.excluded(target):
                continue
            try:
                resp = await ctx.session.get(target, max_bytes=400_000, allow_redirects=False)
            except ScanLimitReached:
                return results
            tested += 1
            if resp.error or not resp.text:
                continue
            lowered = resp.text.lower()
            matched = next((marker for marker in TRAVERSAL_MARKERS if marker.lower() in lowered), None)
            if not matched:
                continue
            index = lowered.find(matched.lower())
            results.append(
                finding(
                    check_id="active.path_traversal",
                    title="路径穿越 / 本地文件读取",
                    severity="high",
                    category="active",
                    confidence="medium",
                    description=f"参数 {param} 可被路径穿越序列绕过，响应中返回了系统文件特征（{matched}），可能导致任意文件读取与源码/凭据泄露。",
                    remediation="不要用用户输入直接拼接文件路径；使用白名单映射或规范化后校验路径必须位于允许目录内，并拒绝 .. 与绝对路径。",
                    url=target,
                    param=param,
                    evidence=truncate(resp.text[max(0, index - 100): index + 300], 400),
                    cwe="CWE-22",
                    owasp="A01:2021",
                    fingerprint=param,
                    **capture(resp, url=target, headers=ctx.session.default_headers),
                )
            )
            break
    return results


async def _injection(ctx: CheckContext, payloads: list[str], check_id: str, title: str, cwe: str) -> list[Finding]:
    results: list[Finding] = []
    tested = 0
    priority = {"host", "ip", "cmd", "exec", "ping", "template", "tpl", "name", "message", "q", "query", "input", "search", "id"}
    candidates = ctx.param_candidates(limit=60)
    candidates.sort(key=lambda item: (0 if item[1].lower() in priority else 1, item[0]))
    for url, param in candidates:
        if tested >= 24 or len(results) >= 2:
            break
        if _is_destructive(param) or _is_destructive_url(url):
            continue
        for payload in payloads:
            if tested >= 24:
                break
            target = replace_query_param(url, param, payload)
            if ctx.excluded(target):
                continue
            try:
                resp = await ctx.session.get(target, max_bytes=400_000, allow_redirects=False)
            except ScanLimitReached:
                return results
            tested += 1
            if resp.error or SUM not in resp.text:
                continue
            index = resp.text.find(SUM)
            results.append(
                finding(
                    check_id=check_id,
                    title=title,
                    severity="critical",
                    category="active",
                    confidence="medium",
                    description=f"参数 {param} 注入算术表达式后，响应中出现了计算结果 {SUM}，说明输入被服务端命令解释器或模板引擎执行。",
                    remediation="禁止把用户输入传入 shell/模板求值；使用参数化 API、命令白名单与模板沙箱，并对输入做严格类型校验。",
                    url=target,
                    param=param,
                    evidence=truncate(resp.text[max(0, index - 100): index + 200], 300),
                    cwe=cwe,
                    owasp="A03:2021",
                    fingerprint=param,
                    **capture(resp, url=target, headers=ctx.session.default_headers),
                )
            )
            break
    return results


async def check_command_injection(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks:
        return []
    return await _injection(ctx, SHELL_PAYLOADS, "active.command_injection", "命令注入", "CWE-78")


async def check_ssti(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks:
        return []
    return await _injection(ctx, SSTI_PAYLOADS, "active.ssti", "服务端模板注入（SSTI）", "CWE-1336")


async def _raw_probe(host: str, port: int, use_tls: bool, path: str, headers: list[str], body: str, timeout: float) -> tuple[bool, bool, str, int]:
    context = None
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host if use_tls else None),
            timeout=5,
        )
        lines = [f"POST {path} HTTP/1.1", "Connection: close", *headers]
        raw = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("latin-1", errors="replace")
        writer.write(raw)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(200), timeout)
        return bool(data), False, data.decode("latin-1", errors="replace"), int((time.monotonic() - started) * 1000)
    except asyncio.TimeoutError:
        return False, True, "", int((time.monotonic() - started) * 1000)
    except (OSError, ValueError):
        return False, False, "", int((time.monotonic() - started) * 1000)
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass


async def check_request_smuggling(ctx: CheckContext) -> list[Finding]:
    if not ctx.config.intrusive_checks or ctx.config.proxy:
        return []
    root = ctx.root_page
    if root is None:
        return []
    parsed = urlparse(root.url)
    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = parsed.netloc
    baseline = [f"Host: {host_header}", "Transfer-Encoding: chunked"]
    conflict = [f"Host: {host_header}", "Content-Length: 6", "Transfer-Encoding: chunked"]
    ok, timed_out, _, _ = await _raw_probe(host, port, use_tls, path, baseline, "0\r\n\r\n", timeout=5)
    if not ok or timed_out:
        return []
    ok2, timed_out2, _, elapsed = await _raw_probe(host, port, use_tls, path, conflict, "0\r\n\r\n", timeout=6)
    if ok2 or not timed_out2:
        return []
    return [
        finding(
            check_id="active.request_smuggling",
            title="疑似 HTTP 请求走私（CL.TE 解析差异）",
            severity="medium",
            category="active",
            confidence="low",
            description="发送同时包含 Content-Length 与 Transfer-Encoding 的请求时，服务端未在超时内返回，而正常 chunked 请求可以响应。可能存在前后端解析差异，建议人工用 Burp 复核。",
            remediation="在反向代理与后端统一使用同一种 body 解析方式，拒绝同时包含 CL 与 TE 的请求，并升级已知存在走私问题的代理/服务器。",
            url=root.url,
            evidence=f"冲突请求等待 {elapsed}ms 未返回；基线 chunked 请求正常响应。",
            cwe="CWE-444",
            owasp="A05:2021",
            fingerprint=parsed.netloc,
        )
    ]

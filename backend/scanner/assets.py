from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from .models import AssetReport, ScanConfig

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    873: "rsync",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2181: "ZooKeeper",
    2375: "Docker API",
    3000: "Node/Dev",
    3306: "MySQL",
    3389: "RDP",
    4444: "Unknown",
    5000: "Upstream/Dev",
    5432: "PostgreSQL",
    5601: "Kibana",
    6379: "Redis",
    7001: "WebLogic",
    8000: "HTTP-alt",
    8009: "AJP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9000: "App",
    9042: "Cassandra",
    9090: "Prometheus",
    9200: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    15672: "RabbitMQ",
    27017: "MongoDB",
}

LogFn = Callable[[str, str], Awaitable[None]]


def parse_target(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def base_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_part_tlds = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.au", "net.au", "com.hk", "com.tw", "co.jp", "co.kr", "com.sg", "com.br",
    }
    if ".".join(labels[-2:]) in two_part_tlds and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def resolve_dns(host: str, log: LogFn) -> list[str]:
    if is_ip(host):
        return [host]
    ips: list[str] = []
    try:
        import dns.resolver

        loop = asyncio.get_running_loop()
        for rtype in ("A", "AAAA"):
            try:
                answers = await loop.run_in_executor(None, lambda rt=rtype: dns.resolver.resolve(host, rt, lifetime=5))
                ips.extend(str(a) for a in answers)
            except Exception:
                continue
    except Exception as exc:  # dnspython missing or resolver failure
        await log("warn", f"DNS 解析库不可用，回退系统解析：{exc}")
    if not ips:
        try:
            infos = await asyncio.get_running_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            )
            for info in infos:
                addr = info[4][0]
                if addr not in ips:
                    ips.append(addr)
        except Exception as exc:
            await log("warn", f"DNS 解析失败：{exc}")
    return ips


async def scan_ports(host: str, ports: list[int], log: LogFn) -> list[dict[str, Any]]:
    if not ports:
        return []
    if is_ip(host) is False and host == "localhost":
        host = "127.0.0.1"
    sem = asyncio.Semaphore(80)
    results: list[dict[str, Any]] = []

    async def probe(port: int) -> None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                results.append({"port": port, "service": SERVICE_NAMES.get(port, "unknown")})
            except Exception:
                return

    await log("info", f"端口探测：{len(ports)} 个常见端口")
    await asyncio.gather(*(probe(p) for p in ports))
    results.sort(key=lambda item: item["port"])
    return results


def _tls_handshake(host: str, port: int, min_ver: Any = None, max_ver: Any = None, verify: bool = True) -> dict[str, Any]:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_ver is not None:
        ctx.minimum_version = min_ver
    if max_ver is not None:
        ctx.maximum_version = max_ver
    with socket.create_connection((host, port), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            info: dict[str, Any] = {
                "protocol": tls.version(),
                "cipher": (tls.cipher() or ("", "", 0))[0],
            }
            cert = tls.getpeercert()
            if cert:
                info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        info["not_after"] = expires.isoformat()
                        info["days_left"] = (expires - datetime.now(timezone.utc)).days
                    except Exception:
                        info["not_after"] = not_after
                info["san"] = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"][:20]
            return info


def _tls_probe_sync(host: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"port": port, "supported": False}
    try:
        result.update(_tls_handshake(host, port, verify=True))
        result["verified"] = True
        result["supported"] = True
    except ssl.SSLCertVerificationError as exc:
        result["supported"] = True
        result["verified"] = False
        result["verify_error"] = str(exc)
        try:
            result.update(_tls_handshake(host, port, verify=False))
        except Exception:
            pass
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    legacy: list[str] = []
    for name, version in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            _tls_handshake(host, port, min_ver=version, max_ver=version, verify=False)
            legacy.append(name)
        except Exception:
            continue
    result["legacy_protocols"] = legacy
    return result


async def tls_probe(host: str, port: int, log: LogFn) -> dict[str, Any]:
    await log("info", f"TLS 探测：{host}:{port}")
    return await asyncio.get_running_loop().run_in_executor(None, _tls_probe_sync, host, port)


async def enumerate_subdomains(host: str, log: LogFn) -> list[str]:
    if is_ip(host) or host == "localhost":
        return []
    domain = base_domain(host)
    words = [
        "www", "api", "app", "admin", "portal", "test", "dev", "staging", "beta", "demo",
        "mail", "webmail", "smtp", "pop", "imap", "vpn", "gateway", "proxy", "cdn", "static",
        "assets", "img", "media", "files", "download", "upload", "docs", "wiki", "git", "gitlab",
        "jenkins", "ci", "monitor", "grafana", "prometheus", "kibana", "db", "mysql", "redis",
        "mongo", "es", "search", "log", "logs", "status", "health", "internal", "intranet",
    ]
    try:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.5
    except Exception:
        await log("warn", "dnspython 不可用，跳过子域名枚举")
        return []

    sem = asyncio.Semaphore(25)
    found: list[str] = []

    async def probe(word: str) -> None:
        name = f"{word}.{domain}"
        async with sem:
            try:
                await resolver.resolve(name, "A")
                found.append(name)
            except Exception:
                return

    await log("info", f"子域名枚举：{len(words)} 个常见前缀（{domain}）")
    await asyncio.gather(*(probe(w) for w in words))
    return sorted(set(found))


async def run_assets(config: ScanConfig, log: LogFn) -> AssetReport:
    parsed = urlparse(parse_target(config.target))
    host = parsed.hostname or ""
    report = AssetReport()
    report.resolved_ips = await resolve_dns(host, log)

    if config.scan_ports:
        report.open_ports = await scan_ports(host, config.ports, log)
        await log("info", f"开放端口：{len(report.open_ports)} 个")

    default_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tls_port = default_port if parsed.scheme == "https" else 443
    should_tls = parsed.scheme == "https" or any(p["port"] == 443 for p in report.open_ports)
    if should_tls and host and not is_ip(host):
        try:
            report.tls = await tls_probe(host, tls_port, log)
        except Exception as exc:
            await log("warn", f"TLS 探测失败：{exc}")

    if config.subdomain_enum:
        report.subdomains = await enumerate_subdomains(host, log)
        if report.subdomains:
            await log("info", f"发现子域名：{len(report.subdomains)} 个")

    return report


def tls_findings(assets: AssetReport) -> list[dict[str, Any]]:
    """Convert raw TLS asset data into human-readable risk notes."""
    tls = assets.tls or {}
    findings: list[dict[str, Any]] = []
    if not tls or not tls.get("supported"):
        return findings
    if tls.get("verified") is False:
        findings.append(
            {
                "check_id": "tls.certificate",
                "title": "TLS 证书校验失败",
                "severity": "medium",
                "category": "tls",
                "confidence": "high",
                "description": f"目标 TLS 证书无法通过校验：{tls.get('verify_error', '未知原因')}。可能存在证书过期、自签名或域名不匹配。",
                "evidence": tls.get("verify_error", ""),
                "remediation": "为站点配置受信任 CA 签发的有效证书，确保证书域名覆盖实际访问域名，并在到期前及时续期。",
                "cwe": "CWE-295",
                "owasp": "A02:2021",
            }
        )
    days_left = tls.get("days_left")
    if isinstance(days_left, int) and days_left < 0:
        findings.append(
            {
                "check_id": "tls.expired",
                "title": "TLS 证书已过期",
                "severity": "high",
                "category": "tls",
                "confidence": "high",
                "description": f"证书已于 {tls.get('not_after', '未知时间')} 过期，浏览器会向用户显示安全警告。",
                "evidence": f"not_after={tls.get('not_after')}",
                "remediation": "立即续期证书并部署到所有节点，配置自动续期（如 certbot 或云厂商托管证书）。",
                "cwe": "CWE-298",
            }
        )
    for proto in tls.get("legacy_protocols") or []:
        findings.append(
            {
                "check_id": "tls.legacy_protocol",
                "title": f"启用了过时协议 {proto}",
                "severity": "medium",
                "category": "tls",
                "confidence": "high",
                "description": f"服务端仍接受 {proto} 握手，该协议存在已知安全缺陷。",
                "evidence": f"legacy_protocols={tls.get('legacy_protocols')}",
                "remediation": "在 Web 服务器或负载均衡上禁用 TLS 1.0/1.1，仅保留 TLS 1.2 与 TLS 1.3。",
                "cwe": "CWE-326",
            }
        )
    return findings

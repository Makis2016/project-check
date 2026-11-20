from __future__ import annotations

import csv
import html
import io
import json
import time
from typing import Any
from urllib.parse import urlparse

from .models import SEVERITIES, SEVERITY_LABEL

REPORT_VERSION = "1.3.0"

DISCLAIMER = (
    "本报告由 VulnLens 在本机对授权目标执行自动化检查生成。自动化结果可能存在误报或漏报，"
    "请结合人工复核；扫描不包含口令爆破、盲注等高风险行为。"
)


def _risk_level(summary: dict[str, Any] | None) -> str:
    if not summary:
        return "未知"
    if summary.get("critical"):
        return "严重"
    if summary.get("high"):
        return "高"
    if summary.get("medium"):
        return "中"
    if summary.get("low"):
        return "低"
    return "良好"


def _fmt_time(epoch: float | None) -> str:
    if not epoch:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def build_markdown(scan: dict[str, Any]) -> str:
    summary = scan.get("summary") or {}
    config = scan.get("config") or {}
    discovery = scan.get("discovery") or {}
    assets = scan.get("assets") or {}
    findings = scan.get("findings") or []

    lines: list[str] = []
    lines.append(f"# VulnLens 安全体检报告 · {scan['target']}")
    lines.append("")
    scan_type = config.get("scan_type") or "web"
    is_host = scan_type in ("linux", "windows")
    is_windows = scan_type == "windows"
    host_label = "Windows" if is_windows else "Linux"
    host_info = discovery.get("host") or {}
    lines.append(f"- **目标**：{scan['target']}")
    lines.append(f"- **扫描时间**：{_fmt_time(scan.get('created_at'))}")
    lines.append(f"- **耗时**：{(summary.get('duration_ms') or 0) / 1000:.1f} 秒")
    lines.append(f"- **风险等级**：{_risk_level(summary)}")
    if is_host:
        lines.append(f"- **扫描类型**：{host_label} 主机只读巡检（不修改目标系统）")
        lines.append(
            f"- **操作系统**：{host_info.get('pretty') or host_info.get('id') or '未知'}"
            f"　**{'系统版本' if is_windows else '内核'}**：{host_info.get('kernel') or '-'}"
        )
    else:
        lines.append(f"- **扫描预设**：{scan.get('preset', '-')}")
        lines.append(f"- **请求数**：{summary.get('request_count', 0)}　**页面**：{summary.get('page_count', 0)}　**接口**：{summary.get('endpoint_count', 0)}")
        if config.get("active_checks"):
            lines.append("- **主动验证**：已开启（反射 XSS / 报错 SQLi / 开放重定向）")
        else:
            lines.append("- **主动验证**：未开启")
    lines.append("")

    lines.append("## 风险概览")
    lines.append("")
    lines.append("| 严重 | 高危 | 中危 | 低危 | 信息 | 合计 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    lines.append(
        f"| {summary.get('critical', 0)} | {summary.get('high', 0)} | {summary.get('medium', 0)} "
        f"| {summary.get('low', 0)} | {summary.get('info', 0)} | {summary.get('total', 0)} |"
    )
    lines.append("")

    lines.append("## 主机与系统信息" if is_host else "## 资产与暴露面")
    lines.append("")
    if is_host:
        ssh = discovery.get("ssh") or {}
        firewall = discovery.get("firewall") or {}
        modules = discovery.get("security_modules") or {}
        lines.append(f"- **主机名**：{host_info.get('hostname') or '-'}")
        lines.append(f"- **操作系统**：{host_info.get('pretty') or '-'}")
        lines.append(
            f"- **{'系统版本' if is_windows else '内核'} / 架构**：{host_info.get('kernel') or '-'} / {host_info.get('arch') or '-'}"
        )
        lines.append(f"- **SSH 指纹**：`{host_info.get('fingerprint') or '-'}`")
        if is_windows:
            hotfixes = discovery.get("hotfixes") or []
            lines.append(
                f"- **已安装补丁**：采集 {len(hotfixes)} 个　**待更新**：{len(discovery.get('updates') or [])} 个"
            )
            if hotfixes:
                lines.append("- **最近补丁**：" + "、".join(item.get("id", "") for item in hotfixes[:12]))
        else:
            lines.append(f"- **软件包**：{len(discovery.get('packages') or [])} 个　**待更新**：{len(discovery.get('updates') or [])} 个")
        lines.append(f"- **运行服务**：{len(discovery.get('services') or [])} 个　**监听端口**：{len(discovery.get('listeners') or [])} 个")
        lines.append(f"- **防火墙**：{'已启用' if firewall.get('active') else '未检测到'}")
        if is_windows:
            defender = discovery.get("defender") or {}
            if defender.get("present"):
                defender_text = (
                    f"防病毒 {'已启用' if defender.get('antivirus') else '已禁用'}，"
                    f"实时保护 {'已启用' if defender.get('realtime') else '已关闭'}"
                )
                if isinstance(defender.get("signature_age_days"), int):
                    defender_text += f"，病毒库距今 {defender['signature_age_days']} 天"
            else:
                defender_text = "未采集到状态"
            lines.append(f"- **Defender**：{defender_text}")
            lines.append(f"- **SMBv1**：{'已启用' if discovery.get('smb1_enabled') else '未检测到启用'}")
            lines.append(f"- **自动更新**：{'已启用' if discovery.get('autoupdate') else '已禁用'}")
        else:
            lines.append(f"- **SELinux / AppArmor**：{modules.get('selinux', '-')} / {modules.get('apparmor', '-')}")
            lines.append(f"- **SSH 认证**：密码认证 {ssh.get('passwordauthentication', '-')}，root 登录 {ssh.get('permitrootlogin', '-')}")
        listeners = discovery.get("listeners") or []
        if listeners:
            exposed = [item for item in listeners if item.get("exposed")]
            if exposed:
                lines.append(
                    "- **对外监听**：" + "、".join(f"{item['port']}/{item['proto']}" for item in exposed[:30])
                )
        updates = discovery.get("updates") or []
        if updates:
            lines.append(
                f"- **{'待安装 Windows 更新' if is_windows else '待更新软件包'}**："
                + "、".join(
                    f"{item['name']}" + ("（安全）" if item.get("security") else "") for item in updates[:20]
                )
            )
    else:
        ips = assets.get("resolved_ips") or []
        lines.append(f"- **解析地址**：{', '.join(ips) if ips else '未获取'}")
        ports = assets.get("open_ports") or []
        if ports:
            lines.append("- **开放端口**：" + "、".join(f"{p['port']}({p.get('service', '')})" for p in ports[:30]))
        else:
            lines.append("- **开放端口**：未探测或未发现")
        tls = assets.get("tls") or {}
        if tls:
            if tls.get("supported"):
                lines.append(
                    f"- **TLS**：{tls.get('protocol', '-')}，证书校验{'通过' if tls.get('verified') else '失败'}"
                    + (f"，剩余 {tls['days_left']} 天" if isinstance(tls.get("days_left"), int) else "")
                )
            else:
                lines.append("- **TLS**：未启用或探测失败")
        subs = assets.get("subdomains") or []
        if subs:
            lines.append(f"- **子域名**：{', '.join(subs[:30])}")
    lines.append("")

    lines.append("## 漏洞明细")
    lines.append("")
    if not findings:
        lines.append("未发现需要关注的问题。建议保持依赖更新与定期复扫。")
        lines.append("")
    for severity in SEVERITIES:
        group = [f for f in findings if f.get("severity") == severity]
        if not group:
            continue
        lines.append(f"### {SEVERITY_LABEL[severity]}（{len(group)}）")
        lines.append("")
        for index, item in enumerate(group, start=1):
            lines.append(f"#### {index}. {item.get('title', '')}")
            lines.append("")
            lines.append(f"- **等级**：{SEVERITY_LABEL.get(item.get('severity'), item.get('severity'))}　**置信度**：{item.get('confidence', '-')}")
            if item.get("url"):
                lines.append(f"- **位置**：`{item.get('method', 'GET')} {item['url']}`")
            if item.get("param"):
                lines.append(f"- **参数**：`{item['param']}`")
            if item.get("cwe") or item.get("owasp"):
                lines.append(f"- **分类**：{item.get('cwe', '')} {item.get('owasp', '')}".strip())
            lines.append("")
            if item.get("description"):
                lines.append(f"**说明**：{item['description']}")
                lines.append("")
            if item.get("evidence"):
                lines.append("**证据**：")
                lines.append("")
                lines.append("```text")
                lines.append(str(item["evidence"]))
                lines.append("```")
                lines.append("")
            if item.get("remediation"):
                lines.append(f"**修复建议**：{item['remediation']}")
                lines.append("")
            refs = item.get("references") or []
            if refs:
                lines.append("**参考**：" + "、".join(refs))
                lines.append("")
    lines.append("")

    endpoints = discovery.get("endpoints") or []
    if endpoints:
        lines.append("## 发现接口（前 100 条）")
        lines.append("")
        lines.append("| 方法 | 地址 | 来源 | 状态 |")
        lines.append("| --- | --- | --- | --- |")
        for endpoint in endpoints[:100]:
            lines.append(
                f"| {endpoint.get('method', 'GET')} | `{endpoint.get('url', '')}` | {endpoint.get('source', '')} | {endpoint.get('status', '-')} |"
            )
        lines.append("")

    tech = discovery.get("tech") or []
    if tech:
        lines.append("## 组件指纹")
        lines.append("")
        for item in tech:
            lines.append(f"- {item.get('name')} {item.get('version', '')}".strip() + (f"（{item.get('evidence')}）" if item.get("evidence") else ""))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(DISCLAIMER)
    lines.append("")
    return "\n".join(lines)


def _risk_tone(summary: dict[str, Any] | None) -> str:
    if not summary:
        return "info"
    if summary.get("critical"):
        return "critical"
    if summary.get("high"):
        return "high"
    if summary.get("medium"):
        return "medium"
    if summary.get("low"):
        return "low"
    return "ok"


def _mask_secret(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:6] + "***" + value[-3:]


def _public_config(config: dict[str, Any]) -> dict[str, Any]:
    data = dict(config or {})
    if data.get("cookie"):
        data["cookie"] = _mask_secret(str(data["cookie"]))
    if data.get("secondary_cookie"):
        data["secondary_cookie"] = _mask_secret(str(data["secondary_cookie"]))
    proxy = str(data.get("proxy") or "")
    if "@" in proxy:
        parsed = urlparse(proxy)
        if parsed.hostname:
            data["proxy"] = f"{parsed.scheme}://***@{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")
    headers = data.get("headers")
    if isinstance(headers, dict):
        data["headers"] = {
            key: (_mask_secret(str(value)) if key.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token") else value)
            for key, value in headers.items()
        }
    return data


def _html_finding(item: dict[str, Any], index: int) -> str:
    severity = str(item.get("severity") or "info")
    parts = [
        f'<article class="finding sev-{html.escape(severity)}">',
        f'<div class="finding-head"><span class="num">{index}</span><h3>{html.escape(str(item.get("title") or ""))}</h3>',
        f'<span class="badge sev-{html.escape(severity)}">{html.escape(SEVERITY_LABEL.get(severity, severity))}</span></div>',
        '<div class="meta">',
    ]
    if item.get("url"):
        parts.append(f'<span class="chip mono">{html.escape(str(item.get("method") or "GET"))} {html.escape(str(item["url"]))}</span>')
    if item.get("param"):
        parts.append(f'<span class="chip">参数 {html.escape(str(item["param"]))}</span>')
    if item.get("cwe"):
        parts.append(f'<span class="chip">{html.escape(str(item["cwe"]))}</span>')
    if item.get("owasp"):
        parts.append(f'<span class="chip">{html.escape(str(item["owasp"]))}</span>')
    if item.get("confidence"):
        parts.append(f'<span class="chip">置信度 {html.escape(str(item["confidence"]))}</span>')
    parts.append("</div>")
    if item.get("description"):
        parts.append(f'<p class="desc">{html.escape(str(item["description"]))}</p>')
    if item.get("evidence"):
        parts.append(f'<div class="block"><div class="block-label">证据</div><pre>{html.escape(str(item["evidence"]))}</pre></div>')
    if item.get("remediation"):
        parts.append(f'<div class="remediation"><div class="block-label">修复建议</div><p>{html.escape(str(item["remediation"]))}</p></div>')
    if item.get("curl") or item.get("request") or item.get("response"):
        parts.append('<details class="repro"><summary>复现请求与响应</summary>')
        if item.get("curl"):
            parts.append(f'<div class="block-label">cURL</div><pre>{html.escape(str(item["curl"]))}</pre>')
        if item.get("request"):
            parts.append(f'<div class="block-label">请求</div><pre>{html.escape(str(item["request"]))}</pre>')
        if item.get("response"):
            parts.append(f'<div class="block-label">响应</div><pre>{html.escape(str(item["response"]))}</pre>')
        parts.append("</details>")
    refs = item.get("references") or []
    if refs:
        parts.append('<div class="refs">参考：' + "、".join(html.escape(str(ref)) for ref in refs) + "</div>")
    parts.append("</article>")
    return "".join(parts)


def build_html(scan: dict[str, Any]) -> str:
    summary = scan.get("summary") or {}
    config = scan.get("config") or {}
    discovery = scan.get("discovery") or {}
    assets = scan.get("assets") or {}
    findings = scan.get("findings") or []
    risk = _risk_level(summary)
    tone = _risk_tone(summary)
    scan_type = config.get("scan_type") or "web"
    is_host = scan_type in ("linux", "windows")
    is_windows = scan_type == "windows"
    host_label = "Windows" if is_windows else "Linux"
    host_info = discovery.get("host") or {}

    cards = "".join(
        f'<div class="card sev-{severity}"><b>{summary.get(severity, 0)}</b><span>{SEVERITY_LABEL[severity]}</span></div>'
        for severity in SEVERITIES
    )
    cards += f'<div class="card total"><b>{summary.get("total", 0)}</b><span>合计</span></div>'

    if is_host:
        ssh = discovery.get("ssh") or {}
        firewall = discovery.get("firewall") or {}
        modules = discovery.get("security_modules") or {}
        exposed = [item for item in (discovery.get("listeners") or []) if item.get("exposed")]
        hotfixes = discovery.get("hotfixes") or []
        package_count = len(hotfixes) if is_windows else len(discovery.get("packages") or [])
        assets_rows = [
            ("主机名", host_info.get("hostname") or "—"),
            ("操作系统", host_info.get("pretty") or "—"),
            (
                "系统版本 / 架构" if is_windows else "内核 / 架构",
                f"{host_info.get('kernel') or '—'} / {host_info.get('arch') or '—'}",
            ),
            ("SSH 指纹", host_info.get("fingerprint") or "—"),
            (
                "已安装补丁" if is_windows else "软件包",
                f"{'采集 ' if is_windows else ''}{package_count} 个，待更新 {len(discovery.get('updates') or [])} 个",
            ),
            ("运行服务", f"{len(discovery.get('services') or [])} 个，监听端口 {len(discovery.get('listeners') or [])} 个"),
            ("对外监听", "、".join(f"{item['port']}/{item['proto']}" for item in exposed[:30]) or "未发现"),
            ("防火墙", "已启用" if firewall.get("active") else "未检测到"),
        ]
        if is_windows:
            defender = discovery.get("defender") or {}
            if defender.get("present"):
                defender_text = (
                    f"防病毒 {'已启用' if defender.get('antivirus') else '已禁用'}，"
                    f"实时保护 {'已启用' if defender.get('realtime') else '已关闭'}"
                )
                if isinstance(defender.get("signature_age_days"), int):
                    defender_text += f"，病毒库距今 {defender['signature_age_days']} 天"
            else:
                defender_text = "未采集到状态"
            assets_rows.extend(
                [
                    ("最近补丁", "、".join(item.get("id", "") for item in hotfixes[:12]) or "未采集到"),
                    ("Defender", defender_text),
                    ("SMBv1", "已启用" if discovery.get("smb1_enabled") else "未检测到启用"),
                    ("自动更新", "已启用" if discovery.get("autoupdate") else "已禁用"),
                ]
            )
        else:
            assets_rows.extend(
                [
                    ("SELinux / AppArmor", f"{modules.get('selinux', '—')} / {modules.get('apparmor', '—')}"),
                    ("SSH 认证", f"密码认证 {ssh.get('passwordauthentication', '—')}，root 登录 {ssh.get('permitrootlogin', '—')}"),
                ]
            )
    else:
        assets_rows = [
            ("解析地址", "、".join(assets.get("resolved_ips") or []) or "未获取"),
            ("开放端口", "、".join(f"{p.get('port')}({p.get('service', '')})" for p in (assets.get("open_ports") or [])[:30]) or "未探测或未发现"),
            ("子域名", "、".join((assets.get("subdomains") or [])[:30]) or "未启用或未发现"),
        ]
        tls = assets.get("tls") or {}
        if tls.get("supported"):
            assets_rows.append(
                (
                    "TLS",
                    f"{tls.get('protocol', '-')}，"
                    + ("证书校验通过" if tls.get("verified") else "证书校验失败")
                    + (f"，剩余 {tls['days_left']} 天" if isinstance(tls.get("days_left"), int) else ""),
                )
            )
        tech = discovery.get("tech") or []
        if tech:
            assets_rows.append(("组件指纹", "、".join(f"{t.get('name')} {t.get('version', '')}".strip() for t in tech)))

    findings_html: list[str] = []
    for severity in SEVERITIES:
        group = [item for item in findings if item.get("severity") == severity]
        if not group:
            continue
        findings_html.append(f'<h2 class="sev-title sev-{severity}">{SEVERITY_LABEL[severity]}（{len(group)}）</h2>')
        for index, item in enumerate(group, start=1):
            findings_html.append(_html_finding(item, index))
    if not findings_html:
        findings_html.append('<div class="empty">未发现需要关注的问题。建议保持依赖更新与定期复扫。</div>')

    endpoints = discovery.get("endpoints") or []
    endpoint_rows = "".join(
        f"<tr><td class=\"mono\">{html.escape(str(item.get('method') or 'GET'))}</td>"
        f"<td class=\"mono url\">{html.escape(str(item.get('url') or ''))}</td>"
        f"<td>{html.escape(str(item.get('source') or ''))}</td>"
        f"<td class=\"mono\">{html.escape(str(item.get('status') if item.get('status') is not None else '—'))}</td></tr>"
        for item in endpoints[:100]
    )

    title = f"VulnLens 安全体检报告 · {scan.get('target', '')}"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #eef2f6; color: #16202b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; font-size: 13px; line-height: 1.65; }}
  .page {{ width: min(1040px, 100%); margin: 24px auto; background: #fff; border-radius: 14px; box-shadow: 0 18px 50px rgba(15, 35, 55, 0.12); overflow: hidden; }}
  .cover {{ padding: 34px 40px 26px; background: linear-gradient(135deg, #07222b, #0d3b45 58%, #0b5a5a); color: #ecfeff; }}
  .brand {{ font-size: 11px; letter-spacing: .22em; text-transform: uppercase; color: #67e8f9; }}
  h1 {{ margin: 10px 0 6px; font-size: 26px; line-height: 1.25; word-break: break-all; }}
  .cover-meta {{ display: flex; flex-wrap: wrap; gap: 8px 18px; font-size: 11.5px; color: #a7cfd6; }}
  .risk {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #062c2e; background: #5eead4; }}
  .risk.high, .risk.critical {{ background: #fecdd3; color: #7f1d1d; }}
  .risk.medium {{ background: #fef3c7; color: #78350f; }}
  .risk.low {{ background: #dbeafe; color: #1e3a8a; }}
  .risk.ok {{ background: #dcfce7; color: #14532d; }}
  .body {{ padding: 26px 40px 34px; }}
  h2 {{ font-size: 16px; margin: 28px 0 12px; padding-bottom: 7px; border-bottom: 1px solid #e2e8f0; }}
  h2:first-child {{ margin-top: 0; }}
  .cards {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 9px; }}
  .card {{ border: 1px solid #e2e8f0; border-top: 3px solid #94a3b8; border-radius: 9px; padding: 12px; text-align: center; background: #f8fafc; }}
  .card b {{ display: block; font-size: 24px; font-family: ui-monospace, Consolas, monospace; line-height: 1.1; }}
  .card span {{ font-size: 10.5px; color: #64748b; }}
  .card.sev-critical {{ border-top-color: #e11d48; }} .card.sev-critical b {{ color: #be123c; }}
  .card.sev-high {{ border-top-color: #ea580c; }} .card.sev-high b {{ color: #c2410c; }}
  .card.sev-medium {{ border-top-color: #ca8a04; }} .card.sev-medium b {{ color: #a16207; }}
  .card.sev-low {{ border-top-color: #0284c7; }} .card.sev-low b {{ color: #0369a1; }}
  .card.sev-info {{ border-top-color: #64748b; }} .card.sev-info b {{ color: #475569; }}
  .card.total {{ border-top-color: #0f766e; }} .card.total b {{ color: #0f766e; }}
  .kv {{ display: grid; grid-template-columns: 110px 1fr; gap: 6px 14px; font-size: 12px; }}
  .kv dt {{ color: #64748b; }} .kv dd {{ margin: 0; word-break: break-all; }}
  .finding {{ border: 1px solid #e2e8f0; border-left: 4px solid #94a3b8; border-radius: 10px; padding: 14px 16px; margin-bottom: 10px; page-break-inside: avoid; }}
  .finding.sev-critical {{ border-left-color: #e11d48; }} .finding.sev-high {{ border-left-color: #ea580c; }}
  .finding.sev-medium {{ border-left-color: #ca8a04; }} .finding.sev-low {{ border-left-color: #0284c7; }}
  .finding-head {{ display: flex; align-items: center; gap: 9px; }}
  .finding-head h3 {{ margin: 0; font-size: 14px; flex: 1; }}
  .num {{ font-family: ui-monospace, Consolas, monospace; color: #94a3b8; font-size: 11px; }}
  .badge {{ padding: 1px 8px; border-radius: 999px; font-size: 10px; font-weight: 700; background: #f1f5f9; color: #334155; }}
  .badge.sev-critical {{ background: #ffe4e6; color: #be123c; }} .badge.sev-high {{ background: #ffedd5; color: #c2410c; }}
  .badge.sev-medium {{ background: #fef9c3; color: #a16207; }} .badge.sev-low {{ background: #e0f2fe; color: #0369a1; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 9px 0 8px; }}
  .chip {{ padding: 1px 7px; border: 1px solid #e2e8f0; border-radius: 5px; font-size: 10px; color: #475569; background: #f8fafc; }}
  .mono {{ font-family: ui-monospace, "JetBrains Mono", Consolas, monospace; }}
  .desc {{ margin: 6px 0 10px; color: #334155; }}
  .block {{ margin-top: 9px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; background: #f8fafc; }}
  .block-label {{ padding: 5px 10px; font-size: 9.5px; letter-spacing: .1em; color: #64748b; background: #f1f5f9; border-bottom: 1px solid #e2e8f0; }}
  .block pre {{ margin: 0; padding: 9px 11px; font-size: 10.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-all; color: #334155; max-height: 260px; overflow: auto; }}
  .remediation {{ margin-top: 9px; border: 1px solid #ccfbf1; border-radius: 8px; background: #f0fdfa; padding: 8px 11px 10px; }}
  .remediation .block-label {{ padding: 0 0 3px; background: none; border: 0; color: #0f766e; font-weight: 700; }}
  .remediation p {{ margin: 0; color: #115e59; }}
  .repro {{ margin-top: 9px; }}
  .repro summary {{ cursor: pointer; color: #0369a1; font-size: 11.5px; }}
  .repro pre {{ margin: 7px 0 0; padding: 9px 11px; border-radius: 8px; background: #0f172a; color: #cbd5e1; font-size: 10.5px; white-space: pre-wrap; word-break: break-all; max-height: 260px; overflow: auto; }}
  .refs {{ margin-top: 8px; font-size: 11px; color: #0369a1; word-break: break-all; }}
  .sev-title {{ font-size: 14px; margin: 22px 0 10px; color: #334155; }}
  .sev-title.sev-critical {{ color: #be123c; }} .sev-title.sev-high {{ color: #c2410c; }}
  .sev-title.sev-medium {{ color: #a16207; }} .sev-title.sev-low {{ color: #0369a1; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10.5px; }}
  th, td {{ border-bottom: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #f8fafc; color: #64748b; font-weight: 600; }}
  td.url {{ word-break: break-all; }}
  .empty {{ padding: 22px; text-align: center; color: #64748b; border: 1px dashed #cbd5e1; border-radius: 10px; }}
  footer {{ margin-top: 26px; padding-top: 14px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 10.5px; }}
  @media print {{
    body {{ background: #fff; }}
    .page {{ width: 100%; margin: 0; border-radius: 0; box-shadow: none; }}
    .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .repro[open] pre {{ max-height: none; }}
    @page {{ margin: 12mm; }}
  }}
</style>
</head>
<body>
<main class="page">
  <header class="cover">
    <div class="brand">VulnLens · {host_label + " Host Security Report" if is_host else "Web Security Report"}</div>
    <h1>{html.escape(str(scan.get("target") or ""))}</h1>
    <div class="cover-meta">
      <span class="risk {tone}">风险等级：{html.escape(risk)}</span>
      <span>扫描时间：{html.escape(_fmt_time(scan.get("created_at")))}</span>
      <span>耗时：{(summary.get("duration_ms") or 0) / 1000:.1f}s</span>
      <span>{"巡检：" + host_label + " 主机" if is_host else "预设：" + html.escape(str(scan.get("preset") or "-"))}</span>
      {"" if is_host else f'<span>请求：{summary.get("request_count", 0)}</span><span>页面：{summary.get("page_count", 0)}</span><span>接口：{summary.get("endpoint_count", 0)}</span>'}
    </div>
  </header>
  <div class="body">
    <h2>风险概览</h2>
    <div class="cards">{cards}</div>
    <h2>{"主机与系统信息" if is_host else "资产与暴露面"}</h2>
    <dl class="kv">{"".join(f"<dt>{html.escape(str(k))}</dt><dd>{html.escape(str(v))}</dd>" for k, v in assets_rows)}</dl>
    <h2>漏洞明细</h2>
    {''.join(findings_html)}
    {'' if is_host else '<h2>发现接口（前 100 条）</h2>'}
    {'' if is_host else ('<table><thead><tr><th>方法</th><th>地址</th><th>来源</th><th>状态</th></tr></thead><tbody>' + endpoint_rows + '</tbody></table>' if endpoint_rows else '<div class="empty">未发现接口</div>')}
    <footer>
      {html.escape(DISCLAIMER)}<br>
      生成时间：{html.escape(_fmt_time(time.time()))} · VulnLens v{REPORT_VERSION}
    </footer>
  </div>
</main>
</body>
</html>
"""


def build_json(scan: dict[str, Any]) -> str:
    discovery = scan.get("discovery") or {}
    payload = {
        "tool": "VulnLens",
        "version": REPORT_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "scan": {
            "id": scan.get("id"),
            "target": scan.get("target"),
            "preset": scan.get("preset"),
            "status": scan.get("status"),
            "created_at": scan.get("created_at"),
            "finished_at": scan.get("finished_at"),
            "error": scan.get("error"),
            "config": _public_config(scan.get("config") or {}),
            "summary": scan.get("summary"),
            "assets": scan.get("assets"),
            "discovery": {
                "endpoints": discovery.get("endpoints") or [],
                "tech": discovery.get("tech") or [],
                "docs": discovery.get("docs") or [],
                "forms": discovery.get("forms") or [],
                "cookies": discovery.get("cookies") or [],
                "robots": discovery.get("robots") or [],
                "sitemaps": discovery.get("sitemaps") or [],
                **(
                    {
                        "host": discovery.get("host") or {},
                        "packages": discovery.get("packages") or [],
                        "hotfixes": discovery.get("hotfixes") or [],
                        "updates": discovery.get("updates") or [],
                        "services": discovery.get("services") or [],
                        "listeners": discovery.get("listeners") or [],
                        "ssh": discovery.get("ssh") or {},
                        "firewall": discovery.get("firewall") or {},
                        "security_modules": discovery.get("security_modules") or {},
                        "defender": discovery.get("defender") or {},
                        "smb1_enabled": discovery.get("smb1_enabled") or False,
                        "reboot_required": discovery.get("reboot_required") or False,
                        "autoupdate": discovery.get("autoupdate") or False,
                    }
                    if (scan.get("config") or {}).get("scan_type") in ("linux", "windows")
                    else {}
                ),
            },
            "findings": scan.get("findings") or [],
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


CSV_HEADERS = ["等级", "置信度", "标题", "检查项", "分类", "方法", "URL", "参数", "CWE", "OWASP", "说明", "证据", "修复建议", "参考链接", "cURL"]


def build_csv(scan: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADERS)
    for item in scan.get("findings") or []:
        severity = str(item.get("severity") or "info")
        writer.writerow(
            [
                SEVERITY_LABEL.get(severity, severity),
                item.get("confidence", ""),
                item.get("title", ""),
                item.get("check_id", ""),
                item.get("category", ""),
                item.get("method", ""),
                item.get("url", ""),
                item.get("param", ""),
                item.get("cwe", ""),
                item.get("owasp", ""),
                item.get("description", ""),
                item.get("evidence", ""),
                item.get("remediation", ""),
                " ".join(item.get("references") or []),
                item.get("curl", ""),
            ]
        )
    return "\ufeff" + buffer.getvalue()

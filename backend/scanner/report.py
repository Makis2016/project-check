from __future__ import annotations

import time
from typing import Any

from .models import SEVERITIES, SEVERITY_LABEL

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
    lines.append(f"- **目标**：{scan['target']}")
    lines.append(f"- **扫描时间**：{_fmt_time(scan.get('created_at'))}")
    lines.append(f"- **耗时**：{(summary.get('duration_ms') or 0) / 1000:.1f} 秒")
    lines.append(f"- **扫描预设**：{scan.get('preset', '-')}")
    lines.append(f"- **风险等级**：{_risk_level(summary)}")
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

    lines.append("## 资产与暴露面")
    lines.append("")
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

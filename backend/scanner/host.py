from __future__ import annotations

import asyncio
import datetime as dt
import re
import time
import traceback
from typing import Any, Awaitable, Callable

from .. import db
from .models import Finding, ScanConfig, SEVERITIES, Summary

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]

EOL_DATES: dict[tuple[str, str], str] = {
    ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-04-30",
    ("ubuntu", "24.04"): "2029-04-30",
    ("debian", "10"): "2024-06-30",
    ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30",
    ("centos", "7"): "2024-06-30",
    ("centos", "8"): "2021-12-31",
    ("rocky", "8"): "2029-05-31",
    ("rocky", "9"): "2032-05-31",
    ("almalinux", "8"): "2029-05-31",
    ("almalinux", "9"): "2032-05-31",
}

COMMANDS: list[tuple[str, str, int]] = [
    ("os", "cat /etc/os-release 2>/dev/null; echo '---'; uname -srm; echo '---'; hostname 2>/dev/null", 15),
    (
        "packages",
        "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null; "
        "elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null; fi",
        30,
    ),
    (
        "updates",
        "if command -v apt >/dev/null 2>&1; then LC_ALL=C apt list --upgradable 2>/dev/null | head -n 800; "
        "elif command -v dnf >/dev/null 2>&1; then dnf -q updateinfo list security 2>/dev/null | head -n 800; "
        "elif command -v yum >/dev/null 2>&1; then yum -q updateinfo list security 2>/dev/null | head -n 800; fi",
        40,
    ),
    ("services", "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -n 300", 20),
    ("listeners", "ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null", 20),
    ("sshd", "sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null", 20),
    (
        "firewall",
        "systemctl is-active firewalld 2>/dev/null; ufw status 2>/dev/null; "
        "nft list ruleset 2>/dev/null | head -n 60; iptables -S 2>/dev/null | head -n 60",
        20,
    ),
    ("selinux", "getenforce 2>/dev/null; aa-status --enabled >/dev/null 2>&1; echo apparmor=$?", 15),
    ("accounts", "getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null", 15),
    ("reboot", "test -f /var/run/reboot-required && echo yes || echo no", 10),
    (
        "autoupdate",
        "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; rpm -q dnf-automatic 2>/dev/null",
        10,
    ),
    ("docker", "ls -l /var/run/docker.sock 2>/dev/null", 10),
]


def _split_sections(text: str) -> list[str]:
    return text.split("---")


def parse_os(text: str) -> dict[str, str]:
    lines = [line.strip() for line in text.splitlines() if "=" in line and not line.startswith("#")]
    data: dict[str, str] = {}
    for line in lines:
        key, _, value = line.partition("=")
        data[key.strip().upper()] = value.strip().strip('"').strip("'")
    kernel_part = ""
    sections = _split_sections(text)
    if len(sections) >= 2:
        kernel_part = sections[1].strip().splitlines()[0] if sections[1].strip() else ""
    hostname = sections[2].strip().splitlines()[0] if len(sections) >= 3 and sections[2].strip() else ""
    kernel = ""
    arch = ""
    if kernel_part:
        parts = kernel_part.split()
        if len(parts) >= 2:
            kernel = parts[1]
            arch = parts[2] if len(parts) > 2 else ""
    return {
        "id": data.get("ID", "").lower(),
        "version_id": data.get("VERSION_ID", ""),
        "name": data.get("NAME", ""),
        "pretty": data.get("PRETTY_NAME", ""),
        "kernel": kernel,
        "arch": arch,
        "hostname": hostname,
    }


def parse_packages(text: str, limit: int = 2000) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        name, _, version = line.partition("\t")
        name = name.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        packages.append({"name": name, "version": version.strip()})
        if len(packages) >= limit:
            break
    return packages


def parse_updates(text: str, os_id: str) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Listing..."):
            continue
        if os_id in ("ubuntu", "debian", "linuxmint", "pop"):
            match = re.match(r"^([^/\s]+)/([^\s]+)\s+(\S+)\s+(\S+)(?:\s+\[upgradable from: ([^\]]+)\])?", line)
            if not match:
                continue
            name, repo, new_version, arch, old_version = match.groups()
            security = "security" in repo.lower()
            item = {
                "name": name,
                "repo": repo,
                "version": new_version,
                "old_version": old_version or "",
                "arch": arch,
                "security": security,
            }
        else:
            if line.lower().startswith(("last metadata", "available", "obsoleting", "security:")):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            if "/" in name:
                name, _, _ = name.partition("/")
            security = "security" in line.lower() or "sec." in line.lower() or "rhsa" in line.lower()
            item = {"name": name, "repo": "", "version": parts[-1], "old_version": "", "arch": "", "security": security}
        key = f"{item['name']}|{item['version']}"
        if key in seen:
            continue
        seen.add(key)
        updates.append(item)
    return updates


def parse_services(text: str) -> list[str]:
    services: list[str] = []
    for line in text.splitlines():
        line = line.strip().lstrip("●* ").strip()
        if not line:
            continue
        name = line.split()[0]
        if name.endswith(".service") and name not in services:
            services.append(name)
    return services[:200]


def parse_listeners(text: str) -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for line in text.splitlines():
        if not line.strip() or line.startswith(("Netid", "Active")):
            continue
        proto = line.split()[0]
        if proto not in ("tcp", "udp", "tcp6", "udp6", "LISTEN", "UNCONN"):
            continue
        match = re.search(r"(\S+):(\d+)\s+\S+:\*", line)
        if not match:
            continue
        address, port_text = match.group(1), match.group(2)
        try:
            port = int(port_text)
        except ValueError:
            continue
        exposed = address in ("0.0.0.0", "[::]", "::", "*")
        key = (proto, port, address)
        if key in seen:
            continue
        seen.add(key)
        listeners.append({"proto": proto, "address": address, "port": port, "exposed": exposed})
    return sorted(listeners, key=lambda item: (not item["exposed"], item["port"]))


def parse_sshd(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key in ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "port", "maxauthtries"):
            values[key] = parts[1].strip().lower()
    return values


def parse_accounts(text: str) -> list[str]:
    accounts: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 4:
            continue
        if parts[2] == "0" and parts[0] != "root":
            accounts.append(parts[0])
    return accounts


def inspect_firewall(text: str) -> dict[str, Any]:
    lowered = text.lower()
    ufw_active = "status: active" in lowered
    firewalld_active = any(line.strip() == "active" for line in text.splitlines())
    nft_rules = len([line for line in text.splitlines() if line.strip() and not line.startswith("table")])
    iptables_rules = len([line for line in text.splitlines() if line.startswith("-A ")])
    return {
        "ufw": ufw_active,
        "firewalld": firewalld_active,
        "nft": nft_rules > 2,
        "iptables": iptables_rules > 0,
        "active": ufw_active or firewalld_active or nft_rules > 2 or iptables_rules > 0,
    }


def inspect_security_modules(text: str) -> dict[str, str]:
    lowered = text.lower()
    selinux = "enforcing" if "enforcing" in lowered else ("permissive" if "permissive" in lowered else "disabled")
    apparmor = "enabled" if "apparmor=0" in lowered else "disabled"
    return {"selinux": selinux, "apparmor": apparmor}


def parse_autoupdate(text: str) -> bool:
    lowered = text.lower()
    return 'unattended-upgrade "1"' in lowered or "dnf-automatic" in lowered


def parse_docker_socket(text: str) -> dict[str, Any]:
    parts = text.strip().split()
    if len(parts) < 4 or not parts[0].startswith("s"):
        return {"present": False}
    mode = parts[0]
    return {
        "present": True,
        "mode": mode,
        "owner": parts[2],
        "group": parts[3],
        "world_writable": len(mode) >= 10 and "w" in mode[-3:],
    }


def _eol_status(os_id: str, version: str) -> tuple[str, int] | None:
    version = version.strip()
    if not version:
        return None
    if os_id in ("debian", "ubuntu"):
        key_version = ".".join(version.split(".")[:2]) if os_id == "ubuntu" else version.split(".")[0]
    else:
        key_version = version.split(".")[0]
    eol_text = EOL_DATES.get((os_id, key_version))
    if not eol_text:
        return None
    eol_date = dt.date.fromisoformat(eol_text)
    today = dt.date.today()
    days = (eol_date - today).days
    if days < 0:
        return eol_text, days
    if days <= 180:
        return eol_text, days
    return None


def _host_finding(
    config: ScanConfig,
    check_id: str,
    title: str,
    severity: str,
    description: str,
    remediation: str,
    evidence: str,
    confidence: str = "high",
    cwe: str = "",
) -> Finding:
    url = f"ssh://{config.ssh_user}@{config.target}:{config.ssh_port}"
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        category="host",
        confidence=confidence,
        url=url,
        method="SSH",
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        fingerprint=check_id,
        request=f"SSH {config.ssh_user}@{config.target}:{config.ssh_port}（只读命令）",
        response=evidence,
    )


def build_findings(config: ScanConfig, info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    host = info["host"]
    os_id = host.get("id", "")
    version = host.get("version_id", "")
    eol = _eol_status(os_id, version)
    if eol:
        eol_date, days = eol
        if days < 0:
            findings.append(
                _host_finding(
                    config,
                    "host.os_eol",
                    "操作系统已停止维护",
                    "high",
                    f"{host.get('pretty') or os_id} 的官方支持已于 {eol_date} 结束，继续使用将无法获得安全补丁。",
                    "制定升级计划，迁移到仍受支持的发行版版本；升级前先做兼容性评估与备份。",
                    f"OS: {host.get('pretty')}\nEOL: {eol_date}",
                    cwe="CWE-1104",
                )
            )
        else:
            findings.append(
                _host_finding(
                    config,
                    "host.os_eol_soon",
                    "操作系统即将停止维护",
                    "medium",
                    f"{host.get('pretty') or os_id} 将在 {eol_date} 结束支持（剩余 {days} 天）。",
                    "在 EOL 前完成升级或迁移，并为关键组件准备长期支持方案。",
                    f"OS: {host.get('pretty')}\nEOL: {eol_date}",
                    cwe="CWE-1104",
                )
            )

    updates = info.get("updates", [])
    security_updates = [item for item in updates if item.get("security")]
    if security_updates:
        names = [item["name"] for item in security_updates[:15]]
        severity = "high" if len(security_updates) >= 10 else "medium"
        findings.append(
            _host_finding(
                config,
                "host.security_updates",
                "存在未安装的安全更新",
                severity,
                f"检测到 {len(security_updates)} 个安全更新待安装，系统可能暴露于已公开漏洞。",
                "在维护窗口内安装安全更新，优先处理 openssl、openssh、内核、glibc 等基础组件；更新后按需重启。",
                "、".join(names),
                cwe="CWE-1035",
            )
        )
    elif updates:
        findings.append(
            _host_finding(
                config,
                "host.pending_updates",
                "存在待安装的软件更新",
                "low",
                f"检测到 {len(updates)} 个可升级软件包，其中未能识别出安全更新标记。",
                "评估并安装可用的软件包更新，保持系统组件处于受支持版本。",
                "、".join(item["name"] for item in updates[:15]),
                cwe="CWE-1104",
            )
        )

    if info.get("reboot_required"):
        findings.append(
            _host_finding(
                config,
                "host.reboot_required",
                "系统需要重启以完成更新",
                "medium",
                "系统存在 /var/run/reboot-required 标记，部分更新（通常包括内核）尚未生效。",
                "安排维护窗口重启主机，重启前确认业务高可用与回滚方案。",
                "/var/run/reboot-required 存在",
                cwe="CWE-1104",
            )
        )

    ssh = info.get("ssh", {})
    root_login = ssh.get("permitrootlogin", "")
    if root_login == "yes":
        findings.append(
            _host_finding(
                config,
                "host.ssh_root_login",
                "SSH 允许 root 直接登录",
                "medium",
                "sshd 配置 PermitRootLogin yes，攻击者可直接对 root 账号进行密码或密钥尝试。",
                "设置 PermitRootLogin prohibit-password 或 no，改用普通账号登录后再提权。",
                f"permitrootlogin={root_login}",
                cwe="CWE-250",
            )
        )
    if ssh.get("passwordauthentication") == "yes":
        findings.append(
            _host_finding(
                config,
                "host.ssh_password_auth",
                "SSH 开启密码认证",
                "medium",
                "密码认证容易遭受撞库与暴力破解，且弱口令风险高。",
                "优先使用密钥或硬件令牌认证；如需保留密码，启用 Fail2ban、限制来源 IP 并强制强口令。",
                f"passwordauthentication={ssh.get('passwordauthentication')}",
                cwe="CWE-521",
            )
        )
    if ssh.get("permitemptypasswords") == "yes":
        findings.append(
            _host_finding(
                config,
                "host.ssh_empty_password",
                "SSH 允许空密码",
                "critical",
                "sshd 配置 PermitEmptyPasswords yes，空口令账号可直接登录。",
                "立即设置 PermitEmptyPasswords no，并为所有账号设置强口令或禁用登录。",
                "permitemptypasswords=yes",
                cwe="CWE-258",
            )
        )

    firewall = info.get("firewall", {})
    if not firewall.get("active"):
        findings.append(
            _host_finding(
                config,
                "host.firewall_disabled",
                "未检测到启用的主机防火墙",
                "medium",
                "未发现 ufw、firewalld、nftables 或 iptables 的有效规则，暴露服务可能缺少网络层访问控制。",
                "启用 ufw/firewalld/nftables，仅放行必要端口，并限制管理端口来源 IP。",
                str(firewall),
                confidence="low",
                cwe="CWE-284",
            )
        )

    modules = info.get("security_modules", {})
    if modules.get("selinux") == "disabled" and modules.get("apparmor") == "disabled":
        findings.append(
            _host_finding(
                config,
                "host.mac_disabled",
                "SELinux 与 AppArmor 均未启用",
                "low",
                "缺少强制访问控制，单一服务漏洞更容易扩大为系统级影响。",
                "在兼容性允许的情况下启用 SELinux Enforcing 或 AppArmor，并为业务配置最小权限策略。",
                f"SELinux={modules.get('selinux')}; AppArmor={modules.get('apparmor')}",
                cwe="CWE-693",
            )
        )

    uid0 = info.get("uid0_accounts", [])
    if uid0:
        findings.append(
            _host_finding(
                config,
                "host.uid0_account",
                "存在 root 之外的 UID 0 账号",
                "high",
                "除 root 外还有账号的 UID 为 0，登录后即拥有 root 权限，绕过了权限分离。",
                "确认账号用途并改为非 0 UID；如为后门账号，立即删除并排查入侵痕迹。",
                "、".join(uid0[:10]),
                cwe="CWE-269",
            )
        )

    docker_socket = info.get("docker_socket") or {}
    if docker_socket.get("present") and docker_socket.get("world_writable"):
        findings.append(
            _host_finding(
                config,
                "host.docker_socket",
                "Docker socket 权限过宽",
                "high",
                "Docker socket 允许任意用户写入，任何本地用户都可借此启动特权容器，等同于获得 root 权限。",
                "将 docker.sock 权限收紧为 root:docker 660；不要把普通业务账号加入 docker 组，必要时使用 rootless Docker。",
                f"{docker_socket.get('mode')} {docker_socket.get('owner')}:{docker_socket.get('group')}",
                cwe="CWE-269",
            )
        )

    if not info.get("autoupdate"):
        findings.append(
            _host_finding(
                config,
                "host.autoupdate_missing",
                "未启用自动安全更新",
                "low",
                "未检测到 unattended-upgrades 或 dnf-automatic 的自动更新配置，补丁可能长期滞后。",
                "启用无人值守安全更新，并在测试环境验证后再推广到生产；保留重启与回滚策略。",
                "未发现 20auto-upgrades 或 dnf-automatic",
                cwe="CWE-1104",
            )
        )
    return findings


class HostScanEngine:
    def __init__(self, scan_id: str, config: ScanConfig, emit: EmitFn) -> None:
        self.scan_id = scan_id
        self.config = config
        self._emit = emit
        self.started_at = time.monotonic()

    async def emit(self, event: dict[str, Any]) -> None:
        event.setdefault("scan_id", self.scan_id)
        await self._emit(event)

    async def log(self, level: str, message: str) -> None:
        await self.emit({"type": "log", "level": level, "message": message})

    async def progress(self, value: float, phase: str, label: str) -> None:
        await self.emit({"type": "phase", "phase": phase, "label": label, "progress": round(min(value, 1.0), 3)})

    async def run(self) -> None:
        status = "completed"
        try:
            db.set_status(self.scan_id, "running")
            await self.log(
                "info",
                f"连接主机 {self.config.ssh_user}@{self.config.target}:{self.config.ssh_port}（只读采集）",
            )
            await self.progress(0.1, "connect", "SSH 连接")
            info = await asyncio.to_thread(self._collect)
            await self.emit(
                {"type": "stats", "requests": 0, "elapsed_ms": int((time.monotonic() - self.started_at) * 1000)}
            )
            await self.progress(0.55, "inspect", "系统巡检")
            findings = build_findings(self.config, info)
            for item in findings:
                await self.emit({"type": "finding", "finding": item.to_dict()})
            await self.progress(0.9, "report", "生成报告")

            findings.sort(key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 99, f.check_id))
            duration_ms = int((time.monotonic() - self.started_at) * 1000)
            summary = Summary.from_findings(findings, duration_ms=duration_ms).to_dict()
            summary["package_count"] = len(info["packages"])
            summary["service_count"] = len(info["services"])
            summary["update_count"] = len(info["updates"])

            assets = {
                "host": info["host"],
                "package_count": len(info["packages"]),
                "update_count": len(info["updates"]),
                "security_update_count": len([item for item in info["updates"] if item.get("security")]),
                "service_count": len(info["services"]),
                "listener_count": len(info["listeners"]),
            }
            discovery = {
                "host": info["host"],
                "packages": info["packages"],
                "updates": info["updates"],
                "services": info["services"],
                "listeners": info["listeners"],
                "ssh": info["ssh"],
                "firewall": info["firewall"],
                "security_modules": info["security_modules"],
                "uid0_accounts": info["uid0_accounts"],
                "reboot_required": info["reboot_required"],
                "autoupdate": info["autoupdate"],
                "docker_socket": info["docker_socket"],
            }
            db.save_results(self.scan_id, summary, assets, discovery, [item.to_dict() for item in findings])
            db.set_status(self.scan_id, status)
            await self.progress(1.0, "report", "完成")
            await self.emit({"type": "done", "summary": summary, "status": status})
            await self.log("success", f"主机巡检完成：共 {summary['total']} 条发现，耗时 {duration_ms / 1000:.1f}s")
        except asyncio.CancelledError:
            db.set_status(self.scan_id, "stopped", "主机巡检已被用户中止")
            await self.emit({"type": "stopped", "message": "主机巡检已被用户中止"})
            raise
        except Exception as exc:
            status = "failed"
            message = self._friendly_error(exc)
            db.set_status(self.scan_id, status, message)
            await self.log("error", message)
            await self.emit({"type": "error", "message": message, "detail": traceback.format_exc()[-1200:]})

    def _collect(self) -> dict[str, Any]:
        try:
            import paramiko
        except ImportError as exc:
            raise RuntimeError("缺少 paramiko 依赖，无法进行 SSH 巡检") from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.config.target,
                port=self.config.ssh_port,
                username=self.config.ssh_user,
                password=self.config.ssh_password or None,
                key_filename=self.config.ssh_key_path or None,
                passphrase=self.config.ssh_key_passphrase or None,
                timeout=12,
                banner_timeout=12,
                auth_timeout=12,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = client.get_transport()
            key = transport.get_remote_server_key() if transport else None
            fingerprint = key.get_fingerprint().hex(":") if key else ""
            outputs: dict[str, str] = {}
            for name, command, timeout in COMMANDS:
                outputs[name] = self._exec(client, command, timeout)

            os_info = parse_os(outputs.get("os", ""))
            os_info.update(
                {
                    "user": self.config.ssh_user,
                    "port": self.config.ssh_port,
                    "target": self.config.target,
                    "fingerprint": fingerprint,
                }
            )
            packages = parse_packages(outputs.get("packages", ""))
            updates = parse_updates(outputs.get("updates", ""), os_info.get("id", ""))
            firewall = inspect_firewall(outputs.get("firewall", ""))
            security_modules = inspect_security_modules(outputs.get("selinux", ""))
            return {
                "host": os_info,
                "packages": packages,
                "updates": updates,
                "services": parse_services(outputs.get("services", "")),
                "listeners": parse_listeners(outputs.get("listeners", "")),
                "ssh": parse_sshd(outputs.get("sshd", "")),
                "firewall": firewall,
                "security_modules": security_modules,
                "uid0_accounts": parse_accounts(outputs.get("accounts", "")),
                "reboot_required": "yes" in outputs.get("reboot", "").lower(),
                "autoupdate": parse_autoupdate(outputs.get("autoupdate", "")),
                "docker_socket": parse_docker_socket(outputs.get("docker", "")),
            }
        except Exception as exc:
            raise RuntimeError(self._friendly_error(exc)) from exc
        finally:
            client.close()

    @staticmethod
    def _exec(client: Any, command: str, timeout: int) -> str:
        try:
            _, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=False)
            text = stdout.read(2_000_000).decode("utf-8", errors="replace")
            if not text:
                text = stderr.read(200_000).decode("utf-8", errors="replace")
            return text
        except Exception:
            return ""

    @staticmethod
    def _friendly_error(exc: Exception) -> str:
        name = type(exc).__name__
        text = str(exc)
        if text.startswith(("SSH ", "主机巡检失败")):
            return text
        if "Authentication" in name:
            return "SSH 认证失败：请检查用户名、密码或私钥是否正确"
        if "NoValidConnectionsError" in name or "timed out" in text.lower():
            return "SSH 连接失败：主机不可达或端口未开放"
        return f"主机巡检失败：{name}: {text}"

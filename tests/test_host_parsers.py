from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scanner.host import (  # noqa: E402
    build_findings,
    build_windows_info,
    inspect_firewall,
    inspect_security_modules,
    parse_accounts,
    parse_autoupdate,
    parse_docker_socket,
    parse_listeners,
    parse_os,
    parse_packages,
    parse_services,
    parse_sshd,
    parse_updates,
    parse_windows_defender,
    parse_windows_firewall,
    parse_windows_hotfixes,
    parse_windows_listeners,
    parse_windows_os,
    parse_windows_updates,
)
from backend.scanner.models import ScanConfig, build_config  # noqa: E402
from backend.scanner.report import build_html, build_json, build_markdown  # noqa: E402

OS_TEXT = """NAME="Ubuntu"
VERSION_ID="20.04"
PRETTY_NAME="Ubuntu 20.04.6 LTS"
ID=ubuntu
---
Linux 5.15.0-91-generic x86_64
---
web-01
"""

SSHD_TEXT = """port 22
permitrootlogin yes
passwordauthentication yes
permitemptypasswords no
"""

SS_OUTPUT = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      128    127.0.0.1:5432     0.0.0.0:*
udp   UNCONN 0      0      0.0.0.0:68         0.0.0.0:*
"""


def host_info(**overrides):
    info = {
        "host": parse_os(OS_TEXT),
        "packages": parse_packages("openssl\t1.1.1f-1\nbash\t5.0-6\n"),
        "updates": parse_updates(
            "Listing...\nopenssl/focal-security 1.1.1f-1ubuntu2.22 amd64 [upgradable from: 1.1.1f-1ubuntu2.21]\n"
            "bash/focal-updates 5.0-6ubuntu1.2 amd64 [upgradable from: 5.0-6ubuntu1.1]\n",
            "ubuntu",
        ),
        "services": parse_services("ssh.service loaded active running OpenBSD Secure Shell server\n"),
        "listeners": parse_listeners(SS_OUTPUT),
        "ssh": parse_sshd(SSHD_TEXT),
        "firewall": inspect_firewall("inactive\n"),
        "security_modules": inspect_security_modules("Disabled\napparmor=1\n"),
        "uid0_accounts": parse_accounts("root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/:/bin/sh\n"),
        "reboot_required": True,
        "autoupdate": parse_autoupdate(""),
        "docker_socket": parse_docker_socket("srw-rw-rw- 1 root docker 0 Nov 20 10:00 /var/run/docker.sock"),
    }
    info.update(overrides)
    return info


WINDOWS_OS_JSON = """WARNING: sample warning
{"Caption":"Microsoft Windows Server 2012 R2 Standard","Version":"6.3.9600","Build":"9600","OSArchitecture":"64-bit","Hostname":"WIN-APP01"}
"""

WINDOWS_UPDATES_JSON = """[
  {"Title":"Security Update for Windows Server (KB5030001)","Security":true},
  {"Title":"Update for Windows Server (KB5030002)","Security":false}
]
"""


def windows_host_info(**overrides):
    outputs = {
        "updates": WINDOWS_UPDATES_JSON,
        "hotfixes": '{"HotFixID":"KB5031419","Description":"Security Update","InstalledOn":"/Date(1735689600000)/"}',
        "services": "WinDefend\nW32Time\n",
        "listeners": """[
          {"LocalAddress":"0.0.0.0","LocalPort":3389},
          {"LocalAddress":"127.0.0.1","LocalPort":5985},
          {"LocalAddress":"::","LocalPort":3389}
        ]""",
        "firewall": '[{"Name":"Domain","Enabled":false},{"Name":"Public","Enabled":false}]',
        "defender": '{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureLastUpdated":"/Date(0)/"}',
        "smb": '{"EnableSMB1Protocol":true}',
        "autoupdate": '{"NoAutoUpdate":1,"AUOptions":2}',
        "reboot": "True",
    }
    info = build_windows_info(outputs, parse_windows_os(WINDOWS_OS_JSON))
    info.update(overrides)
    return info


class ParserTests(unittest.TestCase):
    def test_parse_os(self):
        parsed = parse_os(OS_TEXT)
        self.assertEqual(parsed["id"], "ubuntu")
        self.assertEqual(parsed["version_id"], "20.04")
        self.assertEqual(parsed["kernel"], "5.15.0-91-generic")
        self.assertEqual(parsed["arch"], "x86_64")
        self.assertEqual(parsed["hostname"], "web-01")

    def test_parse_packages_dedupe(self):
        packages = parse_packages("openssl\t1\nopenssl\t1\nbash\t2\n")
        self.assertEqual([p["name"] for p in packages], ["openssl", "bash"])

    def test_parse_updates_security(self):
        updates = parse_updates(
            "Listing...\nopenssl/focal-security 1.1.1f-1 amd64 [upgradable from: 1.1.1f-0]\n"
            "bash/focal-updates 5.0-6 amd64 [upgradable from: 5.0-5]\n",
            "ubuntu",
        )
        self.assertEqual(len(updates), 2)
        self.assertTrue(updates[0]["security"])
        self.assertFalse(updates[1]["security"])
        self.assertEqual(updates[0]["old_version"], "1.1.1f-0")

    def test_parse_services(self):
        services = parse_services("ssh.service loaded active running sshd\ncron.service loaded active running cron\n")
        self.assertEqual(services, ["ssh.service", "cron.service"])

    def test_parse_listeners(self):
        listeners = parse_listeners(SS_OUTPUT)
        self.assertEqual(len(listeners), 3)
        self.assertTrue(next(item for item in listeners if item["port"] == 22)["exposed"])
        self.assertFalse(next(item for item in listeners if item["port"] == 5432)["exposed"])

    def test_parse_sshd(self):
        parsed = parse_sshd(SSHD_TEXT)
        self.assertEqual(parsed["permitrootlogin"], "yes")
        self.assertEqual(parsed["passwordauthentication"], "yes")
        self.assertEqual(parsed["permitemptypasswords"], "no")

    def test_parse_accounts(self):
        self.assertEqual(parse_accounts("root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/:/bin/sh\n"), ["backdoor"])

    def test_inspect_firewall(self):
        self.assertTrue(inspect_firewall("Status: active\n")["active"])
        self.assertFalse(inspect_firewall("Status: inactive\n")["active"])

    def test_security_modules(self):
        modules = inspect_security_modules("Disabled\napparmor=0\n")
        self.assertEqual(modules["selinux"], "disabled")
        self.assertEqual(modules["apparmor"], "enabled")

    def test_autoupdate(self):
        self.assertTrue(parse_autoupdate('APT::Periodic::Unattended-Upgrade "1";'))
        self.assertFalse(parse_autoupdate(""))

    def test_docker_socket(self):
        parsed = parse_docker_socket("srw-rw-rw- 1 root docker 0 Nov 20 10:00 /var/run/docker.sock")
        self.assertTrue(parsed["present"])
        self.assertTrue(parsed["world_writable"])
        self.assertFalse(parse_docker_socket("srw-rw---- 1 root docker 0 Nov 20 10:00 /var/run/docker.sock")["world_writable"])
        self.assertFalse(parse_docker_socket("")["present"])

    def test_build_findings(self):
        config = ScanConfig(target="10.0.0.12", scan_type="linux", ssh_user="ops")
        findings = build_findings(config, host_info())
        ids = {item.check_id for item in findings}
        self.assertIn("host.os_eol", ids)
        self.assertIn("host.security_updates", ids)
        self.assertIn("host.reboot_required", ids)
        self.assertIn("host.ssh_root_login", ids)
        self.assertIn("host.ssh_password_auth", ids)
        self.assertIn("host.firewall_disabled", ids)
        self.assertIn("host.mac_disabled", ids)
        self.assertIn("host.uid0_account", ids)
        self.assertIn("host.docker_socket", ids)
        self.assertIn("host.autoupdate_missing", ids)

    def test_build_config_masks_secrets(self):
        config = build_config(
            {
                "target": "10.0.0.12",
                "scan_type": "linux",
                "ssh_port": "2222",
                "ssh_user": "ops",
                "ssh_password": "secret",
                "ssh_key_passphrase": "pass",
            }
        )
        self.assertEqual(config.scan_type, "linux")
        self.assertEqual(config.ssh_port, 2222)
        data = config.to_dict()
        self.assertNotIn("ssh_password", data)
        self.assertNotIn("ssh_key_passphrase", data)


class WindowsParserTests(unittest.TestCase):
    def test_parse_os_tolerates_warning(self):
        parsed = parse_windows_os(WINDOWS_OS_JSON)
        self.assertEqual(parsed["id"], "windows")
        self.assertEqual(parsed["pretty"], "Microsoft Windows Server 2012 R2 Standard")
        self.assertEqual(parsed["version_id"], "6.3.9600")
        self.assertEqual(parsed["hostname"], "WIN-APP01")

    def test_parse_updates_and_single_hotfix(self):
        updates = parse_windows_updates(WINDOWS_UPDATES_JSON)
        self.assertEqual(len(updates), 2)
        self.assertTrue(updates[0]["security"])
        hotfixes = parse_windows_hotfixes(
            '{"HotFixID":"KB5031419","Description":"Security Update","InstalledOn":"/Date(1735689600000)/"}'
        )
        self.assertEqual(hotfixes[0]["id"], "KB5031419")
        self.assertTrue(hotfixes[0]["installed_on"].startswith("2025-01-"))

    def test_parse_listeners_dedupe(self):
        listeners = parse_windows_listeners(
            '[{"LocalAddress":"0.0.0.0","LocalPort":3389},{"LocalAddress":"::","LocalPort":3389},'
            '{"LocalAddress":"127.0.0.1","LocalPort":5985}]'
        )
        self.assertEqual([item["port"] for item in listeners], [3389, 5985])
        self.assertTrue(listeners[0]["exposed"])
        self.assertFalse(listeners[1]["exposed"])

    def test_parse_firewall_and_defender(self):
        firewall = parse_windows_firewall('[{"Name":"Domain","Enabled":true}]')
        self.assertTrue(firewall["active"])
        defender = parse_windows_defender(
            '{"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"AntivirusSignatureLastUpdated":"/Date(0)/"}'
        )
        self.assertTrue(defender["present"])
        self.assertFalse(defender["realtime"])
        self.assertGreater(defender["signature_age_days"], 7)

    def test_build_windows_info(self):
        info = windows_host_info()
        self.assertEqual(info["services"], ["WinDefend", "W32Time"])
        self.assertEqual(info["hotfixes"][0]["id"], "KB5031419")
        self.assertTrue(info["smb1_enabled"])
        self.assertTrue(info["reboot_required"])
        self.assertFalse(info["autoupdate"])

    def test_build_windows_findings(self):
        config = ScanConfig(target="10.0.0.20", scan_type="windows", ssh_user="Administrator")
        findings = build_findings(config, windows_host_info())
        ids = {item.check_id for item in findings}
        self.assertEqual(
            ids,
            {
                "host.os_eol",
                "host.security_updates",
                "host.reboot_required",
                "host.firewall_disabled",
                "host.defender_realtime_off",
                "host.defender_signature_stale",
                "host.smb1_enabled",
                "host.autoupdate_missing",
            },
        )

    def test_windows_reports(self):
        config = ScanConfig(target="10.0.0.20", scan_type="windows", ssh_user="Administrator")
        info = windows_host_info()
        findings = [item.to_dict() for item in build_findings(config, info)]
        scan = {
            "id": "windows-test",
            "target": "ssh://Administrator@10.0.0.20:22",
            "preset": "standard",
            "status": "completed",
            "created_at": 1_700_000_000,
            "finished_at": 1_700_000_001,
            "error": None,
            "config": config.to_dict(),
            "summary": {"duration_ms": 1000, "total": len(findings)},
            "assets": {},
            "discovery": info,
            "findings": findings,
        }
        markdown = build_markdown(scan)
        html = build_html(scan)
        payload = json.loads(build_json(scan))
        self.assertIn("Windows 主机只读巡检", markdown)
        self.assertIn("KB5031419", markdown)
        self.assertIn("Windows Host Security Report", html)
        self.assertIn("Defender", html)
        self.assertIn("SMBv1", html)
        discovery = payload["scan"]["discovery"]
        self.assertEqual(discovery["hotfixes"][0]["id"], "KB5031419")
        self.assertTrue(discovery["smb1_enabled"])
        self.assertNotIn("ssh_password", payload["scan"]["config"])

    def test_missing_firewall_output_is_not_a_finding(self):
        config = ScanConfig(target="10.0.0.20", scan_type="windows", ssh_user="Administrator")
        info = windows_host_info(firewall={"active": False, "profiles": []})
        ids = {item.check_id for item in build_findings(config, info)}
        self.assertNotIn("host.firewall_disabled", ids)

    def test_windows_config_masks_secrets(self):
        config = build_config(
            {
                "target": "10.0.0.20",
                "scan_type": "windows",
                "ssh_user": "Administrator",
                "ssh_password": "secret",
                "ssh_key_passphrase": "pass",
            }
        )
        self.assertEqual(config.scan_type, "windows")
        self.assertNotIn("ssh_password", config.to_dict())
        self.assertNotIn("ssh_key_passphrase", config.to_dict())


if __name__ == "__main__":
    unittest.main()

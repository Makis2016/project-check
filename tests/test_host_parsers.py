from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scanner.host import (  # noqa: E402
    build_findings,
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
)
from backend.scanner.models import ScanConfig, build_config  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()

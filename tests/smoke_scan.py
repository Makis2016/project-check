from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("VULNLENS_DATA_DIR", str(ROOT / "data-test"))

from backend import db  # noqa: E402
from backend.app import compare_scan  # noqa: E402
from backend.scanner.engine import ScanEngine  # noqa: E402
from backend.scanner.exclude import is_excluded  # noqa: E402
from backend.scanner.models import ScanConfig, build_config  # noqa: E402
from backend.scanner.report import build_csv, build_html, build_json  # noqa: E402

PORT = 8901


def wait_port(port: int, timeout: float = 15) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError("fixture server did not start")


async def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "tests.fixtures.vuln_app:app", "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    events: list[dict] = []
    try:
        wait_port(PORT)
        config = ScanConfig(
            target=f"http://127.0.0.1:{PORT}",
            preset="standard",
            authorization_confirmed=True,
            rate_limit=30,
            max_pages=15,
            max_requests=800,
            scan_ports=False,
            subdomain_enum=False,
            active_checks=True,
            cookie="sessionid=smoke",
            secondary_cookie="sessionid=other",
            quality_checks=True,
            auth_checks=True,
            intrusive_checks=True,
        )
        state = {"value": "running"}

        cfg = build_config(
            {
                "target": f"http://127.0.0.1:{PORT}",
                "proxy": "http://127.0.0.1:8080",
                "exclude_paths": "/logout\n*.pdf",
            }
        )
        assert cfg.proxy == "http://127.0.0.1:8080" and cfg.exclude_paths == ["/logout", "*.pdf"]
        assert is_excluded("https://example.com/logout?next=1", ["/logout"])
        assert is_excluded("https://cdn.example.com/app.js", ["cdn.example.com"])
        assert is_excluded("https://example.com/doc.pdf", ["*.pdf"])
        assert not is_excluded("https://example.com/login", ["/logout"])

        db.init_db()
        db.delete_scan("smoke-test")
        db.delete_scan("smoke-base")

        base_config = config.to_dict()
        db.create_scan("smoke-base", base_config)
        root_url = f"http://127.0.0.1:{PORT}/"
        db.save_results(
            "smoke-base",
            {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 2},
            {},
            {"endpoints": [], "tech": [], "docs": [], "forms": [], "cookies": [], "robots": [], "sitemaps": []},
            [],
        )
        db.add_findings(
            "smoke-base",
            [
                {
                    "check_id": "headers.csp",
                    "title": "缺少 CSP",
                    "severity": "medium",
                    "category": "headers",
                    "confidence": "high",
                    "url": root_url,
                    "param": "",
                    "fingerprint": "",
                },
                {
                    "check_id": "legacy.removed",
                    "title": "已修复的历史问题",
                    "severity": "high",
                    "category": "config",
                    "confidence": "high",
                    "url": root_url + "old",
                    "param": "",
                    "fingerprint": "",
                },
            ],
        )
        db.set_status("smoke-base", "completed")

        db.create_scan("smoke-test", config.to_dict())

        async def emit(event: dict) -> None:
            events.append(event)
            if event.get("type") in ("done", "error", "stopped"):
                state["value"] = event.get("type")

        engine = ScanEngine("smoke-test", config, emit)
        await engine.run()

        findings = [e["finding"] for e in events if e.get("type") == "finding"]
        print(f"events={len(events)} findings={len(findings)} status={state['value']}")
        for item in findings:
            print(f"  [{item['severity']:8}] {item['check_id']:32} {item['title'][:50]}")
        errors = [e for e in events if e.get("type") == "error"]
        if errors:
            print("ERROR:", errors[-1])
        done = [e for e in events if e.get("type") == "done"]
        if done:
            print("summary:", done[-1]["summary"])

        ids = {i["check_id"] for i in findings}
        expected = {
            "headers.csp",
            "headers.frame",
            "cookie.flags",
            "cors.credentials",
            "exposure.directory_listing",
            "exposure.git.config",
            "exposure.env",
            "exposure.sourcemap",
            "exposure.js_secret",
            "exposure.stack_trace",
            "active.xss_reflected",
            "active.sqli_error",
            "active.open_redirect",
            "jwt.no_exp",
            "exposure.graphql",
            "headers.host_injection",
            "csrf.missing_token",
            "exposure.backup_file",
            "quality.js_load_error",
            "quality.broken_link",
            "quality.server_error",
            "auth.unauthorized_api",
            "auth.idor",
            "active.stored_xss",
            "active.ssrf",
            "active.path_traversal",
            "active.command_injection",
        }
        missing = expected - ids
        print("missing:", sorted(missing) if missing else "none")

        scan = db.get_scan("smoke-test")
        assert scan is not None
        endpoints = (scan.get("discovery") or {}).get("endpoints") or []
        openapi_endpoints = [item for item in endpoints if "openapi" in str(item.get("source"))]
        print("openapi endpoints:", len(openapi_endpoints))
        if not any("message=1" in item["url"] for item in openapi_endpoints):
            print("FAIL: OpenAPI 参数未注入接口列表")
            return 1
        if not any(item["check_id"] == "active.xss_reflected" and item.get("param") == "message" for item in findings):
            print("FAIL: OpenAPI 注入参数未被主动扫描")
            return 1
        xss = next(item for item in findings if item["check_id"] == "active.xss_reflected")
        if not (xss.get("request") and xss.get("response") and xss.get("curl")):
            print("FAIL: 请求/响应原文或 cURL 缺失")
            return 1

        diff = await compare_scan("smoke-test")
        print("diff:", diff.get("counts"), "available:", diff.get("available"))
        if not diff.get("available") or diff["counts"]["resolved"] < 1:
            print("FAIL: 扫描对比结果异常")
            return 1

        html_report = build_html(scan)
        json_report = build_json(scan)
        csv_report = build_csv(scan)
        payload = json.loads(json_report)
        if scan["target"] not in html_report or payload["scan"]["target"] != scan["target"]:
            print("FAIL: HTML/JSON 报告内容异常")
            return 1
        if not csv_report.startswith("\ufeff") or "active.xss_reflected" not in csv_report:
            print("FAIL: CSV 报告内容异常")
            return 1
        print("reports:", len(html_report), len(json_report), len(csv_report))

        return 0 if not missing else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

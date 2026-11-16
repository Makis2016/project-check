from __future__ import annotations

import asyncio
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
from backend.scanner.engine import ScanEngine  # noqa: E402
from backend.scanner.models import ScanConfig  # noqa: E402

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
        )
        state = {"value": "running"}

        db.init_db()
        db.delete_scan("smoke-test")
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
        }
        missing = expected - ids
        print("missing:", sorted(missing) if missing else "none")
        return 0 if not missing else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

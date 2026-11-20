from __future__ import annotations

import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .scanner.engine import ScanEngine
from .scanner.host import HostScanEngine
from .scanner.models import SEVERITIES, build_config, new_scan_id
from .scanner.report import build_csv, build_html, build_json, build_markdown

VERSION = "1.3.0"
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


@dataclass
class Runner:
    buffer: list[dict] = field(default_factory=list)
    task: asyncio.Task | None = None
    finished: bool = False


runners: dict[str, Runner] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="VulnLens", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def validate_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="请输入目标地址")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="目标地址格式不正确，示例：https://example.com")
    if parsed.hostname.lower() in BLOCKED_HOSTS:
        raise HTTPException(status_code=400, detail="该地址为云元数据端点，禁止扫描")
    return raw.rstrip("/")


HOST_PATTERN = re.compile(r"^[A-Za-z0-9._:%-]+$")


def validate_ssh_target(raw: str) -> str:
    host = (raw or "").strip()
    if "://" in host:
        parsed = urlparse(host)
        host = (parsed.hostname or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="请输入主机 IP 或域名")
    if len(host) > 253 or not HOST_PATTERN.match(host):
        raise HTTPException(status_code=400, detail="主机地址格式不正确，只填写 IP 或域名，不要带协议和路径")
    if host.lower() in BLOCKED_HOSTS:
        raise HTTPException(status_code=400, detail="该地址为云元数据端点，禁止扫描")
    return host


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "name": "VulnLens", "version": VERSION}


@app.post("/api/scans")
async def create_scan(request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体不是合法 JSON")
    if not payload.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="请先确认：你拥有该目标的所有权或已获得扫描授权")

    scan_type = "linux" if payload.get("scan_type") == "linux" else "web"
    if scan_type == "linux":
        host = validate_ssh_target(payload.get("target", ""))
        ssh_user = str(payload.get("ssh_user") or "").strip()
        if not ssh_user:
            raise HTTPException(status_code=400, detail="请填写 SSH 用户名")
        password = str(payload.get("ssh_password") or "")
        key_path = str(payload.get("ssh_key_path") or "").strip()
        if not password and not key_path:
            raise HTTPException(status_code=400, detail="请填写 SSH 密码或私钥路径")
        if key_path and not Path(key_path).expanduser().is_file():
            raise HTTPException(status_code=400, detail="私钥文件不存在，请检查路径")
        config = build_config({**payload, "target": host, "scan_type": "linux"})
        target = f"ssh://{ssh_user}@{host}:{config.ssh_port}"
    else:
        target = validate_target(payload.get("target", ""))
        config = build_config({**payload, "target": target})

    scan_id = new_scan_id()
    db.create_scan(scan_id, config.to_dict())

    runner = Runner()
    runners[scan_id] = runner

    async def emit(event: dict) -> None:
        runner.buffer.append(event)
        if len(runner.buffer) > 6000:
            del runner.buffer[:1000]

    engine = HostScanEngine(scan_id, config, emit) if scan_type == "linux" else ScanEngine(scan_id, config, emit)

    async def run_engine() -> None:
        try:
            await engine.run()
        finally:
            runner.finished = True

    runner.task = asyncio.create_task(run_engine())
    return {"id": scan_id, "status": "queued", "target": target}


@app.get("/api/scans")
async def list_scans() -> dict:
    return {"scans": db.list_scans()}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    runner = runners.get(scan_id)
    if runner is not None:
        scan["live"] = not runner.finished
        scan["live_findings"] = [
            event["finding"] for event in runner.buffer if event.get("type") == "finding"
        ][-200:]
        last_phase = next((e for e in reversed(runner.buffer) if e.get("type") == "phase"), None)
        scan["live_phase"] = last_phase
    return scan


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    runner = runners.get(scan_id)
    if runner is None:
        raise HTTPException(status_code=404, detail="扫描任务不在运行中")

    async def event_stream():
        index = 0
        idle = 0
        while True:
            while index < len(runner.buffer):
                event = runner.buffer[index]
                index += 1
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") in ("done", "error", "stopped"):
                    yield "event: end\ndata: {}\n\n"
                    return
            if runner.finished and index >= len(runner.buffer):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.2)
            idle += 1
            if idle % 75 == 0:
                yield ": ping\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    runner = runners.get(scan_id)
    if runner is None or runner.finished or runner.task is None:
        raise HTTPException(status_code=400, detail="任务已结束")
    runner.task.cancel()
    return {"ok": True}


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    runner = runners.get(scan_id)
    if runner is not None and runner.task is not None and not runner.finished:
        runner.task.cancel()
    runners.pop(scan_id, None)
    db.delete_scan(scan_id)
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report.md")
async def download_report(scan_id: str) -> PlainTextResponse:
    scan = _scan_or_404(scan_id)
    markdown = build_markdown(scan)
    filename = f"vulnlens-{scan_id}.md"
    return PlainTextResponse(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _scan_or_404(scan_id: str) -> dict:
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    return scan


@app.get("/api/scans/{scan_id}/report.html")
async def download_report_html(scan_id: str) -> HTMLResponse:
    scan = _scan_or_404(scan_id)
    return HTMLResponse(
        build_html(scan),
        headers={"Content-Disposition": f'attachment; filename="vulnlens-{scan_id}.html"'},
    )


@app.get("/api/scans/{scan_id}/export.json")
async def download_export_json(scan_id: str) -> Response:
    scan = _scan_or_404(scan_id)
    return Response(
        build_json(scan),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulnlens-{scan_id}.json"'},
    )


@app.get("/api/scans/{scan_id}/export.csv")
async def download_export_csv(scan_id: str) -> Response:
    scan = _scan_or_404(scan_id)
    return Response(
        build_csv(scan),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulnlens-{scan_id}.csv"'},
    )


def _finding_key(item: dict) -> str:
    return "|".join(str(item.get(name) or "") for name in ("check_id", "url", "param", "fingerprint"))


def _severity_counts(items: list[dict]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for item in items:
        severity = str(item.get("severity") or "info")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


@app.get("/api/scans/{scan_id}/compare")
async def compare_scan(scan_id: str, base: str | None = None) -> dict:
    current = _scan_or_404(scan_id)
    if base:
        previous = db.get_scan(base)
        if previous is None:
            raise HTTPException(status_code=404, detail="基线扫描不存在")
    else:
        previous = None
        for item in db.list_scans(limit=100):
            if item["id"] == scan_id:
                continue
            if item["target"] != current["target"] or item["status"] != "completed":
                continue
            if (item.get("created_at") or 0) >= (current.get("created_at") or 0):
                continue
            previous = db.get_scan(item["id"])
            break
    if previous is None:
        return {"available": False, "reason": "没有同一目标的历史已完成扫描可供对比"}

    current_map = {_finding_key(item): item for item in current.get("findings") or []}
    previous_map = {_finding_key(item): item for item in previous.get("findings") or []}
    added = [item for key, item in current_map.items() if key not in previous_map]
    resolved = [item for key, item in previous_map.items() if key not in current_map]
    persisting = [item for key, item in current_map.items() if key in previous_map]
    order = {severity: index for index, severity in enumerate(SEVERITIES)}
    added.sort(key=lambda item: order.get(str(item.get("severity")), 99))
    resolved.sort(key=lambda item: order.get(str(item.get("severity")), 99))
    persisting.sort(key=lambda item: order.get(str(item.get("severity")), 99))
    return {
        "available": True,
        "base": {
            "id": previous["id"],
            "created_at": previous.get("created_at"),
            "summary": previous.get("summary"),
            "preset": previous.get("preset"),
        },
        "current": {
            "id": current["id"],
            "created_at": current.get("created_at"),
            "summary": current.get("summary"),
            "preset": current.get("preset"),
        },
        "counts": {
            "added": len(added),
            "resolved": len(resolved),
            "persisting": len(persisting),
        },
        "severity": {
            "added": _severity_counts(added),
            "resolved": _severity_counts(resolved),
            "persisting": _severity_counts(persisting),
        },
        "added": added[:200],
        "resolved": resolved[:200],
        "persisting": persisting[:200],
    }


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="ui")
else:

    @app.get("/")
    async def dev_root() -> JSONResponse:
        return JSONResponse(
            {
                "name": "VulnLens",
                "version": VERSION,
                "hint": "前端尚未构建。开发模式请在 frontend 目录运行 npm run dev（http://localhost:5173）。",
            }
        )

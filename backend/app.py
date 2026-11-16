from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .scanner.engine import ScanEngine
from .scanner.models import build_config, new_scan_id
from .scanner.report import build_markdown

VERSION = "1.0.0"
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

    engine = ScanEngine(scan_id, config, emit)

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
    scan = db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    markdown = build_markdown(scan)
    filename = f"vulnlens-{scan_id}.md"
    return PlainTextResponse(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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

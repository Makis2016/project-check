"""VulnLens 桌面入口：本地启动扫描服务，用系统 WebView 承载界面。"""

from __future__ import annotations

import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WINDOW_TITLE = "VulnLens · Web 安全体检"


def free_port() -> int:
    """向系统借一个空闲的回环端口。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_server(port: int) -> None:
    """在后台线程中运行 FastAPI，仅监听 127.0.0.1。"""
    import uvicorn

    from backend.app import app

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        log_config=None,
        access_log=False,
    )
    server = uvicorn.Server(config)

    def run() -> None:
        try:
            server.run()
        except Exception as exc:  # pragma: no cover - 启动失败时给出可读提示
            print(f"[VulnLens] 服务启动失败: {exc}", file=sys.stderr)

    threading.Thread(target=run, name="vulnlens-api", daemon=True).start()


def wait_ready(base_url: str, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/api/health", timeout=1) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def run_browser_mode(url: str) -> int:
    webbrowser.open(url)
    print(f"[VulnLens] 已在浏览器打开 {url}")
    print("[VulnLens] 按 Ctrl+C 退出。")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


class DesktopApi:
    """暴露给前端的本地能力（窗口内 JS 通过 window.pywebview.api 调用）。"""

    def save_report(self, filename: str, content: str, file_types: list[str] | None = None) -> dict:
        import webview

        windows = webview.windows
        if not windows:
            return {"ok": False, "error": "窗口不可用"}

        dialog = getattr(webview, "FileDialog", None)
        save_dialog = dialog.SAVE if dialog is not None else webview.SAVE_DIALOG
        types = tuple(file_types) if file_types else ("Markdown (*.md)",)
        selected = windows[0].create_file_dialog(
            save_dialog,
            save_filename=filename,
            file_types=types,
        )
        if not selected:
            return {"ok": False, "cancelled": True}

        path = selected[0] if isinstance(selected, (list, tuple)) else selected
        Path(path).write_text(content, encoding="utf-8")
        return {"ok": True, "path": str(path)}


def main(port: int | None = None) -> int:
    port = port or free_port()
    start_server(port)
    url = f"http://127.0.0.1:{port}"
    if not wait_ready(url):
        print("[VulnLens] 后端未能就绪，请检查 Python 依赖是否完整。", file=sys.stderr)
        return 1

    try:
        import webview
    except Exception:
        webview = None  # type: ignore[assignment]

    if webview is None:
        return run_browser_mode(url)

    try:
        webview.create_window(
            WINDOW_TITLE,
            url,
            width=1360,
            height=900,
            min_size=(1024, 720),
            background_color="#060a0f",
            js_api=DesktopApi(),
        )
        webview.start()
        return 0
    except Exception as exc:
        print(f"[VulnLens] WebView 启动失败（{exc}），改用浏览器模式。", file=sys.stderr)
        return run_browser_mode(url)


if __name__ == "__main__":
    raise SystemExit(main())

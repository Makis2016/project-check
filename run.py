#!/usr/bin/env python3
"""VulnLens 启动脚本。

用法：
    python run.py              # 本地启动并打开浏览器
    python run.py --desktop    # 使用桌面窗口（pywebview）
    python run.py --port 8000  # 指定端口
    python run.py --no-browser # 只启动服务
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "frontend" / "dist"


def build_frontend() -> bool:
    if (DIST / "index.html").exists():
        return True
    if shutil.which("npm") is None:
        print("[VulnLens] 未找到前端构建产物，且未安装 Node.js/npm。", file=sys.stderr)
        print("           请先执行：cd frontend && npm install && npm run build", file=sys.stderr)
        return False
    print("[VulnLens] 首次运行，正在构建前端界面…")
    result = subprocess.run(
        ["npm", "run", "build"],
        cwd=str(ROOT / "frontend"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        print("[VulnLens] 前端构建失败，请检查 Node.js 环境。", file=sys.stderr)
        return False
    return (DIST / "index.html").exists()


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnLens 本地安全体检工具")
    parser.add_argument("--port", type=int, default=0, help="监听端口，默认自动选择空闲端口")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    parser.add_argument("--desktop", action="store_true", help="使用桌面窗口模式")
    args = parser.parse_args()

    if not build_frontend():
        return 1

    if args.desktop:
        from desktop.main import main as desktop_main

        return desktop_main(args.port or None)

    from desktop.main import free_port, start_server, wait_ready

    port = args.port or free_port()
    start_server(port)
    url = f"http://127.0.0.1:{port}"
    if not wait_ready(url):
        print("[VulnLens] 服务未能就绪，请检查依赖：pip install -r requirements.txt", file=sys.stderr)
        return 1

    print(f"[VulnLens] 服务地址：{url}")
    if not args.no_browser:
        webbrowser.open(url)
    print("[VulnLens] 按 Ctrl+C 退出。")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

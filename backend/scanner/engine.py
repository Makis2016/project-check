from __future__ import annotations

import asyncio
import time
import traceback
from typing import Any, Awaitable, Callable

from .. import db

from .assets import run_assets
from .checks import ACTIVE_CHECKS, PASSIVE_CHECKS, CheckContext
from .crawler import CrawlError, Crawler
from .http_client import HttpSession, ScanLimitReached
from .models import Finding, ScanConfig, Summary, SEVERITIES

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]


class ScanEngine:
    def __init__(self, scan_id: str, config: ScanConfig, emit: EmitFn) -> None:
        self.scan_id = scan_id
        self.config = config
        self._emit = emit
        self.started_at = time.monotonic()
        self.session: HttpSession | None = None

    async def emit(self, event: dict[str, Any]) -> None:
        event.setdefault("scan_id", self.scan_id)
        await self._emit(event)

    async def log(self, level: str, message: str) -> None:
        await self.emit({"type": "log", "level": level, "message": message})

    async def progress(self, value: float, phase: str, label: str) -> None:
        await self.emit({"type": "phase", "phase": phase, "label": label, "progress": round(min(value, 1.0), 3)})

    async def _on_request(self, count: int) -> None:
        await self.emit(
            {
                "type": "stats",
                "requests": count,
                "elapsed_ms": int((time.monotonic() - self.started_at) * 1000),
            }
        )

    async def run(self) -> None:
        status = "completed"
        error_message: str | None = None
        findings: list[Finding] = []
        assets = None
        discovery = None
        try:
            db.set_status(self.scan_id, "running")
            await self.log("info", "扫描开始，已启用限速与请求预算保护")

            self.session = HttpSession(
                rate_limit=self.config.rate_limit,
                max_requests=self.config.max_requests,
                ignore_tls=self.config.ignore_tls,
                headers=self.config.headers,
                cookie=self.config.cookie,
                proxy=self.config.proxy,
                on_request=self._on_request,
            )
            if self.config.proxy:
                await self.log("info", f"已通过代理发起请求：{self.config.proxy}")
            if self.config.exclude_paths:
                await self.log("info", f"排除规则：{'、'.join(self.config.exclude_paths)}")

            await self.progress(0.02, "assets", "资产探测")
            assets = await run_assets(self.config, self.log)
            await self.progress(0.16, "assets", "资产探测")
            await self.log(
                "success",
                f"资产探测完成：{len(assets.resolved_ips)} 个解析地址，{len(assets.open_ports)} 个开放端口",
            )

            await self.progress(0.2, "discovery", "接口发现")
            crawler = Crawler(self.config, self.session, self.log)
            discovery = await crawler.run()
            await self.progress(0.55, "discovery", "接口发现")
            if discovery.docs:
                await self.log("warn", "检测到公开的接口文档，已加入检查项")

            await self.progress(0.58, "checks", "配置类检测")
            ctx = CheckContext(
                config=self.config,
                session=self.session,
                discovery=discovery,
                assets=assets,
                log=self.log,
            )

            passive_checks = PASSIVE_CHECKS
            for index, check in enumerate(passive_checks, start=1):
                if not self.config.scan_ports and check.__name__ == "check_ports":
                    continue
                try:
                    results = await check(ctx)
                except ScanLimitReached:
                    await self.log("warn", "请求预算耗尽，跳过剩余配置检查")
                    break
                except Exception as exc:
                    await self.log("warn", f"检测器 {check.__name__} 异常：{exc}")
                    continue
                if results:
                    for item in results:
                        await self.emit({"type": "finding", "finding": item.to_dict()})
                findings.extend(results)
                await self.progress(0.58 + 0.28 * (index / max(len(passive_checks), 1)), "checks", "配置类检测")

            if self.config.active_checks:
                await self.progress(0.87, "active", "主动验证")
                for index, check in enumerate(ACTIVE_CHECKS, start=1):
                    try:
                        results = await check(ctx)
                    except ScanLimitReached:
                        await self.log("warn", "请求预算耗尽，跳过剩余主动验证")
                        break
                    except Exception as exc:
                        await self.log("warn", f"主动检测器 {check.__name__} 异常：{exc}")
                        continue
                    if results:
                        for item in results:
                            await self.emit({"type": "finding", "finding": item.to_dict()})
                    findings.extend(results)
                    await self.progress(0.87 + 0.1 * (index / max(len(ACTIVE_CHECKS), 1)), "active", "主动验证")
            else:
                await self.log("info", "主动验证已关闭，仅执行配置类检测")

            await self.progress(0.98, "report", "生成报告")
            findings = self._dedupe(findings)
            findings.sort(key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 99, f.check_id))

            duration_ms = int((time.monotonic() - self.started_at) * 1000)
            summary = Summary.from_findings(
                findings,
                endpoint_count=len(discovery.endpoints),
                page_count=len(discovery.pages),
                request_count=self.session.request_count,
                duration_ms=duration_ms,
            )
            db.save_results(
                self.scan_id,
                summary.to_dict(),
                assets.to_dict(),
                discovery.to_dict(),
                [f.to_dict() for f in findings],
            )
            db.set_status(self.scan_id, status)
            await self.progress(1.0, "report", "完成")
            await self.emit({"type": "done", "summary": summary.to_dict(), "status": status})
            await self.log("success", f"扫描完成：共 {summary.total} 条发现，耗时 {duration_ms / 1000:.1f}s")
        except asyncio.CancelledError:
            status = "stopped"
            error_message = "扫描已被用户中止"
            db.set_status(self.scan_id, "stopped", error_message)
            await self.emit({"type": "stopped", "message": error_message})
            raise
        except CrawlError as exc:
            status = "failed"
            error_message = str(exc)
            db.set_status(self.scan_id, "failed", error_message)
            await self.emit({"type": "error", "message": error_message})
        except Exception as exc:
            status = "failed"
            error_message = f"{type(exc).__name__}: {exc}"
            db.set_status(self.scan_id, "failed", error_message)
            await self.log("error", f"扫描异常：{error_message}")
            await self.emit({"type": "error", "message": error_message, "detail": traceback.format_exc()[-1200:]})
        finally:
            if self.session is not None:
                await self.session.close()

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for item in findings:
            key = item.key()
            if key not in seen:
                seen[key] = item
        return list(seen.values())

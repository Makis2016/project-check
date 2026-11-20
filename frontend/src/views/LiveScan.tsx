import { useEffect, useRef, useState } from "react";
import { stopScan, streamScan } from "../api";
import type { Finding, LogEntry, ScanEvent } from "../types";
import { SeverityBadge } from "../components/Severity";
import { AlertIcon, CheckIcon, StopIcon } from "../components/Icons";
import { formatDuration, hostOf, PRESET_LABEL } from "../format";

const PHASES = [
  { key: "assets", label: "资产探测" },
  { key: "discovery", label: "接口发现" },
  { key: "checks", label: "配置检测" },
  { key: "active", label: "主动验证" },
  { key: "report", label: "生成报告" },
];

const HOST_PHASES = [
  { key: "connect", label: "SSH 连接" },
  { key: "inspect", label: "系统巡检" },
  { key: "report", label: "生成报告" },
];

const LEVEL_LABEL: Record<string, string> = {
  info: "INFO",
  success: "OK",
  warn: "WARN",
  error: "ERR",
};

interface Props {
  scanId: string;
  target: string;
  preset: string;
  scanType?: string;
  onDone: (id: string) => void;
}

export default function LiveScan({ scanId, target, preset, scanType, onDone }: Props) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [progress, setProgress] = useState(0);
  const isHost = scanType === "linux" || scanType === "windows" || target.startsWith("ssh://");
  const phases = isHost ? HOST_PHASES : PHASES;
  const [phase, setPhase] = useState(isHost ? "connect" : "assets");
  const [stats, setStats] = useState({ requests: 0, elapsed: 0 });
  const [status, setStatus] = useState<"running" | "completed" | "failed" | "stopped">("running");
  const [message, setMessage] = useState("");
  const [stopping, setStopping] = useState(false);
  const logId = useRef(0);
  const statusRef = useRef(status);
  const onDoneRef = useRef(onDone);
  const terminalRef = useRef<HTMLDivElement>(null);

  onDoneRef.current = onDone;
  statusRef.current = status;

  useEffect(() => {
    const close = streamScan(scanId, (event: ScanEvent) => {
      switch (event.type) {
        case "log": {
          const entry: LogEntry = {
            id: logId.current++,
            level: String(event.level ?? "info"),
            message: String(event.message ?? ""),
            time: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
          };
          setLogs((previous) => [...previous.slice(-299), entry]);
          break;
        }
        case "finding": {
          const finding = event.finding as Finding;
          if (finding) setFindings((previous) => [...previous, finding]);
          break;
        }
        case "phase": {
          setProgress(Number(event.progress ?? 0));
          setPhase(String(event.phase ?? "assets"));
          break;
        }
        case "stats": {
          setStats({ requests: Number(event.requests ?? 0), elapsed: Number(event.elapsed_ms ?? 0) });
          break;
        }
        case "done": {
          setProgress(1);
          setStatus("completed");
          statusRef.current = "completed";
          window.setTimeout(() => onDoneRef.current(scanId), 900);
          break;
        }
        case "error": {
          setStatus("failed");
          statusRef.current = "failed";
          setMessage(String(event.message ?? "扫描失败"));
          break;
        }
        case "stopped": {
          setStatus("stopped");
          statusRef.current = "stopped";
          setMessage(String(event.message ?? "扫描已中止"));
          break;
        }
        default:
          break;
      }
    }, () => undefined);
    return close;
  }, [scanId]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const currentIndex = Math.max(
    0,
    phases.findIndex((item) => item.key === phase),
  );

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopScan(scanId);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "停止失败");
    } finally {
      setStopping(false);
    }
  };

  const percent = Math.round(progress * 100);

  return (
    <div className="view live-view">
      <header className="scan-head">
        <div>
          <div className="eyebrow">
            <span className={`live-dot ${status !== "running" ? "idle" : ""}`} />
            {status === "running" ? "LIVE SCAN" : status === "completed" ? "SCAN COMPLETED" : "SCAN INTERRUPTED"}
          </div>
          <h1>{hostOf(target)}</h1>
          <div className="scan-sub mono">
            {target} · {isHost ? "主机只读巡检" : PRESET_LABEL[preset] ?? preset}
          </div>
        </div>
        <div className="scan-actions">
          {status === "running" ? (
            <button className="btn btn-danger" onClick={() => void handleStop()} disabled={stopping}>
              <StopIcon width={16} height={16} />
              {stopping ? "停止中" : "停止扫描"}
            </button>
          ) : null}
        </div>
      </header>

      <div className="stepper">
        {phases.map((item, index) => {
          const done = status === "completed" || index < currentIndex;
          const active = status === "running" && index === currentIndex;
          return (
            <div key={item.key} className={`step ${done ? "done" : ""} ${active ? "active" : ""}`}>
              <span className="step-dot">{done ? <CheckIcon width={12} height={12} /> : index + 1}</span>
              <span className="step-label">{item.label}</span>
              {index < phases.length - 1 ? <span className="step-line" /> : null}
            </div>
          );
        })}
      </div>

      <section className="panel progress-panel">
        <div className="progress-top">
          <div>
            <div className="progress-title">
              {status === "running" ? phases[currentIndex]?.label : status === "completed" ? "扫描完成" : "已停止"}
            </div>
            <div className="progress-sub">
              {isHost ? `SSH 只读采集 · 耗时 ${formatDuration(stats.elapsed)}` : `已发起 ${stats.requests} 个请求 · 耗时 ${formatDuration(stats.elapsed)}`}
            </div>
          </div>
          <div className="progress-number">
            {status === "completed" ? 100 : percent}
            <span>%</span>
          </div>
        </div>
        <div className="progress-track">
          <div className={`progress-fill ${status === "failed" ? "failed" : ""}`} style={{ width: `${status === "completed" ? 100 : percent}%` }} />
        </div>
      </section>

      {status === "completed" ? (
        <div className="notice success">
          <CheckIcon width={16} height={16} /> 扫描完成，共发现 {findings.length} 条问题，正在打开报告…
        </div>
      ) : null}
      {status === "failed" || status === "stopped" ? (
        <div className="notice error">
          <AlertIcon width={16} height={16} /> {message}
        </div>
      ) : null}

      <div className="live-grid">
        <section className="panel terminal-panel">
          <header className="panel-head">
            <span>实时日志</span>
            <span className="panel-count mono">{logs.length}</span>
          </header>
          <div className="terminal" ref={terminalRef}>
            {logs.map((log) => (
              <div key={log.id} className={`log-line level-${log.level}`}>
                <span className="log-time">{log.time}</span>
                <span className="log-level">{LEVEL_LABEL[log.level] ?? log.level.toUpperCase()}</span>
                <span className="log-message">{log.message}</span>
              </div>
            ))}
            {logs.length === 0 ? <div className="terminal-empty">等待扫描事件…</div> : null}
          </div>
        </section>

        <section className="panel stream-panel">
          <header className="panel-head">
            <span>实时发现</span>
            <span className="panel-count mono">{findings.length}</span>
          </header>
          <div className="finding-stream">
            {findings.map((finding, index) => (
              <div key={`${finding.check_id}-${index}`} className="stream-item">
                <SeverityBadge severity={finding.severity} compact />
                <div className="stream-copy">
                  <div className="stream-title">{finding.title}</div>
                  <div className="stream-url mono ellipsis">{finding.url || target}</div>
                </div>
              </div>
            ))}
            {findings.length === 0 ? (
              <div className="stream-empty">
                <span className="scan-wait" />
                正在探测，发现问题会实时出现在这里
              </div>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  );
}

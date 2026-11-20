import { useCallback, useEffect, useState } from "react";
import { deleteScan, listScans } from "../api";
import type { Scan } from "../types";
import { RefreshIcon, TrashIcon, RadarIcon } from "../components/Icons";
import { formatDuration, formatTime, hostOf, PRESET_LABEL, riskLevel } from "../format";
import { SEVERITY_ORDER } from "../components/Severity";

interface Props {
  onOpen: (id: string) => void;
  onNew: () => void;
}

const STATUS_LABEL: Record<string, string> = {
  queued: "排队中",
  running: "进行中",
  completed: "已完成",
  failed: "失败",
  stopped: "已中止",
};

export default function HistoryView({ onOpen, onNew }: Props) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans();
      setScans(data.scans);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载历史失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const remove = async (id: string) => {
    if (!window.confirm("删除这条扫描记录？该操作不可恢复。")) return;
    try {
      await deleteScan(id);
      setScans((previous) => previous.filter((scan) => scan.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "删除失败");
    }
  };

  return (
    <div className="view history-view">
      <header className="page-head">
        <div>
          <div className="eyebrow">SCAN ARCHIVE</div>
          <h1>扫描历史</h1>
          <p>所有扫描记录保存在本机 SQLite，可随时回看与导出。</p>
        </div>
        <div className="page-actions">
          <button className="btn" onClick={() => void load()}>
            <RefreshIcon width={16} height={16} /> 刷新
          </button>
          <button className="btn btn-primary" onClick={onNew}>新建扫描</button>
        </div>
      </header>

      {error ? <div className="notice error">{error}</div> : null}

      {loading ? (
        <div className="panel loading-panel"><span className="spinner" /> 正在加载…</div>
      ) : scans.length === 0 ? (
        <div className="panel empty large">
          <RadarIcon width={28} height={28} />
          <strong>还没有扫描记录</strong>
          <p>输入一个已授权的站点地址，开始第一次安全体检。</p>
          <button className="btn btn-primary" onClick={onNew}>开始第一次扫描</button>
        </div>
      ) : (
        <div className="history-list">
          {scans.map((scan) => {
            const risk = riskLevel(scan.summary);
            const total = scan.summary?.total ?? 0;
            const scanType = scan.config?.scan_type;
            const isHost = scanType === "linux" || scanType === "windows";
            return (
              <article key={scan.id} className="history-row" onClick={() => onOpen(scan.id)}>
                <div className="history-main">
                  <div className="history-title-row">
                    <span className="history-title">{hostOf(scan.target)}</span>
                    <span className={`risk-pill small tone-${risk.tone}`}>{risk.label}</span>
                    <span className={`status-pill status-${scan.status}`}>{STATUS_LABEL[scan.status] ?? scan.status}</span>
                  </div>
                  <div className="history-sub mono">{scan.target}</div>
                  <div className="history-meta">
                    <span>{formatTime(scan.created_at)}</span>
                    <span>
                      {scanType === "windows" ? "Windows 巡检" : scanType === "linux" ? "Linux 巡检" : PRESET_LABEL[scan.preset] ?? scan.preset}
                    </span>
                    <span>{formatDuration(scan.summary?.duration_ms)}</span>
                    <span>
                      {isHost ? `${scan.summary?.update_count ?? 0} 待更新` : `${scan.summary?.endpoint_count ?? 0} 接口`}
                    </span>
                  </div>
                </div>
                <div className="history-stats">
                  <div className="mini-bars">
                    {SEVERITY_ORDER.map((severity) => {
                      const value = scan.summary?.[severity] ?? 0;
                      return (
                        <span
                          key={severity}
                          className={`mini-bar sev-bg-${severity}`}
                          style={{ flex: value || 0.15 }}
                          title={`${severity}: ${value}`}
                        />
                      );
                    })}
                  </div>
                  <div className="history-total">
                    <b>{total}</b> 条发现
                  </div>
                </div>
                <button
                  className="icon-btn danger"
                  title="删除记录"
                  onClick={(event) => {
                    event.stopPropagation();
                    void remove(scan.id);
                  }}
                >
                  <TrashIcon width={16} height={16} />
                </button>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

import { useEffect, useState } from "react";
import { createScan, getScan } from "./api";
import type { Scan, ScanPayload } from "./types";
import HistoryView from "./views/HistoryView";
import HostScan from "./views/HostScan";
import LiveScan from "./views/LiveScan";
import NewScan from "./views/NewScan";
import ReportView from "./views/ReportView";
import { HistoryIcon, PlusIcon, RadarIcon, ServerIcon, ShieldIcon } from "./components/Icons";

type View = "new" | "host" | "live" | "report" | "history";

interface ActiveScan {
  id: string;
  target: string;
  preset: string;
  scanType?: string;
}

export default function App() {
  const [view, setView] = useState<View>("new");
  const [active, setActive] = useState<ActiveScan | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [initialTarget, setInitialTarget] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!error) return;
    const timer = window.setTimeout(() => setError(""), 6000);
    return () => window.clearTimeout(timer);
  }, [error]);

  const startScan = async (payload: ScanPayload) => {
    const result = await createScan(payload);
    setActive({ id: result.id, target: result.target, preset: payload.preset, scanType: payload.scan_type });
    setView("live");
  };

  const handleLiveDone = async (id: string) => {
    try {
      const data = await getScan(id);
      setScan(data);
      setView("report");
    } catch (err) {
      setError(err instanceof Error ? err.message : "读取扫描结果失败");
      setView("history");
    }
  };

  const handleOpen = async (id: string) => {
    try {
      const data = await getScan(id);
      if (data.live) {
        setActive({ id: data.id, target: data.target, preset: data.preset, scanType: data.config?.scan_type });
        setView("live");
      } else {
        setScan(data);
        setView("report");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "读取扫描记录失败");
    }
  };

  const goNew = () => {
    setInitialTarget("");
    setView("new");
  };

  const goHost = () => {
    setInitialTarget("");
    setView("host");
  };

  const rescan = (target: string, scanType?: string) => {
    setInitialTarget(target);
    setView(scanType === "linux" ? "host" : "new");
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldIcon width={20} height={20} />
          </div>
          <div className="brand-text">
            <span className="brand-name">VulnLens</span>
            <span className="brand-sub">WEB 安全体检</span>
          </div>
        </div>

        <nav className="nav">
          <button className={`nav-item ${view === "new" ? "active" : ""}`} onClick={goNew}>
            <PlusIcon width={17} height={17} />
            <span>新建扫描</span>
            <span className="nav-key">N</span>
          </button>
          <button className={`nav-item ${view === "host" ? "active" : ""}`} onClick={goHost}>
            <ServerIcon width={17} height={17} />
            <span>主机巡检</span>
          </button>
          <button className={`nav-item ${view === "history" ? "active" : ""}`} onClick={() => setView("history")}>
            <HistoryIcon width={17} height={17} />
            <span>扫描历史</span>
          </button>
          <div className={`nav-item ghost ${view === "report" ? "active" : ""}`}>
            <RadarIcon width={17} height={17} />
            <span>扫描结果</span>
          </div>
        </nav>

        <div className="sidebar-note">
          <div className="note-title">授权使用</div>
          <p>仅扫描你拥有或已获授权的目标。主机巡检通过 SSH 只读采集，不修改目标系统。</p>
        </div>

        <div className="sidebar-foot">
          <span className="version">v1.3.0</span>
          <span className="dot-sep" />
          <span>本地运行</span>
        </div>
      </aside>

      <main className="main">
        {view === "new" ? <NewScan initialTarget={initialTarget} onStart={startScan} /> : null}

        {view === "host" ? <HostScan initialTarget={initialTarget} onStart={startScan} /> : null}

        {view === "live" && active ? (
          <LiveScan
            scanId={active.id}
            target={active.target}
            preset={active.preset}
            scanType={active.scanType}
            onDone={(id) => void handleLiveDone(id)}
          />
        ) : null}

        {view === "report" && scan ? (
          <ReportView scan={scan} onBack={() => setView("history")} onRescan={rescan} />
        ) : null}

        {view === "history" ? (
          <HistoryView onOpen={(id) => void handleOpen(id)} onNew={goNew} />
        ) : null}
      </main>

      {error ? <div className="toast">{error}</div> : null}
    </div>
  );
}

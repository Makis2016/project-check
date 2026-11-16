import { useMemo, useState } from "react";
import type { Finding, Scan, ScanDiff, Severity } from "../types";
import {
  compareScan,
  desktopBridge,
  exportFilename,
  exportMeta,
  fetchExport,
  type ExportFormat,
} from "../api";
import FindingCard from "../components/FindingCard";
import { SEVERITY_META, SEVERITY_ORDER, SeverityBadge, SeveritySummary } from "../components/Severity";
import {
  AlertIcon,
  ChevronIcon,
  DiffIcon,
  DownloadIcon,
  LinkIcon,
  RefreshIcon,
  SearchIcon,
  ServerIcon,
} from "../components/Icons";
import { formatDuration, formatTime, hostOf, PRESET_LABEL, riskLevel } from "../format";

type Tab = "findings" | "endpoints" | "assets" | "compare";

interface Props {
  scan: Scan;
  onBack: () => void;
  onRescan: (target: string) => void;
}

const STATUS_LABEL: Record<string, string> = {
  completed: "已完成",
  running: "进行中",
  failed: "失败",
  stopped: "已中止",
  queued: "排队中",
};

function DiffList({
  title,
  tone,
  items,
}: {
  title: string;
  tone: "added" | "resolved" | "persisting";
  items: Finding[];
}) {
  if (!items.length) return null;
  return (
    <section className={`diff-list diff-${tone}`}>
      <header>
        <span>{title}</span>
        <b>{items.length}</b>
      </header>
      <ul>
        {items.slice(0, 50).map((item, index) => (
          <li key={`${item.check_id}-${item.url}-${index}`}>
            <span className={`diff-sev sev-bg-${item.severity}`} />
            <span className="diff-title">{item.title}</span>
            <span className="diff-url mono">{item.method || "GET"} {item.url}</span>
          </li>
        ))}
      </ul>
      {items.length > 50 ? <div className="table-foot">仅展示前 50 条</div> : null}
    </section>
  );
}

export default function ReportView({ scan, onBack, onRescan }: Props) {
  const [tab, setTab] = useState<Tab>("findings");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [query, setQuery] = useState("");
  const [exporting, setExporting] = useState<ExportFormat | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [exportNote, setExportNote] = useState("");
  const [exportFailed, setExportFailed] = useState(false);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState("");

  const handleExport = async (format: ExportFormat) => {
    if (exporting) return;
    setExportOpen(false);
    setExporting(format);
    setExportNote("");
    setExportFailed(false);
    const meta = exportMeta(format);
    try {
      const text = await fetchExport(scan.id, format);
      const filename = exportFilename(scan.id, format);
      const bridge = desktopBridge();
      if (bridge?.save_report) {
        const result = await bridge.save_report(filename, text, [meta.fileType]);
        if (result?.cancelled) return;
        if (!result?.ok) throw new Error(result?.error || "保存失败");
        setExportNote(`已保存${meta.label}到 ${result.path ?? filename}`);
      } else {
        const blob = new Blob([text], { type: meta.mime });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setExportNote(`已导出 ${meta.label}`);
      }
    } catch (error) {
      setExportFailed(true);
      setExportNote(error instanceof Error ? error.message : "导出失败，请重试");
    } finally {
      setExporting(null);
    }
  };

  const openTab = (next: Tab) => {
    setTab(next);
    if (next === "compare" && !diff && !diffLoading) {
      void loadDiff();
    }
  };

  const loadDiff = async () => {
    setDiffLoading(true);
    setDiffError("");
    try {
      const result = await compareScan(scan.id);
      setDiff(result);
    } catch (error) {
      setDiffError(error instanceof Error ? error.message : "对比失败");
    } finally {
      setDiffLoading(false);
    }
  };

  const summary = scan.summary;
  const findings = scan.findings ?? [];
  const endpoints = scan.discovery?.endpoints ?? [];
  const tech = scan.discovery?.tech ?? [];
  const assets = scan.assets;
  const risk = riskLevel(summary);

  const counts = useMemo(() => {
    const base: Record<string, number> = { all: findings.length };
    SEVERITY_ORDER.forEach((item) => {
      base[item] = findings.filter((finding) => finding.severity === item).length;
    });
    return base;
  }, [findings]);

  const filtered = useMemo(() => {
    const lower = query.trim().toLowerCase();
    return findings.filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false;
      if (!lower) return true;
      return [finding.title, finding.url, finding.description, finding.check_id]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(lower));
    });
  }, [findings, severity, query]);

  const filteredEndpoints = useMemo(() => {
    const lower = query.trim().toLowerCase();
    if (!lower) return endpoints;
    return endpoints.filter((endpoint) => endpoint.url.toLowerCase().includes(lower));
  }, [endpoints, query]);

  const tls = (assets?.tls ?? {}) as Record<string, unknown>;
  const issuer = (tls.issuer ?? {}) as Record<string, string>;

  return (
    <div className="view report-view">
      <header className="report-head">
        <div className="report-head-main">
          <button className="back-link" onClick={onBack}>← 返回</button>
          <div className="report-title-row">
            <h1>{hostOf(scan.target)}</h1>
            <span className={`risk-pill tone-${risk.tone}`}>{risk.label}</span>
            <span className={`status-pill status-${scan.status}`}>{STATUS_LABEL[scan.status] ?? scan.status}</span>
          </div>
          <div className="scan-sub mono">{scan.target}</div>
          <div className="report-meta">
            <span>{formatTime(scan.created_at)}</span>
            <span>{formatDuration(summary?.duration_ms)}</span>
            <span>{PRESET_LABEL[scan.preset] ?? scan.preset}</span>
            <span>{summary?.request_count ?? 0} 请求</span>
            <span>{summary?.page_count ?? 0} 页面</span>
            <span>{summary?.endpoint_count ?? 0} 接口</span>
          </div>
        </div>
        <div className="report-actions">
          <span className={`export-note ${exportFailed ? "is-error" : ""}`}>{exportNote}</span>
          <div className="export-menu">
            <button className="btn" onClick={() => setExportOpen((value) => !value)} disabled={Boolean(exporting)}>
              <DownloadIcon width={16} height={16} /> {exporting ? `导出 ${exportMeta(exporting).label}…` : "导出报告"}
              <ChevronIcon className={`chevron export-chevron ${exportOpen ? "rotated" : ""}`} width={14} height={14} />
            </button>
            {exportOpen && !exporting ? (
              <div className="export-list">
                {(["html", "md", "json", "csv"] as ExportFormat[]).map((format) => (
                  <button key={format} className="export-item" onClick={() => void handleExport(format)}>
                    <span>{exportMeta(format).label}</span>
                    <em>.{exportMeta(format).ext}</em>
                  </button>
                ))}
              </div>
            ) : null}
          </div>
          <button className="btn btn-primary" onClick={() => onRescan(scan.target)}>
            <RefreshIcon width={16} height={16} /> 重新扫描
          </button>
        </div>
      </header>

      {scan.status === "failed" ? (
        <div className="notice error">
          <AlertIcon width={16} height={16} /> {scan.error || "扫描失败"}
        </div>
      ) : null}
      {scan.status === "stopped" ? (
        <div className="notice warn">
          <AlertIcon width={16} height={16} /> 扫描被中止，以下为已完成部分的发现。
        </div>
      ) : null}

      {summary ? <SeveritySummary summary={summary} /> : null}

      <div className="metric-row">
        <div className="metric"><span>页面</span><b>{summary?.page_count ?? 0}</b></div>
        <div className="metric"><span>接口</span><b>{summary?.endpoint_count ?? 0}</b></div>
        <div className="metric"><span>开放端口</span><b>{assets?.open_ports?.length ?? 0}</b></div>
        <div className="metric"><span>组件指纹</span><b>{tech.length}</b></div>
        <div className="metric"><span>请求</span><b>{summary?.request_count ?? 0}</b></div>
      </div>

      <div className="tabs">
        <button className={`tab ${tab === "findings" ? "active" : ""}`} onClick={() => openTab("findings")}>
          发现 <span>{findings.length}</span>
        </button>
        <button className={`tab ${tab === "endpoints" ? "active" : ""}`} onClick={() => openTab("endpoints")}>
          接口 <span>{endpoints.length}</span>
        </button>
        <button className={`tab ${tab === "assets" ? "active" : ""}`} onClick={() => openTab("assets")}>
          资产 <span>{(assets?.open_ports?.length ?? 0) + tech.length}</span>
        </button>
        <button className={`tab ${tab === "compare" ? "active" : ""}`} onClick={() => openTab("compare")}>
          <DiffIcon width={14} height={14} /> 对比
          {diff?.available && diff.counts ? <span className="tab-delta">+{diff.counts.added}</span> : null}
        </button>
        {tab !== "compare" ? (
          <div className="toolbar-search">
            <SearchIcon width={15} height={15} />
            <input
              className="search-input"
              placeholder={tab === "findings" ? "搜索发现…" : "搜索接口…"}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
        ) : null}
      </div>

      {tab === "findings" ? (
        <>
          <div className="chips">
            <button className={`chip ${severity === "all" ? "active" : ""}`} onClick={() => setSeverity("all")}>
              全部 <span>{counts.all}</span>
            </button>
            {SEVERITY_ORDER.map((item) => (
              <button
                key={item}
                className={`chip chip-${item} ${severity === item ? "active" : ""}`}
                onClick={() => setSeverity(item)}
              >
                <span className={`chip-dot sev-bg-${item}`} />
                {SEVERITY_META[item].label} <span>{counts[item] ?? 0}</span>
              </button>
            ))}
          </div>

          <div className="finding-list">
            {filtered.map((finding, index) => (
              <FindingCard key={`${finding.check_id}-${index}`} finding={finding} index={index} />
            ))}
            {filtered.length === 0 ? (
              <div className="empty">
                <LinkIcon width={22} height={22} />
                <strong>没有匹配的发现</strong>
                <p>调整筛选条件，或扫描完成后回来查看。</p>
              </div>
            ) : null}
          </div>
        </>
      ) : null}

      {tab === "endpoints" ? (
        <div className="panel table-panel">
          <table className="data-table">
            <thead>
              <tr>
                <th>方法</th>
                <th>地址</th>
                <th>来源</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {filteredEndpoints.slice(0, 300).map((endpoint, index) => (
                <tr key={`${endpoint.method}-${endpoint.url}-${index}`}>
                  <td><span className="method-chip">{endpoint.method}</span></td>
                  <td className="mono cell-url">{endpoint.url}</td>
                  <td><span className="source-chip">{endpoint.source}</span></td>
                  <td className="mono">{endpoint.status ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filteredEndpoints.length === 0 ? <div className="empty-row">没有发现接口</div> : null}
          {filteredEndpoints.length > 300 ? <div className="table-foot">仅展示前 300 条</div> : null}
        </div>
      ) : null}

      {tab === "compare" ? (
        <div className="compare-view">
          {diffLoading ? (
            <div className="panel compare-loading"><span className="spinner" /> 正在查找同一目标的上一次扫描…</div>
          ) : null}
          {diffError ? (
            <div className="notice error"><AlertIcon width={16} height={16} /> {diffError}</div>
          ) : null}
          {diff && !diff.available ? (
            <div className="empty">
              <DiffIcon width={24} height={24} />
              <strong>暂无可对比的历史扫描</strong>
              <p>{diff.reason ?? "完成一次新的扫描后再回来查看变化。"}</p>
            </div>
          ) : null}
          {diff?.available ? (
            <>
              <div className="diff-overview">
                <div className="diff-side">
                  <span>基线扫描</span>
                  <b>{formatTime(diff.base?.created_at)}</b>
                  <em>{PRESET_LABEL[diff.base?.preset ?? ""] ?? diff.base?.preset}</em>
                </div>
                <div className="diff-arrow">→</div>
                <div className="diff-side">
                  <span>当前扫描</span>
                  <b>{formatTime(diff.current?.created_at)}</b>
                  <em>{PRESET_LABEL[diff.current?.preset ?? ""] ?? diff.current?.preset}</em>
                </div>
                <div className="diff-stats">
                  <div className="diff-stat added"><b>+{diff.counts?.added ?? 0}</b><span>新增</span></div>
                  <div className="diff-stat resolved"><b>-{diff.counts?.resolved ?? 0}</b><span>已修复</span></div>
                  <div className="diff-stat persisting"><b>{diff.counts?.persisting ?? 0}</b><span>仍存在</span></div>
                </div>
              </div>
              <DiffList title="新增风险" tone="added" items={diff.added ?? []} />
              <DiffList title="已修复" tone="resolved" items={diff.resolved ?? []} />
              <DiffList title="仍存在" tone="persisting" items={diff.persisting ?? []} />
              {(diff.counts?.added ?? 0) === 0 && (diff.counts?.resolved ?? 0) === 0 ? (
                <div className="table-foot">与基线相比没有变化。</div>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}

      {tab === "assets" ? (
        <div className="asset-grid">
          <section className="panel asset-card">
            <header className="panel-head"><span><ServerIcon width={15} height={15} /> 解析与端口</span></header>
            <div className="asset-body">
              <div className="asset-label">解析地址</div>
              <div className="tag-row">
                {(assets?.resolved_ips ?? []).map((ip) => <span key={ip} className="tag mono">{ip}</span>)}
                {!assets?.resolved_ips?.length ? <span className="muted">未获取</span> : null}
              </div>
              <div className="asset-label">开放端口</div>
              <div className="tag-row">
                {(assets?.open_ports ?? []).map((port) => (
                  <span key={port.port} className={`tag mono ${[2375, 6379, 9200, 11211, 27017, 3306].includes(port.port) ? "tag-risk" : ""}`}>
                    {port.port} <em>{port.service}</em>
                  </span>
                ))}
                {!assets?.open_ports?.length ? <span className="muted">未探测或未发现</span> : null}
              </div>
            </div>
          </section>

          <section className="panel asset-card">
            <header className="panel-head"><span>TLS 证书</span></header>
            <div className="asset-body">
              {tls.supported ? (
                <dl className="kv">
                  <dt>协议</dt><dd className="mono">{String(tls.protocol ?? "—")}</dd>
                  <dt>校验</dt><dd>{tls.verified ? "通过" : "失败"}</dd>
                  <dt>到期</dt><dd className="mono">{String(tls.not_after ?? "—")}</dd>
                  <dt>剩余</dt><dd>{typeof tls.days_left === "number" ? `${tls.days_left} 天` : "—"}</dd>
                  <dt>签发者</dt><dd>{issuer.O || issuer.CN || "—"}</dd>
                </dl>
              ) : (
                <span className="muted">未探测到 TLS，或目标为 HTTP。</span>
              )}
            </div>
          </section>

          <section className="panel asset-card">
            <header className="panel-head"><span>组件指纹</span></header>
            <div className="asset-body">
              <div className="tag-row">
                {tech.map((item) => (
                  <span key={`${item.name}-${item.version}`} className="tag">
                    {item.name} {item.version ? <em>{item.version}</em> : null}
                  </span>
                ))}
                {!tech.length ? <span className="muted">未识别到组件</span> : null}
              </div>
            </div>
          </section>

          <section className="panel asset-card">
            <header className="panel-head"><span>子域名与文档</span></header>
            <div className="asset-body">
              <div className="asset-label">子域名</div>
              <div className="tag-row">
                {(assets?.subdomains ?? []).map((item) => <span key={item} className="tag mono">{item}</span>)}
                {!assets?.subdomains?.length ? <span className="muted">未启用或未发现</span> : null}
              </div>
              <div className="asset-label">接口文档</div>
              <div className="tag-row">
                {(scan.discovery?.docs ?? []).map((item) => (
                  <a key={item} className="tag tag-link mono" href={item} target="_blank" rel="noreferrer">{item}</a>
                ))}
                {!scan.discovery?.docs?.length ? <span className="muted">未发现公开文档</span> : null}
              </div>
            </div>
          </section>
        </div>
      ) : null}

      <footer className="report-foot">
        自动化结果可能存在误报或漏报，请结合人工复核。本工具不执行口令爆破、盲注等高风险行为。
      </footer>
    </div>
  );
}

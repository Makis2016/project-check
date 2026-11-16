import type { Severity, Summary } from "../types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<Severity, { label: string; short: string }> = {
  critical: { label: "严重", short: "CRIT" },
  high: { label: "高危", short: "HIGH" },
  medium: { label: "中危", short: "MED" },
  low: { label: "低危", short: "LOW" },
  info: { label: "信息", short: "INFO" },
};

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info;
  return (
    <span className={`severity-badge sev-${severity}`}>
      <span className="severity-dot" />
      {compact ? meta.short : meta.label}
    </span>
  );
}

export function SeveritySummary({ summary }: { summary: Summary }) {
  return (
    <div className="summary-grid">
      {SEVERITY_ORDER.map((severity) => (
        <div key={severity} className={`summary-card sev-border-${severity}`}>
          <div className={`summary-count sev-text-${severity}`}>{summary[severity] ?? 0}</div>
          <div className="summary-label">{SEVERITY_META[severity].label}</div>
          <div className="summary-bar">
            <span
              className={`summary-bar-fill sev-bg-${severity}`}
              style={{ width: `${Math.min(100, ((summary[severity] ?? 0) / Math.max(summary.total, 1)) * 100)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

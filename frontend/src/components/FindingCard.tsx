import { useState } from "react";
import type { Finding } from "../types";
import { ChevronIcon, CodeIcon } from "./Icons";
import { SeverityBadge } from "./Severity";

const CONFIDENCE_LABEL: Record<string, string> = { high: "高置信", medium: "中置信", low: "低置信" };

export default function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(index < 2);
  return (
    <article className={`finding-card sev-left-${finding.severity} ${open ? "open" : ""}`}>
      <button className="finding-head" onClick={() => setOpen((value) => !value)}>
        <span className={`finding-index sev-text-${finding.severity}`}>{index + 1}</span>
        <div className="finding-heading">
          <div className="finding-title">{finding.title}</div>
          <div className="finding-sub">
            {finding.url ? <span className="mono ellipsis">{finding.method || "GET"} {finding.url}</span> : null}
            {finding.param ? <span className="param-chip">参数 {finding.param}</span> : null}
          </div>
        </div>
        <div className="finding-badges">
          <SeverityBadge severity={finding.severity} />
          <span className="confidence">{CONFIDENCE_LABEL[finding.confidence] ?? finding.confidence}</span>
          <ChevronIcon className={`chevron ${open ? "rotated" : ""}`} width={16} height={16} />
        </div>
      </button>
      {open ? (
        <div className="finding-body">
          {finding.description ? <p className="finding-desc">{finding.description}</p> : null}
          {finding.evidence ? (
            <div className="evidence">
              <div className="evidence-label"><CodeIcon width={14} height={14} /> 证据</div>
              <pre>{finding.evidence}</pre>
            </div>
          ) : null}
          {finding.remediation ? (
            <div className="remediation">
              <div className="remediation-label">修复建议</div>
              <p>{finding.remediation}</p>
            </div>
          ) : null}
          <div className="finding-meta">
            {finding.cwe ? <span className="meta-chip">{finding.cwe}</span> : null}
            {finding.owasp ? <span className="meta-chip">{finding.owasp}</span> : null}
            {finding.category ? <span className="meta-chip">{finding.category}</span> : null}
            {(finding.references ?? []).map((reference) => (
              <a key={reference} className="meta-link" href={reference} target="_blank" rel="noreferrer">
                参考链接
              </a>
            ))}
          </div>
        </div>
      ) : null}
    </article>
  );
}

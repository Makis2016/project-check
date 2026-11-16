import { useState } from "react";
import type { Finding } from "../types";
import { ChevronIcon, CodeIcon, CopyIcon } from "./Icons";
import { SeverityBadge } from "./Severity";

const CONFIDENCE_LABEL: Record<string, string> = { high: "高置信", medium: "中置信", low: "低置信" };

type ExchangeTab = "request" | "response" | "curl";

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

export default function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(index < 2);
  const [exchangeTab, setExchangeTab] = useState<ExchangeTab | null>(null);
  const [copied, setCopied] = useState("");

  const allTabs: Array<{ id: ExchangeTab; label: string; text?: string }> = [
    { id: "request", label: "请求", text: finding.request },
    { id: "response", label: "响应", text: finding.response },
    { id: "curl", label: "cURL", text: finding.curl },
  ];
  const tabs = allTabs.filter((item) => Boolean(item.text));
  const activeTab = tabs.find((item) => item.id === exchangeTab) ?? tabs[0];

  const copy = async (text: string | undefined, label: string) => {
    if (!text) return;
    await copyText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1600);
  };

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
          {tabs.length ? (
            <div className="exchange">
              <div className="exchange-head">
                <div className="exchange-tabs">
                  {tabs.map((item) => (
                    <button
                      key={item.id}
                      className={`exchange-tab ${activeTab?.id === item.id ? "active" : ""}`}
                      onClick={() => setExchangeTab(item.id)}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
                <button className="exchange-copy" onClick={() => void copy(activeTab?.text, activeTab?.id ?? "")}>
                  <CopyIcon width={13} height={13} />
                  {copied === activeTab?.id ? "已复制" : "复制"}
                </button>
              </div>
              <pre className="exchange-body">{activeTab?.text}</pre>
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
            {finding.curl ? (
              <button className="meta-copy" onClick={() => void copy(finding.curl, "curl")}>
                <CopyIcon width={12} height={12} />
                {copied === "curl" ? "已复制 cURL" : "复制 cURL"}
              </button>
            ) : null}
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

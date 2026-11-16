import { useEffect, useState } from "react";
import type { ScanPayload } from "../types";
import { AlertIcon, CheckIcon, PlayIcon, ShieldIcon } from "../components/Icons";

interface Props {
  initialTarget?: string;
  onStart: (payload: ScanPayload) => Promise<void>;
}

const PRESETS = [
  {
    id: "quick",
    name: "快速体检",
    tag: "轻量",
    desc: "只做配置与暴露面检查，不发主动 payload",
    meta: "约 20 页面 · 被动检测",
  },
  {
    id: "standard",
    name: "标准扫描",
    tag: "推荐",
    desc: "配置检测 + 低风险主动验证，覆盖常见问题",
    meta: "约 60 页面 · 含 XSS/SQLi 验证",
  },
  {
    id: "deep",
    name: "深度扫描",
    tag: "全面",
    desc: "扩大抓取与端口范围，追加子域名枚举",
    meta: "约 150 页面 · 用时更长",
  },
];

export default function NewScan({ initialTarget = "", onStart }: Props) {
  const [target, setTarget] = useState(initialTarget);
  const [preset, setPreset] = useState("standard");
  const [authorized, setAuthorized] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [cookie, setCookie] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [rate, setRate] = useState(5);
  const [activeChecks, setActiveChecks] = useState(true);
  const [scanPorts, setScanPorts] = useState(true);
  const [portsText, setPortsText] = useState("");
  const [subdomains, setSubdomains] = useState(false);
  const [ignoreTls, setIgnoreTls] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (initialTarget) setTarget(initialTarget);
  }, [initialTarget]);

  const choosePreset = (id: string) => {
    setPreset(id);
    setActiveChecks(id !== "quick");
    setScanPorts(id !== "quick");
    setSubdomains(id === "deep");
  };

  const parseHeaders = (): Record<string, string> => {
    const headers: Record<string, string> = {};
    headersText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((line) => {
        const index = line.indexOf(":");
        if (index > 0) {
          const key = line.slice(0, index).trim();
          const value = line.slice(index + 1).trim();
          if (key) headers[key] = value;
        }
      });
    return headers;
  };

  const parsePorts = (): number[] | undefined => {
    const parts = portsText
      .split(/[\s,]+/)
      .map((part) => Number(part.trim()))
      .filter((port) => Number.isInteger(port) && port > 0 && port < 65536);
    return parts.length ? parts : undefined;
  };

  const submit = async () => {
    setError("");
    const cleanTarget = target.trim();
    if (!cleanTarget) {
      setError("请输入要体检的站点地址");
      return;
    }
    if (!authorized) {
      setError("请先确认你拥有该目标的所有权或已获得授权");
      return;
    }
    setSubmitting(true);
    try {
      await onStart({
        target: cleanTarget,
        preset,
        authorization_confirmed: true,
        cookie: cookie.trim() || undefined,
        headers: Object.keys(parseHeaders()).length ? parseHeaders() : undefined,
        rate_limit: rate,
        active_checks: activeChecks,
        scan_ports: scanPorts,
        ports: parsePorts(),
        subdomain_enum: subdomains,
        ignore_tls: ignoreTls,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "启动扫描失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="view new-scan">
      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="pulse-dot" />
            WEB SECURITY CHECKUP
          </div>
          <h1>
            给站点做一次
            <br />
            <span className="gradient-text">全身检查</span>
          </h1>
          <p>
            自动发现页面与接口，检查安全配置、暴露面与常见注入风险，
            并为每一条问题给出可执行的修复建议。
          </p>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="radar">
            <span className="radar-ring ring-1" />
            <span className="radar-ring ring-2" />
            <span className="radar-ring ring-3" />
            <span className="radar-sweep" />
            <span className="radar-node node-1" />
            <span className="radar-node node-2" />
            <span className="radar-node node-3" />
            <div className="radar-core">
              <ShieldIcon width={26} height={26} />
            </div>
          </div>
          <div className="hero-chip chip-a">接口发现</div>
          <div className="hero-chip chip-b">配置检测</div>
          <div className="hero-chip chip-c">修复建议</div>
        </div>
      </section>

      <section className="panel scan-panel">
        <div className="url-row">
          <div className="url-input-wrap">
            <span className="url-prefix">https://</span>
            <input
              className="url-input"
              placeholder="your-site.com"
              value={target.replace(/^https?:\/\//, "")}
              onChange={(event) => setTarget(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void submit();
              }}
              spellCheck={false}
              autoFocus
            />
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => void submit()} disabled={submitting}>
            {submitting ? <span className="spinner" /> : <PlayIcon width={18} height={18} />}
            {submitting ? "启动中" : "开始体检"}
          </button>
        </div>
        <div className="url-hint">支持 http/https 地址；扫描全程限速，且受请求预算保护。</div>

        <div className="preset-grid">
          {PRESETS.map((item) => (
            <button
              key={item.id}
              className={`preset-card ${preset === item.id ? "active" : ""}`}
              onClick={() => choosePreset(item.id)}
            >
              <div className="preset-top">
                <span className="preset-name">{item.name}</span>
                <span className={`preset-tag ${item.id === "standard" ? "hot" : ""}`}>{item.tag}</span>
                {preset === item.id ? <CheckIcon className="preset-check" width={16} height={16} /> : null}
              </div>
              <p>{item.desc}</p>
              <div className="preset-meta">{item.meta}</div>
            </button>
          ))}
        </div>

        <button className="advanced-toggle" onClick={() => setAdvanced((value) => !value)}>
          <span className={`toggle-arrow ${advanced ? "open" : ""}`}>›</span>
          高级选项
          <span className="advanced-sub">会话 Cookie、自定义 Header、限速、端口</span>
        </button>

        {advanced ? (
          <div className="advanced-panel">
            <div className="field-grid">
              <label className="field">
                <span className="label">会话 Cookie</span>
                <input
                  className="input mono"
                  placeholder="sessionid=...; token=..."
                  value={cookie}
                  onChange={(event) => setCookie(event.target.value)}
                  spellCheck={false}
                />
                <span className="hint">填写后可覆盖登录后的页面与接口</span>
              </label>
              <label className="field">
                <span className="label">自定义请求 Header</span>
                <textarea
                  className="input mono textarea"
                  placeholder={"Authorization: Bearer xxx\nX-Custom: value"}
                  value={headersText}
                  onChange={(event) => setHeadersText(event.target.value)}
                  rows={3}
                  spellCheck={false}
                />
                <span className="hint">每行一个，格式 Key: Value</span>
              </label>
            </div>

            <div className="field-grid three">
              <label className="field">
                <span className="label">请求速率 · {rate} req/s</span>
                <input
                  type="range"
                  min={1}
                  max={20}
                  step={1}
                  value={rate}
                  onChange={(event) => setRate(Number(event.target.value))}
                />
                <span className="hint">速率越高越快，但更容易触发告警</span>
              </label>
              <label className="field">
                <span className="label">端口列表（可选）</span>
                <input
                  className="input mono"
                  placeholder="80, 443, 8080"
                  value={portsText}
                  onChange={(event) => setPortsText(event.target.value)}
                  spellCheck={false}
                />
                <span className="hint">留空则使用预设常见端口</span>
              </label>
              <div className="field switches">
                <span className="label">扫描开关</span>
                <label className="switch-row">
                  <input type="checkbox" checked={activeChecks} onChange={(e) => setActiveChecks(e.target.checked)} />
                  <span className="switch" />
                  主动验证（XSS / SQLi / 重定向）
                </label>
                <label className="switch-row">
                  <input type="checkbox" checked={scanPorts} onChange={(e) => setScanPorts(e.target.checked)} />
                  <span className="switch" />
                  端口探测
                </label>
                <label className="switch-row">
                  <input type="checkbox" checked={subdomains} onChange={(e) => setSubdomains(e.target.checked)} />
                  <span className="switch" />
                  子域名枚举
                </label>
                <label className="switch-row">
                  <input type="checkbox" checked={ignoreTls} onChange={(e) => setIgnoreTls(e.target.checked)} />
                  <span className="switch" />
                  忽略 TLS 证书错误
                </label>
              </div>
            </div>
          </div>
        ) : null}

        <label className="auth-box">
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
          <span className="auth-check"><CheckIcon width={14} height={14} /></span>
          <span>
            我确认对该目标拥有所有权，或已获得明确的扫描授权。扫描行为会记录在本地历史中。
          </span>
        </label>

        {error ? (
          <div className="error-banner">
            <AlertIcon width={16} height={16} />
            {error}
          </div>
        ) : null}
      </section>

      <section className="feature-row">
        <div className="feature">
          <span className="feature-num">01</span>
          <div>
            <strong>接口尽量发现</strong>
            <p>爬虫、表单、JS 包、robots、sitemap 与 API 文档多路并行。</p>
          </div>
        </div>
        <div className="feature">
          <span className="feature-num">02</span>
          <div>
            <strong>证据可复核</strong>
            <p>每条发现保留请求位置与响应片段，拒绝“只报不证”。</p>
          </div>
        </div>
        <div className="feature">
          <span className="feature-num">03</span>
          <div>
            <strong>修复可落地</strong>
            <p>建议包含配置片段与代码改法，导出 Markdown 直接进工单。</p>
          </div>
        </div>
      </section>
    </div>
  );
}

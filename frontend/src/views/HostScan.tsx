import { useState } from "react";
import type { ScanPayload } from "../types";
import { AlertIcon, CheckIcon, PlayIcon, ServerIcon } from "../components/Icons";

type HostType = "linux" | "windows";

interface Props {
  initialTarget?: string;
  initialScanType?: HostType;
  onStart: (payload: ScanPayload) => Promise<void>;
}

function parseSshTarget(target: string) {
  const value = target.trim();
  if (!value.startsWith("ssh://")) return { host: value, port: "22", user: "" };
  try {
    const parsed = new URL(value);
    return {
      host: parsed.hostname.replace(/^\[|\]$/g, ""),
      port: parsed.port || "22",
      user: decodeURIComponent(parsed.username),
    };
  } catch {
    return { host: value, port: "22", user: "" };
  }
}

export default function HostScan({ initialTarget = "", initialScanType = "linux", onStart }: Props) {
  const initial = parseSshTarget(initialTarget);
  const [scanType, setScanType] = useState<HostType>(initialScanType);
  const [host, setHost] = useState(initial.host);
  const [port, setPort] = useState(initial.port);
  const [user, setUser] = useState(initial.user || (initialScanType === "windows" ? "Administrator" : "root"));
  const [authMode, setAuthMode] = useState<"password" | "key">("password");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const chooseScanType = (next: HostType) => {
    setScanType(next);
    setUser((current) => {
      if (next === "windows" && (!current || current === "root")) return "Administrator";
      if (next === "linux" && (!current || current === "Administrator")) return "root";
      return current;
    });
  };

  const submit = async () => {
    setError("");
    const cleanHost = parseSshTarget(host).host.trim();
    if (!cleanHost) {
      setError("请输入主机 IP 或域名");
      return;
    }
    if (!user.trim()) {
      setError("请填写 SSH 用户名");
      return;
    }
    if (authMode === "password" && !password) {
      setError("请填写 SSH 密码，或切换到私钥认证");
      return;
    }
    if (authMode === "key" && !keyPath.trim()) {
      setError("请填写私钥文件路径");
      return;
    }
    if (!authorized) {
      setError("请先确认你拥有该主机的所有权或已获得授权");
      return;
    }
    setSubmitting(true);
    try {
      await onStart({
        target: cleanHost,
        preset: "standard",
        scan_type: scanType,
        authorization_confirmed: true,
        ssh_port: Number(port) || 22,
        ssh_user: user.trim(),
        ssh_password: authMode === "password" ? password : undefined,
        ssh_key_path: authMode === "key" ? keyPath.trim() : undefined,
        ssh_key_passphrase: authMode === "key" ? passphrase : undefined,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "启动巡检失败");
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
            {scanType === "windows" ? "WINDOWS" : "LINUX"} HOST CHECKUP
          </div>
          <h1>
            给服务器做一次
            <br />
            <span className="gradient-text">补丁与配置体检</span>
          </h1>
          <p>
            {scanType === "windows"
              ? "通过 Windows OpenSSH 调用 PowerShell 只读采集系统、补丁、防火墙、Defender 与 SMBv1 状态，全程不修改目标系统。"
              : "通过 SSH 只读采集系统信息、待安装更新与服务配置，检查补丁滞后、SSH 加固、防火墙与权限隔离等主机层风险。"}
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
              <ServerIcon width={26} height={26} />
            </div>
          </div>
          <div className="hero-chip chip-a">补丁检查</div>
          <div className="hero-chip chip-b">{scanType === "windows" ? "Defender / SMBv1" : "SSH 加固"}</div>
          <div className="hero-chip chip-c">只读采集</div>
        </div>
      </section>

      <section className="panel scan-panel">
        <div className="url-row">
          <div className="url-input-wrap">
            <span className="url-prefix">ssh://</span>
            <input
              className="url-input"
              placeholder="10.0.0.12 或 server.example.com"
              value={host}
              onChange={(event) => setHost(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void submit();
              }}
              spellCheck={false}
              autoFocus
            />
          </div>
          <button className="btn btn-primary btn-lg" onClick={() => void submit()} disabled={submitting}>
            {submitting ? <span className="spinner" /> : <PlayIcon width={18} height={18} />}
            {submitting ? "连接中" : "开始巡检"}
          </button>
        </div>
        <div className="url-hint">只执行读取类命令，不使用 sudo，不安装软件，不修改任何配置。</div>

        <div className="chips" aria-label="主机系统类型">
          <button className={`chip ${scanType === "linux" ? "active" : ""}`} onClick={() => chooseScanType("linux")} type="button">
            Linux
          </button>
          <button className={`chip ${scanType === "windows" ? "active" : ""}`} onClick={() => chooseScanType("windows")} type="button">
            Windows
          </button>
        </div>

        <div className="field-grid">
          <label className="field">
            <span className="label">SSH 端口</span>
            <input
              className="input mono"
              value={port}
              onChange={(event) => setPort(event.target.value.replace(/[^\d]/g, "").slice(0, 5))}
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span className="label">SSH 用户名</span>
            <input
              className="input mono"
              placeholder={scanType === "windows" ? "Administrator" : "root"}
              value={user}
              onChange={(event) => setUser(event.target.value)}
              spellCheck={false}
            />
            <span className="hint">
              {scanType === "windows" ? "建议使用可读取系统、更新与安全状态的巡检账号" : "建议使用具有只读权限的普通账号"}
            </span>
          </label>
        </div>

        <div className="chips">
          <button
            className={`chip ${authMode === "password" ? "active" : ""}`}
            onClick={() => setAuthMode("password")}
            type="button"
          >
            密码认证
          </button>
          <button
            className={`chip ${authMode === "key" ? "active" : ""}`}
            onClick={() => setAuthMode("key")}
            type="button"
          >
            私钥认证
          </button>
        </div>

        {authMode === "password" ? (
          <div className="field-grid">
            <label className="field">
              <span className="label">SSH 密码</span>
              <input
                className="input"
                type="password"
                placeholder="仅用于本次连接"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="off"
              />
              <span className="hint">密码只用于建立连接，不会写入扫描记录或报告</span>
            </label>
          </div>
        ) : (
          <div className="field-grid">
            <label className="field">
              <span className="label">私钥文件路径</span>
              <input
                className="input mono"
                placeholder="C:\\Users\\me\\.ssh\\id_ed25519 或 /home/me/.ssh/id_rsa"
                value={keyPath}
                onChange={(event) => setKeyPath(event.target.value)}
                spellCheck={false}
              />
              <span className="hint">填写本机上的私钥文件路径，巡检时读取一次，不会复制内容</span>
            </label>
            <label className="field">
              <span className="label">私钥口令（可选）</span>
              <input
                className="input"
                type="password"
                placeholder="私钥已加密时填写"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                autoComplete="off"
              />
            </label>
          </div>
        )}

        <label className="auth-box">
          <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
          <span className="auth-check"><CheckIcon width={14} height={14} /></span>
          <span>
            我确认拥有该主机的所有权，或已获得明确的巡检授权。巡检记录会保存在本地历史中。
          </span>
        </label>

        {error ? (
          <div className="error-banner">
            <AlertIcon width={16} height={16} />
            {error}
          </div>
        ) : null}

        <div className="url-hint">
          {scanType === "windows"
            ? "巡检会采集：操作系统与版本、Windows Update、已安装补丁、运行服务与监听端口、防火墙、Defender、SMBv1、自动更新与重启标记。目标需启用 Windows OpenSSH Server 和 PowerShell。"
            : "巡检会采集：操作系统与内核、待安装更新、运行服务与监听端口、SSH 配置、防火墙、SELinux/AppArmor、UID 0 账号、自动更新与重启标记。"}
        </div>
      </section>
    </div>
  );
}

import type { Scan, ScanDiff, ScanEvent, ScanPayload } from "./types";

const BASE = "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    let detail = `请求失败（${response.status}）`;
    try {
      const data = await response.json();
      detail = data.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export function createScan(payload: ScanPayload): Promise<{ id: string; target: string; status: string }> {
  return request("/api/scans", { method: "POST", body: JSON.stringify(payload) });
}

export function getScan(id: string): Promise<Scan> {
  return request(`/api/scans/${id}`);
}

export function listScans(): Promise<{ scans: Scan[] }> {
  return request("/api/scans");
}

export function stopScan(id: string): Promise<{ ok: boolean }> {
  return request(`/api/scans/${id}/stop`, { method: "POST" });
}

export function deleteScan(id: string): Promise<{ ok: boolean }> {
  return request(`/api/scans/${id}`, { method: "DELETE" });
}

export type ExportFormat = "md" | "html" | "json" | "csv";

const EXPORT_META: Record<ExportFormat, { path: string; ext: string; mime: string; fileType: string; label: string }> = {
  md: { path: "report.md", ext: "md", mime: "text/markdown;charset=utf-8", fileType: "Markdown (*.md)", label: "Markdown" },
  html: { path: "report.html", ext: "html", mime: "text/html;charset=utf-8", fileType: "HTML (*.html)", label: "HTML 报告" },
  json: { path: "export.json", ext: "json", mime: "application/json;charset=utf-8", fileType: "JSON (*.json)", label: "JSON 数据" },
  csv: { path: "export.csv", ext: "csv", mime: "text/csv;charset=utf-8", fileType: "CSV (*.csv)", label: "CSV 表格" },
};

export function exportMeta(format: ExportFormat) {
  return EXPORT_META[format];
}

export function exportUrl(id: string, format: ExportFormat): string {
  return `${BASE}/api/scans/${id}/${EXPORT_META[format].path}`;
}

export function exportFilename(id: string, format: ExportFormat): string {
  return `vulnlens-${id}.${EXPORT_META[format].ext}`;
}

export async function fetchExport(id: string, format: ExportFormat): Promise<string> {
  const response = await fetch(exportUrl(id, format));
  if (!response.ok) {
    throw new Error(`导出失败（${response.status}）`);
  }
  return response.text();
}

export function compareScan(id: string, base?: string): Promise<ScanDiff> {
  const suffix = base ? `?base=${encodeURIComponent(base)}` : "";
  return request(`/api/scans/${id}/compare${suffix}`);
}

interface DesktopBridge {
  save_report?: (
    filename: string,
    content: string,
    fileTypes?: string[],
  ) => Promise<{ ok: boolean; path?: string; cancelled?: boolean; error?: string }>;
}

export function desktopBridge(): DesktopBridge | null {
  const bridge = (window as unknown as { pywebview?: { api?: DesktopBridge } }).pywebview;
  return bridge?.api ?? null;
}

export function streamScan(
  id: string,
  onEvent: (event: ScanEvent) => void,
  onEnd: () => void,
): () => void {
  const source = new EventSource(`${BASE}/api/scans/${id}/stream`);
  source.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as ScanEvent);
    } catch {
      /* ignore malformed frame */
    }
  };
  source.addEventListener("end", () => {
    source.close();
    onEnd();
  });
  return () => source.close();
}

import type { Scan, ScanEvent, ScanPayload } from "./types";

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

export function reportUrl(id: string): string {
  return `${BASE}/api/scans/${id}/report.md`;
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
